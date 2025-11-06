#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import pathlib

# === Mapeamento "regra -> CWE/OWASP/refs/remediação" ===
MAP = {
    "demo-weak-crypto-md5": {
        "cwe": "CWE-328",
        "owasp": "A02:2021 Cryptographic Failures",
        "references": [
            "https://cwe.mitre.org/data/definitions/328.html",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        ],
        "remediation": "Evite MD5/SHA-1. Use SHA-256/512 para hash não sensível ou KDF moderno "
                       "(bcrypt, scrypt, Argon2) para senhas; adicione sal único por valor."
    },
    "demo-insecure-hostname-verifier": {
        "cwe": "CWE-295",
        "owasp": "A02:2021 Cryptographic Failures",
        "references": [
            "https://cwe.mitre.org/data/definitions/295.html",
            "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning"
        ],
        "remediation": "Não retorne sempre true. Use o verificador padrão do JDK/cliente HTTP ou "
                       "um HostnameVerifier que verifique CN/SAN; considere pinning quando aplicável."
    },
    "demo-aws-key": {
        "cwe": "CWE-798",
        "owasp": "A02:2021 Cryptographic Failures",
        "references": [
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://owasp.org/www-project-top-ten/2017/A3-Sensitive-Data-Exposure"
        ],
        "remediation": "Remova segredos do código. Armazene em cofre (AWS Secrets Manager, Vault), "
                       "injete via variáveis de ambiente/CI, faça rotate das credenciais e adicione secret scanning."
    },
    "demo-sqli-concat": {
        "cwe": "CWE-89",
        "owasp": "A03:2021 Injection",
        "references": [
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/www-community/attacks/SQL_Injection"
        ],
        "remediation": "Use PreparedStatement/queries parametrizadas. Nunca concatene entrada do usuário em SQL; "
                       "valide/normalize entradas e aplique least-privilege no DB."
    }
}

LEVEL_TO_SECURITY_SEVERITY = { "error": "8.5", "warning": "5.0", "note": "2.0" }

def load_sarif(p: pathlib.Path) -> dict:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[]}]}        

def ensure_minimal(sarif: dict) -> dict:
    sarif.setdefault("version","2.1.0")
    sarif.setdefault("runs", [{"tool":{"driver":{"name":"semgrep"}},"results":[]}])
    return sarif

def get_or(obj, path, default=None):
    cur = obj
    for k in path:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        elif isinstance(cur, list) and isinstance(k, int) and 0 <= k < len(cur):
            cur = cur[k]
        else:
            return default
    return cur

def ensure_rule_object(run: dict, rule_id: str) -> dict:
    tool = run.setdefault("tool", {}).setdefault("driver", {})
    rules = tool.setdefault("rules", [])
    for rr in rules:
        if rr.get("id") == rule_id:
            return rr
    rr = {"id": rule_id, "properties": {"tags": []}}
    rules.append(rr)
    return rr

def add_github_recognized_tags(rule_obj: dict, cwe_code: str | None, owasp_id: str | None) -> None:
    props = rule_obj.setdefault("properties", {})
    tags = set(props.get("tags", []))

    # CWE → external/cwe/cwe-89 (minúsculo)
    if cwe_code and cwe_code.upper().startswith("CWE-"):
        try:
            num = cwe_code.split("-", 1)[1].strip()
            tags.add(f"external/cwe/cwe-{num.lower()}")
            # helpUri direto na página da CWE melhora o badge/link
            rule_obj["helpUri"] = f"https://cwe.mitre.org/data/definitions/{num}.html"
        except Exception:
            pass

    # OWASP 2021 → external/owasp/2021/a03 (minúsculo)
    if owasp_id and "2021" in owasp_id.upper():
        left = owasp_id.split()[0]  # ex "A03:2021"
        a_code = (left.split(":")[0]).lower() if ":" in left else left.lower()  # a03
        tags.add(f"external/owasp/2021/{a_code}")

    props["tags"] = sorted(tags)

def enrich(sarif: dict) -> dict:
    sarif = ensure_minimal(sarif)
    for run in sarif.get("runs", []):
        results = run.get("results", []) or []
        for r in results:
            rule_id = r.get("ruleId") or get_or(r, ["rule","id"])
            if not rule_id:
                continue

            # GARANTIR LIGAÇÃO EXPLÍCITA AO driver.rules
            r["ruleId"] = rule_id
            r["rule"] = {"id": rule_id}

            level = r.get("level","warning")
            props = r.get("properties", {}) if isinstance(r.get("properties"), dict) else {}

            m = MAP.get(rule_id)
            if m:
                props["cwe"] = m.get("cwe")
                props["owasp"] = m.get("owasp")
                props["references"] = m.get("references")
                props["remediation"] = m.get("remediation")

                rule_obj = ensure_rule_object(run, rule_id)
                add_github_recognized_tags(rule_obj, m.get("cwe"), m.get("owasp"))

                # Ajuda/Markdown visível ao abrir a regra
                help_chunks = []
                if m.get("remediation"):
                    help_chunks.append(f"**Remediação:** {m['remediation']}")
                if m.get("references"):
                    help_chunks.append("**Referências:**\n" + "\n".join(f"- {u}" for u in m["references"]))
                if help_chunks:
                    rule_obj["help"] = {"text": "\n".join(help_chunks), "markdown": "\n".join(help_chunks)}

            # severidade numérica para ranking
            props["security-severity"] = LEVEL_TO_SECURITY_SEVERITY.get(level, "5.0")
            r["properties"] = props
    return sarif

def write_markdown_summary(sarif: dict, out_md: pathlib.Path) -> None:
    lines = ["# Semgrep – Achados Enriquecidos (CWE/OWASP)\n"]
    total = 0
    for run in sarif.get("runs", []):
        for r in run.get("results") or []:
            total += 1
            rule = r.get("ruleId","(sem id)")
            msg = get_or(r, ["message","text"], "")
            file = get_or(r, ["locations",0,"physicalLocation","artifactLocation","uri"], "")
            line = get_or(r, ["locations",0,"physicalLocation","region","startLine"], "")
            level = r.get("level","warning")
            props = r.get("properties",{}) or {}
            cwe = props.get("cwe")
            owasp = props.get("owasp")
            refs = props.get("references",[])
            remediation = props.get("remediation")

            lines.append(f"## {rule}")
            lines.append(f"- **Arquivo**: `{file}:{line}`")
            lines.append(f"- **Nível (SARIF)**: `{level}`")
            if cwe:   lines.append(f"- **CWE**: `{cwe}`")
            if owasp: lines.append(f"- **OWASP**: `{owasp}`")
            if msg:   lines.append(f"- **Mensagem**: {msg}")
            if remediation:
                lines.append(f"- **Remediação**: {remediation}")
            if refs:
                lines.append("- **Referências:**")
                for u in refs: lines.append(f"  - {u}")
            lines.append("")
    lines.append(f"**Total de achados**: {total}")
    out_md.write_text("\n".join(lines), encoding="utf-8")

def main() -> None:
    in_path = pathlib.Path("semgrep.sarif")
    out_path = pathlib.Path("semgrep.enriched.sarif")
    md_path = pathlib.Path("semgrep.enriched.md")
    sarif = load_sarif(in_path)
    enriched = enrich(sarif)
    out_path.write_text(json.dumps(enriched, ensure_ascii=False), encoding="utf-8")
    write_markdown_summary(enriched, md_path)

if __name__ == "__main__":
    main()
