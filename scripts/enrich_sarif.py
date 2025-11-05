#!/usr/bin/env python3
import sys, json, pathlib

# Mapeamento "regra -> CWE/OWASP/refs/remediação"
MAP = {
  "demo-weak-crypto-md5": {
    "cwe": "CWE-328",
    "owasp": "A02:2021 Cryptographic Failures",
    "references": [
      "https://cwe.mitre.org/data/definitions/328.html",
      "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
    ],
    "remediation": "Evite MD5/SHA-1. Use SHA-256/512 para hash não sensível ou KDF moderno (bcrypt, scrypt, Argon2) para senhas; adicione sal único por valor."
  },
  "demo-insecure-hostname-verifier": {
    "cwe": "CWE-295",
    "owasp": "A02:2021 Cryptographic Failures",
    "references": [
      "https://cwe.mitre.org/data/definitions/295.html",
      "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning"
    ],
    "remediation": "Não retorne sempre true. Use o verificador padrão do JDK/cliente HTTP ou um HostnameVerifier que verifique CN/SAN; considere pinning quando aplicável."
  },
  "demo-aws-key": {
    "cwe": "CWE-798",
    "owasp": "A02:2021 Cryptographic Failures",
    "references": [
      "https://cwe.mitre.org/data/definitions/798.html",
      "https://owasp.org/www-project-top-ten/2017/A3-Sensitive-Data-Exposure"
    ],
    "remediation": "Remova segredos do código. Armazene em cofre (AWS Secrets Manager, Vault), injete via variáveis de ambiente/CI, faça rotate das credenciais e adicione secret scanning."
  },
  "demo-sqli-concat": {
    "cwe": "CWE-89",
    "owasp": "A03:2021 Injection",
    "references": [
      "https://cwe.mitre.org/data/definitions/89.html",
      "https://owasp.org/www-community/attacks/SQL_Injection"
    ],
    "remediation": "Use PreparedStatement/queries parametrizadas. Nunca concatene entrada do usuário em SQL; valide/normalize entradas e aplique least-privilege no DB."
  }
}

def ensure_rule_object(run, rule_id):
    """Garante que a regra exista em driver.rules e retorna o dict dela."""
    tool = run.setdefault("tool", {}).setdefault("driver", {})
    rules = tool.setdefault("rules", [])
    for rr in rules:
        if rr.get("id") == rule_id:
            return rr
    rr = {"id": rule_id, "properties": {"tags": []}}
    rules.append(rr)
    return rr

def add_github_recognized_tags(rule_obj, cwe_code: str, owasp_id: str):
    """Adiciona tags padrão que o GitHub reconhece para mostrar badges."""
    tags = set(rule_obj.get("properties", {}).get("tags", []))
    if cwe_code and cwe_code.startswith("CWE-"):
        cwe_num = cwe_code.split("-", 1)[1]
        tags.add(f"external/cwe/cwe-{cwe_num.lower()}")
    # OWASP Top 10 2021 → formato external/owasp/2021/A03
    if owasp_id and "A" in owasp_id and "2021" in owasp_id:
        # ex.: "A03:2021 Injection" -> "A03"
        a_code = owasp_id.split()[0].split(":")[0]  # "A03:2021" -> "A03"
        tags.add(f"external/owasp/2021/{a_code}")
    rule_obj.setdefault("properties", {})["tags"] = sorted(tags)


# Mapeia level SARIF textual -> severidade numérica (para ordenar no GitHub)
LEVEL_TO_SECURITY_SEVERITY = {
  "error": "8.5",
  "warning": "5.0",
  "note": "2.0"
}

def load_sarif(p):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # SARIF mínimo válido
        return {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[]}]}        

def ensure_minimal(sarif):
    if "version" not in sarif: sarif["version"] = "2.1.0"
    if "runs" not in sarif or not sarif["runs"]:
        sarif["runs"] = [{"tool":{"driver":{"name":"semgrep"}},"results": []}]
    return sarif

def get_or(obj, path, default=None):
    cur=obj
    for k in path:
        if isinstance(cur, dict) and k in cur:
            cur=cur[k]
        else:
            return default
    return cur

def set_in(obj, path, value):
    cur=obj
    for k in path[:-1]:
        if k not in cur or not isinstance(cur[k], dict):
            cur[k] = {}
        cur = cur[k]
    cur[path[-1]] = value

def enrich(sarif):
    sarif = ensure_minimal(sarif)
    runs = sarif.get("runs", [])
    for run in runs:
        results = run.get("results", []) or []
        for r in results:
            rule_id = r.get("ruleId") or get_or(r, ["rule", "id"])
            level = r.get("level","warning")
            props = r.get("properties", {}) if isinstance(r.get("properties"), dict) else {}

            if rule_id in MAP:
                m = MAP[rule_id]
              # Garante badge de CWE/OWASP no topo do alerta
rule_obj = ensure_rule_object(run, rule_id)
add_github_recognized_tags(rule_obj, m.get("cwe"), m.get("owasp"))
# Opcional: colocar help text rico na regra
help_text = []
if m.get("remediation"):
    help_text.append(f"**Remediação:** {m['remediation']}")
if m.get("references"):
    help_text.append("\n**Referências:**\n" + "\n".join(f"- {u}" for u in m["references"]))
if help_text:
    rule_obj["help"] = {"text": "\n".join(help_text), "markdown": "\n".join(help_text)}

                props["cwe"] = m["cwe"]
                props["owasp"] = m["owasp"]
                props["references"] = m["references"]
                props["remediation"] = m["remediation"]

            # security-severity ajuda a ordenar/priorizar no GitHub
            props["security-severity"] = LEVEL_TO_SECURITY_SEVERITY.get(level, "5.0")
            r["properties"] = props
    return sarif

def write_markdown_summary(sarif, out_md):
    lines = ["# Semgrep – Achados Enriquecidos (CWE/OWASP)\n"]
    total = 0
    for run in sarif.get("runs", []):
        for r in run.get("results", []) or []:
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
            lines.append(f"## {rule}  \n- **Arquivo**: `{file}:{line}`  \n- **Nível (SARIF)**: `{level}`")
            if cwe: lines.append(f"- **CWE**: `{cwe}`")
            if owasp: lines.append(f"- **OWASP**: `{owasp}`")
            if msg: lines.append(f"- **Mensagem**: {msg}")
            if remediation: lines.append(f"- **Remediação**: {remediation}")
            if refs:
                lines.append("- **Referências:**")
                for u in refs: lines.append(f"  - {u}")
            lines.append("")
    lines.append(f"**Total de achados**: {total}")
    pathlib.Path(out_md).write_text("\n".join(lines), encoding="utf-8")

def main():
    in_path = pathlib.Path("semgrep.sarif")
    out_path = pathlib.Path("semgrep.enriched.sarif")
    md_path = pathlib.Path("semgrep.enriched.md")
    sarif = load_sarif(in_path)
    enriched = enrich(sarif)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(enriched, f, ensure_ascii=False)
    write_markdown_summary(enriched, md_path)

if __name__ == "__main__":
    main()
