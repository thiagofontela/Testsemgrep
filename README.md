# Testesemgrep (demo)

## Como usar
1. Vá em **Settings → Actions → General → Workflow permissions** e marque **Read and write permissions**.
2. Vá em **Actions → semgrep-publish → Run workflow** (branch: `main`).
3. Veja os resultados em **Security → Code scanning alerts** (Tool: **semgrep**).
4. Para testar PR: crie uma branch editando `VulnMainTest.java`, abra um PR para `main`. O workflow **semgrep-pr** roda e aplica gate só para High/Critical.

## Onde ficam os relatórios
Em cada run: **Artifacts → semgrep-reports** (contém `semgrep.sarif` e `semgrep.report.json`).
