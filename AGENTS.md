# AGENTS.md

- Keep changes focused and preserve unrelated work.
- Use the implementation as the source of truth. Update relevant tests and public
  documentation when behavior changes; keep the README and website consistent.
- Use `anyip.dev` in general documentation and examples. Present `lanip.dev` for
  workflows requiring IP-encoded hostnames that do not resolve to public IPs.
  Explain the scope of that restriction without implying application or OAuth trust.
- Keep public content free of credentials, deployed key material, ACME account
  state, private operational details, personal information, and local user paths.
  Use placeholders and documentation addresses in examples.
- If a possible leak is found, report its location without reproducing the value.
  Obtain explicit approval before rotating credentials or rewriting published history.
- Validate changes with focused checks. Do not request live certificates or modify
  deployed services merely to test repository changes.
- Submit changes through a pull request and honor requested human review before merging.
