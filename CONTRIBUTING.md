# Contributing

Start with a synthetic fixture or an issue that names an expected finding and the actual result. Avoid real credentials, proprietary configuration, private hostnames and copied production logs. A manifest schema or policy change should include a short RFC rationale and tests. Run `python -m unittest discover -s tests` after installing with `pip install -e .`.

Pull requests should be focused, explain changed behavior and include a demo command. We review schema compatibility, evidence semantics and secret handling before merging. Maintainers decide on merges; issue discussion is open to everyone. See [GOVERNANCE.md](GOVERNANCE.md) and [SECURITY.md](SECURITY.md).
