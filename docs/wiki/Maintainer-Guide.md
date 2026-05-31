# Maintainer Guide

Before a release:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests
python -m openops_evidence validate -i examples/evidence.sample.json
```

Also verify:

- generated reports are readable
- examples are synthetic
- schemas match generated artifacts
- changelog entries describe user-visible changes
- redacted evidence does not contain sensitive data

Security issues should follow `SECURITY.md`. Release steps should follow
`docs/release-process.md`.
