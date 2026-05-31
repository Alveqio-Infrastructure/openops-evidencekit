## Summary

Describe the change and why it improves OpenOps EvidenceKit.

## Safety Notes

- [ ] No real customer data, secrets, tokens, private hostnames, or private IPs are included.
- [ ] New collectors document what they collect and what they avoid.
- [ ] New checks include remediation text.

## Verification

```text
PYTHONPATH=src python -m unittest discover -s tests
PYTHONPATH=src python -m openops_evidence validate -i examples/evidence.sample.json
```
