# Contributing

Thanks for your interest in `sentinel-harness`. This is a reference implementation
and educational sample for **authorized, defensive** security operations.

## Ground rules

1. **No proprietary or organization-specific data — ever.** This is a public repo.
   Use only generic SecOps content and public threat examples (ATT&CK, public CVEs).
   Company names, internal hostnames, real asset inventories, and the like do not
   belong here. CI enforces a name/secret scan and will fail the build.
2. **No hardcoded secrets or AWS account IDs.** Everything is env-parameterized
   (`SENTINEL_EXECUTION_ROLE_ARN`, `SENTINEL_REGION`, `AWS_PROFILE`). Use the
   `000000000000` placeholder in docs/examples.
3. **Defensive scope only.** Offensive/simulation scenarios must keep a
   human-in-the-loop gate on every action (Play Mode). No autonomous exploitation.
4. **English** for all code, comments, and docs.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e . pytest
export SENTINEL_EXECUTION_ROLE_ARN="arn:aws:iam::000000000000:role/test"  # for offline tests
pytest tests/ -q          # offline config-validation tests (no AWS calls)
```

Live scenarios require real AWS credentials for a **non-production** account and a
real execution role — see `docs/SETUP.md`.

## Style

- Match the existing `sentinel_harness/core.py` API and the `scenarios/` style.
- New scenarios go in `scenarios/`, write their evidence JSON to `evidence/`, and
  should be runnable end-to-end (create → invoke → verdict → leave cleanup to `sentinel cleanup`).
- Keep tool templates deterministic where the design calls for it (e.g. linters must
  not call an LLM).

## Reporting

Security issues: please open a private report rather than a public issue.
