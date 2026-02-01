# Contributing

Thanks for improving TSA. This repo is intentionally lightweight and focused on correctness.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt -r requirements-dev.txt
```

## Quality gates

```bash
make verify
```

For stricter checks (coverage + mutation testing):

```bash
make verify-strict
```

## Style

- Linting and formatting are enforced with `ruff`.
- Keep changes focused and add tests for new behavior.

## Submitting changes

- Keep PRs small and well-scoped.
- Include test updates when behavior changes.
- Prefer clear, security-conscious commit messages.
