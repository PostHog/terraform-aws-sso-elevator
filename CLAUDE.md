# Claude Code Instructions

## Before Committing

Always run these commands before committing changes:

```bash
# Run all pre-commit hooks (linting, formatting, terraform docs, etc.)
uv run --directory src --extra dev pre-commit run --all-files
```

## Running Tests

```bash
cd src && uv run pytest -q
```
