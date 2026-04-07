#!/usr/bin/env bash

set -e

cd src
uv sync --no-install-project --extra dev
LOG_LEVEL=DEBUG uv run pytest -q $1
uv run pyright .
cd ..

uvx pre-commit run -a
