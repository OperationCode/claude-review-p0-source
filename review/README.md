# review

Code for the Claude PR review (see [the design spec](../docs/claude-review-design.md)). Run the unit tests, which make no network or API calls, with `cd review && uv run pytest tests/unit`. CI installs with `uv sync --locked`; `uv.lock` records a hash for every package.
