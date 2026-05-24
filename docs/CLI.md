# Tallow CLI

`tallow --help` lists commands. Foundation commands: `version [--json]`, `server`, `db migrate [--config path]`, `observe`, and `analyze`. `observe` and `analyze` are safe placeholders and do not fetch or execute packages.

Exit codes: 0 success, 1 general error, 2 usage, 3 config, 4 dependency unavailable, 10 not implemented.
