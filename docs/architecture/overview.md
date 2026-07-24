# Architecture overview

Warden is an orchestrator. It runs no analysis of its own — its job is to
invoke four third-party scanners consistently, reconcile their incompatible
output formats into one model, and reduce the result to a single exit code.

## System context

```mermaid
flowchart LR
    user([Developer or CI]) --> cli[warden CLI]
    cli --> cfg[".warden.yaml"]
    cli -->|subprocess| trivy[Trivy]
    cli -->|subprocess| semgrep[Semgrep]
    cli -->|subprocess| gitleaks[Gitleaks]
    cli -->|docker run| zap[OWASP ZAP]
    trivy --> reports[".security_reports/*.json"]
    semgrep --> reports
    gitleaks --> reports
    zap --> reports
    reports --> agg[Aggregator]
    agg --> json["security_audit.json"]
    agg --> exit([Exit code])
```

The three static scanners run as subprocesses against the filesystem. ZAP is
different: it is a container launched through the Docker daemon, and it needs a
running application rather than source files.

## Components

All under `src/warden/`.

| Module | Responsibility |
| --- | --- |
| `cli.py` | Entry point. Parses arguments, sequences the stages, prints progress, returns the exit code. |
| `config.py` | Parses `.warden.yaml` and resolves it against CLI arguments into a `ResolvedConfig`. Also the `warden-config` entry point. |
| `tooling.py` | Prepares the report directory and builds and runs each scanner's command line. The only module that touches subprocesses. |
| `aggregate.py` | Assembles the report from the parsed findings and writes it. Also the `warden-aggregate` entry point. |
| `_parsers.py` | Turns each tool's JSON into `Finding` records and normalises severities. |
| `_summary.py` | Counts findings by severity and category and prints the terminal table. |
| `_json.py` | Type-narrowing helpers for walking untrusted JSON. |
| `_models.py` | Shared dataclasses, typed dicts, and constants. No logic. |

The dependency direction is one-way: `cli` depends on `config`, `tooling`, and
`aggregate`, which do not depend on each other. `aggregate` depends on
`_parsers` and `_summary`; those depend on `_json`. `_models` is a leaf.

`aggregate.py` and its three helper modules were one file until the parsing,
rendering, and JSON-walking concerns had each grown large enough to change for
their own reasons.

## Data flow through a scan

1. **Resolve configuration.** `config.resolve_config` reads `.warden.yaml` if
   present and merges it with CLI arguments. A missing or unparsable file yields
   defaults.
2. **Prepare the report directory.** `.security_reports/` is created in the
   project root, and appended to `.gitignore` if that file exists and does not
   already list it. Any report left by a previous run is deleted, so a tool that
   is now disabled or that crashes cannot contribute stale findings.
3. **Run each enabled tool.** Each writes its native JSON into the report
   directory. A tool that is missing or fails produces a warning; the sequence
   continues regardless.
4. **Aggregate.** Each report file that exists is parsed into a common `Finding`
   record and severities are normalised onto one scale.
5. **Report and exit.** Findings are sorted by severity, written to
   `security_audit.json`, summarised as a table, and reduced to an exit code.

The stages communicate through files on disk, not in memory. That is why
`warden-aggregate` can run standalone against a directory of reports that some
other process produced.

## Design notes

### Failure is non-fatal by default

A scanner that is missing or crashes does not abort the run or fail the build.
The rationale is that a partial scan is more useful than none — but the
consequence is that a green build does not prove every scanner ran. `tools_run`
in the report records which reports were actually found.

### Only Critical and High fail the build

`DEFAULT_FAIL_ON_SEVERITIES` is `("CRITICAL", "HIGH")`. The threshold is a
parameter of `generate_report`, but nothing in the CLI or config file exposes
it, so in practice it is fixed. Lower severities are still collected and
reported.

Two normalisation choices interact with this and are worth stating plainly:
Gitleaks findings are assigned `CRITICAL` unconditionally, so any detected
secret fails a build; and Semgrep's `ERROR` maps to `HIGH`, so Semgrep's own
notion of a serious finding also fails a build. See
[Report format](../reference/report-format.md#severity-normalisation).

### The config parser is deliberately minimal

`.warden.yaml` is read by about 110 lines of hand-written parsing rather than
a YAML library, which keeps the runtime dependency list to `rich` and `semgrep`.
The trade-off is real: only the exact shapes Warden needs are supported, and
unsupported syntax is ignored rather than rejected, so a malformed config
degrades to defaults silently. `warden-config` exists largely to make that
failure mode visible.

### ZAP runs as a sibling container

The other three tools are executables on `PATH`. ZAP is invoked as
`docker run ... ghcr.io/zaproxy/zaproxy:stable`, which has two consequences.

First, Docker is a hard prerequisite of both installers even though only the
DAST stage uses it.

Second, when Warden is *itself* containerised, the report path it wants to
mount is a path inside its own container, which the host's Docker daemon cannot
resolve. The `WARDEN_HOST_REPORT_DIR`, `WARDEN_HOST_WORKSPACE`, and
`GITHUB_WORKSPACE` environment variables exist to supply the host path instead.
This is the reason the GitHub Action passes `GITHUB_WORKSPACE` through.

### The container runs unprivileged

The image runs as UID 10001 rather than root. Because callers are expected to
override the UID with `--user` to match the owner of the mounted project, the
image cannot rely on a fixed home directory — scanner caches and settings live
under a world-writable `/var/tmp/warden`, and `safe.directory` is set
system-wide so Gitleaks can read a repository owned by another user.

### Wrappers exist for source checkouts

`bin/` holds shell, PowerShell, and batch wrappers that locate the project root
and delegate to the installed CLI, preferring `uv run` and falling back to
`python -m warden`. They exist so the tool is runnable from a plain checkout
without installation. They add no behaviour of their own.

## Trade-offs not taken

Three limitations are consequences of the design rather than oversights:

- **No incremental or diff-aware scanning.** Every run scans the whole tree.
- **No severity policy per tool.** You can disable a tool entirely, but you
  cannot say "fail on Trivy High but not Semgrep High".
- **No suppression mechanism.** There is no allowlist or baseline file, so a
  finding you have accepted will fail every subsequent build. Excluding the
  containing directory is the only lever, and it is a blunt one.
