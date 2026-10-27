# agent-pkg-audit

**A zero-dependency, read-only pre-publish gate for agent packages and agent repos.**

Agent packages ship prompts, tool definitions and configuration. A single leaked
email address, a stale absolute path, or a broken skill reference turns a
working package into an incident — and you usually find out after publishing.

`agent-pkg-audit` is a command-line gate that catches those before release. It
exits non-zero on blockers, so it can sit in CI and stop a bad publish.

```bash
npx agent-pkg-audit ./my-agent-package
# exit 0 = clean, safe to publish
# exit 1 = blockers found, fix before publishing
```

---

## Why this exists

This tool is distilled from a production governance toolkit that has been
running as a pre-publish gate on a multi-window agent system since August 2026.
It is not a theoretical linter. Every rule in it corresponds to a failure mode
that actually happened:

| Failure mode | What the rule catches |
|---|---|
| PII leaking through agent prompts | `email`, `cn_id_card`, `abs_windows_path`, `abs_posix_home_path` |
| A credential pasted into a skill file and committed | `secret_assignment`, `private_key_block` |
| A skill reference pointing at a directory that no longer exists | `broken-xref` |
| A manifest missing required keys, so the package silently fails to load | `config` |
| Unfinished markers (`TODO`, `待补`) shipping in a "final" agent | `drift` |
| A package that only runs on one harness | `harness_coupling` (warning) |
| Tampered or truncated files in a distributed bundle | SHA256 manifest verification |

---

## What it checks

**A. Package structure** — plugin manifest validity, required keys, agent files
present, agent frontmatter has `name` and `description`, agent body not empty.

**B. Secret / PII gate** — the main event. Credentials, personal data, national
ID numbers, private key material, and absolute local paths. Every match near an
explicit redaction marker (`[redacted]`, `[local path]`, `[PII]`, …) is ignored,
so intentional placeholders do not produce noise.

**C. Portability** — flags harness-specific coupling so you know whether your
package is truly portable. Warning, not blocker.

**D. Integrity** — if a `MANIFEST.json` is present, every listed file is
SHA256-verified against it.

**E. Static fault proxies** — the statically-detectable subset of a 15-class
multi-agent failure taxonomy: role ambiguity, broken cross-references,
configuration faults, instruction drift.

---

## Install

```bash
npm install -g agent-pkg-audit     # global
npx agent-pkg-audit ./path         # one-off
```

Or run the auditor directly with any Python 3.9+ interpreter — it has **zero
dependencies**, standard library only:

```bash
python3 lib/audit_core.py ./path
```

---

## Usage

```bash
agent-pkg-audit [path] [--rules <file>] [--report <file>] [--version] [--help]
```

| Flag | Effect |
|---|---|
| `[path]` | Repository or package to audit. Default: current directory. |
| `--rules <file>` | Extra / overriding rule file (JSON). Merged over the defaults. |
| `--report <file>` | Write a Markdown report to this path. |
| `--exclude <dir>` | Skip a directory by name, at any depth. Repeatable. |
| `--version` | Print the version. |
| `--help` | Print full usage. |

### Example output

```
# agent-pkg-audit report
> repository: /work/my-agent-package
> packages detected: 1
> rule categories: pii, portability

## A. Package structure
- my-agent  OK  2 agent file(s)

## B. Secret / PII gate | C. Portability | E. Static fault proxies
- BLOCK  agents/reviewer.md -> [email] reviewer@company.internal
- WARN   skills/deploy/SKILL.md -> [harness_coupling] harness-specific coupling

## D. Integrity (SHA256 manifest)
- OK    all 14 file(s) verified

## Summary
- packages: 1
- blockers: 1
- warnings: 1

> exit 1 (blockers found — fix before publishing)
```

---

## Use it as a CI gate

```yaml
# .github/workflows/release.yml
- name: Audit agent package
  run: npx agent-pkg-audit . --report audit-report.md
```

The step fails the job when blockers are present, because the tool exits `1`.

You can also wire it into `npm publish` so a bad package can never reach the
registry:

```json
{
  "scripts": {
    "prepublishOnly": "agent-pkg-audit ."
  }
}
```

---

## Custom rules

Rules are plain JSON. Copy `rules/default.json`, edit it, and pass it with
`--rules`. Later files win on rule `id`, so you can override a default or add
your own.

```json
{
  "pii": [
    {
      "id": "internal_codename",
      "severity": "blocker",
      "pattern": "(?i)project\\s+[\\u4e00-\\u9fa5]{2,6}",
      "message": "internal codename leaked",
      "except": ["\\bexample\\b"]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `id` | Stable identifier. Used for override matching. |
| `severity` | `blocker` (exits 1) or `warning` (exits 0). |
| `pattern` | Regular expression, Python syntax. |
| `message` | Human-readable explanation shown in the report. |
| `except` | Optional list of regexes. A match is ignored if any of them matches. |
| `scope` | Optional. `all` (default), `runtime`, or `docs`. See below. |

### Protecting your own project

Real names, internal codenames and private vocabulary are specific to your
project. Hard-coding one project's names into the tool would make it
meaningless to everyone else — so the shipped defaults stay neutral, and you
add your own via `--rules`.

A rule in the `persona` category applies to **runtime content** only: source
files, agent prompts, skill definitions. A real person's name inside a system
prompt is a leak. The same name in a README signature line is attribution, and
flagging it would be wrong.

```json
{
  "_comment": "documentation keys starting with _ are ignored",
  "persona": [
    {
      "id": "persona_real_name",
      "severity": "blocker",
      "pattern": "Your\\s+Name",
      "message": "real name inside runtime content — use a handle instead"
    }
  ],
  "codename": [
    {
      "id": "internal_codename",
      "severity": "warning",
      "pattern": "(?:PROJECT|TEAM|INTERNAL)",
      "message": "internal codename — meaningless outside the project"
    }
  ]
}
```

Then run:

```bash
agent-pkg-audit . --rules ./my-project-rules.json
```

The `codename` category applies to everything; the `persona` category applies
to runtime content only. A rule may also declare `"scope": "docs"` to target
documentation specifically.

---

## Design guarantees

- **Read only.** The tool never writes to the audited tree. `--report` writes
  only to the path you give it.
- **Zero dependencies.** Python standard library only. No `pip install`, no
  transitive supply chain.
- **Deterministic.** Same input, same output, same exit code. No network calls.
- **Portable.** Runs on Linux, macOS and Windows.

---

## License

MIT
