#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent-pkg-audit · core
============================================================
A zero-dependency, read-only auditor for agent packages and agent repos.

What it checks
--------------
A. Package structure  — plugin manifest, agent frontmatter, skill directories
B. Secret / PII gate   — credentials, personal data, absolute local paths
C. Portability        — harness-specific coupling (warn, not block)
D. Integrity           — SHA256 manifest verification
E. Static fault proxies— the statically-detectable subset of a 15-class
                         multi-agent failure taxonomy

Design constraints
------------------
- Python 3.9+, standard library only. No install-time dependencies.
- READ ONLY. Never writes to the audited tree (except an optional --report file
  that is written outside it).
- Exit code 0 = no blockers. Exit code 1 = blockers found. Designed to be used
  as a CI gate.

Provenance
----------
Derived from a production governance toolkit that has been running as a
pre-publish gate on a multi-window agent system since 2026-08. The rules encode
failure modes observed in the wild: PII leakage through agent prompts, manifest
drift, broken skill references, instruction drift, local-path coupling.

Rule configuration
------------------
Rules live in `rules/default.json` and are merged over the built-in defaults.
Override with `--rules path/to/rules.json`. Every rule has an `id`, a `pattern`
(regular expression), a `severity` ("blocker" | "warning"), and a `message`.
Users can add their own patterns without touching this file.
"""
import hashlib
import json
import os
import re
import sys

__version__ = "0.1.0"

# --------------------------------------------------------------------------
# Built-in default rules
# --------------------------------------------------------------------------
DEFAULT_RULES = {
    "pii": [
        {
            "id": "email",
            "severity": "blocker",
            "pattern": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "message": "email address",
            "except": [
                r"@[\w.-]*\.local$",
                r"@example\.(com|org|net)$",
                r"@users\.noreply\.github\.com$",
                r"@company\.internal$",
                r"@internal\.example$",
                # scp-style git remotes are not email addresses
                r"^git@",
                r"@github\.com$",
            ],
        },
        {
            "id": "abs_windows_path",
            "severity": "blocker",
            # Require a plausible path character after the drive separator.
            # Without this, string escapes such as "s:\n" or "d:\n{details}"
            # are read as Windows paths — a false positive that dominated the
            # output when scanning real third-party repositories.
            # Exclude string escape sequences (s:\n, d:\n{details}, \t, \r,
            # \uXXXX, \xNN, \\0). Without this, escaped newlines inside string
            # literals are read as Windows paths — a false positive that
            # accounted for 97 of 99 hits on a real third-party repository.
            # A Windows path starts with a drive letter, a backslash and then
            # a path component. String escapes such as s:\n, d:\n{details},
            # s:\n\nConversations, \t, \r, \uXXXX must NOT be read as paths.
            # The negative lookahead below rejects a leading escape letter
            # even when it is followed by more escapes.
            "pattern": r"[A-Za-z]:\\+(?![nrtbfv0xuU\\])(?:[A-Za-z0-9_.\-~$]{1,}|[uU]ser?s?\\)[^\s\"'`]*|[A-Za-z]:\\+[uU]sers?\\[^\s\"'`]*",
            "message": "absolute Windows path",
            "except": [
                r"^[A-Za-z]:\\\$",
                r"^[A-Za-z]:\\\$\{",
                r"^[A-Za-z]:\\\.\.\.",
                # documentation placeholders: <你的用户名>, <wxid>, <output-dir>
                r"<[^>]*>",
                r"^[A-Za-z]:\\Users\\\.\.\.",
                r"^[A-Za-z]:\\Users\\[^\\]*\.\.\.",
            ],
        },
        {
            "id": "abs_posix_home_path",
            "severity": "blocker",
            "pattern": r"/(?:home|Users)/[A-Za-z0-9._-]+/[^\s\"'`]*",
            "message": "absolute home path",
            # "you" is the documentation placeholder, not a real home dir
            "except": [r"/(?:home|Users)/you/"],
        },
        {
            "id": "secret_assignment",
            "severity": "blocker",
            "pattern": r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|bearer)\b\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}",
            "message": "possible hard-coded secret",
        },
        {
            "id": "private_key_block",
            "severity": "blocker",
            "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
            "message": "private key material",
        },
        {
            "id": "cn_id_card",
            "severity": "blocker",
            "pattern": r"\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b",
            "message": "national ID number",
        },
    ],
    # Applied only to runtime content (agent / skill / prompt files).
    # A real person's name in a system prompt is a leak; the same name in a
    # README signature line is attribution. Only the former is a defect.
    #
    # The shipped defaults are deliberately empty: real names and internal
    # codenames are project-specific, so hard-coding one project's names would
    # make this tool meaningless to everyone else. Add your own with --rules.
    # See the README section "Protecting your own project".
    "persona": [],
    "codename": [
        {
            "id": "workflow_leak_marker",
            "severity": "warning",
            "pattern": r"(?:鸿窗|议窗|天璇|归藏|启明|玄览|墨章|砚)\s*(?:执行|授权|执行人)",
            "message": "internal workflow reference — meaningless outside the project",
        },
    ],
    "portability": [
        {
            "id": "harness_coupling",
            "severity": "warning",
            "pattern": r"(?:~/\.workbuddy|\.workbuddy/skills|\.claude/(?:agents|commands|skills)|\.codebuddy-plugin|opencode_agents\.json)",
            "message": "harness-specific coupling — package is not fully portable",
        }
    ],
}

# Text fragments that, when adjacent to a match, mean it is already redacted.
ALLOWED_TOKENS = [
    "[redacted]", "[masked]", "[local path]", "[sensitive path]", "[credential]",
    "[PII]", "[user]", "[local vault]", "[placeholder]",
]

REQUIRED_PLUGIN_KEYS = ["name", "description"]
AGENT_MIN_BODY_CHARS = 200
TODO_TOKENS = ["待补", "TODO", "XXX", "FIXME", "TBD"]


# --------------------------------------------------------------------------
# Rule loading
# --------------------------------------------------------------------------
def load_rules(extra_path=None):
    """Merge built-in defaults with the packaged rules file and an optional
    user-supplied override file. Later files win on rule id."""
    rules = json.loads(json.dumps(DEFAULT_RULES))
    packaged = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "default.json"
    )
    for path in [packaged, extra_path]:
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    extra = json.load(fh)
            except Exception as exc:  # noqa: BLE001
                print("! could not read rules file %s: %s" % (path, exc), file=sys.stderr)
                continue
            for category, items in (extra or {}).items():
                if category.startswith("_"):
                    # keys like "_comment" are documentation, not rules
                    continue
                if not isinstance(items, list):
                    print("! rules file %s: category %r is not a list, skipped"
                          % (path, category), file=sys.stderr)
                    continue
                bucket = rules.setdefault(category, [])
                index = {r["id"]: i for i, r in enumerate(bucket) if isinstance(r, dict)}
                for item in items:
                    if not isinstance(item, dict):
                        print("! rules file %s: rule entry in %r is not an object, skipped"
                              % (path, category), file=sys.stderr)
                        continue
                    if item.get("id") in index:
                        bucket[index[item["id"]]] = item
                    else:
                        bucket.append(item)
    compiled = {}
    for category, items in rules.items():
        compiled[category] = []
        for item in items:
            try:
                item = dict(item)
                item["_re"] = re.compile(item["pattern"])
                item["_except_res"] = [re.compile(p) for p in item.get("except", [])]
                compiled[category].append(item)
            except re.error as exc:
                print("! invalid regex in rule %s: %s" % (item.get("id"), exc), file=sys.stderr)
    return compiled


# --------------------------------------------------------------------------
# Frontmatter parsing (minimal YAML subset)
# --------------------------------------------------------------------------
def parse_scalar(value):
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [x.strip().strip('"').strip("'") for x in inner.split(",")]
    if len(value) > 1 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_frontmatter(text):
    """Parse the YAML frontmatter subset used by agent/skill files.
    Supports: `key: value`, inline lists `key: [a, b]`, nested mappings
    (indented `key: value`) and block sequences (indented `- item`).
    Returns (data, body, status)."""
    if not text.startswith("---"):
        return None, text, "no_frontmatter"
    end = text.find("\n---", 3)
    if end == -1:
        return None, text, "unclosed_frontmatter"
    block = text[3:end].strip("\n")
    body = text[end + 4:]
    data, current = {}, None
    try:
        lines = block.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if not line.strip():
                i += 1
                continue
            # block sequence item:  "  - value"
            seq = re.match(r"^\s+-\s+(.*)$", line)
            if seq and current is not None:
                if not isinstance(data.get(current), list):
                    data[current] = []
                data[current].append(parse_scalar(seq.group(1)))
                i += 1
                continue
            top = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", line)
            if top and not line.startswith(" "):
                current = top.group(1)
                raw = top.group(2).strip()
                data[current] = {} if raw == "" else parse_scalar(raw)
                # a key with an empty value may be followed by a block sequence
                if raw == "":
                    j = i + 1
                    while j < len(lines) and not lines[j].strip():
                        j += 1
                    if j < len(lines) and re.match(r"^\s+-\s+", lines[j]):
                        data[current] = []
            elif line.startswith(" ") and current and isinstance(data.get(current), dict):
                nested = re.match(r"^\s+([A-Za-z_][\w-]*):\s*(.*)$", line)
                if nested:
                    data[current][nested.group(1)] = parse_scalar(nested.group(2).strip())
            i += 1
    except Exception as exc:  # noqa: BLE001
        return None, body, "parse_error: %s" % exc
    return data, body, "ok"


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
def scan_text(text, rel, rules, runtime=False):
    """Return (blockers, warnings) for one file.

    A rule may declare its own scope:
      "scope": "runtime"  — only applied to model-visible content
      "scope": "all"      — applied everywhere (default)
      "scope": "docs"     — applied only to documentation
    The `runtime` argument is the fallback used when a rule declares no
    scope but lives in a category that defaults to runtime-only.
    """
    blockers, warnings = [], []
    categories = [("pii", "blocker"), ("portability", "warning"),
                  ("codename", "warning"), ("persona", "blocker")]
    is_doc = rel.replace(os.sep, "/").lower().startswith(("docs/", "readme", "contributing", "license"))
    for category, default_severity in categories:
        for rule in rules.get(category, []):
            severity = rule.get("severity", default_severity)
            scope = rule.get("scope")
            if scope is None:
                scope = "runtime" if category == "persona" else "all"
            if scope == "runtime" and not runtime:
                continue
            if scope == "docs" and not is_doc:
                continue
            for match in rule["_re"].finditer(text):
                snippet = match.group(0)
                window = text[max(0, match.start() - 48): match.end() + 48]
                # `except` is matched against the matched text OR the
                # surrounding context — so a rule can exempt an occurrence
                # that appears next to a known-safe marker.
                if any(rx.search(snippet) or rx.search(window) for rx in rule["_except_res"]):
                    continue
                if any(tok in window for tok in ALLOWED_TOKENS):
                    continue
                entry = (rule["id"], rel, snippet[:120], rule.get("message", ""))
                (blockers if severity == "blocker" else warnings).append(entry)
    return blockers, warnings


def list_files(root, extensions, exclude_dirs=None):
    """Collect files with the given extensions, skipping build/VCS noise and
    any directory listed in `exclude_dirs` (by name, matched at any depth)."""
    skip = {".git", "node_modules", "__pycache__", ".venv", "dist", "build"}
    if exclude_dirs:
        skip |= set(exclude_dirs)
    out = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in files:
            if name.endswith(extensions):
                out.append(os.path.join(base, name))
    return out


def discover_packages(repo):
    """Identify agent packages inside a repository.
    A package is a directory containing a plugin manifest or an agents/ dir."""
    found = []
    for name in sorted(os.listdir(repo)):
        if name.startswith(".") or name in ("node_modules", "tools", "bin", "lib", "rules", "skills"):
            continue
        path = os.path.join(repo, name)
        if not os.path.isdir(path):
            continue
        has_manifest = os.path.exists(os.path.join(path, ".codebuddy-plugin", "plugin.json"))
        has_agents = os.path.isdir(os.path.join(path, "agents"))
        if has_manifest or has_agents:
            found.append(name)
    if not found:
        if os.path.exists(os.path.join(repo, "agents")) or os.path.exists(
            os.path.join(repo, ".codebuddy-plugin", "plugin.json")
        ):
            found.append(".")
    return found


def audit(repo, rules, report_path=None, exclude_dirs=None):
    repo = os.path.abspath(repo)
    blockers, warnings = [], []
    packages = discover_packages(repo)

    print("# agent-pkg-audit report")
    print("> repository: %s" % repo)
    print("> packages detected: %d" % len(packages))
    print("> rule categories: %s" % ", ".join(sorted(rules.keys())))
    print("")

    # ---- A. structure -----------------------------------------------------
    print("## A. Package structure")
    if not packages:
        warnings.append(("structure", repo, "no agent package detected"))
        print("- (none found)")
    for pkg in packages:
        pdir = os.path.join(repo, pkg) if pkg != "." else repo
        label = pkg if pkg != "." else "(repo root)"
        manifest_path = os.path.join(pdir, ".codebuddy-plugin", "plugin.json")
        if not os.path.exists(manifest_path):
            warnings.append(("structure", label, "no plugin manifest"))
            print("- %s  WARN  no plugin manifest" % label)
        else:
            try:
                with open(manifest_path, encoding="utf-8") as fh:
                    manifest = json.load(fh)
            except Exception as exc:  # noqa: BLE001
                blockers.append(("config", label, "plugin manifest is not valid JSON: %s" % exc))
                print("- %s  BLOCK  invalid plugin manifest" % label)
                continue
            missing = [k for k in REQUIRED_PLUGIN_KEYS if k not in manifest]
            if missing:
                blockers.append(("config", label, "plugin manifest missing keys: %s" % ", ".join(missing)))
                print("- %s  BLOCK  manifest missing %s" % (label, ",".join(missing)))
                continue
        agents_dir = os.path.join(pdir, "agents")
        agent_files = []
        if os.path.isdir(agents_dir):
            agent_files = [f for f in os.listdir(agents_dir) if f.endswith(".md")]
        if not agent_files:
            blockers.append(("structure", label, "no agent files under agents/"))
            print("- %s  BLOCK  no agents/*.md" % label)
            continue
        print("- %s  OK  %d agent file(s)" % (label, len(agent_files)))

    # ---- B/C/E. content scan ---------------------------------------------
    print("")
    print("## B. Secret / PII gate | C. Portability | E. Static fault proxies")
    # Scan the whole repository, not just detected agent packages. A repo may
    # ship no agent package at all and still contain a leaked credential in a
    # script or a doc.
    scan_targets = list_files(
        repo,
        (".md", ".json", ".yaml", ".yml", ".js", ".mjs", ".ts", ".py", ".toml", ".txt", ".sh"),
        exclude_dirs=exclude_dirs,
    )
    for extra in ("README.md", "LICENSE", "COPYING", "NOTICE", "package.json"):
        candidate = os.path.join(repo, extra)
        if os.path.exists(candidate):
            scan_targets.append(candidate)
    seen, unique = set(), []
    for path in scan_targets:
        if path not in seen:
            seen.add(path)
            unique.append(path)

    pii_total = 0
    for path in unique:
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except Exception:
            continue
        rel = os.path.relpath(path, repo)
        rel_norm = rel.replace(os.sep, "/")
        # "Runtime content" = anything that becomes model-visible behaviour:
        # agent prompts, skill definitions, plugin manifests — and source
        # files, whose comments and docstrings ship with the package.
        # Pure documentation (README, docs/, LICENSE) is attribution, not runtime.
        is_doc = rel_norm.lower().startswith(("docs/", "readme", "contributing", "license", "notice"))
        is_runtime = not is_doc
        file_blockers, file_warnings = scan_text(text, rel, rules, runtime=is_runtime)
        for entry in file_blockers:
            pii_total += 1
            blockers.append(("secret/pii", entry[1], "%s: %s" % (entry[3], entry[2])))
            print("- BLOCK  %s -> [%s] %s" % (entry[1], entry[0], entry[2]))
        for entry in file_warnings:
            warnings.append(("portability", entry[1], "%s: %s" % (entry[3], entry[2])))
            print("- WARN   %s -> [%s] %s" % (entry[1], entry[0], entry[2]))

        if path.endswith(".md") and ("/agents/" in "/" + rel_norm):
            fm, body, status = parse_frontmatter(text)
            if status != "ok":
                warnings.append(("frontmatter", rel, status))
                continue
            if not fm.get("name") or not fm.get("description"):
                blockers.append(("agent", rel, "frontmatter missing name or description"))
            if len(body.strip()) < AGENT_MIN_BODY_CHARS:
                warnings.append(("agent", rel, "agent body shorter than %d chars" % AGENT_MIN_BODY_CHARS))
            for token in TODO_TOKENS:
                if token in body:
                    warnings.append(("drift", rel, "unfinished marker: %s" % token))
            declared = fm.get("skills") or []
            if isinstance(declared, str):
                declared = [declared]
            elif isinstance(declared, dict):
                # `skills:` with no inline value parses to {} — treat nested
                # mappings as a list of their keys.
                declared = list(declared.keys())
            elif not isinstance(declared, (list, tuple)):
                declared = [str(declared)]
            pkg_root = os.path.dirname(os.path.dirname(path))
            for skill in declared:
                if not os.path.isdir(os.path.join(pkg_root, "skills", skill)):
                    warnings.append(("broken-xref", rel, "skills[%s] directory does not exist" % skill))

    if pii_total == 0:
        print("- OK    no secret / PII violations detected")

    # ---- D. integrity -----------------------------------------------------
    print("")
    print("## D. Integrity (SHA256 manifest)")
    manifest_path = os.path.join(repo, "MANIFEST.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, encoding="utf-8") as fh:
                manifest = json.load(fh)
            bad = 0
            for rel_path, expected in manifest.get("files", {}).items():
                target = os.path.join(repo, rel_path)
                if not os.path.exists(target):
                    print("- BLOCK  missing: %s" % rel_path)
                    bad += 1
                    continue
                with open(target, "rb") as fh:
                    digest = hashlib.sha256(fh.read()).hexdigest()
                if digest.lower() != str(expected).lower():
                    print("- BLOCK  sha256 mismatch: %s" % rel_path)
                    bad += 1
            if bad == 0:
                print("- OK    all %d file(s) verified" % len(manifest.get("files", {})))
            else:
                blockers.append(("integrity", "MANIFEST.json", "%d file(s) failed verification" % bad))
        except Exception as exc:  # noqa: BLE001
            warnings.append(("integrity", "MANIFEST.json", "could not parse: %s" % exc))
            print("- WARN   could not parse manifest: %s" % exc)
    else:
        print("- SKIP   no MANIFEST.json in tree")

    # ---- summary ----------------------------------------------------------
    print("")
    print("## Summary")
    print("- packages: %d" % len(packages))
    print("- blockers: %d" % len(blockers))
    print("- warnings: %d" % len(warnings))
    if blockers:
        print("")
        print("### Blockers")
        for kind, where, msg in blockers:
            print("- [%s] %s -- %s" % (kind, where, msg))
    if warnings:
        print("")
        print("### Warnings")
        for kind, where, msg in warnings:
            print("- [%s] %s -- %s" % (kind, where, msg))

    if report_path:
        try:
            with open(report_path, "w", encoding="utf-8") as fh:
                fh.write("# agent-pkg-audit report\n\n")
                fh.write("packages=%d blockers=%d warnings=%d\n\n" % (len(packages), len(blockers), len(warnings)))
                fh.write("## blockers\n")
                for kind, where, msg in blockers:
                    fh.write("- [%s] %s -- %s\n" % (kind, where, msg))
                fh.write("\n## warnings\n")
                for kind, where, msg in warnings:
                    fh.write("- [%s] %s -- %s\n" % (kind, where, msg))
        except Exception as exc:  # noqa: BLE001
            print("! could not write report: %s" % exc, file=sys.stderr)

    print("")
    print("> exit %d (%s)" % (
        1 if blockers else 0,
        "blockers found — fix before publishing" if blockers else "clean — safe to publish",
    ))
    return 1 if blockers else 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    repo = "."
    rules_path = None
    report_path = None
    exclude_dirs = []
    positional = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-r", "--repo"):
            i += 1
            repo = argv[i]
        elif arg == "--rules":
            i += 1
            rules_path = argv[i]
        elif arg == "--report":
            i += 1
            report_path = argv[i]
        elif arg == "--exclude":
            i += 1
            exclude_dirs.append(argv[i])
        elif arg in ("-v", "--version"):
            print(__version__)
            return 0
        elif arg in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            positional.append(arg)
        i += 1
    if positional:
        repo = positional[0]
    if not os.path.isdir(repo):
        print("! not a directory: %s" % repo, file=sys.stderr)
        return 2
    rules = load_rules(rules_path)
    return audit(repo, rules, report_path, exclude_dirs=exclude_dirs)


if __name__ == "__main__":
    sys.exit(main())
