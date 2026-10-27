#!/usr/bin/env node
/**
 * agent-pkg-audit · CLI
 * ---------------------------------------------------------------
 * Zero-dependency wrapper that ships the Python auditor as a
 * self-contained single-file script and runs it with whichever
 * Python 3.9+ interpreter is available.
 *
 * Usage:
 *   npx agent-pkg-audit [path] [--rules <file>] [--report <file>]
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const PKG = require('../package.json');
const CORE = path.join(__dirname, '..', 'lib', 'audit_core.py');

function findPython() {
  // On Windows, `py -3` is the launcher and `py` alone may map to Python 2.
  // Probe with explicit argument vectors so no shell quoting is involved.
  const candidates = process.platform === 'win32'
    ? [['py', ['-3']], ['python3', []], ['python', []]]
    : [['python3', []], ['python', []]];
  for (const [cmd, prefix] of candidates) {
    const probe = spawnSync(
      cmd,
      [...prefix, '-c', 'import sys; sys.exit(0 if sys.version_info>=(3,9) else 1)'],
      { stdio: 'ignore', shell: false },
    );
    if (!probe.error && probe.status === 0) return { cmd, prefix };
  }
  return null;
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('-v') || args.includes('--version')) {
    console.log(PKG.version);
    return;
  }
  if (args.includes('-h') || args.includes('--help')) {
    console.log(fs.readFileSync(CORE, 'utf8').split('"""')[1].trim());
    console.log('\nUsage: npx agent-pkg-audit [path] [--rules <file>] [--report <file>]');
    return;
  }

  const python = findPython();
  if (!python) {
    console.error('agent-pkg-audit requires Python 3.9 or newer on PATH.');
    console.error('Install Python 3.9+ and retry, or run the auditor directly:');
    console.error('  python3 ' + CORE + ' <path>');
    process.exit(2);
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-pkg-audit-'));
  const script = path.join(tmp, 'audit_core.py');
  fs.copyFileSync(CORE, script);

  const result = spawnSync(python.cmd, [...python.prefix, script, ...args], {
    stdio: 'inherit',
    shell: false,
  });
  try {
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch (_) {
    /* best effort cleanup */
  }
  process.exit(result.status === null ? 1 : result.status);
}

main();
