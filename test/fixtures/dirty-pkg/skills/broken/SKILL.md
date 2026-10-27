---
name: broken
description: Skill directory exists but no agent references it. Used to test that the auditor does not flag unreferenced skills as errors.
---

# Unreferenced skill

This skill is intentionally not referenced by any agent. It exists so the
auditor has something valid to walk past — unreferenced skills are legal, only
broken references are not.
