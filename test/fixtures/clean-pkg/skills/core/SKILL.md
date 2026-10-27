---
name: core
description: Shared review conventions for locating, describing and prioritising findings.
---

# Core review conventions

A finding is a tuple of `location`, `problem`, `impact`. A finding without a
location is an opinion, not a finding.

Priority order: correctness first, then reversibility (can the reader undo the
mistake), then clarity. A wrong sentence outranks a clumsy one.

Write the impact as a consequence, not a label. "The reader will compute the
wrong total" is an impact. "Unclear" is not.
