---
name: complex-test-skill
description: A complex skill bundle with nested directories, binary content, and Unicode for SBA test vector TV-2
version: 2.0.0
compatibility:
  - codex
  - claude
---

# Complex Test Skill

This skill demonstrates the SBA digest algorithm with:

- Nested directory structures
- Multiple file types
- Unicode filenames
- Binary content

## Structure

```
tv-2-complex/
├── SKILL.md
├── helper.py
├── nested/
│   ├── config.json
│   └── deep/
│       └── template.txt
└── resources/
    ├── données.txt
    └── icon.bin
```
