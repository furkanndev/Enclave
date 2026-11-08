# Enclave - Workspace Agent Guidelines

This workspace is governed by the project rules and the Professional Python GUI UI/UX standards.

The agent must strictly comply with:
1. `@[Project Rules](.agents/rules/project_rules.md)`
2. `@[Python GUI UI/UX Standards](.agents/rules/python_gui_standard.md)`

### Key Inviolable Directives:
- **Automatic EXE Build:** Every prompt completion that modifies code MUST run `python build_exe.py` and verify `dist/Enclave.exe` is successfully generated with exit code 0.
- **Zero Neon / Zero Retro Emojis:** Use clean Apple Minimal / Modern Fluent design tokens, no neon green/purple or emojis, 100% SVG vector icons.
- **Zero Forensic Trace:** Strict RAM-only execution for encrypted container files, zero unencrypted disk cache, DoD secure wiping with fsync.
- **UI/UX & Dynamic Layout Standards:** No absolute positioning, no hardcoded fixed button/input sizes (use padding + min-width/min-height), always set word-wrap on dynamic/descriptive labels, consistent container spacing/padding, and responsive layouts.
- **Visual Testing & Layout Stability:** Run tests and verify rendered interface layouts before marking any UI task complete.

