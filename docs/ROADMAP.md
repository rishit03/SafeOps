# SafeOps Roadmap

This document outlines the planned evolution of SafeOps beyond V1.

## V1 (Current)

SafeOps provides:

- SSH misconfiguration detection
- Risky port detection
- Firewall status checks
- Risky service detection
- State tracking for findings
- Finding lifecycle classification:
  - new
  - existing
  - worsened
  - resolved
- Slack alerts for new or worsened High/Critical findings
- Guided fix flow
- Backup and rollback support
- CLI-based workflow
- Local user-scoped configuration and state storage

---

## V1.1 (Next Iteration)

Focus: Improve detection quality and usability

Planned additions:

- Improved exposure detection:
  - distinguish between localhost and public bindings
- Service exposure context:
  - flag services bound to 0.0.0.0
- File permission checks:
  - world-readable sensitive files
- CLI output improvements:
  - cleaner formatting
  - improved summaries

---

## V1.2

Focus: Broader system coverage

Planned additions:

- Basic cloud awareness (AWS/GCP checks)
- More service checks
- Expanded misconfiguration detection
- Better error handling and logging

---

## V2

Focus: Product-level capabilities

Planned additions:

- Multi-machine support
- Central aggregation of results
- Optional lightweight dashboard
- Policy-based scanning
- Improved alerting controls

---

## Long-term Vision

SafeOps aims to become:

A simple, startup-friendly security posture tool that:
- requires minimal setup
- provides high-signal findings
- helps users fix real risks quickly
- integrates easily into developer workflows