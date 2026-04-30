# Changelog

All notable changes to SafeOps will be documented in this file.

## [0.1.0] - 2026-04-29

### Added
- Initial SafeOps CLI packaging
- SSH misconfiguration detection
- Risky port detection
- Firewall status checks
- Risky services detection
- Config-driven module execution
- State persistence using local JSON storage
- Finding lifecycle tracking:
  - new
  - existing
  - worsened
  - resolved
- Slack alerts for new or worsened High/Critical findings
- Guided fix flow
- Targeted fix execution
- Backup creation before real fixes
- Rollback command support
- Privilege-aware fix behavior
- Auto re-scan after successful fix
- User-scoped runtime storage in `~/.safeops/`

### Notes
- SafeOps V1 is designed primarily for local Linux-oriented posture checking, while development and partial testing can be done on macOS.
- Exposure and advanced service validation remain limited in this version.