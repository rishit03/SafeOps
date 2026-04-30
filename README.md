# SafeOps

SafeOps is a lightweight security posture and exposure scanner designed
for startups and small teams that need simple, practical security checks
without enterprise complexity.

It focuses on high-signal findings, guided remediation, and easy local
usage through a CLI.

## Why SafeOps

Many startups and small teams do not have a dedicated security function, and often lack the time, budget, or awareness to continuously check their systems for risky misconfigurations and exposure issues.

SafeOps is designed to make that problem simpler.

It provides a lightweight, CLI-based way to identify high-signal security issues, track how risk changes over time, and guide remediation without requiring enterprise security tooling.

## Project Goal

SafeOps aims to help small companies and startup environments:

- detect meaningful security posture issues early
- avoid alert fatigue by focusing on high-signal findings
- fix practical misconfigurations safely
- build better security hygiene with minimal setup

## Quick Start

Run SafeOps locally in a few steps:

```bash
git clone <your-repo-url>
cd safeops

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install -e .

safeops scan
``` id="l7rd3q"

View status:

```bash
safeops status
``` id="g2eq6k"

Apply guided fixes:

```bash
safeops fix
``` id="aq8qlr"

## Current V1 Capabilities

-   SSH misconfiguration detection
-   Risky port detection
-   Firewall status checks
-   State tracking for findings
-   Status classification:
    -   new
    -   existing
    -   worsened
    -   resolved
-   Slack alerts for new or worsened High/Critical findings
-   Guided fix flow
-   Backup creation before real fixes
-   Rollback command for restoring backups

## Target Environment

SafeOps V1 is designed primarily for Linux systems.

Development can be done on macOS, but some checks and fix behavior may
differ depending on OS-specific system configuration.

## Installation

### 1. Create and activate a virtual environment

``` bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install dependencies

``` bash
pip install -r requirements.txt
```

### 3. Install SafeOps as a CLI tool

``` bash
pip install -e .
```

## Usage

### Run a scan

``` bash
safeops scan
```

### Show current status

``` bash
safeops status
```

### Show config

``` bash
safeops config show
```

### Update config

``` bash
safeops config set scan_interval_minutes 30
safeops config set offline_mode false
safeops config set enabled_checks ssh,ports,firewall
```

### Run guided fixes

``` bash
safeops fix
safeops fix SSH_PASSWORD_AUTH
```

### Roll back from a backup

``` bash
safeops rollback <backup_path> <original_path>
```

## Current Commands

-   `safeops scan`
-   `safeops status`
-   `safeops fix`
-   `safeops fix <issue_id>`
-   `safeops config show`
-   `safeops config set <key> <value>`
-   `safeops rollback <backup_path> <original_path>`

## Config and State Paths

SafeOps stores runtime files in:

\~/.safeops/

Including: - config.json - state.json

## Sample Configuration

A reference configuration is available in:

sample_config.json

SafeOps will automatically create a config file in:

~/.safeops/config.json

You can update values using:

```bash
safeops config set <key> <value>

## Sudo / Privilege Note

Some fixes require elevated privileges.

For example:

``` bash
sudo safeops fix SSH_PASSWORD_AUTH
```

Use caution when applying real fixes on system configuration files.

## Slack Alerts

SafeOps can send Slack alerts for: - new findings - worsened findings

Only High and Critical findings are alerted.

Set the webhook with:

``` bash
safeops config set slack_webhook_url <your_webhook_url>
```

## Current V1 Scope

Implemented: - SSH checks - Ports checks - Firewall checks - Slack
alerts - Guided remediation - Backup and rollback

Placeholder modules: - exposure - services

Not yet implemented: - cloud checks - dashboard - multi-machine
support - compliance mapping - advanced exposure validation

## Project Status

SafeOps is currently in active V1 development.

## Roadmap

See the project roadmap:

docs/ROADMAP.md

## Project Structure

safeops/
├── safeops/
│   ├── cli/
│   ├── modules/
│   ├── engine/
│   ├── fixes/
│   ├── alerts/
│   ├── config/
│   ├── orchestrator/
│   ├── utils/
│   └── main.py
├── docs/
├── requirements.txt
├── setup.py
├── README.md
├── CHANGELOG.md
├── sample_config.json


## Known Limitations

- V1 is primarily tested on local systems and may behave differently across operating systems
- Some detection modules (exposure, advanced service validation) are still basic
- Cloud environment scanning is not included in this version
- No dashboard or centralized view yet

## Future Work

- Improved exposure detection (public vs localhost)
- Expanded service validation
- File permission checks
- Cloud security checks (AWS/GCP)
- Multi-machine support
- Optional dashboard for aggregated results