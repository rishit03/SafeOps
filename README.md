# SafeOps

SafeOps is a lightweight security posture and exposure scanner designed
for startups and small teams that need simple, practical security checks
without enterprise complexity.

It focuses on high-signal findings, guided remediation, and easy local
usage through a CLI.

## Why SafeOps

Many startups and small teams do not have a dedicated security function,
and often lack the time, budget, or awareness to continuously check
their systems for risky misconfigurations and exposure issues.

SafeOps is designed to make that problem simpler.

It provides a lightweight, CLI-based way to identify high-signal
security issues, track how risk changes over time, and guide remediation
without requiring enterprise security tooling.

## Project Goal

SafeOps aims to help small companies and startup environments:

-   detect meaningful security posture issues early
-   avoid alert fatigue by focusing on high-signal findings
-   fix practical misconfigurations safely
-   build better security hygiene with minimal setup

## Quick Start

``` bash
git clone https://github.com/rishit03/SafeOps.git
cd SafeOps

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install -e .

safeops scan
```

## One-line install (recommended)

``` bash
curl -sSL https://raw.githubusercontent.com/rishit03/SafeOps/main/install.sh | bash
```

## Usage

### Run a scan

``` bash
safeops scan
```

### Quick health check

``` bash
safeops check
```

### Show status

``` bash
safeops status
safeops status --summary
```

### Fix issues (safe mode)

``` bash
safeops fix
```

### Apply real fixes

``` bash
safeops fix --apply
```

### Run scheduler

``` bash
safeops start
```

### Rollback

``` bash
safeops rollback <backup_path> <original_path>
```

## Features

-   SSH misconfiguration detection
-   Port exposure detection (binding-aware)
-   Service detection
-   Exposure classification
-   File permission checks
-   Firewall checks

## Intelligence

-   Finding lifecycle tracking
-   Risk scoring
-   Risk delta tracking

## Alerts

-   Slack integration
-   Alerts only for new/worsened High/Critical issues

## Remediation

-   Guided fixes
-   Dry-run by default
-   Explicit apply mode
-   Backup + rollback

## Logging

Logs are stored in:

    ~/.safeops/safeops.log

## Config

Runtime config:

    ~/.safeops/config.json

Reference config:

    sample_config.json

## Known Limitations

-   Primarily tested on local systems
-   Limited exposure detection (no external validation)
-   No cloud checks yet
-   No centralized dashboard

## Roadmap

See:

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

## License

MIT License
