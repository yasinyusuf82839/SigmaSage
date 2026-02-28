# SigmaSage
Tagline: “SIEM-grade detections, without the SIEM.”

## Vertical slice (initial)

This repository now includes a minimal Python package with:

- Sigma-style rule parsing for YAML files (`process_creation` category only)
- Rule compilation into executable predicates with a constrained condition syntax
- JSON / NDJSON event evaluation
- Deterministic alert JSON and NDJSON evidence output
- CLI entrypoint: `sigmasage`

### Supported subset

- **Logsource category**: `process_creation`
- **Field primitives**:
  - `Field: value` (equals)
  - `Field|contains: value`
- **Condition primitives**:
  - `<name>`
  - `<name> and <name>`
  - `<name> or <name>`

### Example

Rule (`rule.yml`):

```yaml
id: demo-1
title: Suspicious Command
logsource:
  category: process_creation
detection:
  selection:
    Image|contains: cmd.exe
    CommandLine|contains: whoami
  condition: selection
```

Events (`events.ndjson`):

```json
{"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami"}
{"Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "notepad.exe"}
```

Run:

```bash
python -m sigmasage.cli rule.yml --input events.ndjson --output out/
```

Outputs:

- `out/alerts.json`
- `out/evidence.ndjson`
