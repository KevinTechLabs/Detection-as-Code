# Detection-as-Code

![Detection pipeline](https://github.com/YOUR_USERNAME/detection-as-code/actions/workflows/detections.yml/badge.svg)

Detection rules for my homelab, written in [Sigma](https://github.com/SigmaHQ/sigma), version-controlled, and tested in CI like any other code. Every rule ships with logs that prove it fires on the attack **and** stays quiet on look-alike benign activity. A rule that stops working, or starts firing on noise, fails the build before it ever reaches the SIEM.

Several rules come straight out of my [incident write-up](LINK_TO_YOUR_INCIDENT_REPO): the behaviors found during the investigation became detections, so the same attack gets caught automatically next time.

## Pipeline

```
 write rule ──► sigma check ──► replay test logs ──► convert ──► deploy to SIEM
 (rules/*.yml)   (syntax/spec)   (pos must fire,      (Lucene for Wazuh
                                  neg must not)        dashboard, Splunk)
```

| Stage | What it does | Fails when |
|---|---|---|
| `validate` | `sigma check` validates every rule against the Sigma spec | bad YAML, unknown modifiers, invalid fields |
| `test` | `scripts/test_rules.py` lints metadata and replays sample logs | missing ATT&CK tag, missing tests, a positive doesn't fire, a negative does |
| `convert` | `sigma convert` builds Lucene and Splunk queries | a rule can't be translated to a backend |

Converted queries are uploaded as build artifacts on every run.

## Rules

| Rule | ATT&CK | Level |
|---|---|---|
| Bash reverse shell via `/dev/tcp` | T1059.004 | high |
| Cron persistence with download-and-execute | T1053.003 | high |
| Local account created outside config management | T1136.001 | medium |
| PowerShell encoded command | T1027.010 | medium |
| Path traversal in web request | T1190 | high |

## Repo layout

```
rules/<platform>/<rule>.yml       Sigma rules
tests/<rule>/positive.jsonl       events the rule MUST match
tests/<rule>/negative.jsonl       benign look-alikes it must NOT match
scripts/test_rules.py             lint + replay harness
.github/workflows/detections.yml  CI pipeline
```

## Adding a rule

1. Write `rules/<platform>/<name>.yml` (new UUID: `python -c "import uuid; print(uuid.uuid4())"`).
2. Add `tests/<name>/positive.jsonl` with at least one real attack event.
3. Add `tests/<name>/negative.jsonl` with the closest benign event you can think of.
4. Run `python scripts/test_rules.py` locally, then open a PR. CI must pass to merge.

## Run locally

```bash
pip install -r requirements.txt
sigma check rules/
python scripts/test_rules.py
sigma plugin install elasticsearch
sigma convert -t lucene --without-pipeline rules/linux/lnx_reverse_shell_dev_tcp.yml
```

## Design notes

- **Test logs use Sigma's generic field names** (`Image`, `CommandLine`, `cs-uri-query`). In production, a pySigma processing pipeline maps these to the SIEM's real fields (for Wazuh: `data.audit.exe`, `data.audit.command`, etc.).
- **Wazuh deployment:** there's no official Sigma→Wazuh-XML backend, so the Lucene output is used for hunting in the Wazuh dashboard (OpenSearch). Native Wazuh rules for the same detections live in my SIEM Lab repo.
- **Negative tests matter more than positive ones.** Each one documents a false positive I've thought about, which is what keeps a SOC from drowning in alerts.
