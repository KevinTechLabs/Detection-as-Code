# Detection-as-Code

[![Detection pipeline](https://github.com/KevinTechLabs/detection-as-code/actions/workflows/detections.yml/badge.svg)](https://github.com/KevinTechLabs/detection-as-code/actions/workflows/detections.yml)

Detection rules for my homelab, written in [Sigma](https://github.com/SigmaHQ/sigma), version-controlled, and tested in CI like any other code. Every rule ships with logs that prove it fires on the attack **and** stays quiet on look-alike benign activity. A rule that stops working, or starts firing on noise, fails the build before it ever reaches the SIEM.

Half the rules come straight out of my [October 2026 threat hunt](https://github.com/KevinTechLabs/Homelab-Threat-Hunt). The hunt found detections that were noisy (one was right 1 time in 109) or blind (a stopped sensor alerted at level 3). Each fix is rewritten here as a Sigma rule, and the benign events that caused the noise became its negative tests, so the same mistake can't come back.

## From hunt to rule

| Hunt finding | Problem in production | Rule | Tests built from |
|---|---|---|---|
| **H6** · 5,083 "process injection" alerts | 0 requested injection rights; per-app allowlists kept missing new apps | [Explorer opened with injection rights](rules/windows/win_explorer_access_injection_rights.yml): filters on the access mask, not the app | OneDriveSetup, Etcher, MSI and OneDrive masks from the hunt |
| **H7** · credential search | Right 1 time in 109 | [Credential file search with find/grep](rules/linux/lnx_credential_search_find_grep.yml): matches the arguments, not every `find` | The real Atomic hit vs. `phpsessionclean`, Brave and `grep ^tcp` |
| **H7** · `/etc/shadow` access | 56 of 68 alerts were PAM and Wazuh | [/etc/shadow read by unexpected binary](rules/linux/lnx_shadow_read_unexpected_binary.yml) | `unix_chkpwd` and `wazuh-syscheckd` |
| **H2** · sensor went dark for 7 days | Agent stop alerted at level 3 | [Wazuh agent stopped or disabled](rules/linux/lnx_wazuh_agent_stopped.yml): catches the command before the agent goes silent | `stop`/`disable` vs. `restart`/`status` |
| **Finding 9** · DoH bypasses Pi-hole | `cloudflare-dns.com` still resolved | [DNS-over-HTTPS resolver lookup](rules/dns/dns_doh_resolver_lookup.yml) | Domains seen resolving during the hunt |

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

| Rule | ATT&CK | Level | Source |
|---|---|---|---|
| Explorer opened with injection rights | T1055 | high | Hunt H6 |
| Credential file search with find/grep | T1552.001 | medium | Hunt H7 |
| /etc/shadow read by unexpected binary | T1003.008 | high | Hunt H7 |
| Wazuh agent stopped or disabled | T1562.001 | high | Hunt H2 |
| DNS-over-HTTPS resolver lookup | T1572 | medium | Hunt finding 9 |
| Bash reverse shell via `/dev/tcp` | T1059.004 | high | Common attack |
| Cron persistence with download-and-execute | T1053.003 | high | Common attack |
| Local account created outside config management | T1136.001 | medium | Common attack |
| PowerShell encoded command | T1027.010 | medium | Common attack |
| Path traversal in web request | T1190 | high | Common attack |

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
