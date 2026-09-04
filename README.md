# Centralized SIEM with Splunk — Aggregating Wazuh, Suricata, Linux, and Windows into a Single Detection Platform

`Splunk` `Wazuh` `Suricata` `Windows` `Linux` `MITRE`  **Status: Complete**

## Overview

This is **Phase 5** of a progressive security monitoring series. The previous four phases built a complete detection stack — host-based intrusion detection with OSSEC, a full Wazuh SIEM, a hybrid cloud SOC on AWS, and a dual-layer Suricata + Wazuh network/host lab. Every one of those phases ended with the same note: *Splunk is next.* This phase delivers it.

Here, **Splunk Enterprise becomes the central aggregation and correlation platform**. Instead of each tool reporting into its own separate dashboard, all detection sources feed one SIEM. Suricata's network alerts, Wazuh's host alerts, raw Linux authentication logs, and Windows Event Logs are ingested into Splunk simultaneously, where they can be searched, correlated, and visualized from a single pane of glass.

The result is what a real SOC actually looks like: one platform where an analyst sees a single attack reflected across the network layer, the host layer, and the raw OS logs at the same time.

> **Phase 1** — OSSEC Host-Based IDS
> **Phase 2** — Wazuh On-Premise SIEM
> **Phase 3** — Wazuh + AWS Hybrid SOC
> **Phase 4** — Suricata + Wazuh Dual-Layer Detection
> **Phase 5** — This project: all sources unified in Splunk

---

## Why Centralize into Splunk

The earlier phases proved that individual detection tools work. But in each one, the data lived in its own silo — Suricata wrote to its log, Wazuh had its own dashboard, Linux and Windows logs sat on their own machines. An analyst investigating an incident would have to jump between four separate places and mentally stitch the timeline together.

A SIEM solves this. By ingesting every source into one indexed, searchable platform, a single query can pull the complete picture of an attack. When an SSH brute force hits the Ubuntu server, the same event is now visible three ways in one search — as raw `Failed password` lines from the OS, as a severity-scored correlated alert from Wazuh, and (for network-visible activity) as Suricata signatures — all timestamped and cross-referenceable.

This is the difference between *log collection* and *security operations*.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          ATTACK SURFACE                               │
│   Kali Linux Attacker — 192.168.0.50                                  │
│   SSH brute force · reconnaissance                                    │
└─────────────────────────────┬────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────────┐
│              UBUNTU SOC SERVER — 192.168.0.150 / 192.168.56.101       │
│                                                                        │
│   ┌────────────────┐   ┌────────────────┐   ┌──────────────────────┐ │
│   │ Suricata NIDS  │   │ Wazuh Manager  │   │ Linux OS Logs        │ │
│   │ eve.json       │   │ alerts.json    │   │ syslog · auth.log    │ │
│   │ (network)      │   │ (host detect)  │   │ (raw OS events)      │ │
│   └───────┬────────┘   └───────┬────────┘   └──────────┬───────────┘ │
│           │                    │                        │             │
│           └────────────────────┼────────────────────────┘             │
│                                ▼                                       │
│                    ┌───────────────────────┐                          │
│                    │   SPLUNK ENTERPRISE   │                          │
│                    │   Indexer + Search    │                          │
│                    │   Web UI :8000        │                          │
│                    │   Receiver :9997      │                          │
│                    └───────────┬───────────┘                          │
└────────────────────────────────┼──────────────────────────────────────┘
                                 ▲
                                 │  forwards over :9997
                                 │
┌────────────────────────────────┴──────────────────────────────────────┐
│              WINDOWS ENDPOINT — 192.168.0.200                          │
│              Splunk Universal Forwarder                                │
│              WinEventLog: Security · System · Application              │
└────────────────────────────────────────────────────────────────────────┘
```

| Component | Role | Detail |
|---|---|---|
| Ubuntu SOC Server | Splunk indexer + all local sources | Splunk Enterprise 10.2.3 |
| Splunk Web UI | Search, dashboards, analysis | Port 8000 |
| Splunk Receiver | Ingests forwarder data | Port 9997 |
| Wazuh Manager | Host detection sensor → Splunk | Wazuh 4.7.5, JSON output |
| Suricata | Network detection sensor → Splunk | eve.json, ~49,895 ET rules |
| Windows Endpoint | Monitored endpoint | Splunk Universal Forwarder 10.2.3 |
| Kali Linux | Attacker | 192.168.0.50 |

**Architectural note:** In this project Wazuh runs purely as a **detection sensor** feeding Splunk, not as a standalone SIEM. Its heavy indexer and dashboard components are disabled to keep the platform stable on a resource-constrained VM — Splunk is the search and storage engine. Automated active-response blocking is demonstrated separately in the OSSEC and Suricata + Wazuh phases; the focus here is centralized aggregation and correlation.

---

## Data Sources Ingested

Four independent source types, six log streams, two hosts — all landing in Splunk simultaneously.

| Source | Sourcetype | Host | Layer |
|---|---|---|---|
| `/var/log/suricata/eve.json` | `suricata` | ubuntu | Network |
| `/var/ossec/logs/alerts/alerts.json` | `wazuh_alerts` | ubuntu | Host detection |
| `/var/log/syslog` | `syslog` | ubuntu | OS system |
| `/var/log/auth.log` | `linux_secure` | ubuntu | OS authentication |
| `WinEventLog:Security` | `WinEventLog:Security` | Emmanuel-Desktop | Windows security |
| `WinEventLog:System` | `WinEventLog:System` | Emmanuel-Desktop | Windows system |
| `WinEventLog:Application` | `WinEventLog:Application` | Emmanuel-Desktop | Windows application |

Verification search confirming all sources live simultaneously:

```spl
index=* earliest=-15m | stats count by source sourcetype host
```

> *Screenshot: `all-sources-ingesting.png` — all six sourcetypes reporting at once*

---

## Configuration

### Splunk receiver (Ubuntu)

Enable the receiving port for the Windows forwarder, in `/opt/splunk/etc/system/local/inputs.conf`:

```ini
[splunktcp://9997]
connection_host = ip
disabled = false
```

### Local source monitors (Ubuntu)

```ini
[monitor:///var/log/syslog]
disabled = false
index = main
sourcetype = syslog

[monitor:///var/log/auth.log]
disabled = false
index = main
sourcetype = linux_secure

[monitor:///var/ossec/logs/alerts/alerts.json]
disabled = false
index = main
sourcetype = wazuh_alerts
```

Suricata's `eve.json` is monitored the same way. Wazuh's **JSON** output is used rather than the plain-text `alerts.log` so that fields (rule level, description, source IP, MITRE mapping) parse natively into Splunk rather than needing regex extraction.

### Windows Universal Forwarder

On the Windows endpoint, `inputs.conf` collects the event logs via the Windows Event Log API:

```ini
[WinEventLog://Security]
disabled = false
index = main

[WinEventLog://System]
disabled = false
index = main

[WinEventLog://Application]
disabled = false
index = main
```

And the forwarder is pointed at the Splunk receiver:

```
splunk add forward-server 192.168.0.150:9997
```

---

## Attack Demonstration & Detection

### SSH Brute Force — detected across three layers

From Kali, a credential brute force was launched against the Ubuntu SSH service:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.0.150 -t 4 -V
```

> *Screenshot: `hydra-attack.png` — attacker view from Kali*

The same attack was then observed in Splunk at multiple fidelities.

**1 — Raw OS authentication failures (`linux_secure` / auth.log):**

```spl
index=* sourcetype=linux_secure "Failed password" earliest=-10m
```

Returned the raw daemon lines, e.g.:

```
Failed password for root from 192.168.0.50 port 51986 ssh2
Failed password for root from 192.168.0.50 port 52006 ssh2
```

> *Screenshot: `auth-log-failures.png`*

**2 — Wazuh correlated detection with severity escalation (`wazuh_alerts`):**

```spl
index=* sourcetype=wazuh_alerts earliest=-10m
| search rule.description="*authentication*" OR rule.description="*brute*"
| table _time rule.level rule.description data.srcip
```

This is the core result. Individual failed logins register as **Level 5** (`sshd: authentication failed`), but Wazuh's correlation engine recognizes the *pattern* of repeated failures from a single source and escalates to **Level 10** — `sshd: brute force trying to get access to the system` — all attributed to source IP `192.168.0.50`.

| _time | rule.level | rule.description | data.srcip |
|---|---|---|---|
| 22:08:23 | 5 | sshd: authentication failed | 192.168.0.50 |
| 22:08:26 | 5 | sshd: authentication failed | 192.168.0.50 |
| **22:08:27** | **10** | **sshd: brute force trying to get access to the system** | 192.168.0.50 |
| 22:08:29 | 5 | sshd: authentication failed | 192.168.0.50 |

> *Screenshot: `wazuh-bruteforce-correlation.png` — the Level 5 → Level 10 escalation*

**3 — Full attack window across all sources:**

```spl
index=* earliest=-15m | stats count by source sourcetype host
```

Shows the same attack window reflected simultaneously across Suricata (network), Wazuh and auth.log (host), and Windows logs — the defense-in-depth picture in a single frame.

> *Screenshot: `all-sources-during-attack.png`*

The value demonstrated here: **raw evidence and correlated detection of the same event, side by side, in one platform.** The auth.log lines are ground truth; the Wazuh alert is the interpreted, severity-scored, attributable detection an analyst would actually action.

---

## Troubleshooting Log

Real deployment issues encountered and how they were resolved.

### Splunk could not read Linux system logs (permissions)

**Symptom:** `syslog` and `auth.log` inputs were configured correctly and the files were actively being written, yet no `syslog` or `linux_secure` events ever appeared in Splunk. Suricata and Wazuh JSON ingested fine.

**Root cause:** Splunk runs as the `splunk` service user. On Ubuntu, `/var/log/syslog` and `/var/log/auth.log` are owned `syslog:adm` with permissions `-rw-r-----` — readable only by the `syslog` user and the `adm` group. This is deliberate: Linux restricts authentication logs because they contain sensitive security data. The `splunk` user was not in the `adm` group, so it silently failed to read the files.

**Fix:**

```bash
sudo usermod -aG adm splunk
sudo systemctl restart splunk
```

After the restart, `syslog` and `linux_secure` immediately began ingesting. This is the classic Splunk-on-Linux ingestion gotcha — the config is correct but the service account lacks read permission on protected logs.

### Duplicate ingestion from scattered config files

**Symptom:** Wazuh alerts were being counted two to three times; `syslog` and `auth.log` each appeared multiple times in the effective config.

**Root cause:** Input stanzas had accumulated across multiple `inputs.conf` files — `system/local`, `apps/launcher/local`, and `apps/search/local`. Splunk merges inputs from all app contexts, so appending to one file over multiple sessions produced duplicates. Additionally, both Wazuh's `alerts.log` (plain text) and `alerts.json` were being monitored, ingesting every alert twice.

**Fix:** Used `btool` to find every effective definition, then consolidated to a single clean stanza per source and kept only the JSON Wazuh output:

```bash
sudo /opt/splunk/bin/splunk btool inputs list --debug | grep "monitor://"
```

`btool` shows the *merged* configuration across all locations with the source file for each setting — the reliable way to debug "but I already removed it" duplication.

### Windows forwarder inactive after downtime

**Symptom:** After the lab sat idle, the Universal Forwarder service was running but showed `Configured but inactive forwards` — no Windows data reaching Splunk.

**Root cause:** The forwarder connection had not re-established after the extended downtime, though the network path was intact (`Test-NetConnection` to port 9997 succeeded).

**Fix:** Restarting the forwarder service re-established the connection:

```powershell
Restart-Service SplunkForwarder
```

The forward flipped to `Active forwards: 192.168.0.150:9997` and Windows Event Logs resumed. A reminder that forwarders can silently go inactive after downtime and should be verified, not assumed.

---

## Splunk Free — Known Limitations

This lab runs on **Splunk Free** (after the Enterprise trial period). These constraints are documented honestly as they affect the deployment:

| Limitation | Impact on this lab |
|---|---|
| **No authentication** | Splunk Free removes login entirely — the web UI is open as admin on the local network. In production, Enterprise with role-based access control would be required. |
| **500 MB/day ingestion cap** | Sufficient for lab volumes, but a real environment generating this many Suricata + Wazuh events would exceed it quickly. |
| **No alerting / scheduled searches** | Real-time triggered alerts are disabled. Detection here is demonstrated through searches; automated response is shown in the OSSEC and Suricata + Wazuh phases, and Wazuh's own active response operates independently of Splunk licensing. |

Documenting these is itself part of the exercise — understanding SIEM licensing tiers and their operational tradeoffs is a real-world skill.

---

## What This Completes

Across five phases this series has moved from a single host-based IDS engine to a unified SIEM aggregating network, host, and multi-OS telemetry:

```
Phase 1 — OSSEC          Raw host-based detection engine
Phase 2 — Wazuh          Full SIEM, multi-agent, MITRE mapping
Phase 3 — Wazuh + AWS    Hybrid cloud + on-premise SOC
Phase 4 — Suricata+Wazuh Network layer added — HIDS + NIDS
Phase 5 — Splunk         All sources unified in one SIEM
```

Every detection capability built across the series now reports into a single searchable platform. An analyst can pivot from a network signature to a host alert to a raw OS log for the same event in one query — which is the fundamental workflow of a Security Operations Center.

---

## Key Skills Demonstrated

- Splunk Enterprise deployment — indexer, receiver, Universal Forwarder
- Multi-source data onboarding — file monitors, WinEventLog API, forwarder
- Cross-source correlation of a single attack (network + host + OS logs)
- SPL search for threat detection and evidence retrieval
- Real-world troubleshooting — Linux log permissions, config precedence, forwarder recovery
- Understanding SIEM architecture and licensing tradeoffs

---

## Author

**Emmanuel Siamoonga**
Cloud Infrastructure · Network and Cloud Security

*LinkedIn · GitHub*

> *"Defense in depth is not about adding more tools. It is about ensuring every layer catches what the previous layer missed — and that one platform can see them all."*
