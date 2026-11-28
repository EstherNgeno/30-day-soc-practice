# Day 03 – Home Lab Refresh: Architecture, Isolation & the Log Pipeline

**Focus:** how my SOC home lab is built and isolated, how a Windows event becomes a SIEM alert, collection vs detection gaps
**Tools:** VirtualBox, Wazuh 4.14.9, Sysmon 15.22, Windows Event Viewer, Linux `systemctl` / `journalctl`
**Lab:** my own isolated lab ([Virtual-Cybersecurity-Lab](https://github.com/EstherNgeno/Virtual-Cybersecurity-Lab)). Real events generated on lab-owned VMs only
**MITRE ATT&CK:** T1110 Brute Force (failed-logon detections)

---

## 1. What I learned

### Lab architecture
```
         Host laptop (Windows 11 + VirtualBox)
         browser → https://127.0.0.1:8443  (Wazuh dashboard)
                          │
   ┌──────────────┐   ┌───┴──────────┐
   │ KALI         │   │ WAZUH-SRV    │  SIEM: manager, indexer, dashboard
   │ 10.10.10.50  │   │ 10.10.10.10  │
   └──────┬───────┘   └───▲──────────┘
          │               │ agent logs over TCP 1514
 ═════════╪═══ soc-lab 10.10.10.0/24 (Internal Network, no gateway) ═══
          │               │
   ┌──────┴───────┐   ┌───┴──────────┐
   │ LNX-TGT      │   │ WIN-TGT      │  Windows 11 endpoint:
   │ 10.10.10.30  │   │ 10.10.10.20  │  Sysmon + Wazuh agent
   │ Metasploitable│  └──────────────┘
   └──────────────┘
```
| VM | Role in a real SOC |
|---|---|
| WAZUH-SRV | The SIEM the analyst monitors |
| WIN-TGT | A monitored employee endpoint |
| KALI | Attacker, used to generate realistic activity |
| LNX-TGT | Intentionally vulnerable server for scanning practice |

### How a log becomes an alert
```
① Event happens on WIN-TGT (process starts, logon fails)
② Windows Security log / Sysmon writes the event
③ Wazuh agent reads it and sends it → TCP 1514 → WAZUH-SRV
④ Manager decodes the event and checks it against rules
⑤ Rule level ≥ 3 → ALERT   (level 0 = recorded, never alerted)
⑥ Alert stored in the indexer → shown on the dashboard
```

### Collection gap vs detection gap
- **Collection gap:** the event never reaches the SIEM (it isn't logged, or the agent filters it).
- **Detection gap:** the event reaches the SIEM, but no rule turns it into an alert.
- In my Phase 10 simulations, 3 out of 4 missing alerts were collection gaps, so it pays to check both.

### Sysmon Event IDs
| ID | Meaning |
|---|---|
| 1 | Process created |
| 3 | Network connection |
| 11 | File created |
| 13 | Registry value set |
| 16 | Sysmon configuration changed |
| 22 | DNS query |

---

## 2. Troubleshooting: "Wazuh dashboard site cannot be reached"

Getting the lab running turned into a real SIEM outage investigation.

| Step | Symptom | Diagnosis | Fix |
|---|---|---|---|
| 1 | `https://127.0.0.1:8443` → *site cannot be reached* | The TCP port opened but nothing answered. The VM's **NAT adapter cable was disconnected**, and the dashboard and SSH port-forwards depend on that adapter | Reconnected Adapter 2 (`VBoxManage controlvm WAZUH-SRV setlinkstate2 on`) |
| 2 | *Wazuh dashboard server is not ready yet* (HTTP 503) | `systemctl is-active` → **wazuh-indexer = failed**; manager, filebeat and dashboard were active | Read the indexer log |
| 3 | `journalctl -u wazuh-indexer` | `start operation timed out` after the 10-minute limit, with only **3 min 24 s of CPU time**. The indexer was **CPU-starved** because WIN-TGT booted while it was still starting (WAZUH-SRV has 1 vCPU and the host was low on RAM) | Shut down WIN-TGT, freed host memory, `sudo systemctl restart wazuh-indexer` → **active** |

**Lessons:**
- Separate the **symptom** ("the site won't load") from the **root cause** ("the indexer timed out because it was starved of CPU").
- **Start order:** start WAZUH-SRV, wait until the dashboard login page loads, *then* start WIN-TGT.
- If the dashboard is unreachable, check first: WAZUH-SRV → Settings → Network → Adapter 2 → *Cable Connected*.

---

## 3. Lab exercises

### Exercise A: follow a process launch through the pipeline
Opened Notepad on WIN-TGT and found **Sysmon Event ID 1** in *Event Viewer → Microsoft → Windows → Sysmon → Operational* (Image `C:\Windows\System32\notepad.exe`, ParentImage `C:\Windows\explorer.exe`).
Searched the dashboard for `agent.name:WIN-TGT and data.win.system.eventID:1`. **Notepad was not there**, because a normal process start matches a **level 0** rule, so it is collected but never alerted.

### Exercise B: generate and detect failed logons
On WIN-TGT: `runas /user:labadmin cmd` with a wrong password ×2, then `runas /user:fakeuser cmd` ×8.
Dashboard search: `agent.name:WIN-TGT and data.win.system.eventID:4625`

| Rule ID | Level | Description | Meaning |
|---|---|---|---|
| 60122 | 5 | Logon Failure - Unknown user or bad password | A single failed logon |
| 60204 | 10 | Multiple Windows Logon Failures | Correlated burst, a brute-force pattern (T1110) |

### Exercise C: clean shutdown
Shut down WIN-TGT first, then WAZUH-SRV, using the guest OS shutdown (not "Save state" or "Power off").

---

## 4. Investigation questions: model answers

**Q1. The 6 steps from "Notepad opened" to "alert on the dashboard"**
1. Notepad starts on WIN-TGT.
2. Sysmon writes Event ID 1 (process created) to its log.
3. The Wazuh agent reads the event and sends it to WAZUH-SRV over TCP 1514.
4. The Wazuh manager decodes the event and checks it against its rules.
5. If the matching rule is level 3 or above, it becomes an alert; level 0 means recorded but not alerted.
6. The alert is stored in the indexer and shown on the dashboard.

**Q2. Which port does the agent use, and how do you prove it's connected?**
TCP **1514** for events (TCP **1515** for enrolment). Port 8443 is only the dashboard, for the browser.
Proof: ① *Agents management → Summary* shows WIN-TGT as **Active**; ② new WIN-TGT events keep arriving on the dashboard (e.g. 4625 alerts seconds after the failed `runas`). Also possible: `sudo /var/ossec/bin/agent_control -l` on WAZUH-SRV.

**Q3. Was Notepad's Event ID 1 in Event Viewer? On the dashboard?**
In Event Viewer: **yes** (Sysmon logged it). On the dashboard: **no**. A normal process start matches a **level 0** rule, so the event reaches the manager but never becomes an alert. "Not on the dashboard" does not mean "not collected".

**Q4. Rule ID, level and description of a 4625 alert**
Rule **60122**, level **5**, *"Logon Failure - Unknown user or bad password"*.

**Q5. Logon type and subStatus for labadmin and fakeuser**
| Account | logonType | subStatus | Meaning |
|---|---|---|---|
| labadmin | 2 | 0xC000006A | Interactive logon; account exists, wrong password |
| fakeuser | 2 | 0xC0000064 | Interactive logon; account does not exist |

The difference shows whether an attacker knows real usernames or is guessing.

**Q6. Did a higher-level alert appear after the burst?**
Yes: rule **60204**, level **10**, *"Multiple Windows Logon Failures"*. One 4625 could be a typo; 60204 **correlates** many failures in a short time window into one alert, which is the pattern of a brute-force or password-spraying attack (T1110).

**Q7. Three isolation controls and the threat each prevents**
| Control | Threat prevented |
|---|---|
| Internal Network `soc-lab` with no gateway | Attack traffic routing out of the lab |
| No bridged adapters on any VM | Lab traffic reaching the home network |
| LNX-TGT has no NAT or internet adapter | A vulnerable host being reachable from the internet |
| NAT cables disconnected during exercises + `preflight.sh` check | Human error before scans or simulations |
| Snapshots before simulations | Permanent changes from attacks |

**Q8. Why is the dashboard bound to 127.0.0.1?**
Only the host laptop can open it, not other devices on the home Wi-Fi. SIEMs are high-value targets, because an attacker who controls one can hide their own alerts.

---

## 5. Quiz: model answers
1. **Sysmon Event IDs:** 1 = process created, 3 = network connection.
2. **Wazuh rule level 0:** the event matched a rule but isn't worth an alert, so it isn't shown on the dashboard.
3. **Collection vs detection gap:** *Collection:* in the Phase 10 port scan, Windows wasn't auditing blocked packets (Event 5152) and the agent filtered them out. *Detection:* in the Phase 10 PowerShell → port 4444 test, the Sysmon Event 3 arrived, but the custom rule was attached to the wrong parent rule (the correct anchor was 92101).
4. **Why snapshot before a simulation?** It gives a clean restore point. Simulations change the system, and a snapshot lets you roll back to a known-good state and repeat the test.
5. **Interview: "How does a log get from an endpoint into a SIEM and become an alert?"**
   > An event happens on the endpoint, like a failed logon or a new process, and Windows or Sysmon writes it to a log. A SIEM agent reads that log and forwards it to the SIEM server; in Wazuh that's over TCP 1514. The server decodes the event and checks it against detection rules. If a rule matches above the alert threshold, an alert is created, stored in the indexer, and shown on the dashboard for an analyst to triage. In my home lab I've seen that an alert can be missing for two reasons: the event was never collected, or it arrived but no rule matched, so I check both.

---

## 6. Additional finding: rule 61618 "Sysmon - Suspicious Process - svchost.exe"

While searching for Event ID 1, the dashboard showed **2 × level 12 alerts** from WIN-TGT: rule **61618**, *"Sysmon - Suspicious Process - svchost.exe"*, mapped to ATT&CK **Process Injection**.

**Triage approach for this alert:**
- Record `image`, `parentImage`, `commandLine`, `user` and the exact time from the alert.
- Compare against the norm: legitimate `svchost.exe` is started by `services.exe`.
- Check what the host was doing at that time (these alerts appeared shortly after WIN-TGT booted).
- Classify it as a true positive, false positive or benign true positive, with evidence.

---

## 7. Mistakes I made and what I learned from them

| Mistake | Lesson |
|---|---|
| Described my clicks instead of the 6 pipeline steps (Q1) and gave incident response actions instead of isolation controls (Q7) | **Read the question twice** and answer what it asks |
| Said the agent uses port 8443 | 8443 is the dashboard. The agent uses **1514** (events) and **1515** (enrolment) |
| Took the svchost alerts for Notepad's event | Check the **image** field. Notepad's event was level 0, so it was never alerted |
| Reported 0xC0000064 for labadmin | labadmin exists, so it's **0xC000006A** (wrong password) |
| Defined collection vs detection gaps without an example | Back every concept with evidence from my own lab |

---

## 8. Results
| Section | Score |
|---|---|
| Investigation | 35 / 80 |
| Quiz | 4.25 / 5 |

**Skills practised:** SIEM operation (Wazuh) · Sysmon and Windows Security log analysis · detecting failed logons and brute force · SIEM service troubleshooting (`systemctl`, `journalctl`) · lab network isolation design
