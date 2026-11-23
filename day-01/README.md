# Day 01 – SOC Fundamentals & Windows Logon Event Triage

**Focus:** SOC roles, the alert lifecycle, Windows Security events 4624 / 4625 / 4672
**Scenario type:** Simulated alert and logs (training exercise)
**MITRE ATT&CK:** T1110.003 Password Spraying · T1078.002 Valid Accounts: Domain Accounts

---

## 1. What I learned

- **SOC tiers:** Tier 1 handles alert triage (true or false positive, context, escalate or close, document). Tier 2 handles incident response. Tier 3 handles threat hunting and detection engineering.
- **Alert lifecycle:** Detection → Triage → Investigation → Decision → Documentation.
- **Alert classification:** True Positive, False Positive, Benign True Positive (authorised activity, such as an IT vulnerability scan).
- **Key Windows Security events:**

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4672 | Special privileges assigned (admin-level logon) |
| 4740 | Account locked out |

| Logon Type | Meaning |
|---|---|
| 2 | Interactive (keyboard) |
| 3 | Network (SMB, remote tools) |
| 5 | Service |
| 10 | RemoteInteractive (RDP) |

| 4625 SubStatus | Meaning |
|---|---|
| 0xC000006A | Valid user, wrong password |
| 0xC0000064 | User does not exist |
| 0xC0000234 | Account locked |

- **Brute force** (T1110.001) is one account with many passwords. **Password spraying** (T1110.003) is many accounts with a few passwords each, spread out over time to avoid lockouts.

---

## 2. Lab: Alert #20461, "Excessive failed logons" on WS-FIN-07

### Context
| Item | Detail |
|---|---|
| Target host | WS-FIN-07 (Finance workstation, Windows 11) |
| Source IP | 10.0.5.23 = PRINT-SRV-02 (print server) |
| `svc_backup` | Domain Admin service account. Normally logs on only from BKP-SRV-01 (10.0.9.4) at ~01:00 |
| `j.mwangi` | Regular user of WS-FIN-07 |

### Evidence (log extract)
```
TimeCreated (UTC)     EventID  TargetUser     LogonType  SourceIP     SubStatus
2026-11-16 07:58:11   4625     j.mwangi       2          127.0.0.1    0xC000006A
2026-11-16 07:58:30   4624     j.mwangi       2          127.0.0.1    -
2026-11-16 08:41:02   4625     administrator  3          10.0.5.23    0xC000006A
2026-11-16 08:41:04   4625     admin          3          10.0.5.23    0xC0000064
2026-11-16 08:41:05   4625     j.mwangi       3          10.0.5.23    0xC000006A
2026-11-16 08:41:07   4625     a.otieno       3          10.0.5.23    0xC000006A
2026-11-16 08:41:08   4625     p.kamau        3          10.0.5.23    0xC000006A
2026-11-16 08:41:10   4625     svc_backup     3          10.0.5.23    0xC000006A
2026-11-16 08:43:31   4625     administrator  3          10.0.5.23    0xC000006A
2026-11-16 08:43:33   4625     j.mwangi       3          10.0.5.23    0xC000006A
2026-11-16 08:43:34   4625     a.otieno       3          10.0.5.23    0xC000006A
2026-11-16 08:43:36   4625     p.kamau        3          10.0.5.23    0xC000006A
2026-11-16 08:43:37   4624     svc_backup     3          10.0.5.23    -
2026-11-16 08:43:37   4672     svc_backup     -          -            -
```

### Findings
| # | Finding | Evidence |
|---|---|---|
| 1 | **Benign activity:** the user mistyped their password at the keyboard | 07:58:11 failure followed by 07:58:30 success, type 2, from 127.0.0.1, 43 min before the attack |
| 2 | **Password spraying** from an internal server | 6 accounts, one attempt each per round, two rounds ~2.5 min apart, all from 10.0.5.23 |
| 3 | **Attacker had done some reconnaissance** | Most usernames were valid (0xC000006A); one generic guess (`admin`, 0xC0000064) |
| 4 | **Account compromised:** `svc_backup` | 4624 type 3 at 08:43:37; spraying stopped right after the success |
| 5 | **Domain Admin access gained** | 4672 at 08:43:37. The account already had admin rights, so this is valid-account abuse, not privilege escalation |
| 6 | **PRINT-SRV-02 likely compromised** | A print server should never start logons to workstations, which points to lateral movement |

### Verdict
- **Classification:** True Positive
- **Severity:** **Critical** (Domain Admin account + internal attack source + successful logon)
- **Decision:** Escalate to Tier 2 immediately

### Recommended response
1. Disable `svc_backup` and reset its password (coordinate with IT, since backups depend on it).
2. Isolate PRINT-SRV-02 and WS-FIN-07 from the network.
3. Search the SIEM for every `svc_backup` logon since 08:43:37 to find where the attacker went next.
4. Check for any other successful logons from 10.0.5.23.
5. Investigate how PRINT-SRV-02 was compromised.

### Triage note (handover to Tier 2)
> At 08:41–08:43 UTC on 2026-11-16, internal host PRINT-SRV-02 (10.0.5.23) ran a password-spraying attack (T1110.003) against WS-FIN-07, targeting 6 accounts over 2 rounds. At 08:43:37 the Domain Admin service account `svc_backup` logged on successfully (4624, type 3) with special privileges (4672). This account normally only logs on from BKP-SRV-01 around 01:00, so this is a confirmed compromise (T1078.002), and PRINT-SRV-02 is likely compromised too. Severity: **Critical**. Recommended actions: disable `svc_backup`, isolate both hosts, and search for further `svc_backup` activity since 08:43.

---

## 3. Mistakes I made and what I learned from them

| Mistake | Lesson |
|---|---|
| Labelled every event as malicious | Separate normal activity from the attack first. The user's own typo was benign. |
| Gave ATT&CK *Software* IDs (S0606, S0488) | **T** = Technique, **S** = Software, **G** = Group. Map behaviour to T-IDs. |
| Called the 4672 event "privilege escalation" | The account was already a Domain Admin. Use precise wording. |
| Triage note had no specifics or recommendation | Use the structure **When → Where → What → Impact → Severity → Recommendation** |
| Answered "Type 10 = remote logon" | Type 3 is also remote. Type 10 is specifically **RDP**. |

---

## 4. Interview prep: "How would you triage a brute-force alert?"
1. Confirm the facts: source IP, target accounts, host, time window.
2. Identify the pattern: brute force (one account) or spraying (many accounts). Check the failure codes.
3. **Check whether any attempt succeeded** (4625 followed by 4624 for the same account).
4. Add context: internal or external source, known asset, how privileged the account is.
5. Decide: no success and a known source → document it and consider blocking. Success → escalate immediately with a timeline and containment recommendations.

---

## 5. Results
| Section | Score |
|---|---|
| Investigation | 54 / 100 |
| Quiz | 3.5 / 5 |

**Skills practised:** Windows event log analysis · alert triage · ATT&CK mapping · incident severity rating · SOC reporting
