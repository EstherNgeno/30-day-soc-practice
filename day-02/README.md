# Day 02 – Networking for SOC Analysts: Ports, Protocols & Suspicious Traffic

**Focus:** IP addressing, TCP vs UDP, the TCP handshake, key ports, beaconing, port scans, data exfiltration
**Tools:** Wireshark, PowerShell (`Get-NetTCPConnection`)
**Scenario type:** Simulated alert and firewall logs (training exercise)
**MITRE ATT&CK:** T1566.001 · T1204.002 · T1571 · T1046 · T1039 · T1041

---

## 1. What I learned

### Private (internal) IP ranges
| Range | Typical use |
|---|---|
| `10.0.0.0/8` (10.x.x.x) | Large businesses |
| `172.16.0.0/12` (172.16.x – 172.31.x) | Medium networks, Docker |
| `192.168.0.0/16` (192.168.x.x) | Home and small office |
| `127.0.0.1` | The machine itself (localhost) |

- **Internal → external** traffic can mean C2 or data theft. **Internal → internal** traffic between machines that don't normally talk can mean lateral movement.

### TCP vs UDP
- **TCP:** connection-based and reliable, starts with a three-way handshake (web, email, SMB, RDP).
- **UDP:** no handshake, fast but unreliable (DNS, DHCP, streaming). Not less secure, but attackers abuse UDP services like DNS for C2 and tunnelling.

### The TCP three-way handshake
```
SYN → SYN/ACK → ACK   = port OPEN, connection established
SYN → RST             = port CLOSED
```

### Ports every analyst should know
| Port | Protocol | SOC notes |
|---|---|---|
| 21 / 23 | FTP / Telnet | Unencrypted |
| 22 | SSH | Linux remote admin, a brute-force target |
| 25 | SMTP | Email, where phishing arrives |
| 53 | DNS (UDP) | Can be abused for C2 or tunnelling |
| 80 / 443 | HTTP / HTTPS | Most C2 hides in 443 |
| 135 | RPC | Used to run commands remotely |
| 445 | SMB | Lateral movement, ransomware |
| 3389 | RDP | Remote Desktop, heavily targeted |
| 4444 | (none) | Metasploit default port, a red flag |

### Suspicious patterns
- **Beaconing:** regular intervals and similar byte sizes to the same external IP, a sign of command-and-control (C2).
- **Port scanning:** one source sending SYNs to many ports or hosts within milliseconds.
- **Lookalike domains:** a brand name combined with an unusual top-level domain (e.g. `update-msoffice-cdn[.]xyz`).
- **Exfiltration:** data copied in from an internal server, followed by a similar amount sent out to an external IP.
- **Macro files:** `.docm`, `.xlsm` and `.pptm` contain code, a classic phishing payload.

---

## 2. Lab: Alert #20588, "Connection to non-standard port" on WS-HR-03

### Context
| Item | Detail |
|---|---|
| Host | WS-HR-03 (10.0.3.15), user `l.wanjiru` |
| 10.0.0.53 | Internal DNS server |
| 10.0.3.20 | HR-FILESRV-01 (employee records) |
| 52.97.208.2 | Microsoft (Office 365) |
| 09:13 | User opened attachment `Salary_Review_2026.docm` |

### Evidence (firewall / connection log)
```
Time (UTC)     Proto  Source              Destination           Result / Flags        Bytes    Info
09:02:11.200   UDP    10.0.3.15:58321  →  10.0.0.53:53          ALLOW                 74       DNS query: outlook.office365.com
09:02:11.410   TCP    10.0.3.15:50112  →  52.97.208.2:443       ALLOW  SYN→SYN/ACK    18,422
09:14:40.031   UDP    10.0.3.15:61002  →  10.0.0.53:53          ALLOW                 81       DNS query: update-msoffice-cdn[.]xyz
09:14:40.090   UDP    10.0.0.53:53     →  10.0.3.15:61002       ALLOW                 97       DNS answer: 185.220.101.47
09:14:41.002   TCP    10.0.3.15:50140  →  185.220.101.47:4444   ALLOW  SYN→SYN/ACK    1,206
09:15:41.004   TCP    10.0.3.15:50141  →  185.220.101.47:4444   ALLOW  SYN→SYN/ACK    1,198
09:16:41.001   TCP    10.0.3.15:50142  →  185.220.101.47:4444   ALLOW  SYN→SYN/ACK    1,211
09:17:41.003   TCP    10.0.3.15:50143  →  185.220.101.47:4444   ALLOW  SYN→SYN/ACK    1,204
09:22:30.101   TCP    10.0.3.15:50311  →  10.0.3.20:21          SYN→RST               60
09:22:30.102   TCP    10.0.3.15:50312  →  10.0.3.20:22          SYN→RST               60
09:22:30.104   TCP    10.0.3.15:50313  →  10.0.3.20:23          SYN→RST               60
09:22:30.105   TCP    10.0.3.15:50314  →  10.0.3.20:80          SYN→RST               60
09:22:30.107   TCP    10.0.3.15:50315  →  10.0.3.20:135         SYN→SYN/ACK           60
09:22:30.108   TCP    10.0.3.15:50316  →  10.0.3.20:445         SYN→SYN/ACK           60
09:22:30.110   TCP    10.0.3.15:50317  →  10.0.3.20:3389        SYN→SYN/ACK           60
09:22:30.111   TCP    10.0.3.15:50318  →  10.0.3.20:8080        SYN→RST               60
09:24:02.550   TCP    10.0.3.15:50402  →  10.0.3.20:445         ALLOW  SYN→SYN/ACK    2,431,880
09:24:15.003   TCP    10.0.3.15:50403  →  185.220.101.47:443    ALLOW  SYN→SYN/ACK    2,398,112
```

### Findings
| # | Finding | Evidence |
|---|---|---|
| 1 | **Normal traffic** | DNS lookup to the internal server and HTTPS to a Microsoft IP at 09:02, before the attachment was opened |
| 2 | **Lookalike malicious domain** | `update-msoffice-cdn[.]xyz` uses Microsoft branding with a `.xyz` ending, was looked up ~1 min after the macro document was opened, and resolved to a non-Microsoft IP |
| 3 | **C2 beaconing** | Connections every 60 s, each ~1,200 bytes, to 185.220.101.47 on port 4444 (the Metasploit default) |
| 4 | **Internal port scan** | 8 ports on HR-FILESRV-01 in ~10 ms. Ports 135 (RPC), 445 (SMB) and 3389 (RDP) were open (SYN/ACK) |
| 5 | **Data copied from the file server** | 2,431,880 bytes over SMB from HR-FILESRV-01 |
| 6 | **Data exfiltration** | 2,398,112 bytes sent to the C2 IP over port 443, 13 s later, nearly the same size |

### Attack timeline
| Time | Event | ATT&CK |
|---|---|---|
| 09:13 | User opens macro-enabled `Salary_Review_2026.docm` | T1566.001, T1204.002 |
| 09:14:40 | Macro resolves `update-msoffice-cdn[.]xyz` → 185.220.101.47 | |
| 09:14:41–09:17:41 | Beaconing every 60 s to port 4444 | T1571 |
| 09:22:30 | Port scan of HR-FILESRV-01 | T1046 |
| 09:24:02 | 2.43 MB copied from the HR file share over SMB | T1039 |
| 09:24:15 | 2.40 MB sent to the attacker over port 443 | T1041 |

### Verdict
- **Classification:** True Positive
- **Severity:** **Critical** (active C2 plus likely theft of employee personal data)
- **Decision:** Escalate immediately as a potential data breach

### Recommended response
1. Isolate WS-HR-03 (keep it powered on to preserve evidence in memory).
2. Block 185.220.101.47 and `update-msoffice-cdn[.]xyz` at the firewall and DNS.
3. Search the SIEM for other hosts that contacted that domain or IP.
4. Review the HR-FILESRV-01 access logs to find exactly which files were taken.
5. Find and remove the phishing email from every recipient's inbox.
6. Reset `l.wanjiru`'s credentials.
7. Escalate as a data breach, since personal data may trigger a deadline to notify the regulator.

### Triage note (handover to Tier 2)
> On 2026-11-23 between 09:13 and 09:24 UTC, HR workstation WS-HR-03 (10.0.3.15, user `l.wanjiru`) was compromised after the user opened the macro-enabled attachment `Salary_Review_2026.docm`. The host then beaconed to C2 server 185.220.101.47:4444 (`update-msoffice-cdn[.]xyz`) every 60 seconds, port-scanned HR-FILESRV-01 (10.0.3.20), copied about 2.4 MB from it over SMB, and sent about 2.4 MB to the C2 server over port 443. This is likely exfiltration of employee personal data. Severity: **Critical**. Recommended actions: isolate WS-HR-03, block the IP and domain, identify the files accessed on HR-FILESRV-01, find other recipients of the phishing email, and escalate as a potential data breach.

---

## 3. Hands-on: Wireshark and PowerShell on my own machine

- Listed live connections with `Get-NetTCPConnection -State Established` and matched them to processes with `Get-Process -Id`.
- Installed Wireshark and captured my own traffic while browsing to `http://neverssl.com` and `https://example.com`.

**Useful display filters**
| Filter | Shows |
|---|---|
| `dns` | DNS lookups and answers |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | New connection attempts |
| `ip.addr == x.x.x.x` | Traffic to or from one IP |
| `tcp.port == 443` | HTTPS |
| `tcp.flags.reset == 1` | Refused connections |

**How to read the results**
- The **DNS server** I asked (my router, a private IP) is different from the **IP in the DNS answer** (example.com, a public IP). Find the answer under *Domain Name System → Answers*.
- You can see TCP flags in the **Info** column (`[SYN]`, `[SYN, ACK]`, `[ACK]`) or under *Transmission Control Protocol → Flags*.
- HTTP uses port **80** and HTTPS uses port **443**.

**Status:** redo in progress. I still have to identify the handshake flags, the destination ports, and whether the HTTP page content is readable in plain text.

---

## 4. Mistakes I made and what I learned from them

| Mistake | Lesson |
|---|---|
| Said "it is a malicious domain" without reasons | **Claim plus evidence**, always |
| Thought the stolen file was the `.docm` attachment | The `.docm` was the **delivery method**. Follow the **bytes**: in from the file server, then out to the attacker = exfiltration |
| Suggested "close all ports" | Contain the **specific** hosts, IPs and accounts involved, without disrupting the business |
| Left the triage note blank | Always attempt every question; use the structure **When → Where → What → Impact → Severity → Recommendation** |
| Called 172.20.5.4 public | 172.**16** to 172.**31** is private |
| Said UDP is "easily compromised" | UDP isn't less secure; it just has no handshake |
| Confused the DNS server IP with the resolved IP | Read the DNS **answer** section |

---

## 5. Interview prep: "What's the difference between TCP and UDP, and why does it matter to a SOC analyst?"
> TCP sets up a connection with a three-way handshake and guarantees delivery, so it's used for web, email, SMB and RDP. UDP sends without a handshake, which is faster but unreliable, so it's used for DNS, DHCP and streaming. For a SOC analyst, the handshake shows whether a port is open or closed, which is how we spot scans. Attackers also abuse UDP services like DNS for C2 and data tunnelling, since that traffic is often less closely monitored.

---

## 6. Results
| Section | Score |
|---|---|
| Investigation | 49 / 100 |
| Wireshark practical | 1 / 5 (redo in progress) |
| Quiz | 3.5 / 5 |

**Skills practised:** firewall and DNS log analysis · identifying beaconing, port scans and exfiltration · building an attack timeline · ATT&CK mapping · packet capture with Wireshark · SOC reporting
