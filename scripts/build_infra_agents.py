#!/usr/bin/env python3
"""
NeuroSploit v3.5.1 — infrastructure host agents (Linux / Windows / Active Directory).
Writes agents_md/infra/*.md. Credits: Joas A Santos & Red Team Leaders.
"""
import os
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "agents_md", "infra")


def render(a):
    L = [f"# {a['title']} Agent\n", "## User Prompt",
         f"You are testing **{{target}}** (a host/infrastructure target) for {a['for']}.\n",
         "**Recon Context:**\n{recon_json}\n",
         "Authentication/credentials, if provided, are described in the operator directives above.\n",
         "**METHODOLOGY:**\n"]
    for i, (s, bs) in enumerate(a["steps"], 1):
        L.append(f"### {i}. {s}")
        L += [f"- {b}" for b in bs]
        L.append("")
    n = len(a["steps"]) + 1
    L += [f"### {n}. Report Format", "For each CONFIRMED finding:", "```", "FINDING:",
          f"- Title: {a['title']} on [host]", f"- Severity: {a['sev']}", f"- CWE: {a['cwe']}",
          "- Endpoint: [host/service]", "- Vector: [how]", "- Payload: [command/PoC]",
          "- Evidence: [raw tool output proving it]", f"- Impact: {a['impact']}",
          f"- Remediation: {a['fix']}", "```\n",
          "## System Prompt", a["system"]]
    return "\n".join(L) + "\n"


def A(name, title, vc, cwe, sev, steps, fix, impact):
    return {"name": name, "title": title, "for": vc, "sev": sev, "cwe": cwe, "impact": impact,
            "fix": fix, "steps": steps,
            "system": f"You are an infrastructure pentest specialist for {vc}. AUTHORIZED engagement. "
                      "Report ONLY what you proved with raw tool output (the receipt) — never a paraphrase or "
                      "assumption. If you lack access/observation to confirm, say so and gather more first. "
                      "Stay in scope; never run destructive or DoS actions. Credits: Joas A Santos & Red Team Leaders."}


INFRA = [
 # ---- recon / network ----
 A("infra_port_service_scan", "Host Port & Service Scan", "open ports and service/version discovery", "CWE-200", "Info",
   [("Scan", ["`rustscan -a {target} -- -sV` if present, else `nmap -sV -sC -Pn {target}`",
              "Identify open TCP/UDP ports, service banners and versions"]),
    ("Triage", ["Flag risky services (SMB, RDP, SSH, WinRM, LDAP, databases) and outdated versions",
                "Correlate versions to known CVEs for downstream agents"])],
   "Close/patch exposed services; restrict by firewall", "Attack-surface mapping"),
 A("infra_smb_enum", "SMB/NetBIOS Enumeration", "SMB shares, sessions and misconfigurations", "CWE-200", "Medium",
   [("Enumerate", ["`netexec smb {target}` / `crackmapexec smb {target}` for hosts, signing, null sessions",
                   "`smbclient -L //{target}/ -N` to list shares; check anonymous read/write"]),
    ("Assess", ["Flag SMB signing disabled (relay risk), guest/anonymous access, writable shares"])],
   "Require SMB signing; disable guest; restrict shares", "Lateral movement, credential relay"),
 # ---- linux ----
 A("linux_priv_esc", "Linux Privilege Escalation", "local privilege-escalation paths on a Linux host", "CWE-269", "High",
   [("Enumerate (authenticated via SSH)", ["Run linpeas/`sudo -l`, SUID/SGID (`find / -perm -4000`), cron, capabilities, writable PATH",
                                            "Check kernel version for known local exploits"]),
    ("Confirm", ["Demonstrate an actual escalation to root (or a clear, reachable path) with command output"])],
   "Patch kernel; fix sudo/SUID/cron/permission issues", "Full host compromise"),
 A("linux_ssh_weak_auth", "SSH Weak Authentication", "weak/guessable SSH credentials or misconfig", "CWE-1391", "High",
   [("Assess", ["Check allowed auth methods; test provided creds with `ssh`/`sshpass`",
                "Only test supplied credentials — never brute force out of scope"]),
    ("Confirm", ["Show authenticated shell access with the credentials, capturing the session banner"])],
   "Key-only auth; strong passwords; fail2ban", "Unauthorized host access"),
 A("linux_sudo_misconfig", "Linux Sudo Misconfiguration", "exploitable sudo rules", "CWE-250", "High",
   [("Enumerate", ["`sudo -l`; look for NOPASSWD binaries and GTFObins-exploitable entries"]),
    ("Confirm", ["Escalate via a permitted binary and show `id`=root output"])],
   "Restrict sudo to least privilege; avoid shell-capable binaries", "Privilege escalation to root"),
 A("linux_cron_writable", "Writable Cron / Service Abuse", "world-writable cron jobs or unit files", "CWE-732", "High",
   [("Find", ["Inspect /etc/cron*, systemd units, and scripts they call for writable paths"]),
    ("Confirm", ["Plant a benign marker that the privileged job executes, proving control"])],
   "Fix permissions on jobs and their targets", "Privilege escalation"),
 # ---- windows ----
 A("windows_priv_esc", "Windows Privilege Escalation", "local privilege escalation on a Windows host", "CWE-269", "High",
   [("Enumerate (authenticated)", ["Run winPEAS/`whoami /priv`; check unquoted service paths, weak service perms, AlwaysInstallElevated, token privileges (SeImpersonate)"]),
    ("Confirm", ["Demonstrate escalation to SYSTEM/admin with command output (e.g. via a Potato technique where applicable)"])],
   "Patch; fix service perms; remove dangerous privileges", "Full host compromise"),
 A("windows_smb_signing", "SMB Signing & Relay Exposure", "SMB signing not required (NTLM relay risk)", "CWE-294", "Medium",
   [("Detect", ["`netexec smb {target}` — note `signing:False`"]),
    ("Assess", ["Explain the NTLM-relay exposure; confirm a coercible auth path only if in scope"])],
   "Enforce SMB signing; disable NTLM where possible", "Credential relay, lateral movement"),
 A("windows_winrm_access", "WinRM Authenticated Access", "remote management access via WinRM", "CWE-287", "Medium",
   [("Connect", ["`evil-winrm -i {target} -u <user> -p <pass>` (or -H <hash>) with supplied creds/hash"]),
    ("Confirm", ["Show an authenticated remote shell and the host context (`whoami`, hostname)"])],
   "Restrict WinRM; strong creds; network segmentation", "Remote host control"),
 # ---- active directory ----
 A("ad_kerberoasting", "AD Kerberoasting", "service accounts with crackable SPNs", "CWE-522", "High",
   [("Request", ["`netexec ldap {target} -u <user> -p <pass> --kerberoasting out.txt` or impacket GetUserSPNs"]),
    ("Crack & confirm", ["Crack the TGS hash offline (hashcat -m 13100); confirm a recovered service-account password"])],
   "Strong/long service-account passwords; gMSA", "Service-account compromise, lateral movement"),
 A("ad_asreproasting", "AD AS-REP Roasting", "accounts with Kerberos pre-auth disabled", "CWE-522", "High",
   [("Enumerate", ["impacket GetNPUsers / `netexec ldap {target} --asreproast out.txt` for DONT_REQ_PREAUTH accounts"]),
    ("Crack & confirm", ["Crack the AS-REP (hashcat -m 18200); confirm a recovered password"])],
   "Require Kerberos pre-auth; strong passwords", "Account compromise"),
 A("ad_acl_privesc", "AD ACL / DACL Abuse", "dangerous Active Directory ACLs", "CWE-269", "High",
   [("Map", ["Collect with bloodhound-python/SharpHound; find GenericAll/WriteDACL/ForceChangePassword edges"]),
    ("Confirm", ["Demonstrate one safe, reversible control step (e.g. shadow-cred / targeted password reset in a lab) proving the path"])],
   "Tighten ACLs; tiered admin model", "Domain privilege escalation"),
 A("ad_dcsync", "AD DCSync Exposure", "replication rights enabling DCSync", "CWE-269", "Critical",
   [("Check rights", ["Identify principals with DS-Replication-Get-Changes(-All) via BloodHound/ACL review"]),
    ("Confirm", ["With authorized creds, prove replication right (e.g. impacket secretsdump -just-dc-user for a single test account)"])],
   "Remove replication rights from non-DC principals", "Full domain credential compromise"),
 A("ad_default_creds", "AD/Host Default & Reused Credentials", "default or reused credentials across the domain", "CWE-798", "High",
   [("Spray (authorized, throttled)", ["With supplied account list, `netexec smb {target} -u users -p pass --continue-on-success` within ROE"]),
    ("Confirm", ["Show a successful authentication that should not have worked (reused/default cred)"])],
   "Rotate defaults; enforce unique strong passwords; lockout", "Lateral movement, domain access"),
]


def main():
    os.makedirs(OUT, exist_ok=True)
    for a in INFRA:
        open(os.path.join(OUT, a["name"] + ".md"), "w").write(render(a))
    print(f"wrote {len(INFRA)} infra agents to {OUT}")


if __name__ == "__main__":
    main()
