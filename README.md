# CVE-2026-41940 IOC + ClamAV Infrastructure Scan

Incident response script for cPanel/WHM servers. Combines the official cPanel CVE-2026-41940 IOC detection logic with ClamAV malware scanning and post-exploitation persistence checks.

## Background

CVE-2026-41940 is a CVSS 9.8 pre-authentication bypass in cPanel & WHM affecting all versions after 11.40. Exploitation via CRLF injection in the Basic Auth header allows an unauthenticated attacker to forge a root-level session. Active exploitation was confirmed from approximately 23 February 2026 — roughly two months before cPanel patched on 28 April 2026. CISA added it to the Known Exploited Vulnerabilities catalog on 30 April 2026.

## Requirements

- Must be run as **root**
- Tested on CentOS/RHEL and Debian/Ubuntu
- ClamAV will be installed automatically if not present

## Usage

```bash
# Basic scan
bash infrastructure_scan.sh

# Verbose — dumps full session file contents for any IOC hits
bash infrastructure_scan.sh --verbose

# Purge compromised session files (interactive confirmation)
bash infrastructure_scan.sh --purge

# Purge without confirmation (for scripted/automated use)
bash infrastructure_scan.sh --purge --yes

# Override default paths
bash infrastructure_scan.sh --sessions-dir /var/cpanel/sessions --access-log /usr/local/cpanel/logs/access_log
```

## What It Checks

### Section 1 — cPanel Version
Checks the installed cPanel version against all patched builds. Alerts if unpatched.

Patched versions: 11.86.0.41, 11.110.0.97, 11.118.0.63, 11.126.0.54, 11.130.0.19, 11.132.0.29, 11.134.0.20, 11.136.0.5

### Section 2 — Official cPanel IOC Session Scan
Scans `/var/cpanel/sessions/raw/` using the official cPanel detection logic for six IOC patterns:

| IOC | Description | Severity |
|-----|-------------|----------|
| IOC-0 | `token_denied` + injected `cp_security_token` on badpass origin | CRITICAL/INFO |
| IOC-1 | Pre-auth session file with auth-success timestamp present | CRITICAL |
| IOC-2 | `tfa_verified=1` with non-legitimate origin method | WARNING |
| IOC-3 | Malformed session lines — raw CRLF injection footprint | CRITICAL |
| IOC-4 | `badpass` origin with auth markers (`hasroot=1`, `tfa_verified`, timestamps) | CRITICAL |
| IOC-5 | Failed exploit attempt — badpass + `token_denied` + anomalous `pass=` line | ATTEMPT |

### Section 3 — Access Log Exploit Signature Check
Scans cPanel access logs for:
- CRLF injection patterns in Basic Auth headers
- POST `/login/?login_only=1` returning 401 (exploit chain indicator)

### Section 4 — Post-Exploitation Persistence
- Root SSH authorized_keys
- WHM/cPanel user accounts
- Crontabs (root, spool, cron.d)
- Recently modified PHP files (potential webshells)
- Webshell content signatures (`eval(base64_decode`, `shell_exec`, `passthru` etc.)
- Suspicious files in `/tmp`, `/var/tmp`, `/dev/shm`
- `.bashrc` / `.bash_profile` modifications

### Section 5 — ClamAV Scan
Installs ClamAV if not present, updates signatures, then scans:
- `/home`
- `/var/www`
- `/tmp`, `/var/tmp`, `/dev/shm`
- `/usr/local/apache/htdocs`

## Output

All output is written to `/root/magn8_scan/`:

| File | Contents |
|------|----------|
| `<hostname>_scan_<datetime>.log` | Full scan log |
| `<hostname>_ALERTS_<datetime>.txt` | Alerts only — clean summary for reporting |
| `<hostname>_clamav_<datetime>.log` | Raw ClamAV output |

## If IOCs Are Found

1. Purge compromised sessions: `rm -f /var/cpanel/sessions/raw/*`
2. Force cPanel update: `/scripts/upcp --force`
3. Restart cPanel service: `/scripts/restartsrv_cpsrvd`
4. Rotate all passwords — root, all WHM users, all cPanel accounts
5. Audit logins: `last -F | head -50`
6. If patching is not immediately possible, block cPanel/WHM ports:
```bash
iptables -A INPUT -p tcp --dport 2083 -j DROP
iptables -A INPUT -p tcp --dport 2087 -j DROP
iptables -A INPUT -p tcp --dport 2095 -j DROP
iptables -A INPUT -p tcp --dport 2096 -j DROP
```

## References

- [cPanel Security Advisory](https://support.cpanel.net/hc/en-us/articles/40073787579671)
- [watchTowr Technical Analysis](https://labs.watchtowr.com/the-internet-is-falling-down-falling-down-falling-down-cpanel-whm-authentication-bypass-cve-2026-41940)
- [Rapid7 ETR](https://www.rapid7.com/blog/post/etr-cve-2026-41940-cpanel-whm-authentication-bypass/)
- [CISA KEV Entry](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
