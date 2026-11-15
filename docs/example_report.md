# LogSentinel Report

Events analyzed: 101  
Findings: 10

| Severity | Count |
|---|---|
| CRITICAL | 2 |
| HIGH | 4 |
| MEDIUM | 2 |
| LOW | 2 |

## Findings

| Severity | Rule | ATT&CK | Source IP | Account(s) | Count | First seen | Last seen |
|---|---|---|---|---|---|---|---|
| CRITICAL | success_after_failures | T1078 | 198.51.100.77 | Administrator | 12 | 2026-11-10 03:00:00 | 2026-11-10 03:01:30 |
| CRITICAL | success_after_failures | T1078 | 192.0.2.44 | deploy | 8 | 2026-11-12 23:40:00 | 2026-11-12 23:41:35 |
| HIGH | brute_force | T1110.001 | 203.0.113.7 | root | 40 | 2026-11-10 02:10:00 | 2026-11-10 02:12:36 |
| HIGH | brute_force | T1110.001 | 198.51.100.77 | Administrator | 12 | 2026-11-10 03:00:00 | 2026-11-10 03:01:06 |
| HIGH | password_spraying | T1110.003 | 198.51.100.23 | admin, ftp, git ... | 12 | 2026-11-11 04:30:00 | 2026-11-11 04:32:45 |
| HIGH | brute_force | T1110.001 | 192.0.2.44 | deploy | 8 | 2026-11-12 23:40:00 | 2026-11-12 23:41:10 |
| MEDIUM | root_login_success | T1078.003 | 198.51.100.77 | Administrator | 1 | 2026-11-10 03:01:30 | 2026-11-10 03:01:30 |
| MEDIUM | root_login_success | T1078.003 | 10.0.0.5 | root | 1 | 2026-11-11 12:00:00 | 2026-11-11 12:00:00 |
| LOW | off_hours_login | T1078 | 198.51.100.77 | Administrator | 1 | 2026-11-10 03:01:30 | 2026-11-10 03:01:30 |
| LOW | off_hours_login | T1078 | 192.0.2.44 | deploy | 1 | 2026-11-12 23:41:35 | 2026-11-12 23:41:35 |

## Recommended actions

- **success_after_failures**: Treat the account as compromised: force a password reset, kill sessions, review activity after login.
- **brute_force**: Block or rate-limit the source IP, enforce key-based login or account lockout.
- **password_spraying**: Block the source IP, review the targeted accounts, require MFA or keys.
- **root_login_success**: Disable direct root login over SSH and use a named account with sudo.
- **off_hours_login**: Confirm the login with the account owner and review what the session did.
