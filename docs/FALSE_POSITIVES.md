# False-Positive Handling

PySOC's philosophy on false positives (FPs):

1. **Emit, don't suppress.** It is almost always better to emit an alert
   with rich context than to silently suppress it — suppression logic that
   looks smart today becomes tomorrow's missed detection.
2. **Document the FP.** Every detector carries a `note` field in its alert
   context describing the most common FPs and how to triage them.
3. **Publish a TPR prior.** Every report includes an estimated true-positive
   rate (TPR) per rule, derived from public IR data. These are priors, not
   measured from the current run.
4. **Make tuning easy.** Every detector's threshold / window / pattern set
   is a constructor argument or a module-level constant. No magic numbers.

## Per-rule FP strategy

### BF-001 — Brute-force login

| FP source | Why it happens | How PySOC handles it | Triage playbook |
|---|---|---|---|
| **Load-balancer health checks** | LB probes a login endpoint with bogus credentials; the endpoint returns 401, which the LB logs as a failed login. | Emit alert with `note`. The `source_ip` is the LB's internal IP — easy to whitelist. | Check `source_ip` against CMDB. If LB: add to allowlist, suppress future alerts from this IP. |
| **Scripts with expired passwords** | A cron job retries a service account login every minute after the password expires. 5 failures in 10 min triggers BF-001. | Emit alert with `note`. The `user_name` is a service account; the `auth_methods` field shows the protocol. | Check if `user_name` is a service account. If yes: rotate password, suppress by user for 24h. |
| **User fat-fingering password** | A human mistypes their password 5+ times in 10 minutes. | Emit alert with `note`. The `source_ip` is the user's normal office IP. | Correlate `source_ip` with the user's known-good IPs. If match: dismiss, no action. |
| **SSH bastion retries** | A bastion host forwards failed SSH attempts from many users; all appear to come from the bastion's IP. | Emit alert with `note`. The `source_ip` is the bastion; `user` varies. | Whitelist the bastion IP. Better: configure the bastion to log the original client IP. |

### SP-001 — Suspicious process execution

| FP source | Why it happens | How PySOC handles it | Triage playbook |
|---|---|---|---|
| **Legitimate admin encoded PowerShell** | Sysadmins use `-EncodedCommand` to avoid quoting issues in scripts. | Decode the payload and include the decoded text in `context.decoded_payload`. | Read the decoded payload. If it's obviously admin (`Get-ADUser`, `Set-Mailbox`): dismiss. If obfuscated/suspicious: escalate. |
| **Signed vendor installer spawning PowerShell** | Many installers (e.g., Azure ARC, SCCM agents) spawn PowerShell as part of their setup. | Include `process_parent_name` in context. Analyst can immediately see "this came from `msiexec.exe`". | Check digital signature on `process_parent_name`. If signed by trusted vendor: dismiss. |
| **EDDR / AV scanning tools** | Security tools like procdump are legitimately used by EDDR agents. | Include `user` in context. Analyst can check if user is a service account. | Check if `user_name` matches a known EDDR service account. If yes: dismiss. |
| **Macro-enabled internal spreadsheets** | Internal finance teams use Excel macros that legitimately spawn PowerShell for ETL. | `suspicious_parent_child:excel.exe->powershell.exe` fires. | Check the spreadsheet's path. If on a trusted internal share: dismiss. If from email/Downloads: escalate. |

### WA-001 — Web attack patterns

| FP source | Why it happens | How PySOC handles it | Triage playbook |
|---|---|---|---|
| **Security scanners** | Nessus, Burp, Qualys routinely probe for SQLi/XSS/path-traversal as part of their default scan templates. | Include `source_ip`, `http_user_agent`, and full `http_url` in context. | Check `source_ip` against scanner inventory; check `http_user_agent` for scanner signatures (`Nessus`, `Burp`, `Qualys`). If match: dismiss. |
| **Aggressive WAF probes** | A WAF may replay modified requests to test detection rules; some look like attacks. | Include full URL + UA. | Check if `source_ip` is the WAF's internal IP. If yes: dismiss. |
| **Legacy app false negatives** | A legacy app uses URL parameters that contain SQL keywords (`select`, `union`) for legitimate reasons. | Pattern `sqli_select_from` is MEDIUM severity; it does not auto-fire HIGH. | Review the URL path. If it matches a known legacy app: tune the pattern or whitelist the path. |
| **CMS preview features** | Some CMSes (Drupal, WordPress) use `?q=` parameters that look like SQLi. | Emit alert. `sqli_or_comment` pattern requires the full `' OR '1'='1` sequence, so `?q=node/1` does not match. | If the CMS is known: add an exclusion in the detector. |

### IT-001 — Impossible travel

| FP source | Why it happens | How PySOC handles it | Triage playbook |
|---|---|---|---|
| **Corporate VPN with multiple POPs** | An employee connects to VPN, which egresses through whichever POP has capacity. Two logins minutes apart may show different egress countries. | Emit alert with `note`. The `from_ip` and `to_ip` will both be VPN egress IPs. | Check `from_ip`/`to_ip` against the VPN POP list. If both are VPN: dismiss. |
| **Mobile network hand-off** | A user on a train logs in via cell, then via Wi-Fi 5 minutes later; the cell tower and Wi-Fi AP are in different countries (border regions). | Emit alert. `distance_km` will be small (<500 km). | Check `distance_km`. If < 500 km: lower-priority triage. |
| **CDN proxy** | A CDN (Cloudflare, Akamai) proxies user requests; the source IP is the CDN edge, which can be in a different country than the user. | Emit alert. The CDN IP is the same for many users. | Check `source_ip` against CDN IP ranges. If CDN: dismiss. |
| **Test / dev environments** | QA engineers test from multiple regions via VPN-less direct connections. | Emit alert. The `user_name` will be a test account. | Whitelist test/dev accounts by name. |

## True-Positive Rate (TPR) priors

These are documented priors derived from public incident-response data
(SANS, Mandiant M-Trends, Verizon DBIR). They are **not** measured from
the current PySOC run.

| Rule ID | Estimated TPR | Source |
|---|---|---|
| BF-001 | 0.85 | Mandiant M-Trends 2024: brute-force remains a top-3 initial-access vector; ~15% of BF-001 alerts are health-check / script FPs. |
| SP-001 | 0.95 | SANS 2024 Threat Hunting Survey: encoded PowerShell in process-creation events is one of the highest-signal detections in IR. |
| WA-001 | 0.80 | Verizon DBIR 2024: web-app attacks are common but noisy; ~20% of pattern matches are scanner traffic that does not lead to compromise. |
| IT-001 | 0.70 | Microsoft Digital Defense Report 2023: impossible-travel alerts have a ~30% FP rate due to VPN / mobile-network artefacts. |

These priors are emitted in every JSON report under
`summary.true_positive_estimates`. A production deployment should replace
them with **measured** TPRs after the first 90 days of operation.
