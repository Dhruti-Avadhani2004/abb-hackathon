# Appendix C - Final Security Assessment: sgc-gatekeeper-testbed

Generated (UTC): 2026-11-14T17:55:01.416717+00:00

## 1. Executive summary

Automated analysis produced **116 scanner findings** for **sgc-gatekeeper-testbed**.

These are automated detections requiring review, not independently confirmed vulnerabilities.

### Severity distribution

| Severity | Count |
| --- | --- |
| CRITICAL | 8 |
| HIGH | 43 |
| MEDIUM | 38 |
| LOW | 10 |
| INFO | 7 |
| UNKNOWN | 10 |

### Top five risks

1. **CRITICAL** - Stripe Secret Key (Trivy, config.py:6)
2. **CRITICAL** - Google (GCP) Service-account (Trivy, credentials.json:2)
3. **CRITICAL** - Directory traversal in Django (Trivy, requirements.txt:?)
4. **CRITICAL** - The (1) django.http.HttpResponseRedirect and (2) django.http.HttpRespo ... (Trivy, requirements.txt:?)
5. **CRITICAL** - python-django: unexpected code execution using reverse() (Trivy, requirements.txt:?)

### Main limitations

Automated findings have not been independently verified. Reachability, runtime exploitability and business impact are not assessed. Offline vulnerability database freshness cannot be established without database timestamps.

## 2. Scope

| Field | Value |
| --- | --- |
| Repository | sgc-gatekeeper-testbed |
| Repository URL | https://github.com/Dhruti-Avadhani2004/sgc-gatekeeper-testbed.git |
| Commit | 5a1844a031d36d741ef96801f1b913a50f14d1ef |
| Branch | main |
| Folders scanned | C:\Users\dhrut\OneDrive\Desktop\abb_hackathon\sgc-gatekeeper-testbed |
| Known exclusions | node_modules |
| Scanner output directory | C:\Users\dhrut\OneDrive\Desktop\abb_hackathon\scanner_output |

Exclusions listed here are only those recorded in the available reports or metadata. Different scanners may have different exclusions.

## 3. Environment

| Field | Recorded value |
| --- | --- |
| OS / VM | Windows-11-10.0.26200-SP0 |
| CPU architecture | 64 |
| Python version | 3.12.0 (tags/v3.12.0:0fb18b0, Oct  2 2023, 13:03:39) [MSC v.1935 64 bit (AMD64)] |
| Rule-set hashes | Not supplied |
| Vulnerability database timestamps | Not supplied |
| Trivy report timestamp | 2026-11-14T22:17:30.7239761+05:30 |
| ScanCode scan start | 2026-11-14T164800.884770 |

### Scanner versions

| Scanner | Version |
| --- | --- |
| Semgrep | 1.185.0 |
| Trivy | 0.76.2 |
| ScanCode | 32.5.0 |
| Syft | 1.55.0 |

### Scanner input status

| Scanner | Input file | Status |
| --- | --- | --- |
| semgrep | semgrep_output.json | Present |
| trivy | trivy_output_offline.json | Present |
| bandit | bandit_output.json | Present |
| eslint | eslint_output.json | Present |
| gitleaks | gitleaks_output.json | Present |
| scancode | scancode_output.json | Present |
| cyclonedx | sbom_cyclonedx.json | Present |
| spdx | sbom_spdx.json | Present |
| dotnet | dotnet_output.txt | Present |

## 4. Method

| Scanner / format | Purpose | Availability |
| --- | --- | --- |
| semgrep | Rule-based static application security testing | Input present |
| bandit | Python static security analysis | Input present |
| eslint | JavaScript lint and security rules | Input present |
| trivy | Dependency and configuration security checks | Input present |
| gitleaks | Potential secret detection | Input present |
| scancode | License, copyright and package analysis | Input present |
| cyclonedx | CycloneDX software bill of materials | Input present |
| spdx | SPDX software bill of materials | Input present |
| dotnet | NuGet dependency vulnerability analysis | Input present |

Exact execution commands, scan options, offline cache configuration and rule provenance may require execution logs or additional metadata.

## 5. Results by repository

| Repository | Critical | High | Medium | Low | Info | Unknown | Confirmed | Unverified |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| sgc-gatekeeper-testbed | 8 | 43 | 38 | 10 | 7 | 10 | 0 | 116 |

All findings are classified as **unverified** until a human reviewer confirms their disposition. Scanner confidence does not establish exploitability.

### Findings by category

| Category | Count |
| --- | --- |
| Dependency vulnerability | 59 |
| security | 34 |
| Potential secret | 9 |
| SAST | 9 |
| Code quality | 3 |
| Security lint rule | 2 |

### Findings by scanner

| Scanner | Count |
| --- | --- |
| .NET | 1 |
| Bandit | 9 |
| ESLint | 5 |
| Gitleaks | 5 |
| Semgrep | 34 |
| Trivy | 62 |

## 6. Top findings

### 1. Stripe Secret Key

| Field | Value |
| --- | --- |
| Finding ID | 0cc082048c4a5f5c |
| Scanner | Trivy |
| Severity | CRITICAL |
| Evidence location | config.py:6 |
| Rule | stripe-secret-token |
| CWE | Not supplied |
| CVE / advisory | Not supplied |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | trivy_output_offline.json |
| Reference | Not supplied |

Evidence summary: Potential secret detected; value withheld.

### 2. Google (GCP) Service-account

| Field | Value |
| --- | --- |
| Finding ID | 6d99db479565218f |
| Scanner | Trivy |
| Severity | CRITICAL |
| Evidence location | credentials.json:2 |
| Rule | gcp-service-account |
| CWE | Not supplied |
| CVE / advisory | Not supplied |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | trivy_output_offline.json |
| Reference | Not supplied |

Evidence summary: Potential secret detected; value withheld.

### 3. Directory traversal in Django

| Field | Value |
| --- | --- |
| Finding ID | 2a12737ecdff29df |
| Scanner | Trivy |
| Severity | CRITICAL |
| Evidence location | requirements.txt |
| Rule | CVE-2011-0698 |
| CWE | CWE-22 |
| CVE / advisory | CVE-2011-0698 |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Review affected package and update to a compatible fixed version: 1.1.4, 1.2.5 |
| Source | trivy_output_offline.json |
| Reference | https://avd.aquasec.com/nvd/cve-2011-0698 |

Evidence summary: Directory traversal vulnerability in Django 1.1.x before 1.1.4 and 1.2.x before 1.2.5 on Windows might allow remote attackers to read or execute files via a / (slash) character in a key in a session cookie, related to session replays.

### 4. The (1) django.http.HttpResponseRedirect and (2) django.http.HttpRespo ...

| Field | Value |
| --- | --- |
| Finding ID | 0a7904e03992c381 |
| Scanner | Trivy |
| Severity | CRITICAL |
| Evidence location | requirements.txt |
| Rule | CVE-2012-3442 |
| CWE | CWE-79 |
| CVE / advisory | CVE-2012-3442 |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Review affected package and update to a compatible fixed version: 1.3.2, 1.4.1 |
| Source | trivy_output_offline.json |
| Reference | https://avd.aquasec.com/nvd/cve-2012-3442 |

Evidence summary: The (1) django.http.HttpResponseRedirect and (2) django.http.HttpResponsePermanentRedirect classes in Django before 1.3.2 and 1.4.x before 1.4.1 do not validate the scheme of a redirect target, which might allow remote attackers to conduct cross-site scripting (XSS) attacks via a data: URL.

### 5. python-django: unexpected code execution using reverse()

| Field | Value |
| --- | --- |
| Finding ID | 8cae1978e171c3c8 |
| Scanner | Trivy |
| Severity | CRITICAL |
| Evidence location | requirements.txt |
| Rule | CVE-2014-0472 |
| CWE | CWE-94 |
| CVE / advisory | CVE-2014-0472 |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Review affected package and update to a compatible fixed version: 1.4.11, 1.5.6, 1.6.3 |
| Source | trivy_output_offline.json |
| Reference | https://avd.aquasec.com/nvd/cve-2014-0472 |

Evidence summary: The django.core.urlresolvers.reverse function in Django before 1.4.11, 1.5.x before 1.5.6, 1.6.x before 1.6.3, and 1.7.x before 1.7 beta 2 allows remote attackers to import and execute arbitrary Python modules by leveraging a view that constructs URLs using user input and a "dotted Python path."

### 6. Django: crafted email address allows account takeover

| Field | Value |
| --- | --- |
| Finding ID | 3fe4111f140e13aa |
| Scanner | Trivy |
| Severity | CRITICAL |
| Evidence location | requirements.txt |
| Rule | CVE-2019-19844 |
| CWE | CWE-640 |
| CVE / advisory | CVE-2019-19844 |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Review affected package and update to a compatible fixed version: 1.11.27, 2.2.9, 3.0.1 |
| Source | trivy_output_offline.json |
| Reference | https://avd.aquasec.com/nvd/cve-2019-19844 |

Evidence summary: Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account takeover. A suitably crafted email address (that is equal to an existing user's email address after case transformation of Unicode characters) would allow an attacker to be sent a password reset token for the matched user account. (One mitigation in the new releases is to send password reset tokens only to the registered user email address.)

### 7. django: potential SQL injection via StringAgg(delimiter)

| Field | Value |
| --- | --- |
| Finding ID | ce738bb908addcc1 |
| Scanner | Trivy |
| Severity | CRITICAL |
| Evidence location | requirements.txt |
| Rule | CVE-2020-7471 |
| CWE | CWE-89 |
| CVE / advisory | CVE-2020-7471 |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Review affected package and update to a compatible fixed version: 1.11.28, 2.2.10, 3.0.3 |
| Source | trivy_output_offline.json |
| Reference | https://avd.aquasec.com/nvd/cve-2020-7471 |

Evidence summary: Django 1.11 before 1.11.28, 2.2 before 2.2.10, and 3.0 before 3.0.3 allows SQL Injection if untrusted data is used as a StringAgg delimiter (e.g., in Django applications that offer downloads of data as a series of rows with a user-specified column delimiter). By passing a suitably crafted delimiter to a contrib.postgres.aggregates.StringAgg instance, it was possible to break escaping and inject malicious SQL.

### 8. django: Django SQL injection

| Field | Value |
| --- | --- |
| Finding ID | 3419da0467e6d239 |
| Scanner | Trivy |
| Severity | CRITICAL |
| Evidence location | requirements.txt |
| Rule | CVE-2025-64459 |
| CWE | CWE-89 |
| CVE / advisory | CVE-2025-64459 |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Review affected package and update to a compatible fixed version: 5.2.8, 5.1.14, 4.2.26 |
| Source | trivy_output_offline.json |
| Reference | https://avd.aquasec.com/nvd/cve-2025-64459 |

Evidence summary: An issue was discovered in 5.1 before 5.1.14, 4.2 before 4.2.26, and 5.2 before 5.2.8. The methods 'QuerySet.filter()', 'QuerySet.exclude()', and 'QuerySet.get()', and the class 'Q()', are subject to SQL injection when using a suitably crafted dictionary, with dictionary expansion, as the '_connector' argument. Earlier, unsupported Django series (such as 5.0.x, 4.1.x, and 3.2.x) were not evaluated and may also be affected. Django would like to thank cyberstan for reporting this issue.

### 9. Vulnerable NuGet package: Microsoft.Extensions.Caching.Memory

| Field | Value |
| --- | --- |
| Finding ID | 91a1e40cc125cd64 |
| Scanner | .NET |
| Severity | HIGH |
| Evidence location | DotNetVulnerabilityTest.csproj |
| Rule | GHSA-qj66-m88j-hmgj |
| CWE | Not supplied |
| CVE / advisory | GHSA-qj66-m88j-hmgj |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | dotnet_output.txt |
| Reference | https://github.com/advisories/GHSA-qj66-m88j-hmgj |

Evidence summary: NuGet vulnerability advisory reported by dotnet.

### 10. start_process_with_a_shell

| Field | Value |
| --- | --- |
| Finding ID | 3fd1d40d84b03c52 |
| Scanner | Bandit |
| Severity | HIGH |
| Evidence location | kitchen_sink.py:22 |
| Rule | B605 |
| CWE | CWE-78 |
| CVE / advisory | Not supplied |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | bandit_output.json |
| Reference | https://bandit.readthedocs.io/en/1.9.4/plugins/b605_start_process_with_a_shell.html |

Evidence summary: Starting a process with a shell, possible injection detected, security issue.

### 11. flask_debug_true

| Field | Value |
| --- | --- |
| Finding ID | adfefd3f3a78014c |
| Scanner | Bandit |
| Severity | HIGH |
| Evidence location | kitchen_sink.py:39 |
| Rule | B201 |
| CWE | CWE-94 |
| CVE / advisory | Not supplied |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | bandit_output.json |
| Reference | https://bandit.readthedocs.io/en/1.9.4/plugins/b201_flask_debug_true.html |

Evidence summary: A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.

### 12. hashlib

| Field | Value |
| --- | --- |
| Finding ID | 8a9e124cd8f404fc |
| Scanner | Bandit |
| Severity | HIGH |
| Evidence location | legacy_code.py:4 |
| Rule | B324 |
| CWE | CWE-327 |
| CVE / advisory | Not supplied |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | bandit_output.json |
| Reference | https://bandit.readthedocs.io/en/1.9.4/plugins/b324_hashlib.html |

Evidence summary: Use of weak MD5 hash for security. Consider usedforsecurity=False

### 13. Detected calls to child_process from a function argument 'req'. This could lead to a command injection if the input is user controllable. Try to avoid calls to child_process, and if it is needed ensure user input is corr

| Field | Value |
| --- | --- |
| Finding ID | bf377183ebe0fc81 |
| Scanner | Semgrep |
| Severity | HIGH |
| Evidence location | broken_gate.js:10 |
| Rule | scanner_output.semgrep-configs.javascript.lang.security.detect-child-process |
| CWE | CWE-78 |
| CVE / advisory | Not supplied |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | semgrep_output.json |
| Reference | https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html#do-not-use-dangerous-functions |

Evidence summary: Detected calls to child_process from a function argument 'req'. This could lead to a command injection if the input is user controllable. Try to avoid calls to child_process, and if it is needed ensure user input is correctly sanitized or sandboxed. 

### 14. Found data from an Express or Next web request flowing to 'eval'. If this data is user-controllable this can lead to execution of arbitrary system commands in the context of your application process. Avoid 'eval' wheneve

| Field | Value |
| --- | --- |
| Finding ID | eb61cb176566abda |
| Scanner | Semgrep |
| Severity | HIGH |
| Evidence location | broken_gate.js:20 |
| Rule | scanner_output.semgrep-configs.javascript.lang.security.audit.code-string-concat |
| CWE | CWE-95 |
| CVE / advisory | Not supplied |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | semgrep_output.json |
| Reference | https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval |

Evidence summary: Found data from an Express or Next web request flowing to 'eval'. If this data is user-controllable this can lead to execution of arbitrary system commands in the context of your application process. Avoid 'eval' whenever possible.

### 15. Private Key detected. This is a sensitive credential and should not be hardcoded here. Instead, store this in a separate, private file.

| Field | Value |
| --- | --- |
| Finding ID | d298d18ff9d8029d |
| Scanner | Semgrep |
| Severity | HIGH |
| Evidence location | config.py:8 |
| Rule | scanner_output.semgrep-configs.generic.secrets.security.detected-private-key |
| CWE | CWE-798 |
| CVE / advisory | Not supplied |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | semgrep_output.json |
| Reference | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures |

Evidence summary: Private Key detected. This is a sensitive credential and should not be hardcoded here. Instead, store this in a separate, private file.

### 16. Google (GCM) Service account detected

| Field | Value |
| --- | --- |
| Finding ID | dcae19129c41bb28 |
| Scanner | Semgrep |
| Severity | HIGH |
| Evidence location | credentials.json:2 |
| Rule | scanner_output.semgrep-configs.generic.secrets.security.detected-google-gcm-service-account |
| CWE | CWE-798 |
| CVE / advisory | Not supplied |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | semgrep_output.json |
| Reference | https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures |

Evidence summary: Google (GCM) Service account detected

### 17. Request data detected in os.system. This could be vulnerable to a command injection and should be avoided. If this must be done, use the 'subprocess' module instead and pass the arguments as a list. See https://owasp.org

| Field | Value |
| --- | --- |
| Finding ID | 1360e2722cd599dd |
| Scanner | Semgrep |
| Severity | HIGH |
| Evidence location | kitchen_sink.py:12 |
| Rule | scanner_output.semgrep-configs.python.django.security.injection.command.command-injection-os-system |
| CWE | CWE-78 |
| CVE / advisory | Not supplied |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | semgrep_output.json |
| Reference | https://owasp.org/www-community/attacks/Command_Injection |

Evidence summary: Request data detected in os.system. This could be vulnerable to a command injection and should be avoided. If this must be done, use the 'subprocess' module instead and pass the arguments as a list. See https://owasp.org/www-community/attacks/Command_Injection for more information.

### 18. Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to e

| Field | Value |
| --- | --- |
| Finding ID | c90111fc4af8d251 |
| Scanner | Semgrep |
| Severity | HIGH |
| Evidence location | kitchen_sink.py:18 |
| Rule | scanner_output.semgrep-configs.python.sqlalchemy.security.sqlalchemy-execute-raw-query |
| CWE | CWE-89 |
| CVE / advisory | Not supplied |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | semgrep_output.json |
| Reference | https://docs.sqlalchemy.org/en/14/core/tutorial.html#using-textual-sql |

Evidence summary: Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query can result in SQL Injection. In order to execute raw query safely, prepared statement should be used. SQLAlchemy provides TextualSQL to easily used prepared statement with named parameters. For complex SQL composition, use SQL Expression Language or Schema Definition Language. In most cases, SQLAlchemy ORM will be a better option.

### 19. Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify

| Field | Value |
| --- | --- |
| Finding ID | d215c1aa9319ba78 |
| Scanner | Semgrep |
| Severity | HIGH |
| Evidence location | kitchen_sink.py:18 |
| Rule | scanner_output.semgrep-configs.python.django.security.injection.tainted-sql-string |
| CWE | CWE-915 |
| CVE / advisory | Not supplied |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | semgrep_output.json |
| Reference | https://docs.djangoproject.com/en/3.0/topics/security/#sql-injection-protection |

Evidence summary: Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using the Django object-relational mappers (ORM) instead of raw SQL queries.

### 20. Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify

| Field | Value |
| --- | --- |
| Finding ID | ad17013d0b9011f1 |
| Scanner | Semgrep |
| Severity | HIGH |
| Evidence location | kitchen_sink.py:18 |
| Rule | scanner_output.semgrep-configs.python.flask.security.injection.tainted-sql-string |
| CWE | CWE-704 |
| CVE / advisory | Not supplied |
| Reachability | Not assessed |
| Impact | Requires review |
| Disposition | Unverified |
| Suggested fix | Manual remediation decision required |
| Source | semgrep_output.json |
| Reference | https://docs.sqlalchemy.org/en/14/core/tutorial.html#using-textual-sql |

Evidence summary: Detected user input used to manually construct a SQL string. This is usually bad practice because manual construction could accidentally result in a SQL injection. An attacker could use a SQL injection to steal or modify contents of the database. Instead, use a parameterized query which is available by default in most database engines. Alternatively, consider using an object-relational mapper (ORM) such as SQLAlchemy which will protect your queries.

Only the first 20 of 116 findings are expanded here. Complete records are available in consolidated_findings.json.

## 7. Supply chain view

Package scanners identified **98 distinct package/version entries** after consolidation.

An SBOM package entry does not itself represent a vulnerability.

### Vulnerable packages and advisories

| Package | Installed | Advisory | Severity | Fixed version | Source |
| --- | --- | --- | --- | --- | --- |
| django | 1.2 | CVE-2011-0698 | CRITICAL | 1.1.4, 1.2.5 | Trivy |
| django | 1.2 | CVE-2012-3442 | CRITICAL | 1.3.2, 1.4.1 | Trivy |
| django | 1.2 | CVE-2014-0472 | CRITICAL | 1.4.11, 1.5.6, 1.6.3 | Trivy |
| django | 1.2 | CVE-2019-19844 | CRITICAL | 1.11.27, 2.2.9, 3.0.1 | Trivy |
| django | 1.2 | CVE-2020-7471 | CRITICAL | 1.11.28, 2.2.10, 3.0.3 | Trivy |
| django | 1.2 | CVE-2025-64459 | CRITICAL | 5.2.8, 5.1.14, 4.2.26 | Trivy |
| Microsoft.Extensions.Caching.Memory | 6.0.1 | GHSA-qj66-m88j-hmgj | HIGH | Not supplied | .NET |
| django | 1.2 | CVE-2010-4534 | HIGH | 1.1.3, 1.2.4 | Trivy |
| django | 1.2 | CVE-2011-0696 | HIGH | 1.1.4, 1.2.5 | Trivy |
| django | 1.2 | CVE-2011-4137 | HIGH | 1.2.7, 1.3.1 | Trivy |
| django | 1.2 | CVE-2011-4138 | HIGH | 1.2.7, 1.3.1 | Trivy |
| django | 1.2 | CVE-2011-4139 | HIGH | 1.2.7, 1.3.1 | Trivy |
| django | 1.2 | CVE-2011-4140 | HIGH | Not supplied | Trivy |
| django | 1.2 | CVE-2012-3443 | HIGH | 1.3.2, 1.4.1 | Trivy |
| django | 1.2 | CVE-2012-3444 | HIGH | 1.3.2, 1.4.1 | Trivy |
| django | 1.2 | CVE-2014-0473 | HIGH | 1.4.11, 1.5.6, 1.6.3 | Trivy |
| django | 1.2 | CVE-2014-0474 | HIGH | 1.4.11, 1.5.6, 1.6.3 | Trivy |
| django | 1.2 | CVE-2014-0480 | HIGH | 1.4.14, 1.5.9, 1.6.6 | Trivy |
| django | 1.2 | CVE-2014-0481 | HIGH | 1.4.14, 1.5.9, 1.6.6 | Trivy |
| django | 1.2 | CVE-2015-0221 | HIGH | 1.4.18, 1.6.10, 1.7.3 | Trivy |
| django | 1.2 | CVE-2015-5143 | HIGH | 1.4.21, 1.7.9, 1.8.3 | Trivy |
| django | 1.2 | CVE-2015-5144 | HIGH | 1.4.21, 1.7.9, 1.8.3 | Trivy |
| django | 1.2 | CVE-2016-7401 | HIGH | 1.8.15, 1.9.10 | Trivy |
| django | 1.2 | CVE-2022-36359 | HIGH | 3.2.15, 4.0.7 | Trivy |
| django | 1.2 | CVE-2025-57833 | HIGH | 4.2.24, 5.1.12, 5.2.6 | Trivy |
| django | 1.2 | CVE-2025-64458 | HIGH | 5.2.8, 5.1.14, 4.2.26 | Trivy |
| django | 1.2 | CVE-2026-15307 | HIGH | 5.2.17, 6.0.8 | Trivy |
| flask | 0.12 | CVE-2018-1000656 | HIGH | 0.12.3 | Trivy |
| flask | 0.12 | CVE-2019-1010083 | HIGH | 1.0 | Trivy |
| flask | 0.12 | CVE-2023-30861 | HIGH | 2.3.2, 2.2.5 | Trivy |
| requests | 2.19.0 | CVE-2018-18074 | HIGH | 2.20.0 | Trivy |
| django | 1.2 | CVE-2010-3082 | MEDIUM | 1.2.2 | Trivy |
| django | 1.2 | CVE-2010-4535 | MEDIUM | 1.1.3, 1.2.4 | Trivy |
| django | 1.2 | CVE-2011-0697 | MEDIUM | 1.1.4, 1.2.5 | Trivy |
| django | 1.2 | CVE-2011-4136 | MEDIUM | 1.2.7, 1.3.1 | Trivy |
| django | 1.2 | CVE-2014-0482 | MEDIUM | 1.4.14, 1.5.9, 1.6.6, 1.7c3 | Trivy |
| django | 1.2 | CVE-2014-0483 | MEDIUM | 1.4.14, 1.5.9, 1.6.6, 1.7c3 | Trivy |
| django | 1.2 | CVE-2015-0219 | MEDIUM | 1.4.18, 1.6.10, 1.7.3 | Trivy |
| django | 1.2 | CVE-2015-0220 | MEDIUM | 1.4.18, 1.6.10, 1.7.3 | Trivy |
| django | 1.2 | CVE-2015-2241 | MEDIUM | 1.7.6, 1.8b2 | Trivy |
| django | 1.2 | CVE-2015-2317 | MEDIUM | 1.4.20, 1.6.11, 1.7.7, 1.8c1 | Trivy |
| django | 1.2 | CVE-2016-2512 | MEDIUM | 1.8.10, 1.9.3 | Trivy |
| django | 1.2 | CVE-2016-6186 | MEDIUM | 1.8.14, 1.9.8, 1.10rc1 | Trivy |
| django | 1.2 | CVE-2021-33203 | MEDIUM | 2.2.24, 3.1.12, 3.2.4 | Trivy |
| django | 1.2 | CVE-2024-45231 | MEDIUM | 5.1.1, 5.0.9, 4.2.16 | Trivy |
| django | 1.2 | CVE-2025-48432 | MEDIUM | 5.2.2, 5.1.10, 4.2.22 | Trivy |
| django | 1.2 | CVE-2026-15830 | MEDIUM | 5.2.17, 6.0.8, 6.1.1 | Trivy |
| django | 1.2 | CVE-2026-53877 | MEDIUM | 5.2.16, 6.0.7 | Trivy |
| django | 1.2 | CVE-2026-53878 | MEDIUM | 5.2.16, 6.0.7 | Trivy |
| requests | 2.19.0 | CVE-2023-32681 | MEDIUM | 2.31.0 | Trivy |
| requests | 2.19.0 | CVE-2024-35195 | MEDIUM | 2.32.0 | Trivy |
| requests | 2.19.0 | CVE-2024-47081 | MEDIUM | 2.32.4 | Trivy |
| requests | 2.19.0 | CVE-2026-25645 | MEDIUM | 2.33.0 | Trivy |
| django | 1.2 | CVE-2016-2513 | LOW | 1.8.10, 1.9.3 | Trivy |
| django | 1.2 | CVE-2026-48587 | LOW | 5.2.15, 6.0.6 | Trivy |
| django | 1.2 | CVE-2026-48588 | LOW | 5.2.16, 6.0.7 | Trivy |
| django | 1.2 | CVE-2026-6873 | LOW | 5.2.15, 6.0.6 | Trivy |
| django | 1.2 | CVE-2026-8404 | LOW | 5.2.15, 6.0.6 | Trivy |
| flask | 0.12 | CVE-2026-27205 | LOW | 3.1.3 | Trivy |

### Package inventory

| Package | Version / constraint | Direct / transitive | License | Source |
| --- | --- | --- | --- | --- |
| actions/checkout | v7 | Unknown | Not identified | Syft CycloneDX, Syft SPDX |
| actions/setup-node | v7 | Unknown | Not identified | Syft CycloneDX, Syft SPDX |
| beemojs/conventional-pr-action | v3 | Unknown | Not identified | Syft CycloneDX, Syft SPDX |
| C:\Users\dhrut\OneDrive\Desktop\abb_hackathon\sgc-gatekeeper-testbed |  | Unknown | Not identified | Syft SPDX |
| django | 1.2 | Unknown | Not assessed | Trivy, Syft CycloneDX, Syft SPDX |
| flask | 0.12 | Unknown | Not assessed | Trivy, Syft CycloneDX, Syft SPDX |
| googleapis/release-please-action | v4 | Unknown | Not identified | Syft CycloneDX, Syft SPDX |
| pkg:npm/%40cacheable/memory@2.2.0 | 2.2.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40cacheable/utils@2.5.0 | 2.5.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40eslint-community/eslint-utils@4.10.1 | 4.10.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40eslint-community/regexpp@4.12.3 | 4.12.3 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40eslint/config-array@0.23.6 | 0.23.6 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40eslint/config-helpers@0.7.0 | 0.7.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40eslint/core@1.2.1 | 1.2.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40eslint/js | ^10.0.1 | Direct | Not assessed | ScanCode dependency |
| pkg:npm/%40eslint/js@10.0.1 | 10.0.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40eslint/object-schema@3.0.5 | 3.0.5 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40eslint/plugin-kit@0.7.3 | 0.7.3 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40humanfs/core@0.19.2 | 0.19.2 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40humanfs/node@0.16.8 | 0.16.8 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40humanfs/types@0.15.0 | 0.15.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40humanwhocodes/module-importer@1.0.1 | 1.0.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40humanwhocodes/retry@0.4.3 | 0.4.3 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40isaacs/nonrecursive-glob-match@1.1.0 | 1.1.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40keyv/bigmap@1.3.1 | 1.3.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40keyv/serialize@1.1.1 | 1.1.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40types/esrecurse@4.3.1 | 4.3.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40types/estree@1.0.10 | 1.0.10 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/%40types/json-schema@7.0.15 | 7.0.15 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/acorn-jsx@5.3.2 | 5.3.2 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/acorn@8.19.0 | 8.19.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/ajv@6.15.0 | 6.15.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/balanced-match@4.0.4 | 4.0.4 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/brace-expansion@5.0.13 | 5.0.13 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/cacheable@2.5.0 | 2.5.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/cross-spawn@7.0.6 | 7.0.6 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/debug@4.4.3 | 4.4.3 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/deep-is@0.1.4 | 0.1.4 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/escape-string-regexp@4.0.0 | 4.0.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/eslint | ^10.15.0 | Direct | Not assessed | ScanCode dependency |
| pkg:npm/eslint-plugin-no-unsanitized | ^4.1.5 | Direct | Not assessed | ScanCode dependency |
| pkg:npm/eslint-plugin-no-unsanitized@4.1.5 | 4.1.5 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/eslint-plugin-security | ^4.2.1 | Direct | Not assessed | ScanCode dependency |
| pkg:npm/eslint-plugin-security@4.2.1 | 4.2.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/eslint-scope@9.1.2 | 9.1.2 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/eslint-visitor-keys@3.4.3 | 3.4.3 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/eslint-visitor-keys@5.0.1 | 5.0.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/eslint@10.15.0 | 10.15.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/espree@11.2.0 | 11.2.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/esquery@1.7.0 | 1.7.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/esrecurse@4.3.0 | 4.3.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/estraverse@5.3.0 | 5.3.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/esutils@2.0.3 | 2.0.3 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/fast-deep-equal@3.1.3 | 3.1.3 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/fast-json-stable-stringify@2.1.0 | 2.1.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/fast-levenshtein@2.0.6 | 2.0.6 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/file-entry-cache@11.1.5 | 11.1.5 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/find-up@5.0.0 | 5.0.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/flat-cache@6.1.23 | 6.1.23 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/flatted@3.4.4 | 3.4.4 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/glob-parent@6.0.2 | 6.0.2 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/globals | ^17.14.0 | Direct | Not assessed | ScanCode dependency |
| pkg:npm/globals@17.14.0 | 17.14.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/hashery@1.5.1 | 1.5.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/hookified@1.15.1 | 1.15.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/hookified@2.2.0 | 2.2.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/ignore@5.3.2 | 5.3.2 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/imurmurhash@0.1.4 | 0.1.4 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/is-extglob@2.1.1 | 2.1.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/is-glob@4.0.3 | 4.0.3 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/isexe@2.0.0 | 2.0.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/json-schema-traverse@0.4.1 | 0.4.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/json-stable-stringify-without-jsonify@1.0.1 | 1.0.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/keyv@5.6.0 | 5.6.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/levn@0.4.1 | 0.4.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/locate-path@6.0.0 | 6.0.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/minimatch@11.0.8 | 11.0.8 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/ms@2.1.3 | 2.1.3 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/natural-compare@1.4.0 | 1.4.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/optionator@0.9.4 | 0.9.4 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/p-limit@3.1.0 | 3.1.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/p-locate@5.0.0 | 5.0.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/path-exists@4.0.0 | 4.0.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/path-key@3.1.1 | 3.1.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/prelude-ls@1.2.1 | 1.2.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/punycode@2.3.1 | 2.3.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/qified@0.10.1 | 0.10.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/regexp-tree@0.1.27 | 0.1.27 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/safe-regex@2.1.1 | 2.1.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/shebang-command@2.0.0 | 2.0.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/shebang-regex@3.0.0 | 3.0.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/type-check@0.4.0 | 0.4.0 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/uri-js@4.4.1 | 4.4.1 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/which@2.0.2 | 2.0.2 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/word-wrap@1.2.5 | 1.2.5 | Transitive | Not assessed | ScanCode dependency |
| pkg:npm/yocto-queue@0.1.0 | 0.1.0 | Transitive | Not assessed | ScanCode dependency |
| requests | 2.19.0 | Unknown | Not assessed | Trivy, Syft CycloneDX, Syft SPDX |
| sgc-gatekeeper-testbed | 1.0.0 | Unknown | ISC | ScanCode, Syft CycloneDX, Syft SPDX |

### Repository license

isc

Detected licenses are not a legal compliance determination. Unknown dependency relationships are not inferred.

## 8. Remediation outcomes

No baseline/post-remediation comparison, patch evidence or test results were supplied.

Before-and-after counts, verified fixes and closure status are **not assessed**.

## 9. Limitations

- Static analysis and dependency scanners can produce false positives and false negatives.
- Reachability, exploitability, runtime controls and business impact have not been validated.
- Offline vulnerability databases and rules may be stale. Report timestamps do not prove database freshness.
- A missing or failed scanner must not be interpreted as reporting zero vulnerabilities.
- Source coverage, excluded files and unsupported language features may not be fully established by scanner reports alone.
- Potential secret findings require validation. Matched secret values are withheld.

## 10. Recommendations

1. **Triage ownership:** Assign each finding to a responsible repository or component owner.
2. **Validate findings:** Confirm whether flagged code and dependencies are deployed and reachable. Record false positives.
3. **Fix timelines:** Establish severity-based remediation SLAs using an approved policy.
4. **CI integration:** Integrate scanners into CI and define policy gates with an exception process.
5. **Supply chain:** Update vulnerable dependencies to compatible patched versions and review license obligations.
6. **Offline maintenance:** Periodically refresh scanner rules and vulnerability databases through an approved process.
7. **Remediation verification:** Rerun scans and tests after fixes. Preserve baseline and follow-up reports.

