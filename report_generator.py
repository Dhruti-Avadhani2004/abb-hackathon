"""
Offline Appendix C Security Report Generator

Reads scanner JSON/TXT reports from scanner_output/
and generates:
    security_report/final_security_assessment.md
    security_report/consolidated_findings.json
    security_report/risk_register.csv

Python 3.10+
No external packages, APIs, LLMs, or internet required.

Run:
    python report_generator.py

Optional:
    python report_generator.py --input scanner_output --output security_report
    python report_generator.py --metadata report_metadata.json
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# ==========================================
# PATHS AND CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent

DEFAULT_INPUT_DIR = BASE_DIR / "scanner_output"
DEFAULT_OUTPUT_DIR = BASE_DIR / "security_report"

SCANNER_FILES = {
    "semgrep": ["semgrep_output.json"],
    "trivy": ["trivy_output_offline.json", "trivy_output.json"],
    "bandit": ["bandit_output.json"],
    "eslint": ["eslint_output.json"],
    "gitleaks": ["gitleaks_output.json"],
    "scancode": ["scancode_output.json"],
    "cyclonedx": ["sbom_cyclonedx.json"],
    "spdx": ["sbom_spdx.json"],
    "dotnet": ["dotnet_output.txt"],
}

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
    "UNKNOWN": 5,
}

# ==========================================
# COMMON HELPERS
# ==========================================

def as_dict(value):
    return value if isinstance(value, dict) else {}

def as_list(value):
    return value if isinstance(value, list) else []

def value_or(value, default="Not available"):
    if value is None or value == "":
        return default
    return str(value)

def normalize_severity(value, scanner=""):
    """
    Normalize security scanner severity values.

    ESLint severity is intentionally kept separate
    from vulnerability severity.
    """
    if scanner == "eslint":
        return "UNKNOWN"

    text = str(value or "").upper()

    mapping = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "WARN": "MEDIUM",
        "MODERATE": "MEDIUM",
        "INFORMATIONAL": "INFO",
    }

    return mapping.get(
        text,
        text if text in SEVERITY_ORDER else "UNKNOWN"
    )

def clean_text(value, limit=500):
    """
    Sanitize text before including it in reports.

    Raw source code, secret matches and credential
    values must never be passed to this function.
    """
    text = value_or(value, "")

    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)

    text = re.sub(
        r"(?i)(authorization\s*[:=]\s*bearer\s+)\S+",
        r"\1[REDACTED]",
        text
    )

    text = re.sub(
        r"(?i)(password|api[_-]?key|secret|token)"
        r"\s*[:=]\s*['\"]?\S+",
        r"\1=[REDACTED]",
        text
    )

    text = re.sub(
        r"\bAKIA[0-9A-Z]{16}\b",
        "[REDACTED]",
        text
    )

    text = re.sub(
        r"\b(?:sk_live_|sk_test_|ghp_|github_pat_)"
        r"[A-Za-z0-9_]+",
        "[REDACTED]",
        text
    )

    return text[:limit]

def markdown_safe(value):
    return (
        clean_text(value)
        .replace("|", "\\|")
        .replace("`", "'")
    )

def normalize_path(path, repository_root=""):
    path = value_or(path, "").replace("\\", "/")

    if repository_root:
        root = str(repository_root).replace("\\", "/").rstrip("/")

        if path.lower().startswith(root.lower() + "/"):
            return path[len(root) + 1:]

    return path

def extract_cwes(value):
    if isinstance(value, dict):
        value = value.get("id")

    if isinstance(value, int):
        return [f"CWE-{value}"]

    if isinstance(value, str) and value.isdigit():
        return [f"CWE-{value}"]

    values = value if isinstance(value, list) else [value]

    cwes = set()

    for item in values:
        matches = re.findall(
            r"CWE-\d+",
            str(item),
            flags=re.IGNORECASE
        )

        cwes.update(match.upper() for match in matches)

    return sorted(cwes)

def read_json(path):
    with path.open("r", encoding="utf-8-sig") as file:
        return json.load(file)

def make_finding(
    scanner,
    category,
    title,
    severity="UNKNOWN",
    path="",
    line=None,
    rule="",
    description="",
    cwe=None,
    cve="",
    package="",
    installed_version="",
    fixed_version="",
    source="",
    reference="",
    confidence="",
    repository_root="",
):
    finding = {
        "scanner": scanner,
        "category": category,
        "title": clean_text(title, 220),
        "severity": normalize_severity(
            severity,
            scanner.lower()
        ),
        "path": normalize_path(path, repository_root),
        "line": line,
        "rule": clean_text(rule, 200),
        "description": clean_text(description, 600),
        "cwe": extract_cwes(cwe),
        "cve": clean_text(cve, 100),
        "package": clean_text(package, 150),
        "installed_version": clean_text(
            installed_version, 80
        ),
        "fixed_version": clean_text(fixed_version, 100),
        "source": source,
        "reference": clean_text(reference, 350),
        "confidence": clean_text(confidence, 30),
        "disposition": "Unverified",
        "reachability": "Not assessed",
        "impact": "Requires review",
        "fix": "Requires review",
    }

    fingerprint_fields = (
        "scanner",
        "rule",
        "path",
        "line",
        "cve",
        "package",
        "installed_version",
        "title",
    )

    fingerprint = "\x1f".join(
        str(finding[field])
        for field in fingerprint_fields
    )

    finding["id"] = hashlib.sha256(
        fingerprint.encode("utf-8")
    ).hexdigest()[:16]

    return finding

# ==========================================
# SEMGREP PARSER
# ==========================================

def parse_semgrep(data, findings, source, root):
    for result in as_list(as_dict(data).get("results")):
        extra = as_dict(result.get("extra"))
        metadata = as_dict(extra.get("metadata"))

        finding = make_finding(
            scanner="Semgrep",
            category=metadata.get("category") or "SAST",
            title=extra.get("message")
                  or result.get("check_id"),
            severity=extra.get("severity"),
            path=result.get("path"),
            line=as_dict(result.get("start")).get("line"),
            rule=result.get("check_id"),
            description=extra.get("message"),
            cwe=metadata.get("cwe"),
            source=source,
            reference=next(
                iter(as_list(metadata.get("references"))),
                ""
            ),
            confidence=metadata.get("confidence"),
            repository_root=root,
        )

        findings.append(finding)

# ==========================================
# TRIVY PARSER
# ==========================================

def parse_trivy(data, findings, packages, source, root):
    for result in as_list(as_dict(data).get("Results")):
        target = result.get("Target", "")

        for package in as_list(result.get("Packages")):
            packages.append({
                "name": value_or(package.get("Name"), ""),
                "version": value_or(
                    package.get("Version"), ""
                ),
                "purl": value_or(
                    as_dict(
                        package.get("Identifier")
                    ).get("PURL"),
                    ""
                ),
                "license": "Not assessed",
                "relationship": "Unknown",
                "source": "Trivy",
                "location": target,
            })

        for vulnerability in as_list(
            result.get("Vulnerabilities")
        ):
            findings.append(
                make_finding(
                    scanner="Trivy",
                    category="Dependency vulnerability",
                    title=vulnerability.get("Title")
                          or vulnerability.get(
                              "VulnerabilityID"
                          ),
                    severity=vulnerability.get("Severity"),
                    path=target,
                    rule=vulnerability.get(
                        "VulnerabilityID"
                    ),
                    description=vulnerability.get(
                        "Description"
                    ),
                    cwe=vulnerability.get("CweIDs"),
                    cve=vulnerability.get(
                        "VulnerabilityID"
                    ),
                    package=vulnerability.get("PkgName"),
                    installed_version=vulnerability.get(
                        "InstalledVersion"
                    ),
                    fixed_version=vulnerability.get(
                        "FixedVersion"
                    ),
                    source=source,
                    reference=vulnerability.get(
                        "PrimaryURL"
                    ),
                    repository_root=root,
                )
            )

        for misconfiguration in as_list(
            result.get("Misconfigurations")
        ):
            findings.append(
                make_finding(
                    scanner="Trivy",
                    category="Misconfiguration",
                    title=misconfiguration.get("Title")
                          or misconfiguration.get("ID"),
                    severity=misconfiguration.get(
                        "Severity"
                    ),
                    path=target,
                    line=as_dict(
                        misconfiguration.get("CauseMetadata")
                    ).get("StartLine"),
                    rule=misconfiguration.get("ID"),
                    description=misconfiguration.get(
                        "Description"
                    ),
                    cwe=misconfiguration.get("CweIDs"),
                    source=source,
                    reference=misconfiguration.get(
                        "PrimaryURL"
                    ),
                    repository_root=root,
                )
            )

        for secret in as_list(result.get("Secrets")):
            findings.append(
                make_finding(
                    scanner="Trivy",
                    category="Potential secret",
                    title=secret.get("Title")
                          or secret.get("RuleID"),
                    severity=secret.get("Severity"),
                    path=target,
                    line=secret.get("StartLine"),
                    rule=secret.get("RuleID"),
                    description=(
                        "Potential secret detected; "
                        "value withheld."
                    ),
                    source=source,
                    repository_root=root,
                )
            )

        for license_item in as_list(
            result.get("Licenses")
        ):
            findings.append(
                make_finding(
                    scanner="Trivy",
                    category="License policy",
                    title=license_item.get("Name")
                          or license_item.get("Category"),
                    severity=license_item.get("Severity"),
                    path=target,
                    rule=license_item.get("Name"),
                    description=(
                        "License policy finding; "
                        "review applicable obligations."
                    ),
                    source=source,
                    repository_root=root,
                )
            )

# ==========================================
# BANDIT PARSER
# ==========================================

def parse_bandit(data, findings, source, root):
    for result in as_list(as_dict(data).get("results")):
        rule = str(result.get("test_id", "")).upper()

        # Bandit issue_text may contain literal credentials.
        if rule in {"B105", "B106", "B107"}:
            description = (
                "Possible hardcoded credential "
                "(value withheld)."
            )
        else:
            description = result.get("issue_text", "")

        findings.append(
            make_finding(
                scanner="Bandit",
                category="SAST",
                title=result.get("test_name")
                      or result.get("test_id"),
                severity=result.get("issue_severity"),
                path=result.get("filename"),
                line=result.get("line_number"),
                rule=result.get("test_id"),
                description=description,
                cwe=result.get("issue_cwe"),
                source=source,
                reference=result.get("more_info"),
                confidence=result.get("issue_confidence"),
                repository_root=root,
            )
        )

# ==========================================
# ESLINT PARSER
# ==========================================

def parse_eslint(data, findings, source, root):
    for file in as_list(data):
        for message in as_list(file.get("messages")):
            rule = message.get("ruleId") or ""

            category = (
                "Security lint rule"
                if rule.startswith("security/")
                else "Code quality"
            )

            findings.append(
                make_finding(
                    scanner="ESLint",
                    category=category,
                    title=rule or "ESLint finding",
                    severity="UNKNOWN",
                    path=file.get("filePath"),
                    line=message.get("line"),
                    rule=rule,
                    description=message.get("message"),
                    source=source,
                    repository_root=root,
                )
            )

# ==========================================
# GITLEAKS PARSER
# ==========================================

def parse_gitleaks(data, findings, source, root):
    for result in as_list(data):
        findings.append(
            make_finding(
                scanner="Gitleaks",
                category="Potential secret",
                title=result.get("Description")
                      or result.get("RuleID")
                      or "Potential secret",
                severity="UNKNOWN",
                path=result.get("File"),
                line=result.get("StartLine"),
                rule=result.get("RuleID"),
                description=(
                    "Potential secret detected. "
                    "Match and secret values withheld."
                ),
                source=source,
                repository_root=root,
            )
        )

# ==========================================
# SCANCODE PARSER
# ==========================================

def parse_scancode(data, packages, license_info):
    data = as_dict(data)
    summary = as_dict(data.get("summary"))

    license_info["declared_license"] = (
        summary.get("declared_license_expression")
        or "Not identified"
    )

    license_info["license_clarity_score"] = (
        as_dict(
            summary.get("license_clarity_score")
        ).get("score")
    )

    license_info["primary_language"] = (
        summary.get("primary_language")
        or "Not identified"
    )

    for package in as_list(data.get("packages")):
        packages.append({
            "name": value_or(package.get("name"), ""),
            "version": value_or(package.get("version"), ""),
            "purl": value_or(package.get("purl"), ""),
            "license": value_or(
                package.get("declared_license_expression_spdx")
                or package.get("declared_license_expression"),
                "Not identified"
            ),
            "relationship": "Unknown",
            "source": "ScanCode",
            "location": ", ".join(
                as_list(package.get("datafile_paths"))
            ),
        })

    for dependency in as_list(data.get("dependencies")):
        direct = dependency.get("is_direct")

        relationship = (
            "Direct" if direct is True
            else "Transitive" if direct is False
            else "Unknown"
        )

        packages.append({
            "name": value_or(
                dependency.get("purl"), ""
            ),
            "version": value_or(
                dependency.get("extracted_requirement"), ""
            ),
            "purl": value_or(
                dependency.get("purl"), ""
            ),
            "license": "Not assessed",
            "relationship": relationship,
            "source": "ScanCode dependency",
            "location": value_or(
                dependency.get("datafile_path"), ""
            ),
        })

# ==========================================
# CYCLONEDX SBOM PARSER
# ==========================================

def parse_cyclonedx(data, packages):
    for component in as_list(
        as_dict(data).get("components")
    ):
        if component.get("type") == "file":
            continue

        licenses = []

        for license_item in as_list(
            component.get("licenses")
        ):
            license_data = as_dict(
                license_item.get("license")
            )

            license_name = (
                license_data.get("id")
                or license_data.get("name")
                or license_item.get("expression")
            )

            if license_name:
                licenses.append(license_name)

        packages.append({
            "name": value_or(component.get("name"), ""),
            "version": value_or(
                component.get("version"), ""
            ),
            "purl": value_or(component.get("purl"), ""),
            "license": (
                ", ".join(licenses)
                or "Not identified"
            ),
            "relationship": "Unknown",
            "source": "Syft CycloneDX",
            "location": "",
        })

# ==========================================
# SPDX SBOM PARSER
# ==========================================

def parse_spdx(data, packages):
    for package in as_list(
        as_dict(data).get("packages")
    ):
        purl = ""

        for reference in as_list(
            package.get("externalRefs")
        ):
            if reference.get("referenceType") == "purl":
                purl = reference.get(
                    "referenceLocator", ""
                )
                break

        license_value = (
            package.get("licenseDeclared")
            or package.get("licenseConcluded")
        )

        if license_value in ("NOASSERTION", "NONE"):
            license_value = "Not identified"

        packages.append({
            "name": value_or(package.get("name"), ""),
            "version": value_or(
                package.get("versionInfo"), ""
            ),
            "purl": purl,
            "license": (
                license_value or "Not identified"
            ),
            "relationship": "Unknown",
            "source": "Syft SPDX",
            "location": "",
        })

# ==========================================
# .NET TEXT PARSER
# ==========================================

def parse_dotnet(text, findings, source, root):
    """
    Best-effort parser for:
    dotnet package list --vulnerable

    NuGet output varies between SDK versions.
    """
    project = ""

    pattern = re.compile(
        r"\s*>\s+(\S+)\s+(\S+)\s+(\S+)\s+"
        r"(Critical|High|Moderate|Medium|Low)\s+"
        r"(https?://\S+)",
        re.IGNORECASE
    )

    for line in text.splitlines():
        if line.strip().lower().startswith("project:"):
            project = line.split(":", 1)[1].strip()

        match = pattern.match(line)

        if not match:
            continue

        package, requested, resolved, severity, url = (
            match.groups()
        )

        advisory = re.search(
            r"(CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)",
            url,
            re.IGNORECASE
        )

        advisory_id = (
            advisory.group(0) if advisory else ""
        )

        findings.append(
            make_finding(
                scanner=".NET",
                category="Dependency vulnerability",
                title=f"Vulnerable NuGet package: {package}",
                severity=severity,
                path=project,
                rule=advisory_id,
                description=(
                    "NuGet vulnerability advisory "
                    "reported by dotnet."
                ),
                cve=(
                    advisory_id
                    if advisory_id.upper().startswith("CVE-")
                    else ""
                ),
                package=package,
                installed_version=resolved,
                source=source,
                reference=url,
                repository_root=root,
            )
        )

# ==========================================
# PACKAGE DEDUPLICATION
# ==========================================

def deduplicate_packages(packages):
    merged = {}

    for package in packages:
        key = (
            package.get("purl")
            or package.get("name", "").lower(),
            package.get("version", "")
        )

        if not key[0]:
            continue

        if key not in merged:
            merged[key] = dict(package)
            merged[key]["sources"] = [
                package["source"]
            ]
            continue

        existing = merged[key]

        if package["source"] not in existing["sources"]:
            existing["sources"].append(
                package["source"]
            )

        if existing["license"] in (
            "Not identified",
            "Not assessed"
        ):
            if package["license"] not in (
                "Not identified",
                "Not assessed"
            ):
                existing["license"] = package["license"]

        if existing["relationship"] == "Unknown":
            if package["relationship"] != "Unknown":
                existing["relationship"] = (
                    package["relationship"]
                )

    return sorted(
        merged.values(),
        key=lambda package: (
            package["name"].lower(),
            package["version"]
        )
    )

# ==========================================
# MARKDOWN TABLE GENERATOR
# ==========================================

def markdown_table(headers, rows):
    if not rows:
        return "No data available.\n"

    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(
            "---" for _ in headers
        ) + " |"
    ]

    for row in rows:
        lines.append(
            "| " + " | ".join(
                markdown_safe(item) for item in row
            ) + " |"
        )

    return "\n".join(lines) + "\n"

# ==========================================
# REPOSITORY IDENTIFICATION
# ==========================================

def identify_repository(data, metadata):
    explicit = (
        metadata.get("repository")
        or metadata.get("repo")
    )

    if explicit:
        return str(explicit)

    trivy = as_dict(data.get("trivy"))

    if trivy.get("ArtifactName"):
        return trivy["ArtifactName"]

    spdx = as_dict(data.get("spdx"))

    if spdx.get("name"):
        return Path(
            str(spdx["name"]).replace("\\", "/")
        ).name

    scancode = as_dict(data.get("scancode"))
    headers = as_list(scancode.get("headers"))

    if headers:
        options = as_dict(
            headers[0].get("options")
        )

        inputs = as_list(options.get("input"))

        if inputs:
            return Path(
                str(inputs[0]).replace("\\", "/")
            ).name

    return "Unknown repository"

# ==========================================
# APPENDIX C REPORT GENERATOR
# ==========================================

def generate_report(
    repository,
    data,
    findings,
    packages,
    metadata,
    loaded_files,
    warnings,
    license_info,
    input_dir,
):
    lines = []

    def write(*items):
        lines.extend(items)

    findings = sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER[finding["severity"]],
            finding["scanner"],
            finding["path"],
            str(finding["line"])
        )
    )

    severity_counts = Counter(
        finding["severity"]
        for finding in findings
    )

    category_counts = Counter(
        finding["category"]
        for finding in findings
    )

    scanner_counts = Counter(
        finding["scanner"]
        for finding in findings
    )

    top_five = findings[:5]

    trivy = as_dict(data.get("trivy"))
    semgrep = as_dict(data.get("semgrep"))
    scancode = as_dict(data.get("scancode"))

    headers = as_list(scancode.get("headers"))

    scancode_header = (
        as_dict(headers[0])
        if headers else {}
    )

    environment = as_dict(
        as_dict(
            scancode_header.get("extra_data")
        ).get("system_environment")
    )

    trivy_metadata = as_dict(
        trivy.get("Metadata")
    )

    commit = (
        metadata.get("commit")
        or trivy_metadata.get("Commit")
    )

    branch = (
        metadata.get("branch")
        or trivy_metadata.get("Branch")
    )

    repository_url = (
        metadata.get("repo_url")
        or trivy_metadata.get("RepoURL")
    )

    scancode_options = as_dict(
        scancode_header.get("options")
    )

    exclusions = (
        metadata.get("exclusions")
        or scancode_options.get("--ignore")
        or []
    )

    folders = (
        metadata.get("folders_scanned")
        or scancode_options.get("input")
        or []
    )

    cyclonedx = as_dict(data.get("cyclonedx"))

    syft_tools = as_list(
        as_dict(
            as_dict(
                cyclonedx.get("metadata")
            ).get("tools")
        ).get("components")
    )

    syft_version = next(
        (
            tool.get("version")
            for tool in syft_tools
            if tool.get("name") == "syft"
        ),
        None
    )

    scanner_versions = {
        "Semgrep": semgrep.get("version"),
        "Trivy": as_dict(
            trivy.get("Trivy")
        ).get("Version"),
        "ScanCode": scancode_header.get(
            "tool_version"
        ),
        "Syft": syft_version,
    }

    scanner_versions.update(
        as_dict(
            metadata.get("scanner_versions")
        )
    )

    # --------------------------------------
    # REPORT HEADER
    # --------------------------------------

    write(
        f"# Appendix C - Final Security Assessment: "
        f"{markdown_safe(repository)}",
        "",
        f"Generated (UTC): "
        f"{datetime.now(timezone.utc).isoformat()}",
        ""
    )

    # --------------------------------------
    # 1. EXECUTIVE SUMMARY
    # --------------------------------------

    write(
        "## 1. Executive summary",
        "",
        f"Automated analysis produced "
        f"**{len(findings)} scanner findings** "
        f"for **{markdown_safe(repository)}**.",
        "",
        "These are automated detections requiring "
        "review, not independently confirmed vulnerabilities.",
        ""
    )

    write(
        "### Severity distribution",
        "",
        markdown_table(
            ["Severity", "Count"],
            [
                (severity, severity_counts[severity])
                for severity in SEVERITY_ORDER
            ]
        )
    )

    write("### Top five risks", "")

    if top_five:
        for index, finding in enumerate(top_five, 1):
            write(
                f"{index}. **{finding['severity']}** - "
                f"{markdown_safe(finding['title'])} "
                f"({finding['scanner']}, "
                f"{markdown_safe(finding['path'])}:"
                f"{value_or(finding['line'], '?')})"
            )
    else:
        write(
            "No findings were present in the "
            "available scanner reports."
        )

    write(
        "",
        "### Main limitations",
        "",
        "Automated findings have not been independently "
        "verified. Reachability, runtime exploitability "
        "and business impact are not assessed. "
        "Offline vulnerability database freshness "
        "cannot be established without database timestamps.",
        ""
    )

    # --------------------------------------
    # 2. SCOPE
    # --------------------------------------

    write("## 2. Scope", "")

    write(
        markdown_table(
            ["Field", "Value"],
            [
                ("Repository", repository),
                (
                    "Repository URL",
                    repository_url or "Not available"
                ),
                (
                    "Commit",
                    commit or "Not available"
                ),
                (
                    "Branch",
                    branch or "Not available"
                ),
                (
                    "Folders scanned",
                    ", ".join(map(str, folders))
                    if isinstance(folders, list)
                    else folders
                ),
                (
                    "Known exclusions",
                    ", ".join(map(str, exclusions))
                    if isinstance(exclusions, list)
                    else exclusions
                ),
                (
                    "Scanner output directory",
                    str(input_dir)
                ),
            ]
        )
    )

    write(
        "Exclusions listed here are only those "
        "recorded in the available reports or metadata. "
        "Different scanners may have different exclusions.",
        ""
    )

    # --------------------------------------
    # 3. ENVIRONMENT
    # --------------------------------------

    write("## 3. Environment", "")

    write(
        markdown_table(
            ["Field", "Recorded value"],
            [
                (
                    "OS / VM",
                    metadata.get("vm_details")
                    or environment.get("platform")
                    or "Not available"
                ),
                (
                    "CPU architecture",
                    environment.get("cpu_architecture")
                    or "Not available"
                ),
                (
                    "Python version",
                    environment.get("python_version")
                    or "Not available"
                ),
                (
                    "Rule-set hashes",
                    metadata.get("rule_set_hashes")
                    or "Not supplied"
                ),
                (
                    "Vulnerability database timestamps",
                    metadata.get("database_timestamps")
                    or "Not supplied"
                ),
                (
                    "Trivy report timestamp",
                    trivy.get("CreatedAt")
                    or "Not available"
                ),
                (
                    "ScanCode scan start",
                    scancode_header.get("start_timestamp")
                    or "Not available"
                ),
            ]
        )
    )

    write("### Scanner versions", "")

    write(
        markdown_table(
            ["Scanner", "Version"],
            [
                (scanner, version or "Not available")
                for scanner, version
                in scanner_versions.items()
            ]
        )
    )

    write("### Scanner input status", "")

    write(
        markdown_table(
            ["Scanner", "Input file", "Status"],
            [
                (
                    scanner,
                    loaded_files.get(
                        scanner, "Not supplied"
                    ),
                    (
                        "Present"
                        if scanner in loaded_files
                        else "Missing"
                    )
                )
                for scanner in SCANNER_FILES
            ]
        )
    )

    # --------------------------------------
    # 4. METHOD
    # --------------------------------------

    write("## 4. Method", "")

    methods = {
        "semgrep": "Rule-based static application security testing",
        "bandit": "Python static security analysis",
        "eslint": "JavaScript lint and security rules",
        "trivy": "Dependency and configuration security checks",
        "gitleaks": "Potential secret detection",
        "scancode": "License, copyright and package analysis",
        "cyclonedx": "CycloneDX software bill of materials",
        "spdx": "SPDX software bill of materials",
        "dotnet": "NuGet dependency vulnerability analysis",
    }

    write(
        markdown_table(
            ["Scanner / format", "Purpose", "Availability"],
            [
                (
                    scanner,
                    purpose,
                    (
                        "Input present"
                        if scanner in loaded_files
                        else "Not supplied"
                    )
                )
                for scanner, purpose in methods.items()
            ]
        )
    )

    write(
        "Exact execution commands, scan options, "
        "offline cache configuration and rule provenance "
        "may require execution logs or additional metadata.",
        ""
    )

    # --------------------------------------
    # 5. RESULTS BY REPOSITORY
    # --------------------------------------

    write("## 5. Results by repository", "")

    write(
        markdown_table(
            [
                "Repository",
                "Critical",
                "High",
                "Medium",
                "Low",
                "Info",
                "Unknown",
                "Confirmed",
                "Unverified",
            ],
            [
                (
                    repository,
                    severity_counts["CRITICAL"],
                    severity_counts["HIGH"],
                    severity_counts["MEDIUM"],
                    severity_counts["LOW"],
                    severity_counts["INFO"],
                    severity_counts["UNKNOWN"],
                    0,
                    len(findings),
                )
            ]
        )
    )

    write(
        "All findings are classified as **unverified** "
        "until a human reviewer confirms their disposition. "
        "Scanner confidence does not establish exploitability.",
        ""
    )

    write("### Findings by category", "")

    write(
        markdown_table(
            ["Category", "Count"],
            sorted(
                category_counts.items(),
                key=lambda item: (
                    -item[1],
                    item[0]
                )
            )
        )
    )

    write("### Findings by scanner", "")

    write(
        markdown_table(
            ["Scanner", "Count"],
            sorted(scanner_counts.items())
        )
    )

    # --------------------------------------
    # 6. TOP FINDINGS
    # --------------------------------------

    write("## 6. Top findings", "")

    if not findings:
        write("No finding records available.", "")

    for index, finding in enumerate(
        findings[:20],
        1
    ):
        write(
            f"### {index}. "
            f"{markdown_safe(finding['title'])}",
            ""
        )

        suggested_fix = (
            "Review affected package and update "
            "to a compatible fixed version: "
            + finding["fixed_version"]
            if finding["fixed_version"]
            else "Manual remediation decision required"
        )

        write(
            markdown_table(
                ["Field", "Value"],
                [
                    ("Finding ID", finding["id"]),
                    (
                        "Scanner",
                        finding["scanner"]
                    ),
                    (
                        "Severity",
                        finding["severity"]
                    ),
                    (
                        "Evidence location",
                        finding["path"]
                        + (
                            ":" + str(finding["line"])
                            if finding["line"]
                            else ""
                        )
                    ),
                    (
                        "Rule",
                        finding["rule"] or "Not supplied"
                    ),
                    (
                        "CWE",
                        ", ".join(finding["cwe"])
                        or "Not supplied"
                    ),
                    (
                        "CVE / advisory",
                        finding["cve"]
                        or (
                            finding["rule"]
                            if finding["category"]
                            == "Dependency vulnerability"
                            else "Not supplied"
                        )
                    ),
                    (
                        "Reachability",
                        finding["reachability"]
                    ),
                    (
                        "Impact",
                        finding["impact"]
                    ),
                    (
                        "Disposition",
                        finding["disposition"]
                    ),
                    (
                        "Suggested fix",
                        suggested_fix
                    ),
                    (
                        "Source",
                        finding["source"]
                    ),
                    (
                        "Reference",
                        finding["reference"]
                        or "Not supplied"
                    ),
                ]
            )
        )

        if finding["description"]:
            write(
                "Evidence summary: "
                + markdown_safe(finding["description"]),
                ""
            )

    if len(findings) > 20:
        write(
            f"Only the first 20 of {len(findings)} "
            "findings are expanded here. "
            "Complete records are available in "
            "consolidated_findings.json.",
            ""
        )

    # --------------------------------------
    # 7. SUPPLY CHAIN VIEW
    # --------------------------------------

    write("## 7. Supply chain view", "")

    write(
        f"Package scanners identified "
        f"**{len(packages)} distinct package/version "
        f"entries** after consolidation.",
        "",
        "An SBOM package entry does not itself "
        "represent a vulnerability.",
        ""
    )

    vulnerable_packages = [
        finding
        for finding in findings
        if finding["category"]
        == "Dependency vulnerability"
    ]

    write("### Vulnerable packages and advisories", "")

    write(
        markdown_table(
            [
                "Package",
                "Installed",
                "Advisory",
                "Severity",
                "Fixed version",
                "Source",
            ],
            [
                (
                    finding["package"],
                    finding["installed_version"],
                    finding["cve"]
                    or finding["rule"],
                    finding["severity"],
                    finding["fixed_version"]
                    or "Not supplied",
                    finding["scanner"],
                )
                for finding in vulnerable_packages[:100]
            ]
        )
    )

    if len(vulnerable_packages) > 100:
        write(
            "Additional dependency findings are "
            "available in the JSON and CSV outputs.",
            ""
        )

    write("### Package inventory", "")

    write(
        markdown_table(
            [
                "Package",
                "Version / constraint",
                "Direct / transitive",
                "License",
                "Source",
            ],
            [
                (
                    package["name"],
                    package["version"],
                    package["relationship"],
                    package["license"],
                    ", ".join(package["sources"]),
                )
                for package in packages[:100]
            ]
        )
    )

    if len(packages) > 100:
        write(
            "Additional package entries are "
            "available in consolidated_findings.json.",
            ""
        )

    write(
        "### Repository license",
        "",
        markdown_safe(
            license_info.get(
                "declared_license",
                "Not available"
            )
        ),
        "",
        "Detected licenses are not a legal "
        "compliance determination. Unknown dependency "
        "relationships are not inferred.",
        ""
    )

    # --------------------------------------
    # 8. REMEDIATION OUTCOMES
    # --------------------------------------

    write("## 8. Remediation outcomes", "")

    remediation = as_dict(
        metadata.get("remediation")
    )

    if remediation:
        write(
            markdown_table(
                ["Metric", "Provided value"],
                list(remediation.items())
            )
        )
    else:
        write(
            "No baseline/post-remediation comparison, "
            "patch evidence or test results were supplied.",
            "",
            "Before-and-after counts, verified fixes "
            "and closure status are **not assessed**.",
            ""
        )

    # --------------------------------------
    # 9. LIMITATIONS
    # --------------------------------------

    write("## 9. Limitations", "")

    limitations = [
        (
            "Static analysis and dependency scanners "
            "can produce false positives and false negatives."
        ),
        (
            "Reachability, exploitability, runtime controls "
            "and business impact have not been validated."
        ),
        (
            "Offline vulnerability databases and rules "
            "may be stale. Report timestamps do not prove "
            "database freshness."
        ),
        (
            "A missing or failed scanner must not be "
            "interpreted as reporting zero vulnerabilities."
        ),
        (
            "Source coverage, excluded files and "
            "unsupported language features may not be "
            "fully established by scanner reports alone."
        ),
        (
            "Potential secret findings require validation. "
            "Matched secret values are withheld."
        ),
    ]

    limitations.extend(warnings)

    for limitation in limitations:
        write(
            "- " + clean_text(limitation, 1000)
        )

    write("")

    # --------------------------------------
    # 10. RECOMMENDATIONS
    # --------------------------------------

    write("## 10. Recommendations", "")

    recommendations = [
        (
            "**Triage ownership:** Assign each finding "
            "to a responsible repository or component owner."
        ),
        (
            "**Validate findings:** Confirm whether "
            "flagged code and dependencies are deployed "
            "and reachable. Record false positives."
        ),
        (
            "**Fix timelines:** Establish severity-based "
            "remediation SLAs using an approved policy."
        ),
        (
            "**CI integration:** Integrate scanners "
            "into CI and define policy gates with "
            "an exception process."
        ),
        (
            "**Supply chain:** Update vulnerable "
            "dependencies to compatible patched versions "
            "and review license obligations."
        ),
        (
            "**Offline maintenance:** Periodically refresh "
            "scanner rules and vulnerability databases "
            "through an approved process."
        ),
        (
            "**Remediation verification:** Rerun scans "
            "and tests after fixes. Preserve baseline "
            "and follow-up reports."
        ),
    ]

    for index, recommendation in enumerate(
        recommendations,
        1
    ):
        write(f"{index}. {recommendation}")

    write("")

    return "\n".join(lines) + "\n"

# ==========================================
# MAIN REPORT GENERATION
# ==========================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate an offline Appendix C "
            "security assessment report."
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help="Directory containing scanner outputs"
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for generated reports"
    )

    parser.add_argument(
        "--metadata",
        type=Path,
        help="Optional report metadata JSON file"
    )

    args = parser.parse_args()

    if not args.input.is_dir():
        parser.error(
            f"Scanner output directory not found: "
            f"{args.input}"
        )

    metadata = {}

    if args.metadata:
        metadata = as_dict(
            read_json(args.metadata)
        )

    loaded = {}
    loaded_files = {}
    warnings = []

    print("\n====================================")
    print(" OFFLINE SECURITY REPORT GENERATOR")
    print("====================================")

    print(f"\nInput directory: {args.input}")

    # --------------------------------------
    # LOAD AVAILABLE SCANNER REPORTS
    # --------------------------------------

    print("\n[1] Loading scanner reports...")

    for scanner, candidates in SCANNER_FILES.items():
        selected = next(
            (
                args.input / filename
                for filename in candidates
                if (args.input / filename).is_file()
            ),
            None
        )

        if selected is None:
            warnings.append(
                f"Missing {scanner} report "
                "(not assessed)."
            )

            print(f"  {scanner}: MISSING")
            continue

        try:
            if selected.suffix.lower() == ".txt":
                content = selected.read_text(
                    encoding="utf-8-sig",
                    errors="replace"
                )
            else:
                content = read_json(selected)

            loaded[scanner] = content
            loaded_files[scanner] = selected.name

            print(
                f"  {scanner}: LOADED "
                f"({selected.name})"
            )

        except (
            OSError,
            ValueError,
            UnicodeError
        ) as error:
            warnings.append(
                f"Could not parse {scanner}: "
                f"{type(error).__name__}"
            )

            print(
                f"  {scanner}: ERROR "
                f"({type(error).__name__})"
            )

    if not loaded:
        parser.error(
            "No recognized scanner reports were found."
        )

    # --------------------------------------
    # IDENTIFY REPOSITORY
    # --------------------------------------

    repository = identify_repository(
        loaded,
        metadata
    )

    scancode = as_dict(
        loaded.get("scancode")
    )

    headers = as_list(
        scancode.get("headers")
    )

    scancode_inputs = []

    if headers:
        scancode_inputs = as_list(
            as_dict(
                headers[0].get("options")
            ).get("input")
        )

    repository_root = (
        metadata.get("repository_path")
        or (
            scancode_inputs[0]
            if scancode_inputs
            else ""
        )
    )

    # --------------------------------------
    # PARSE SCANNER OUTPUTS
    # --------------------------------------

    print("\n[2] Parsing scanner findings...")

    findings = []
    raw_packages = []
    license_info = {}

    scanner_parsers = {
        "semgrep": lambda data, source: parse_semgrep(
            data, findings, source, repository_root
        ),

        "trivy": lambda data, source: parse_trivy(
            data, findings, raw_packages,
            source, repository_root
        ),

        "bandit": lambda data, source: parse_bandit(
            data, findings, source, repository_root
        ),

        "eslint": lambda data, source: parse_eslint(
            data, findings, source, repository_root
        ),

        "gitleaks": lambda data, source: parse_gitleaks(
            data, findings, source, repository_root
        ),

        "scancode": lambda data, source: parse_scancode(
            data, raw_packages, license_info
        ),

        "cyclonedx": lambda data, source: parse_cyclonedx(
            data, raw_packages
        ),

        "spdx": lambda data, source: parse_spdx(
            data, raw_packages
        ),

        "dotnet": lambda data, source: parse_dotnet(
            data, findings, source, repository_root
        ),
    }

    for scanner, data in loaded.items():
        try:
            scanner_parsers[scanner](
                data,
                loaded_files[scanner]
            )

        except (
            TypeError,
            ValueError,
            KeyError,
            AttributeError
        ) as error:
            warnings.append(
                f"Partial or failed parsing of "
                f"{scanner}: {type(error).__name__}. "
                "Verify scanner schema compatibility."
            )

            print(
                f"  WARNING: {scanner} parsing issue"
            )

    # --------------------------------------
    # DEDUPLICATE FINDINGS
    # --------------------------------------

    unique_findings = {
        finding["id"]: finding
        for finding in findings
    }

    findings = list(
        unique_findings.values()
    )

    packages = deduplicate_packages(
        raw_packages
    )

    print(f"  Findings extracted: {len(findings)}")
    print(f"  Package entries: {len(packages)}")

    # --------------------------------------
    # CREATE OUTPUT DIRECTORY
    # --------------------------------------

    args.output.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------
    # GENERATE MARKDOWN REPORT
    # --------------------------------------

    print("\n[3] Generating Appendix C report...")

    report = generate_report(
        repository=repository,
        data=loaded,
        findings=findings,
        packages=packages,
        metadata=metadata,
        loaded_files=loaded_files,
        warnings=warnings,
        license_info=license_info,
        input_dir=args.input,
    )

    markdown_file = (
        args.output / "final_security_assessment.md"
    )

    markdown_file.write_text(
        report,
        encoding="utf-8"
    )

    # --------------------------------------
    # GENERATE CONSOLIDATED JSON
    # --------------------------------------

    print("[4] Generating consolidated JSON...")

    json_file = (
        args.output / "consolidated_findings.json"
    )

    payload = {
        "repository": repository,
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "inputs": loaded_files,
        "warnings": warnings,
        "findings": findings,
        "packages": packages,
        "license_summary": license_info,
    }

    json_file.write_text(
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    # --------------------------------------
    # GENERATE RISK REGISTER CSV
    # --------------------------------------

    print("[5] Generating risk register CSV...")

    csv_file = (
        args.output / "risk_register.csv"
    )

    csv_fields = [
        "id",
        "scanner",
        "category",
        "severity",
        "title",
        "path",
        "line",
        "rule",
        "cwe",
        "cve",
        "package",
        "installed_version",
        "fixed_version",
        "disposition",
        "reachability",
        "source",
    ]

    sorted_findings = sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER[finding["severity"]],
            finding["scanner"]
        )
    )

    with csv_file.open(
        "w",
        encoding="utf-8-sig",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=csv_fields,
            extrasaction="ignore"
        )

        writer.writeheader()

        for finding in sorted_findings:
            row = dict(finding)

            row["cwe"] = ", ".join(
                finding["cwe"]
            )

            # Prevent spreadsheet formula injection.
            for field in csv_fields:
                value = row.get(field)

                if (
                    isinstance(value, str)
                    and value.lstrip().startswith(
                        ("=", "+", "-", "@")
                    )
                ):
                    row[field] = "'" + value

            writer.writerow(row)

    # --------------------------------------
    # SUMMARY
    # --------------------------------------

    print("\n====================================")
    print(" REPORT GENERATION SUMMARY")
    print("====================================")

    print(f"Repository       : {repository}")
    print(f"Reports loaded   : {len(loaded_files)}")
    print(f"Findings         : {len(findings)}")
    print(f"Package entries  : {len(packages)}")
    print(f"Warnings         : {len(warnings)}")

    print("\nGenerated files:")
    print(f"  {markdown_file}")
    print(f"  {json_file}")
    print(f"  {csv_file}")

    print("\nReport generation completed.")

# ==========================================
# ENTRY POINT
# ==========================================

if __name__ == "__main__":
    main()