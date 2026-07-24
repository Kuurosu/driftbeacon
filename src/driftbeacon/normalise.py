"""Normalize scanner JSON output into DriftBeacon findings."""

from __future__ import annotations

import hashlib
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import Finding, normalize_severity
from .redaction import redact_secrets, truncate


def stable_fingerprint(
    scanner: str,
    rule_id: str,
    file_path: str | None,
    resource: str | None,
    line_start: int | None,
) -> str:
    """Create a stable finding fingerprint that avoids timestamps and volatile text."""

    parts = [
        scanner.strip().lower(),
        rule_id.strip().lower(),
        _fingerprint_part(file_path),
        _fingerprint_part(resource),
        str(line_start or ""),
    ]
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return digest[:20]


def normalise_checkov(data: Any, repository_path: Path | None = None) -> list[Finding]:
    """Normalize Checkov JSON output."""

    checks = _collect_checkov_failed_checks(data)
    findings: list[Finding] = []
    for check in checks:
        rule_id = _string(check.get("check_id") or check.get("bc_check_id") or "CHECKOV_UNKNOWN")
        title = redact_secrets(
            _string(check.get("check_name") or check.get("short_description") or rule_id)
        )
        description = redact_secrets(
            _string(
                check.get("description") or _nested_string(check, "check_result", "result") or title
            )
        )
        file_path = _normalise_path(
            check.get("file_path") or check.get("repo_file_path") or check.get("file_abs_path"),
            repository_path,
        )
        line_start = _line_from_checkov(check.get("file_line_range")) or _int_or_none(
            check.get("line_number")
        )
        resource = _optional_string(check.get("resource") or check.get("resource_address"))
        severity = normalize_severity(check.get("severity"))
        category = infer_category(
            _string(check.get("bc_category") or check.get("check_type") or title),
            title,
            resource,
            file_path,
        )
        guideline = _optional_string(check.get("guideline"))
        documentation_url = (
            guideline if guideline and guideline.startswith(("http://", "https://")) else None
        )
        remediation = _remediation_from_guideline(guideline, rule_id)
        fingerprint = stable_fingerprint("checkov", rule_id, file_path, resource, line_start)
        findings.append(
            Finding(
                id=f"checkov-{fingerprint}",
                scanner="checkov",
                rule_id=rule_id,
                title=title,
                description=description,
                severity=severity,
                category=category,
                file_path=file_path,
                line_start=line_start,
                resource=resource,
                status="new",
                first_seen=None,
                last_seen=None,
                fingerprint=fingerprint,
                remediation=remediation,
                documentation_url=documentation_url,
            )
        )
    return _deduplicate_findings(findings)


def normalise_trivy(data: Any, repository_path: Path | None = None) -> list[Finding]:
    """Normalize Trivy filesystem JSON output."""

    if not isinstance(data, dict):
        return []
    results = data.get("Results")
    if not isinstance(results, list):
        return []

    findings: list[Finding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        target = _normalise_path(result.get("Target"), repository_path)
        findings.extend(_trivy_vulnerabilities(result, target))
        findings.extend(_trivy_misconfigurations(result, target, repository_path))
        findings.extend(_trivy_secrets(result, target))
    return _deduplicate_findings(findings)


def apply_observed_time(findings: list[Finding], observed_at: datetime) -> list[Finding]:
    """Set first and last seen timestamps when creating a first-run scan."""

    for finding in findings:
        finding.first_seen = finding.first_seen or observed_at
        finding.last_seen = observed_at
    return findings


def infer_category(*values: str | None) -> str:
    """Infer a broad category from scanner-provided labels and text."""

    text = " ".join(value.lower() for value in values if value)
    if any(word in text for word in ("secret", "credential", "password", "token", "private key")):
        return "secret"
    if any(word in text for word in ("cve", "vulnerability", "package", "dependency", "library")):
        return "vulnerability"
    if any(word in text for word in ("kubernetes", "container", "docker", "pod", "image")):
        return "container"
    if any(word in text for word in ("iam", "policy", "permission", "privilege", "role")):
        return "iam"
    if any(word in text for word in ("s3", "bucket", "storage", "volume", "disk", "encrypt")):
        return "storage"
    if any(word in text for word in ("network", "security group", "ingress", "egress", "public")):
        return "network"
    return "misconfiguration"


def _collect_checkov_failed_checks(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        checks: list[dict[str, Any]] = []
        for item in data:
            checks.extend(_collect_checkov_failed_checks(item))
        return checks
    if not isinstance(data, dict):
        return []
    results = data.get("results")
    if isinstance(results, dict) and isinstance(results.get("failed_checks"), list):
        return [item for item in results["failed_checks"] if isinstance(item, dict)]
    failed_checks = data.get("failed_checks")
    if isinstance(failed_checks, list):
        return [item for item in failed_checks if isinstance(item, dict)]
    return []


def _trivy_vulnerabilities(result: dict[str, Any], target: str | None) -> list[Finding]:
    vulnerabilities = result.get("Vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return []
    findings: list[Finding] = []
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        rule_id = _string(item.get("VulnerabilityID") or "TRIVY_VULNERABILITY_UNKNOWN")
        package = _optional_string(item.get("PkgName"))
        title = redact_secrets(_string(item.get("Title") or f"{rule_id} in {package or 'package'}"))
        description = redact_secrets(_string(item.get("Description") or title))
        fixed_version = _optional_string(item.get("FixedVersion"))
        remediation = (
            f"Upgrade {package} to {fixed_version} or later."
            if package and fixed_version
            else "Upgrade or remove the vulnerable dependency."
        )
        fingerprint = stable_fingerprint("trivy", rule_id, target, package, None)
        findings.append(
            Finding(
                id=f"trivy-{fingerprint}",
                scanner="trivy",
                rule_id=rule_id,
                title=title,
                description=description,
                severity=normalize_severity(item.get("Severity")),
                category="vulnerability",
                file_path=target,
                line_start=None,
                resource=package,
                status="new",
                first_seen=None,
                last_seen=None,
                fingerprint=fingerprint,
                remediation=remediation,
                documentation_url=_optional_string(item.get("PrimaryURL")),
            )
        )
    return findings


def _trivy_misconfigurations(
    result: dict[str, Any], target: str | None, repository_path: Path | None
) -> list[Finding]:
    misconfigurations = result.get("Misconfigurations")
    if not isinstance(misconfigurations, list):
        return []
    findings: list[Finding] = []
    for item in misconfigurations:
        if not isinstance(item, dict):
            continue
        cause = item.get("CauseMetadata")
        cause_data = cause if isinstance(cause, dict) else {}
        file_path = _normalise_path(cause_data.get("FilePath") or target, repository_path)
        line_start = _int_or_none(cause_data.get("StartLine"))
        rule_id = _string(item.get("ID") or "TRIVY_MISCONFIG_UNKNOWN")
        title = redact_secrets(_string(item.get("Title") or item.get("Message") or rule_id))
        description = redact_secrets(
            _string(item.get("Description") or item.get("Message") or title)
        )
        resource = _optional_string(item.get("Resource") or item.get("AVDID"))
        category = infer_category(
            _optional_string(item.get("Type")),
            title,
            description,
            resource,
            file_path,
        )
        fingerprint = stable_fingerprint("trivy", rule_id, file_path, resource, line_start)
        findings.append(
            Finding(
                id=f"trivy-{fingerprint}",
                scanner="trivy",
                rule_id=rule_id,
                title=title,
                description=description,
                severity=normalize_severity(item.get("Severity")),
                category=category,
                file_path=file_path,
                line_start=line_start,
                resource=resource,
                status="new",
                first_seen=None,
                last_seen=None,
                fingerprint=fingerprint,
                remediation=redact_secrets(_optional_string(item.get("Resolution"))),
                documentation_url=_optional_string(item.get("PrimaryURL")),
            )
        )
    return findings


def _trivy_secrets(result: dict[str, Any], target: str | None) -> list[Finding]:
    secrets = result.get("Secrets")
    if not isinstance(secrets, list):
        return []
    findings: list[Finding] = []
    for item in secrets:
        if not isinstance(item, dict):
            continue
        rule_id = _string(item.get("RuleID") or item.get("ID") or "TRIVY_SECRET_UNKNOWN")
        title = redact_secrets(_string(item.get("Title") or item.get("Category") or rule_id))
        match = redact_secrets(_string(item.get("Match") or item.get("Description") or ""))
        description = truncate(f"{title}. Matched text: {match}", 220)
        line_start = _int_or_none(item.get("StartLine"))
        fingerprint = stable_fingerprint(
            "trivy",
            rule_id,
            target,
            _optional_string(item.get("Category")),
            line_start,
        )
        findings.append(
            Finding(
                id=f"trivy-{fingerprint}",
                scanner="trivy",
                rule_id=rule_id,
                title=title,
                description=description,
                severity=normalize_severity(item.get("Severity") or "critical"),
                category="secret",
                file_path=target,
                line_start=line_start,
                resource=_optional_string(item.get("Category")),
                status="new",
                first_seen=None,
                last_seen=None,
                fingerprint=fingerprint,
                remediation="Remove the hardcoded secret and rotate it if it was committed.",
                documentation_url=None,
            )
        )
    return findings


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        unique.append(finding)
    return unique


def _normalise_path(value: object, repository_path: Path | None = None) -> str | None:
    raw = _optional_string(value)
    if raw is None:
        return None
    path = raw.replace("\\", "/")
    if repository_path is not None:
        try:
            resolved_repo = repository_path.resolve()
            resolved_path = Path(raw).resolve()
            if resolved_path.is_relative_to(resolved_repo):
                path = resolved_path.relative_to(resolved_repo).as_posix()
        except (OSError, RuntimeError, ValueError):
            pass
    path = path.strip()
    while path.startswith("./"):
        path = path[2:]
    if path.startswith("/") and not Path(path).exists():
        path = path[1:]
    path = _strip_repository_prefix(path, repository_path)
    return path or None


def _strip_repository_prefix(path: str, repository_path: Path | None) -> str:
    if repository_path is None:
        return path
    candidates: set[str] = set()
    raw_repo = repository_path.as_posix().strip("/")
    if raw_repo and raw_repo != ".":
        candidates.add(raw_repo)
    try:
        resolved_path = repository_path.resolve()
        resolved_repo = resolved_path.as_posix().strip("/")
    except (OSError, RuntimeError):
        resolved_repo = ""
        resolved_path = None
    if resolved_repo:
        candidates.add(resolved_repo)
    if resolved_path is not None:
        with suppress(ValueError):
            candidates.add(resolved_path.relative_to(Path.cwd().resolve()).as_posix())

    for prefix in sorted(candidates, key=len, reverse=True):
        if path == prefix:
            return ""
        if path.startswith(prefix + "/"):
            return path[len(prefix) + 1 :]
    return path


def _line_from_checkov(value: object) -> int | None:
    if isinstance(value, list) and value:
        return _int_or_none(value[0])
    return None


def _int_or_none(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    return str(value)


def _string(value: object) -> str:
    return _optional_string(value) or ""


def _nested_string(data: dict[str, Any], key: str, nested_key: str) -> str | None:
    nested = data.get(key)
    if isinstance(nested, dict):
        return _optional_string(nested.get(nested_key))
    return None


def _remediation_from_guideline(guideline: str | None, rule_id: str) -> str | None:
    if guideline is None:
        return f"Review scanner guidance for {rule_id} and apply the least-risk remediation."
    if guideline.startswith(("http://", "https://")):
        return f"Review the linked guidance for {rule_id} and update the affected resource."
    return redact_secrets(guideline)


def _fingerprint_part(value: str | None) -> str:
    if value is None:
        return ""
    return value.strip().replace("\\", "/").lower()
