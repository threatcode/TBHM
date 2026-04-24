"""
Vulnerability prioritization and remediation guidance module.
"""

import json
import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

SEVERITY_SCORES = {
    "critical": 10,
    "high": 8,
    "medium": 6,
    "low": 3,
    "info": 0,
}

REMEDIATION_TEMPLATES = {
    "sqli": {
        "priority": "critical",
        "steps": [
            "Use parameterized queries (prepared statements) instead of string concatenation",
            "Implement input validation and sanitization",
            "Use stored procedures with restricted permissions",
            "Apply principle of least privilege to database accounts",
            "Implement web application firewall (WAF)",
            "Hash and salt passwords with bcrypt/argon2",
        ],
        "cwe": "CWE-89",
    },
    "cmdi": {
        "priority": "critical",
        "steps": [
            "Avoid shell execution where possible",
            "Use execve() or equivalent without shell interpretation",
            "Implement strict input validation using allowlists",
            "Sanitize special characters: ; | & $ ` ( ) { } [ ] < > \" ' \\",
            "Apply principle of least privilege to process execution",
            "Implement sandboxing for untrusted code",
        ],
        "cwe": "CWE-78",
    },
    "xss": {
        "priority": "high",
        "steps": [
            "Implement context-aware output encoding",
            "Use Content Security Policy (CSP) headers",
            "Enable XSS protection in browser settings",
            "Use modern framework auto-escaping (React, Angular, Vue)",
            "Sanitize HTML input with DOMPurify",
            "Implement HttpOnly and Secure cookies",
        ],
        "cwe": "CWE-79",
    },
    "ssrf": {
        "priority": "high",
        "steps": [
            "Implement allowlist for allowed domains",
            "Block private IP addresses (10.x, 172.16.x, 192.168.x)",
            "Disable unnecessary URL schemas (file://, gopher://, etc.)",
            "Use DNS resolution to verify requested hostname",
            "Implement request timeout and size limits",
            "Disable HTTP meta-redirects",
        ],
        "cwe": "CWE-918",
    },
    "idor": {
        "priority": "high",
        "steps": [
            "Implement proper authorization checks on every access",
            "Use indirect references instead of direct object IDs",
            "Validate user session and permissions for each request",
            "Apply principle of least privilege",
            "Log access attempts for auditing",
            "Implement rate limiting on sensitive endpoints",
        ],
        "cwe": "CWE-639",
    },
    "auth_bypass": {
        "priority": "critical",
        "steps": [
            "Implement multi-factor authentication (MFA)",
            "Enforce strong password policies",
            "Use secure session management with secure cookies",
            "Implement account lockout policies",
            "Use secure password reset flows with time-limited tokens",
            "Enable comprehensive audit logging",
        ],
        "cwe": "CWE-287",
    },
    "exposure": {
        "priority": "medium",
        "steps": [
            "Remove sensitive files from web root",
            "Block access to .git, .env, .htaccess via server config",
            "Implement proper file permissions (chmod 644)",
            "Use environment variables instead of config files",
            "Configure web server to deny file listing",
            "Remove version control metadata",
        ],
        "cwe": "CWE-552",
    },
    "weak_crypto": {
        "priority": "high",
        "steps": [
            "Use TLS 1.3 minimum",
            "Disable TLS 1.0 and 1.1",
            "Use strong cipher suites (AES-GCM, ChaCha20)",
            "Implement HSTS headers",
            "Use secure key management",
            "Rotate keys regularly",
        ],
        "cwe": "CWE-327",
    },
    "default_creds": {
        "priority": "critical",
        "steps": [
            "Change all default credentials immediately",
            "Implement password policy requiring changes on first login",
            "Use unique passwords per installation",
            "Implement credential management solution",
            "Regular credential audits",
            "Disable unused admin interfaces",
        ],
        "cwe": "CWE-255",
    },
}


class FindingPrioritizer:
    """Prioritize vulnerabilities based on risk."""

    def __init__(self):
        self.severity_scores = SEVERITY_SCORES

    def calculate_priority_score(
        self,
        finding: Dict,
        context: Optional[Dict] = None,
    ) -> Dict:
        """Calculate priority score for a finding."""
        severity = finding.get("severity", "info").lower()
        base_score = self.severity_scores.get(severity, 0)

        score = base_score
        factors = []

        if context:
            if context.get("has_public_exposure"):
                score += 2
                factors.append("public_exposure")

            if context.get("has_authentication"):
                score -= 1
                factors.append("requires_auth")

            if context.get("internet_facing"):
                score += 1
                factors.append("internet_facing")

            cvss = context.get("cvss_score")
            if cvss:
                score = max(score, cvss)

        priority = "low"
        if score >= 9:
            priority = "critical"
        elif score >= 7:
            priority = "high"
        elif score >= 4:
            priority = "medium"

        return {
            "score": min(score, 10),
            "priority": priority,
            "factors": factors,
            "severity": severity,
        }

    def prioritize_findings(
        self,
        findings: List[Dict],
        context: Optional[Dict] = None,
    ) -> List[Dict]:
        """Sort and prioritize findings."""
        prioritized = []

        for finding in findings:
            score_info = self.calculate_priority_score(finding, context)
            finding["priority_score"] = score_info["score"]
            finding["priority"] = score_info["priority"]
            finding["factors"] = score_info["factors"]

            category = finding.get("type", finding.get("category", ""))
            remediation = REMEDIATION_TEMPLATES.get(category.lower(), {})
            if remediation:
                finding["remediation"] = remediation.get("steps", [])
                finding["cwe"] = remediation.get("cwe")

            prioritized.append(finding)

        prioritized.sort(
            key=lambda x: (self.severity_scores.get(x.get("severity", "info").lower(), 0), x.get("priority_score", 0)),
            reverse=True,
        )

        return prioritized


class RemediationGuide:
    """Generate remediation guidance for findings."""

    def __init__(self):
        self.templates = REMEDIATION_TEMPLATES

    def generate_guide(self, finding: Dict) -> Dict:
        """Generate remediation guide for a finding."""
        finding_type = finding.get("type", "unknown")
        template = self.templates.get(finding_type.lower(), {})

        guide = {
            "type": finding_type,
            "severity": finding.get("severity", "unknown"),
            "priority": template.get("priority", "medium"),
            "steps": template.get("steps", []),
            "cwe": template.get("cwe"),
            "additional_context": "",
        }

        if not template:
            guide["steps"] = [
                "Review the finding in context",
                "Implement secure coding practices",
                "Test remediation thoroughly",
                "Document changes for audit",
            ]
            guide["additional_context"] = "General remediation - specific guidance unavailable"

        return guide

    def generate_summary(self, findings: List[Dict]) -> Dict:
        """Generate summary report for all findings."""
        by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }

        guides = []

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            by_severity[severity].append(finding)

            guide = self.generate_guide(finding)
            guide["finding"] = {
                "name": finding.get("name", ""),
                "url": finding.get("url", finding.get("matched_at", "")),
            }
            guides.append(guide)

        return {
            "total": len(findings),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "critical_issues": len(by_severity["critical"]) + len(by_severity["high"]),
            "guides": guides[:10],
            "generated_at": datetime.utcnow().isoformat(),
        }


class OWASPCategorizer:
    """Categorize findings according to OWASP Top 10."""

    CATEGORY_MAP = {
        "sqli": "A03:2021 – Injection",
        "cmdi": "A03:2021 – Injection",
        "xss": "A03:2021 – Injection",
        "ssrf": "A10:2021 – Server-Side Request Forgery",
        "idor": "A01:2021 – Broken Access Control",
        "auth_bypass": "A01:2021 – Broken Access Control",
        "exposure": "A02:2021 – Cryptographic Failures",
        "weak_crypto": "A02:2021 – Cryptographic Failures",
        "default_creds": "A02:2021 – Cryptographic Failures",
    }

    def categorize(self, finding: Dict) -> Dict:
        """Map finding to OWASP category."""
        finding_type = finding.get("type", finding.get("category", "")).lower()
        owasp = self.CATEGORY_MAP.get(finding_type, "A05:2021 – Security Misconfiguration")

        return {
            "type": finding_type,
            "owasp_category": owasp,
            "cwe": self._get_cwe(finding_type),
        }

    def _get_cwe(self, finding_type: str) -> str:
        """Get CWE ID for finding type."""
        cwe_map = {
            "sqli": "CWE-89",
            "cmdi": "CWE-78",
            "xss": "CWE-79",
            "ssrf": "CWE-918",
            "idor": "CWE-639",
            "auth_bypass": "CWE-287",
            "exposure": "CWE-552",
            "weak_crypto": "CWE-327",
            "default_creds": "CWE-255",
        }
        return cwe_map.get(finding_type, "CWE-000")


async def run_prioritization(
    target_id: str,
    findings: List[Dict],
    context: Optional[Dict] = None,
) -> dict:
    """Run prioritization on findings."""
    prioritizer = FindingPrioritizer()
    guide = RemediationGuide()
    categorizer = OWASPCategorizer()

    prioritized = prioritizer.prioritize_findings(findings, context)
    for f in prioritized:
        cat = categorizer.categorize(f)

    summary = guide.generate_summary(prioritized)

    return {
        "target_id": target_id,
        "total_findings": len(findings),
        "prioritized": prioritized,
        "summary": summary,
    }