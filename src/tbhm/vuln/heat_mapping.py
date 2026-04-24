"""
Vulnerability heat mapping and scoring module.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

CVSS_WEIGHTS = {
    "critical": 10.0,
    "high": 8.9,
    "medium": 6.9,
    "low": 3.9,
    "info": 0.0,
}

OWASP_WEIGHTS = {
    "a1": 8.5,
    "a2": 8.5,
    "a3": 8.5,
    "a4": 6.0,
    "a5": 6.0,
    "a6": 5.0,
    "a7": 5.0,
    "a8": 6.5,
    "a9": 6.5,
    "a10": 5.0,
}


class VulnerabilityScorer:
    """Calculate vulnerability scores."""

    def __init__(self):
        self.cvss_weights = CVSS_WEIGHTS
        self.owasp_weights = OWASP_WEIGHTS

    def calculate_risk_score(self, vulnerabilities: List[Dict]) -> float:
        """Calculate overall risk score."""
        total_score = 0.0

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            weight = self.cvss_weights.get(severity, 0.0)
            total_score += weight

        normalized = min(total_score / 10.0, 10.0)
        return round(normalized, 2)

    def categorize_findings(self, vulnerabilities: List[Dict]) -> Dict:
        """Categorize findings by type and severity."""
        categories = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            categories[severity].append(vuln)

        return categories


class HeatMapper:
    """Generate vulnerability heat maps."""

    def __init__(self):
        self.scorer = VulnerabilityScorer()

    def generate_heatmap(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate heat map data."""
        heatmap = {
            "total_vulns": len(vulnerabilities),
            "risk_score": self.scorer.calculate_risk_score(vulnerabilities),
            "by_severity": {},
            "by_category": {},
            "high_risk_areas": [],
        }

        by_severity = {}
        by_category = {}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            by_severity[severity] = by_severity.get(severity, 0) + 1

            category = vuln.get("category", "unknown")
            by_category[category] = by_category.get(category, 0) + 1

            if severity in ["critical", "high"]:
                heatmap["high_risk_areas"].append({
                    "name": vuln.get("name", ""),
                    "severity": severity,
                    "url": vuln.get("matched_at", ""),
                })

        heatmap["by_severity"] = by_severity
        heatmap["by_category"] = by_category

        return heatmap

    def identify_entry_points(self, subdomains: List[Dict], vuln_data: Dict) -> List[Dict]:
        """Identify high-risk entry points."""
        entry_points = []

        for subdomain in subdomains:
            host = subdomain.get("host", "")
            services = subdomain.get("services", [])
            vulnerabilities = subdomain.get("vulnerabilities", [])

            risk_score = 0
            if services:
                for service in services:
                    port = service.get("port", 0)
                    if port in [22, 3389, 445, 3306, 5432, 6379, 27017]:
                        risk_score += 3
                    elif port in [80, 443, 8080]:
                        risk_score += 1

            for vuln in vulnerabilities:
                severity = vuln.get("severity", "info").lower()
                if severity == "critical":
                    risk_score += 10
                elif severity == "high":
                    risk_score += 7

            if risk_score > 5:
                entry_points.append({
                    "host": host,
                    "risk_score": risk_score,
                    "service_count": len(services),
                    "vuln_count": len(vulnerabilities),
                })

        entry_points.sort(key=lambda x: x["risk_score"], reverse=True)
        return entry_points[:10]


class ResponseAnalyzer:
    """Analyze HTTP responses for vulnerabilities."""

    def __init__(self):
        self.sensitive_patterns = [
            "password", "token", "secret", "api_key", "apikey",
            "authorization", "bearer", "jwt", "session_id",
            "user_id", "email", "phone", "address",
            "ssn", "credit_card", "cvv",
        ]

    def analyze_response(self, url: str, status_code: int, headers: Dict, body: str) -> List[Dict]:
        """Analyze HTTP response for sensitive data."""
        findings = []

        body_lower = body.lower()
        for pattern in self.sensitive_patterns:
            if pattern in body_lower:
                findings.append({
                    "type": "sensitive_data",
                    "pattern": pattern,
                    "url": url,
                    "status": status_code,
                })

        if status_code == 200 and "application/json" in headers.get("content-type", ""):
            try:
                import json
                data = json.loads(body)
                if isinstance(data, dict):
                    for key, value in data.items():
                        if any(s in key.lower() for s in ["email", "phone", "address"]):
                            findings.append({
                                "type": "pii_exposure",
                                "field": key,
                                "url": url,
                            })
            except Exception:
                pass

        if "error" in body_lower or "exception" in body_lower:
            findings.append({
                "type": "error_disclosure",
                "url": url,
                "status": status_code,
            })

        return findings


async def run_heat_mapping(
    target_id: str,
    vuln_results: Dict,
    subdomain_data: List[Dict],
) -> dict:
    """Run heat mapping analysis."""
    heatmapper = HeatMapper()

    vulnerabilities = vuln_results.get("vulnerabilities", [])

    heatmap = heatmapper.generate_heatmap(vulnerabilities)

    entry_points = heatmapper.identify_entry_points(subdomain_data, vuln_results)

    return {
        "target_id": target_id,
        "heatmap": heatmap,
        "risk_score": heatmap["risk_score"],
        "total_vulns": heatmap["total_vulns"],
        "entry_points": entry_points,
    }