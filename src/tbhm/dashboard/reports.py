"""
Report generation module.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate assessment reports."""

    def __init__(self, template_dir: str = "./templates"):
        self.template_dir = Path(template_dir)

    def generate_target_overview(
        self,
        target_id: str,
        target_name: str,
        domain: str,
        scan_results: Dict,
    ) -> Dict:
        """
        Generate target overview report.

        Args:
            target_id: Target UUID
            target_name: Target name
            domain: Target domain
            scan_results: Combined scan results
        """
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "target": {
                "id": target_id,
                "name": target_name,
                "domain": domain,
            },
            "summary": self._generate_summary(scan_results),
            "findings": self._categorize_findings(scan_results),
            "recommendations": self._generate_recommendations(scan_results),
        }

        return report

    def _generate_summary(self, scan_results: Dict) -> Dict:
        """Generate executive summary."""
        summary = {
            "total_subdomains": 0,
            "total_vulnerabilities": 0,
            "critical_issues": 0,
            "high_risk_areas": [],
            "risk_score": 0.0,
        }

        if "subdomains" in scan_results:
            summary["total_subdomains"] = scan_results["subdomains"].get("total_found", 0)

        if "vulnerabilities" in scan_results:
            vulns = scan_results["vulnerabilities"]
            summary["total_vulnerabilities"] = vulns.get("total", 0)
            by_severity = vulns.get("by_severity", {})
            summary["critical_issues"] = by_severity.get("critical", 0) + by_severity.get("high", 0)

        if "heat_mapping" in scan_results:
            summary["risk_score"] = scan_results["heat_mapping"].get("risk_score", 0)

        return summary

    def _categorize_findings(self, scan_results: Dict) -> Dict:
        """Categorize all findings."""
        findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }

        if "vulnerabilities" in scan_results:
            for vuln in scan_results["vulnerabilities"].get("vulnerabilities", []):
                severity = vuln.get("severity", "info").lower()
                findings[severity].append(vuln)

        return findings

    def _generate_recommendations(self, scan_results: Dict) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        critical = self._categorize_findings(scan_results).get("critical", [])
        if critical:
            recommendations.append(f"Address {len(critical)} critical vulnerabilities immediately")

        high = self._categorize_findings(scan_results).get("high", [])
        if high:
            recommendations.append(f"Prioritize remediation of {len(high)} high-severity issues")

        if scan_results.get("heat_mapping", {}).get("entry_points"):
            recommendations.append("Review high-risk entry points identified in attack surface")

        if not recommendations:
            recommendations.append("Continue regular security assessments")

        return recommendations

    def export_json(self, report: Dict, output_path: str) -> bool:
        """Export report as JSON."""
        try:
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error exporting JSON: {e}")
            return False

    def export_html(self, report: Dict, output_path: str) -> bool:
        """Export report as HTML."""
        html_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>TBHM Report - {report.get('target', {}).get('name', 'Target')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #333; color: white; padding: 20px; }}
        .summary {{ background: #f0f0f0; padding: 15px; margin: 20px 0; }}
        .finding {{ padding: 10px; margin: 10px 0; border-left: 4px solid; }}
        .critical {{ border-color: #d32f2f; background: #ffebee; }}
        .high {{ border-color: #f57c00; background: #fff3e0; }}
        .medium {{ border-color: #fbc02d; background: #fffde7; }}
        .low {{ border-color: #388e3c; background: #e8f5e9; }}
        .info {{ border-color: #1976d2; background: #e3f2fd; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>TBHM Security Report</h1>
        <p>Target: {report.get('target', {}).get('name', 'N/A')}</p>
        <p>Domain: {report.get('target', {}).get('domain', 'N/A')}</p>
        <p>Generated: {report.get('generated_at', 'N/A')}</p>
    </div>
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>Risk Score: {report.get('summary', {}).get('risk_score', 0)}/10</p>
        <p>Total Subdomains: {report.get('summary', {}).get('total_subdomains', 0)}</p>
        <p>Total Vulnerabilities: {report.get('summary', {}).get('total_vulnerabilities', 0)}</p>
    </div>
    <h2>Findings</h2>
    {{findings_html}}
</body>
</html>
"""

        findings_html = ""
        for severity, findings in report.get("findings", {}).items():
            if findings:
                findings_html += f'<h3>{severity.upper()} ({len(findings)})</h3>'
                for finding in findings:
                    findings_html += f'<div class="finding {severity}"><p>{finding.get("name", "")}</p></div>'

        html = html_template.replace("{{findings_html}}", findings_html)

        try:
            with open(output_path, "w") as f:
                f.write(html)
            return True
        except Exception as e:
            logger.error(f"Error exporting HTML: {e}")
            return False


class ThreatModelAnalyzer:
    """Analyze and generate threat models."""

    def __init__(self):
        self.attack_chains = []

    def generate_threat_model(
        self,
        target_id: str,
        assets: List[Dict],
        vulnerabilities: List[Dict],
    ) -> Dict:
        """Generate threat model."""
        model = {
            "target_id": target_id,
            "assets": assets,
            "threats": [],
            "attack_paths": [],
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "").lower()
            if severity in ["critical", "high"]:
                model["threats"].append({
                    "id": vuln.get("id", ""),
                    "title": vuln.get("name", ""),
                    "severity": severity,
                    "likelihood": "high" if severity == "critical" else "medium",
                    "impact": vuln.get("description", "")[:100],
                })

        model["attack_paths"] = self._identify_attack_paths(assets, vulnerabilities)

        return model

    def _identify_attack_paths(self, assets: List[Dict], vulns: List[Dict]) -> List[Dict]:
        """Identify potential attack paths."""
        paths = []

        for vuln in vulns:
            severity = vuln.get("severity", "").lower()
            if severity in ["critical", "high"]:
                paths.append({
                    "from": "external",
                    "to": vuln.get("matched_at", "unknown"),
                    "vulnerability": vuln.get("name", ""),
                    "severity": severity,
                })

        return paths[:10]


async def generate_report(
    target_id: str,
    target_name: str,
    domain: str,
    scan_results: Dict,
    output_format: str = "json",
) -> dict:
    """Generate full assessment report."""
    generator = ReportGenerator()

    report = generator.generate_target_overview(
        target_id, target_name, domain, scan_results
    )

    return report