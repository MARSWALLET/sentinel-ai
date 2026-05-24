# ============================================
# SentinelAI - Dependency Scanner
# ============================================
"""
Software Composition Analysis (SCA) using Trivy, Grype, and OWASP Dependency-Check.
Identifies vulnerable dependencies with known CVEs and outdated packages.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from scanner.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# Package manifest files by language
MANIFEST_FILES = {
    "python": ["requirements.txt", "Pipfile", "pyproject.toml", "setup.py"],
    "javascript": ["package.json", "package-lock.json", "yarn.lock"],
    "ruby": ["Gemfile", "Gemfile.lock"],
    "java": ["pom.xml", "build.gradle"],
    "go": ["go.mod", "go.sum"],
    "php": ["composer.json", "composer.lock"],
    "rust": ["Cargo.toml", "Cargo.lock"],
    "dotnet": ["*.csproj", "packages.config"],
}


class DependencyScanner(BaseScanner):
    """
    Dependency vulnerability scanner.
    Scans package manifests for known CVEs using Trivy, Grype, and OWASP Dependency-Check.
    """
    
    module_name = "dependencies"
    module_description = "Dependency vulnerability scanning (SCA) with CVE detection"
    
    async def run(self) -> List[Dict[str, Any]]:
        """Run dependency scanning."""
        findings = []
        target_dir = self.config.get("file_path", self.target)
        
        if not os.path.isdir(target_dir):
            target_dir = os.path.dirname(target_dir) or "."
        
        # Run Trivy filesystem scan
        trivy_findings = await self._run_trivy(target_dir)
        findings.extend(trivy_findings)
        
        # Run Grype
        grype_findings = await self._run_grype(target_dir)
        findings.extend(grype_findings)
        
        # Run OWASP Dependency-Check for Java projects
        java_manifests = ["pom.xml", "build.gradle"]
        if any(os.path.exists(os.path.join(target_dir, f)) for f in java_manifests):
            owasp_findings = await self._run_owasp_dep_check(target_dir)
            findings.extend(owasp_findings)
        
        # Deduplicate by package + CVE
        seen = set()
        deduplicated = []
        for f in findings:
            key = f"{f.get('evidence', {}).get('package', '')}:{f.get('evidence', {}).get('cve_id', '')}"
            if key not in seen:
                seen.add(key)
                deduplicated.append(f)
        
        logger.info(f"Dependency scan complete: {len(deduplicated)} unique findings")
        return deduplicated
    
    async def _run_trivy(self, target_dir: str) -> List[Dict[str, Any]]:
        """Run Trivy filesystem vulnerability scan."""
        findings = []
        
        try:
            rc, stdout, stderr = self.run_tool("trivy", [
                "fs",
                "--scanners", "vuln",
                "--format", "json",
                "--output", f"{self.workspace_dir}/trivy_output.json",
                "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
                target_dir,
            ], timeout=600)
            
            self.save_raw_output(stderr or "", "trivy")
            
            # Parse JSON output
            output_file = f"{self.workspace_dir}/trivy_output.json"
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    findings.extend(self._parse_trivy_output(data, target_dir))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            
            logger.info(f"Trivy: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Trivy failed: {e}")
        
        return findings
    
    def _parse_trivy_output(self, data: Dict, target_dir: str) -> List[Dict[str, Any]]:
        """Parse Trivy JSON output."""
        findings = []
        
        results = data.get("Results", [])
        for result in results:
            target = result.get("Target", "")
            vulnerabilities = result.get("Vulnerabilities", [])
            
            for vuln in vulnerabilities:
                severity = vuln.get("Severity", "UNKNOWN").lower()
                severity_map = {
                    "critical": "critical",
                    "high": "high",
                    "medium": "medium",
                    "low": "low",
                    "unknown": "info",
                }
                
                # Build remediation
                fixed_version = vuln.get("FixedVersion", "")
                remediation = f"Upgrade {vuln.get('PkgName', '')} from {vuln.get('InstalledVersion', '')} to {fixed_version}" if fixed_version else "No fixed version available. Consider removing or replacing this dependency."
                
                findings.append(self.add_finding(
                    title=f"Vulnerable Dependency: {vuln.get('PkgName', '')} ({vuln.get('VulnerabilityID', '')})",
                    description=vuln.get("Description", f"{vuln.get('PkgName', '')} {vuln.get('InstalledVersion', '')} is affected by {vuln.get('VulnerabilityID', '')}: {vuln.get('Title', '')}"),
                    severity=severity_map.get(severity, "medium"),
                    cwe_id=vuln.get("CweIDs", [None])[0] if vuln.get("CweIDs") else None,
                    cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score") or vuln.get("CVSS", {}).get("ghsa", {}).get("V3Score"),
                    file_path=target,
                    evidence={
                        "package": vuln.get("PkgName", ""),
                        "installed_version": vuln.get("InstalledVersion", ""),
                        "fixed_version": fixed_version,
                        "cve_id": vuln.get("VulnerabilityID", ""),
                        "severity_source": vuln.get("SeveritySource", ""),
                        "primary_url": vuln.get("PrimaryURL", ""),
                        "references": vuln.get("References", []),
                    },
                    remediation=remediation,
                    tool_source="trivy",
                ))
        
        return findings
    
    async def _run_grype(self, target_dir: str) -> List[Dict[str, Any]]:
        """Run Grype vulnerability scan."""
        findings = []
        
        try:
            rc, stdout, stderr = self.run_tool("grype", [
                target_dir,
                "-o", "json",
                "--file", f"{self.workspace_dir}/grype_output.json",
            ], timeout=600)
            
            self.save_raw_output(stderr or "", "grype")
            
            # Parse JSON output
            output_file = f"{self.workspace_dir}/grype_output.json"
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    findings.extend(self._parse_grype_output(data))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            
            logger.info(f"Grype: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Grype failed: {e}")
        
        return findings
    
    def _parse_grype_output(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse Grype JSON output."""
        findings = []
        
        matches = data.get("matches", [])
        for match in matches:
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            
            severity = vuln.get("severity", "Unknown").lower()
            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "negligible": "low",
                "unknown": "info",
            }
            
            # Get CVSS
            cvss = vuln.get("cvss", [])
            cvss_score = None
            if cvss:
                cvss_score = cvss[0].get("metrics", {}).get("baseScore")
            
            # Get fixed versions
            fix = vuln.get("fix", {})
            fixed_versions = fix.get("versions", [])
            fixed_in = fixed_versions[0] if fixed_versions else ""
            
            remediation = f"Upgrade {artifact.get('name', '')} from {artifact.get('version', '')} to {fixed_in}" if fixed_in else "No fixed version available. Consider removing or replacing this dependency."
            
            findings.append(self.add_finding(
                title=f"Vulnerable Dependency: {artifact.get('name', '')} ({vuln.get('id', '')})",
                description=vuln.get("description", f"{artifact.get('name', '')} {artifact.get('version', '')} is affected by {vuln.get('id', '')}"),
                severity=severity_map.get(severity, "medium"),
                cwe_id=None,
                cvss_score=cvss_score,
                file_path=artifact.get("locations", [{}])[0].get("path", ""),
                evidence={
                    "package": artifact.get("name", ""),
                    "installed_version": artifact.get("version", ""),
                    "fixed_version": fixed_in,
                    "cve_id": vuln.get("id", ""),
                    "language": artifact.get("language", ""),
                    "purl": artifact.get("purl", ""),
                    "related_vulns": [v.get("id") for v in match.get("relatedVulnerabilities", [])],
                },
                remediation=remediation,
                tool_source="grype",
            ))
        
        return findings
    
    async def _run_owasp_dep_check(self, target_dir: str) -> List[Dict[str, Any]]:
        """Run OWASP Dependency-Check for Java projects."""
        findings = []
        
        try:
            report_dir = f"{self.workspace_dir}/dependency-check-report"
            
            rc, stdout, stderr = self.run_tool("dependency_check", [
                "--project", "SentinelAI Scan",
                "--scan", target_dir,
                "--format", "JSON",
                "--out", report_dir,
                "--enableExperimental",
                "--noupdate",
            ], timeout=900)
            
            self.save_raw_output(stderr or "", "owasp_dependency_check")
            
            # Parse JSON output
            report_file = f"{report_dir}/dependency-check-report.json"
            try:
                with open(report_file, "r") as f:
                    data = json.load(f)
                    findings.extend(self._parse_owasp_output(data))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            
            logger.info(f"OWASP Dependency-Check: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"OWASP Dependency-Check failed: {e}")
        
        return findings
    
    def _parse_owasp_output(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse OWASP Dependency-Check JSON output."""
        findings = []
        
        dependencies = data.get("dependencies", [])
        for dep in dependencies:
            vulnerabilities = dep.get("vulnerabilities", [])
            
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "Medium").lower()
                severity_map = {
                    "critical": "critical",
                    "high": "high",
                    "medium": "medium",
                    "low": "low",
                }
                
                cvss = vuln.get("cvssv3", {}).get("baseScore") or vuln.get("cvssv2", {}).get("score")
                
                findings.append(self.add_finding(
                    title=f"Vulnerable Dependency: {dep.get('fileName', '')} ({vuln.get('name', '')})",
                    description=vuln.get("description", f"Dependency {dep.get('fileName', '')} has a known vulnerability"),
                    severity=severity_map.get(severity, "medium"),
                    cwe_id=f"CWE-{vuln.get('cwes', [{}])[0].get('cweid', '')}" if vuln.get("cwes") else None,
                    cvss_score=float(cvss) if cvss else None,
                    file_path=dep.get("filePath", ""),
                    evidence={
                        "package": dep.get("fileName", ""),
                        "cve_id": vuln.get("name", ""),
                        "references": vuln.get("references", []),
                        "vulnerable_software": vuln.get("vulnerableSoftware", []),
                    },
                    remediation=f"Upgrade to a non-vulnerable version. See: {vuln.get('references', [{}])[0].get('url', '')}" if vuln.get("references") else "Upgrade to the latest version.",
                    tool_source="owasp_dependency_check",
                ))
        
        return findings