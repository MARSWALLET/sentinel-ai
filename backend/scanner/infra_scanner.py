# ============================================
# SentinelAI - Infrastructure Scanner
# ============================================
"""
Infrastructure scanning using Checkov and Trivy config scan.
Scans Dockerfiles, Terraform, Kubernetes manifests, and CI/CD configurations.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

from scanner.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# Infrastructure file patterns
INFRA_FILES = {
    "dockerfile": ["Dockerfile", "dockerfile", "*.dockerfile"],
    "docker_compose": ["docker-compose.yml", "docker-compose.yaml"],
    "terraform": ["*.tf", "*.tfvars"],
    "kubernetes": ["*.yaml", "*.yml"],
    "github_actions": [".github/workflows/*.yml", ".github/workflows/*.yaml"],
    "ansible": ["*.ansible.yml", "playbook.yml"],
    "cloudformation": ["*.template", "*.cfn.yml"],
}


class InfraScanner(BaseScanner):
    """
    Infrastructure security scanner.
    Scans IaC files (Dockerfile, Terraform, K8s, CI/CD) for misconfigurations.
    """
    
    module_name = "infrastructure"
    module_description = "Infrastructure and IaC misconfiguration scanning"
    
    async def run(self) -> List[Dict[str, Any]]:
        """Run infrastructure scanning."""
        findings = []
        target_dir = self.config.get("file_path", self.target)
        
        if not os.path.isdir(target_dir):
            target_dir = os.path.dirname(target_dir) or "."
        
        # Determine which infrastructure files exist
        has_docker = self._has_files(target_dir, INFRA_FILES["dockerfile"])
        has_docker_compose = self._has_files(target_dir, INFRA_FILES["docker_compose"])
        has_terraform = self._has_files(target_dir, INFRA_FILES["terraform"])
        has_kubernetes = self._has_files(target_dir, INFRA_FILES["kubernetes"])
        has_github_actions = self._has_files(target_dir, INFRA_FILES["github_actions"])
        
        logger.info(f"Infra scan - Docker: {has_docker}, Compose: {has_docker_compose}, "
                    f"TF: {has_terraform}, K8s: {has_kubernetes}, GHA: {has_github_actions}")
        
        # Run Checkov (covers all IaC)
        if any([has_docker, has_docker_compose, has_terraform, has_kubernetes, has_github_actions]):
            checkov_findings = await self._run_checkov(target_dir)
            findings.extend(checkov_findings)
        
        # Run Trivy config scan for additional coverage
        trivy_findings = await self._run_trivy_config(target_dir)
        findings.extend(trivy_findings)
        
        logger.info(f"Infrastructure scan complete: {len(findings)} findings")
        return findings
    
    def _has_files(self, target_dir: str, patterns: List[str]) -> bool:
        """Check if any files matching patterns exist."""
        import fnmatch
        
        for root, dirs, files in os.walk(target_dir):
            # Skip hidden and common non-source directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "vendor")]
            
            for pattern in patterns:
                if "*" in pattern:
                    if any(fnmatch.fnmatch(f, pattern) for f in files):
                        return True
                else:
                    if pattern in files:
                        return True
        
        return False
    
    async def _run_checkov(self, target_dir: str) -> List[Dict[str, Any]]:
        """Run Checkov IaC security scanner."""
        findings = []
        
        try:
            rc, stdout, stderr = self.run_tool("checkov", [
                "-d", target_dir,
                "--framework", "all",
                "--output", "json",
                "--output-file-path", self.workspace_dir,
                "--compact",
                "--quiet",
            ], timeout=600)
            
            self.save_raw_output(stderr or "", "checkov")
            
            # Checkov creates output files per framework
            output_files = [
                f"{self.workspace_dir}/results_json.json",
            ]
            
            for output_file in output_files:
                try:
                    with open(output_file, "r") as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            for item in data:
                                findings.extend(self._parse_checkov_results(item))
                        else:
                            findings.extend(self._parse_checkov_results(data))
                except (FileNotFoundError, json.JSONDecodeError):
                    continue
            
            logger.info(f"Checkov: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Checkov failed: {e}")
        
        return findings
    
    def _parse_checkov_results(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse Checkov JSON results."""
        findings = []
        
        # Checkov can return results in different structures
        results = data.get("results", {}).get("failed_checks", [])
        
        for check in results:
            severity = check.get("severity", "medium") or "medium"
            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "informational": "info",
            }
            
            file_path = check.get("file_path", "")
            resource = check.get("resource", "")
            
            findings.append(self.add_finding(
                title=f"Checkov: {check.get('check_name', 'IaC Misconfiguration')}",
                description=check.get("check_name", ""),
                severity=severity_map.get(severity.lower(), "medium"),
                cwe_id=None,
                file_path=file_path,
                evidence={
                    "check_id": check.get("check_id", ""),
                    "resource": resource,
                    "guideline": check.get("guideline", ""),
                    "file_line_range": check.get("file_line_range", []),
                },
                remediation=check.get("description", f"Fix Checkov check {check.get('check_id', '')}"),
                tool_source="checkov",
            ))
        
        return findings
    
    async def _run_trivy_config(self, target_dir: str) -> List[Dict[str, Any]]:
        """Run Trivy config scan for misconfigurations."""
        findings = []
        
        try:
            rc, stdout, stderr = self.run_tool("trivy", [
                "config",
                "--scanners", "misconfig",
                "--format", "json",
                "--output", f"{self.workspace_dir}/trivy_config_output.json",
                target_dir,
            ], timeout=600)
            
            self.save_raw_output(stderr or "", "trivy_config")
            
            # Parse JSON output
            output_file = f"{self.workspace_dir}/trivy_config_output.json"
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    findings.extend(self._parse_trivy_config_output(data))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            
            logger.info(f"Trivy Config: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Trivy config scan failed: {e}")
        
        return findings
    
    def _parse_trivy_config_output(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse Trivy config scan JSON output."""
        findings = []
        
        results = data.get("Results", [])
        for result in results:
            target = result.get("Target", "")
            misconfigurations = result.get("Misconfigurations", [])
            
            for misconfig in misconfigurations:
                severity = misconfig.get("Severity", "UNKNOWN").lower()
                severity_map = {
                    "critical": "critical",
                    "high": "high",
                    "medium": "medium",
                    "low": "low",
                    "unknown": "info",
                }
                
                findings.append(self.add_finding(
                    title=f"Trivy: {misconfig.get('Title', 'IaC Misconfiguration')}",
                    description=misconfig.get("Description", misconfig.get("Message", "")),
                    severity=severity_map.get(severity, "medium"),
                    cwe_id=misconfig.get("CweIDs", [None])[0] if misconfig.get("CweIDs") else None,
                    file_path=target,
                    evidence={
                        "id": misconfig.get("ID", ""),
                        "avdid": misconfig.get("AVDID", ""),
                        "type": misconfig.get("Type", ""),
                        "resolution": misconfig.get("Resolution", ""),
                        "references": misconfig.get("References", []),
                        "cause_metadata": misconfig.get("CauseMetadata", {}),
                    },
                    remediation=misconfig.get("Resolution", "Fix the misconfiguration as described in the finding details."),
                    tool_source="trivy_config",
                ))
        
        return findings