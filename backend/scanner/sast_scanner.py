# ============================================
# SentinelAI - SAST Scanner
# ============================================
"""
Static Application Security Testing using Semgrep, Bandit, ESLint, Brakeman, and more.
Supports multiple languages: Python, JavaScript, Ruby, Java, PHP, Go.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from scanner.base_scanner import BaseScanner
from utils.file_utils import detect_languages

logger = logging.getLogger(__name__)

# Language to scanner mapping
LANGUAGE_SCANNERS = {
    "python": ["semgrep", "bandit"],
    "javascript": ["semgrep", "eslint"],
    "typescript": ["semgrep", "eslint"],
    "ruby": ["semgrep", "brakeman"],
    "java": ["semgrep", "spotbugs"],
    "php": ["semgrep", "phpstan"],
    "go": ["semgrep", "gosec"],
    "terraform": ["checkov"],
    "dockerfile": ["checkov"],
    "yaml": ["checkov"],
}

# Severity mapping from tools to our standard
SEVERITY_MAP = {
    "critical": "critical",
    "error": "high",
    "warning": "medium",
    "warn": "medium",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
}


class SASTScanner(BaseScanner):
    """
    Static Application Security Testing scanner.
    Auto-detects languages and runs appropriate SAST tools.
    """
    
    module_name = "sast"
    module_description = "Static Application Security Testing (SAST) for multiple languages"
    
    async def run(self) -> List[Dict[str, Any]]:
        """Run SAST scanning."""
        findings = []
        
        # Get target directory
        target_dir = self.config.get("file_path", self.target)
        if not os.path.isdir(target_dir):
            # Single file
            target_dir = os.path.dirname(target_dir) or "."
        
        # Detect languages
        languages = detect_languages(target_dir)
        logger.info(f"Detected languages: {languages}")
        
        # Run Semgrep (universal, runs on all)
        semgrep_findings = await self._run_semgrep(target_dir)
        findings.extend(semgrep_findings)
        
        # Run language-specific scanners
        for lang in languages:
            scanners = LANGUAGE_SCANNERS.get(lang, [])
            for scanner_name in scanners:
                if scanner_name == "semgrep":
                    continue  # Already ran
                
                try:
                    if scanner_name == "bandit" and lang == "python":
                        bandit_findings = await self._run_bandit(target_dir)
                        findings.extend(bandit_findings)
                    elif scanner_name == "eslint" and lang in ("javascript", "typescript"):
                        eslint_findings = await self._run_eslint(target_dir)
                        findings.extend(eslint_findings)
                    elif scanner_name == "brakeman" and lang == "ruby":
                        brakeman_findings = await self._run_brakeman(target_dir)
                        findings.extend(brakeman_findings)
                    elif scanner_name == "gosec" and lang == "go":
                        gosec_findings = await self._run_gosec(target_dir)
                        findings.extend(gosec_findings)
                except Exception as e:
                    logger.warning(f"{scanner_name} failed: {e}")
        
        # Deduplicate findings by file + line + rule
        seen = set()
        deduplicated = []
        for f in findings:
            key = f"{f.get('file_path', '')}:{f.get('line_number', 0)}:{f.get('title', '')}"
            if key not in seen:
                seen.add(key)
                deduplicated.append(f)
        
        logger.info(f"SAST complete: {len(deduplicated)} unique findings (from {len(findings)} raw)")
        return deduplicated
    
    async def _run_semgrep(self, target_dir: str) -> List[Dict[str, Any]]:
        """Run Semgrep security audit."""
        findings = []
        
        try:
            rc, stdout, stderr = self.run_tool("semgrep", [
                "--config=auto",
                "--config=p/security-audit",
                "--config=p/owasp-top-ten",
                "--config=p/cwe-top-25",
                "--json",
                "--output", f"{self.workspace_dir}/semgrep_output.json",
                "--quiet",
                target_dir,
            ], timeout=600)
            
            self.save_raw_output(stderr or "", "semgrep")
            
            # Parse JSON output
            output_file = f"{self.workspace_dir}/semgrep_output.json"
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    findings.extend(self._parse_semgrep_output(data))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            
            logger.info(f"Semgrep: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Semgrep failed: {e}")
        
        return findings
    
    def _parse_semgrep_output(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse Semgrep JSON output."""
        findings = []
        
        results = data.get("results", [])
        for result in results:
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            
            # Map severity
            severity = SEVERITY_MAP.get(extra.get("severity", "warning").lower(), "medium")
            
            # Get CWE
            cwe = None
            cwe_list = metadata.get("cwe", [])
            if cwe_list:
                cwe_match = re.search(r'CWE-\d+', str(cwe_list[0]))
                if cwe_match:
                    cwe = cwe_match.group()
            
            # Get OWASP
            owasp = metadata.get("owasp", [])
            
            findings.append(self.add_finding(
                title=f"Semgrep: {extra.get('message', result.get('check_id', 'Unknown'))[:100]}",
                description=extra.get("message", ""),
                severity=severity,
                cwe_id=cwe,
                file_path=result.get("path", ""),
                line_number=result.get("start", {}).get("line", 0),
                code_snippet=extra.get("lines", ""),
                evidence={
                    "rule_id": result.get("check_id", ""),
                    "owasp": owasp,
                    "references": metadata.get("references", []),
                    "fix": extra.get("fix", ""),
                },
                tool_source="semgrep",
            ))
        
        return findings
    
    async def _run_bandit(self, target_dir: str) -> List[Dict[str, Any]]:
        """Run Bandit Python security scanner."""
        findings = []
        
        try:
            rc, stdout, stderr = self.run_tool("bandit", [
                "-r", target_dir,
                "-f", "json",
                "-o", f"{self.workspace_dir}/bandit_output.json",
                "--skip", "B101",  # Skip assert warnings
            ], timeout=300)
            
            # Parse JSON output
            output_file = f"{self.workspace_dir}/bandit_output.json"
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    findings.extend(self._parse_bandit_output(data))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            
            logger.info(f"Bandit: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Bandit failed: {e}")
        
        return findings
    
    def _parse_bandit_output(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse Bandit JSON output."""
        findings = []
        
        results = data.get("results", [])
        for result in results:
            severity = SEVERITY_MAP.get(result.get("issue_severity", "medium").lower(), "medium")
            
            findings.append(self.add_finding(
                title=f"Bandit: {result.get('issue_text', 'Python Security Issue')}",
                description=result.get("issue_text", ""),
                severity=severity,
                cwe_id=f"CWE-{result.get('issue_cwe', {}).get('id', '')}" if result.get("issue_cwe") else None,
                file_path=result.get("filename", ""),
                line_number=result.get("line_number", 0),
                code_snippet=result.get("code", ""),
                evidence={
                    "test_id": result.get("test_id", ""),
                    "test_name": result.get("test_name", ""),
                    "more_info": result.get("more_info", ""),
                },
                tool_source="bandit",
            ))
        
        return findings
    
    async def _run_eslint(self, target_dir: str) -> List[Dict[str, Any]]:
        """Run ESLint with security plugin."""
        findings = []
        
        try:
            # Create ESLint config
            eslint_config = {
                "plugins": ["security"],
                "extends": ["plugin:security/recommended"],
                "parserOptions": {"ecmaVersion": 2020, "sourceType": "module"},
            }
            
            config_path = f"{self.workspace_dir}/eslint_config.json"
            with open(config_path, "w") as f:
                json.dump(eslint_config, f)
            
            rc, stdout, stderr = self.run_tool("eslint", [
                "-c", config_path,
                "-f", "json",
                "-o", f"{self.workspace_dir}/eslint_output.json",
                "--ext", ".js,.jsx,.ts,.tsx",
                target_dir,
            ], timeout=300)
            
            # Parse JSON output
            output_file = f"{self.workspace_dir}/eslint_output.json"
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    findings.extend(self._parse_eslint_output(data))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            
            logger.info(f"ESLint: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"ESLint failed: {e}")
        
        return findings
    
    def _parse_eslint_output(self, data: List) -> List[Dict[str, Any]]:
        """Parse ESLint JSON output."""
        findings = []
        
        for file_result in data:
            file_path = file_result.get("filePath", "")
            messages = file_result.get("messages", [])
            
            for msg in messages:
                if not msg.get("ruleId", "").startswith("security/"):
                    continue
                
                severity_map = {1: "low", 2: "medium"}
                severity = severity_map.get(msg.get("severity", 2), "medium")
                
                findings.append(self.add_finding(
                    title=f"ESLint Security: {msg.get('message', '')[:80]}",
                    description=msg.get("message", ""),
                    severity=severity,
                    cwe_id=None,  # ESLint security doesn't provide CWE
                    file_path=file_path,
                    line_number=msg.get("line", 0),
                    code_snippet=msg.get("source", ""),
                    evidence={"rule_id": msg.get("ruleId", "")},
                    tool_source="eslint",
                ))
        
        return findings
    
    async def _run_brakeman(self, target_dir: str) -> List[Dict[str, Any]]:
        """Run Brakeman Ruby security scanner."""
        findings = []
        
        try:
            rc, stdout, stderr = self.run_tool("brakeman", [
                "-q",
                "-w2",
                "-f", "json",
                "-o", f"{self.workspace_dir}/brakeman_output.json",
                target_dir,
            ], timeout=300)
            
            # Parse JSON output
            output_file = f"{self.workspace_dir}/brakeman_output.json"
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    findings.extend(self._parse_brakeman_output(data))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            
            logger.info(f"Brakeman: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Brakeman failed: {e}")
        
        return findings
    
    def _parse_brakeman_output(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse Brakeman JSON output."""
        findings = []
        
        warnings = data.get("warnings", [])
        for warning in warnings:
            confidence_map = {"High": "high", "Medium": "medium", "Weak": "low"}
            severity = confidence_map.get(warning.get("confidence", ""), "medium")
            
            findings.append(self.add_finding(
                title=f"Brakeman: {warning.get('warning_type', 'Ruby Security Issue')}",
                description=warning.get("message", ""),
                severity=severity,
                cwe_id=warning.get("cwe_id"),
                file_path=warning.get("file", ""),
                line_number=warning.get("line", 0),
                code_snippet=warning.get("code", ""),
                evidence={
                    "check_name": warning.get("check_name", ""),
                    "user_input": warning.get("user_input", ""),
                    "check_info": warning.get("link", ""),
                },
                tool_source="brakeman",
            ))
        
        return findings
    
    async def _run_gosec(self, target_dir: str) -> List[Dict[str, Any]]:
        """Run Gosec Go security scanner."""
        findings = []
        
        try:
            rc, stdout, stderr = self.run_tool("gosec", [
                "-fmt", "json",
                "-out", f"{self.workspace_dir}/gosec_output.json",
                "-no-fail",
                "./...",
            ], timeout=300, cwd=target_dir)
            
            # Parse JSON output
            output_file = f"{self.workspace_dir}/gosec_output.json"
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    findings.extend(self._parse_gosec_output(data))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            
            logger.info(f"Gosec: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Gosec failed: {e}")
        
        return findings
    
    def _parse_gosec_output(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse Gosec JSON output."""
        findings = []
        
        issues = data.get("Issues", [])
        for issue in issues:
            severity = SEVERITY_MAP.get(issue.get("severity", "medium").lower(), "medium")
            
            findings.append(self.add_finding(
                title=f"Gosec: {issue.get('details', 'Go Security Issue')}",
                description=issue.get("details", ""),
                severity=severity,
                cwe_id=f"CWE-{issue.get('cwe', {}).get('id', '')}" if issue.get("cwe") else None,
                file_path=issue.get("file", ""),
                line_number=issue.get("line", "0").split("-")[0] if issue.get("line") else 0,
                code_snippet=issue.get("code", ""),
                evidence={"rule_id": issue.get("rule_id", ""), "confidence": issue.get("confidence", "")},
                tool_source="gosec",
            ))
        
        return findings