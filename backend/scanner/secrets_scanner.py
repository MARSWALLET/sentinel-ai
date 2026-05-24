# ============================================
# SentinelAI - Secrets Scanner
# ============================================
"""
Secrets and credential scanning using TruffleHog and Gitleaks.
Detects API keys, private keys, tokens, passwords, and connection strings in code and git history.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from scanner.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# Pattern definitions for additional secret detection
SECRET_PATTERNS = {
    "aws_access_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "name": "AWS Access Key ID",
        "severity": "critical",
        "cwe": "CWE-798",
    },
    "aws_secret_key": {
        "pattern": r"['\"][0-9a-zA-Z/+]{40}['\"]",
        "name": "AWS Secret Key (suspected)",
        "severity": "critical",
        "cwe": "CWE-798",
    },
    "github_token": {
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "name": "GitHub Token",
        "severity": "critical",
        "cwe": "CWE-798",
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9a-zA-Z-]+",
        "name": "Slack Token",
        "severity": "critical",
        "cwe": "CWE-798",
    },
    "google_api_key": {
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "name": "Google API Key",
        "severity": "high",
        "cwe": "CWE-798",
    },
    "private_key": {
        "pattern": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY( BLOCK)?-----",
        "name": "Private Key",
        "severity": "critical",
        "cwe": "CWE-798",
    },
    "jwt_secret": {
        "pattern": r"['\"]eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*['\"]",
        "name": "Hardcoded JWT Token",
        "severity": "high",
        "cwe": "CWE-798",
    },
    "generic_api_key": {
        "pattern": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-z0-9]{16,}['\"]",
        "name": "Generic API Key",
        "severity": "high",
        "cwe": "CWE-798",
    },
    "password_in_code": {
        "pattern": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"\s]{4,}['\"]",
        "name": "Hardcoded Password",
        "severity": "critical",
        "cwe": "CWE-798",
    },
    "database_connection": {
        "pattern": r"(?i)(mongodb(\+srv)?://|mysql://|postgres(ql)?://|redis://)[^\s'\"]+",
        "name": "Database Connection String with Credentials",
        "severity": "critical",
        "cwe": "CWE-798",
    },
    "stripe_key": {
        "pattern": r"sk_(live|test)_[0-9a-zA-Z]{24,}",
        "name": "Stripe Secret Key",
        "severity": "critical",
        "cwe": "CWE-798",
    },
    "twilio_key": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "name": "Twilio API Key",
        "severity": "high",
        "cwe": "CWE-798",
    },
    "sendgrid_key": {
        "pattern": r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}",
        "name": "SendGrid API Key",
        "severity": "high",
        "cwe": "CWE-798",
    },
    "telegram_token": {
        "pattern": r"[0-9]+:AA[0-9A-Za-z_-]{33}",
        "name": "Telegram Bot Token",
        "severity": "high",
        "cwe": "CWE-798",
    },
    "oauth_secret": {
        "pattern": r"(?i)(client_secret|consumer_secret|app_secret)\s*[:=]\s*['\"][a-z0-9_-]{16,}['\"]",
        "name": "OAuth Client Secret",
        "severity": "high",
        "cwe": "CWE-798",
    },
    "firebase_key": {
        "pattern": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "name": "Firebase Cloud Messaging Token",
        "severity": "high",
        "cwe": "CWE-798",
    },
}

# Files/directories to skip
SKIP_PATHS = [
    ".git/", "node_modules/", "vendor/", "__pycache__/",
    ".min.js", ".min.css", ".map", "package-lock.json",
    "yarn.lock", "Pipfile.lock", "poetry.lock",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
]


class SecretsScanner(BaseScanner):
    """
    Secrets and credential scanner.
    Detects hardcoded secrets, API keys, and passwords in code and git history.
    """
    
    module_name = "secrets"
    module_description = "Secrets, API keys, and credential scanning in code and git history"
    
    async def run(self) -> List[Dict[str, Any]]:
        """Run secrets scanning."""
        findings = []
        target_dir = self.config.get("file_path", self.target)
        
        # Run TruffleHog
        trufflehog_findings = await self._run_trufflehog(target_dir)
        findings.extend(trufflehog_findings)
        
        # Run Gitleaks
        gitleaks_findings = await self._run_gitleaks(target_dir)
        findings.extend(gitleaks_findings)
        
        # Run pattern-based detection (catches things tools might miss)
        pattern_findings = await self._run_pattern_detection(target_dir)
        findings.extend(pattern_findings)
        
        # Deduplicate by file + line + type
        seen = set()
        deduplicated = []
        for f in findings:
            key = f"{f.get('file_path', '')}:{f.get('line_number', 0)}:{f.get('title', '')}"
            if key not in seen:
                seen.add(key)
                deduplicated.append(f)
        
        logger.info(f"Secrets scan complete: {len(deduplicated)} unique findings")
        return deduplicated
    
    async def _run_trufflehog(self, target_dir: str) -> List[Dict[str, Any]]:
        """Run TruffleHog deep scan."""
        findings = []
        
        # Check if it's a git repo
        is_git_repo = os.path.exists(os.path.join(target_dir, ".git"))
        
        try:
            if is_git_repo:
                # Scan git history
                rc, stdout, stderr = self.run_tool("trufflehog", [
                    "git", target_dir,
                    "--json",
                    "--only-verified",
                ], timeout=600)
            else:
                # Scan filesystem
                rc, stdout, stderr = self.run_tool("trufflehog", [
                    "filesystem", target_dir,
                    "--json",
                    "--only-verified",
                ], timeout=600)
            
            self.save_raw_output(stdout or stderr or "", "trufflehog")
            
            # Parse JSON output (one JSON object per line)
            for line in (stdout or "").split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        finding = self._parse_trufflehog_finding(data)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        pass
            
            logger.info(f"TruffleHog: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"TruffleHog failed: {e}")
        
        return findings
    
    def _parse_trufflehog_finding(self, data: Dict) -> Optional[Dict[str, Any]]:
        """Parse a TruffleHog finding."""
        detector_name = data.get("DetectorName", "Unknown")
        source = data.get("SourceMetadata", {}).get("Data", {})
        
        # Get file info
        git_info = source.get("Git", {})
        file_path = git_info.get("file", "") or source.get("Filesystem", {}).get("file", "")
        line = git_info.get("line", "") or "0"
        commit = git_info.get("commit", "")
        
        # Get raw secret
        raw = data.get("Raw", "")
        
        # Mask the secret
        if len(raw) > 8:
            masked = raw[:4] + "****" + raw[-4:]
        else:
            masked = "****"
        
        return self.add_finding(
            title=f"Exposed Secret: {detector_name}",
            description=f"{detector_name} detected in the codebase. This is a verified secret that must be rotated immediately.",
            severity="critical",
            cwe_id="CWE-798",
            file_path=file_path,
            line_number=int(line) if str(line).isdigit() else 0,
            evidence={
                "detector": detector_name,
                "secret_masked": masked,
                "commit": commit,
                "verified": data.get("Verified", False),
            },
            remediation=f"1. Immediately revoke the exposed {detector_name} in the respective service console\n2. Remove the secret from the codebase\n3. Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault)\n4. Scan git history and remove the secret using git-filter-repo or BFG Repo-Cleaner",
            tool_source="trufflehog",
        )
    
    async def _run_gitleaks(self, target_dir: str) -> List[Dict[str, Any]]:
        """Run Gitleaks scan."""
        findings = []
        
        # Check if it's a git repo
        is_git_repo = os.path.exists(os.path.join(target_dir, ".git"))
        
        try:
            output_file = f"{self.workspace_dir}/gitleaks_output.json"
            
            if is_git_repo:
                rc, stdout, stderr = self.run_tool("gitleaks", [
                    "detect",
                    "-s", target_dir,
                    "-r",
                    "-v",
                    "-f", "json",
                    "-o", output_file,
                ], timeout=600)
            else:
                # For non-git directories, use directory scan
                rc, stdout, stderr = self.run_tool("gitleaks", [
                    "detect",
                    "-s", target_dir,
                    "--no-git",
                    "-v",
                    "-f", "json",
                    "-o", output_file,
                ], timeout=600)
            
            self.save_raw_output(stderr or "", "gitleaks")
            
            # Parse JSON output
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    findings.extend(self._parse_gitleaks_output(data))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            
            logger.info(f"Gitleaks: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Gitleaks failed: {e}")
        
        return findings
    
    def _parse_gitleaks_output(self, data: List) -> List[Dict[str, Any]]:
        """Parse Gitleaks JSON output."""
        findings = []
        
        for leak in data:
            secret = leak.get("Match", "")
            if len(secret) > 8:
                masked = secret[:4] + "****" + secret[-4:]
            else:
                masked = "****"
            
            findings.append(self.add_finding(
                title=f"Exposed Secret: {leak.get('RuleID', 'Unknown')}",
                description=f"{leak.get('Description', 'Secret detected by Gitleaks')}. File: {leak.get('File', '')}",
                severity="critical",
                cwe_id="CWE-798",
                file_path=leak.get("File", ""),
                line_number=leak.get("StartLine", 0),
                evidence={
                    "rule_id": leak.get("RuleID", ""),
                    "secret_masked": masked,
                    "commit": leak.get("Commit", ""),
                    "author": leak.get("Author", ""),
                    "date": leak.get("Date", ""),
                    "tags": leak.get("Tags", []),
                },
                remediation="1. Revoke the exposed secret immediately\n2. Remove from codebase\n3. Use git-filter-repo to clean history\n4. Move secrets to environment variables or a secrets manager",
                tool_source="gitleaks",
            ))
        
        return findings
    
    async def _run_pattern_detection(self, target_dir: str) -> List[Dict[str, Any]]:
        """Run custom pattern-based secret detection."""
        findings = []
        
        # Walk the directory tree
        for root, dirs, files in os.walk(target_dir):
            # Skip hidden directories and common non-source dirs
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "vendor", "__pycache__")]
            
            for filename in files:
                file_path = os.path.join(root, filename)
                
                # Skip binary and large files
                if any(file_path.endswith(ext) for ext in SKIP_PATHS):
                    continue
                
                try:
                    # Check file size
                    if os.path.getsize(file_path) > 1024 * 1024:  # Skip files > 1MB
                        continue
                    
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        lines = content.split("\n")
                        
                        # Check each pattern
                        for pattern_name, pattern_info in SECRET_PATTERNS.items():
                            for match in re.finditer(pattern_info["pattern"], content):
                                # Calculate line number
                                pos = match.start()
                                line_num = content[:pos].count("\n") + 1
                                
                                # Get the matched text
                                matched_text = match.group()
                                
                                # Skip false positives (check context)
                                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                                
                                # Skip test/mock/example data
                                if self._is_likely_false_positive(line_content, pattern_name):
                                    continue
                                
                                # Mask the secret
                                if len(matched_text) > 8:
                                    masked = matched_text[:4] + "****" + matched_text[-4:]
                                else:
                                    masked = "****"
                                
                                rel_path = os.path.relpath(file_path, target_dir)
                                
                                findings.append(self.add_finding(
                                    title=f"Exposed Secret: {pattern_info['name']}",
                                    description=f"{pattern_info['name']} detected in source code. This secret is visible to anyone with repository access and may be exposed in git history.",
                                    severity=pattern_info["severity"],
                                    cwe_id=pattern_info["cwe"],
                                    file_path=rel_path,
                                    line_number=line_num,
                                    code_snippet=line_content.strip()[:200],
                                    evidence={
                                        "pattern": pattern_name,
                                        "secret_masked": masked,
                                        "context": line_content.strip()[:100],
                                    },
                                    remediation=f"1. Remove the hardcoded {pattern_info['name']}\n2. Revoke/rotate the exposed credential\n3. Use environment variables: process.env.{pattern_name.upper()}\n4. Consider using a secrets manager",
                                    tool_source="pattern_scan",
                                ))
                                
                except Exception as e:
                    logger.debug(f"Error scanning {file_path}: {e}")
        
        logger.info(f"Pattern detection: {len(findings)} findings")
        return findings
    
    def _is_likely_false_positive(self, line: str, pattern_name: str) -> bool:
        """Check if a finding is likely a false positive."""
        line_lower = line.lower()
        
        # Skip test files
        if "test" in line_lower and ("unittest" in line_lower or "assert" in line_lower):
            return True
        
        # Skip mock/example placeholder values
        if any(x in line_lower for x in ["example", "placeholder", "your_key", "xxx", "changeme", "todo"]):
            return True
        
        # Skip documentation comments
        if line.strip().startswith("#") or line.strip().startswith("//") or line.strip().startswith("*"):
            if any(x in line_lower for x in ["example:", "format:", "e.g.", "note:"]):
                return True
        
        # Skip variable names that contain the pattern keywords but aren't actual secrets
        if pattern_name in ("generic_api_key", "password_in_code"):
            if "get" in line_lower or "param" in line_lower or "config" in line_lower:
                # Check if the value looks like a placeholder
                if re.search(r"['\"][a-z]+_[a-z]+['\"]", line_lower):
                    return True
        
        return False