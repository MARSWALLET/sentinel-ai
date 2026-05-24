# ============================================
# SentinelAI - Web Application Scanner
# ============================================
"""
Web application security scanner using OWASP ZAP, Nikto, Nuclei, and Wapiti.
Tests for XSS, SQL injection, misconfigurations, security headers, and more.
"""

import json
import logging
import re
import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from scanner.base_scanner import BaseScanner
from config import settings

logger = logging.getLogger(__name__)

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "name": "HSTS (HTTP Strict Transport Security)",
        "severity": "high",
        "cwe": "CWE-319",
        "description": "HSTS header is missing. The site may be vulnerable to SSL stripping attacks.",
    },
    "Content-Security-Policy": {
        "name": "CSP (Content Security Policy)",
        "severity": "medium",
        "cwe": "CWE-693",
        "description": "CSP header is missing. Without CSP, the site is more vulnerable to XSS attacks.",
    },
    "X-Frame-Options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "cwe": "CWE-1021",
        "description": "X-Frame-Options header is missing. The site may be vulnerable to clickjacking attacks.",
    },
    "X-Content-Type-Options": {
        "name": "X-Content-Type-Options",
        "severity": "low",
        "cwe": "CWE-116",
        "description": "X-Content-Type-Options header is missing. MIME type sniffing may lead to XSS.",
    },
    "Referrer-Policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "cwe": "CWE-200",
        "description": "Referrer-Policy header is missing. Sensitive URL parameters may leak to third parties.",
    },
    "Permissions-Policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "cwe": "CWE-693",
        "description": "Permissions-Policy header is missing. Browser features may be abused by attackers.",
    },
}

# Sensitive files to check
SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production",
    ".git/config", ".git/HEAD", ".git/logs/HEAD",
    "wp-config.php", "wp-config.bak", "wp-config.php~",
    "config.php", "configuration.php",
    "phpinfo.php", "info.php",
    "admin/", "administrator/", "admin.php",
    "backup.sql", "database.sql", "dump.sql",
    "robots.txt", "sitemap.xml",
    "api/", "api/v1/", "swagger.json", "openapi.json",
    ".htaccess", ".htpasswd",
    "Dockerfile", "docker-compose.yml",
    "README.md", "CHANGELOG.md",
    "server-status", "server-info",
    "actuator/", "actuator/env", "actuator/health",
    "console/", "jmx-console/",
    "cgi-bin/", "scripts/cgi-bin/",
    "crossdomain.xml", "clientaccesspolicy.xml",
]


class WebScanner(BaseScanner):
    """
    Web application security scanner.
    Uses multiple tools for comprehensive web vulnerability detection.
    """
    
    module_name = "web"
    module_description = "Web application vulnerability scanning (XSS, SQLi, misconfigurations, headers)"
    
    async def run(self) -> List[Dict[str, Any]]:
        """Run web application scanning."""
        findings = []
        target_url = self.target if self.target.startswith("http") else f"http://{self.target}"
        
        # Run security header checks
        header_findings = await self._check_security_headers(target_url)
        findings.extend(header_findings)
        
        # Run sensitive file checks
        file_findings = await self._check_sensitive_files(target_url)
        findings.extend(file_findings)
        
        # Run CORS check
        cors_findings = await self._check_cors(target_url)
        findings.extend(cors_findings)
        
        # Run Nikto scan
        nikto_findings = await self._run_nikto(target_url)
        findings.extend(nikto_findings)
        
        # Run Nuclei scan
        nuclei_findings = await self._run_nuclei(target_url)
        findings.extend(nuclei_findings)
        
        # Run Wapiti scan
        wapiti_findings = await self._run_wapiti(target_url)
        findings.extend(wapiti_findings)
        
        return findings
    
    async def _check_security_headers(self, url: str) -> List[Dict[str, Any]]:
        """Check for missing security headers."""
        findings = []
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=30.0, follow_redirects=True) as client:
                response = await client.get(url)
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                for header_name, header_info in SECURITY_HEADERS.items():
                    header_lower = header_name.lower()
                    if header_lower not in headers:
                        findings.append(self.add_finding(
                            title=f"Missing Security Header: {header_info['name']}",
                            description=header_info["description"],
                            severity=header_info["severity"],
                            cwe_id=header_info["cwe"],
                            url=url,
                            evidence={"missing_header": header_name, "response_headers": dict(response.headers)},
                            remediation=f"Add the '{header_name}' header to all HTTP responses. Example: {header_name}: ...",
                            tool_source="header_check",
                        ))
                    else:
                        # Check for weak configurations
                        if header_name == "X-Frame-Options" and headers[header_lower] not in ("DENY", "SAMEORIGIN"):
                            findings.append(self.add_finding(
                                title=f"Weak X-Frame-Options Configuration",
                                description=f"X-Frame-Options is set to '{headers[header_lower]}' which may not provide adequate protection.",
                                severity="low",
                                cwe_id="CWE-1021",
                                url=url,
                                evidence={"header_value": headers[header_lower]},
                                remediation="Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'.",
                                tool_source="header_check",
                            ))
                        
                        # Check HSTS for includeSubDomains and preload
                        if header_name == "Strict-Transport-Security":
                            hsts = headers[header_lower]
                            if "includeSubDomains" not in hsts:
                                findings.append(self.add_finding(
                                    title="HSTS Missing includeSubDomains Directive",
                                    description="The HSTS header does not include the 'includeSubDomains' directive. Subdomains remain vulnerable to SSL stripping.",
                                    severity="medium",
                                    cwe_id="CWE-319",
                                    url=url,
                                    evidence={"hsts_value": hsts},
                                    remediation="Add includeSubDomains to HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                                    tool_source="header_check",
                                ))
                
                # Check for server version disclosure
                server = headers.get("server", "")
                x_powered = headers.get("x-powered-by", "")
                if server and any(char.isdigit() for char in server):
                    findings.append(self.add_finding(
                        title="Server Version Disclosure",
                        description=f"The 'Server' header reveals the server version: '{server}'. This information can help attackers identify known vulnerabilities.",
                        severity="low",
                        cwe_id="CWE-200",
                        url=url,
                        evidence={"server_header": server, "x-powered-by": x_powered},
                        remediation="Remove or obfuscate the Server header. In Apache: ServerTokens Prod, in Nginx: server_tokens off;",
                        tool_source="header_check",
                    ))
                
                logger.info(f"Security header check complete: {len(findings)} findings")
                
        except Exception as e:
            logger.warning(f"Security header check failed: {e}")
        
        return findings
    
    async def _check_sensitive_files(self, url: str) -> List[Dict[str, Any]]:
        """Check for exposed sensitive files."""
        findings = []
        checked = 0
        
        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=False) as client:
            tasks = []
            for file_path in SENSITIVE_FILES:
                check_url = urljoin(url, file_path)
                tasks.append(self._check_single_file(client, check_url, file_path))
            
            # Run in batches of 10 to avoid overwhelming the server
            for i in range(0, len(tasks), 10):
                batch = tasks[i:i+10]
                results = await asyncio.gather(*batch, return_exceptions=True)
                for result in results:
                    if isinstance(result, dict):
                        findings.append(result)
                checked += len(batch)
        
        logger.info(f"Sensitive file check complete: checked {checked} paths, found {len(findings)} exposures")
        return findings
    
    async def _check_single_file(self, client: httpx.AsyncClient, url: str, path: str) -> Optional[Dict[str, Any]]:
        """Check a single file for exposure."""
        try:
            response = await client.get(url)
            
            if response.status_code in (200, 301, 302, 307, 403):
                content = response.text[:2000]  # First 2KB
                
                # Check for actual sensitive content
                is_sensitive = False
                severity = "medium"
                description = f"The file '{path}' is accessible."
                
                if path == ".env" and ("=" in content or "DB_" in content or "API_KEY" in content):
                    is_sensitive = True
                    severity = "critical"
                    description = f"Environment file '{path}' is exposed and may contain secrets, database credentials, or API keys."
                elif path == ".git/config" and "[core]" in content:
                    is_sensitive = True
                    severity = "high"
                    description = f"Git repository configuration is exposed at '{path}'. This can allow source code retrieval using tools like git-dumper."
                elif path in ("wp-config.php", "wp-config.bak") and ("DB_PASSWORD" in content or "define" in content):
                    is_sensitive = True
                    severity = "critical"
                    description = f"WordPress configuration file '{path}' is exposed, potentially revealing database credentials."
                elif path == "phpinfo.php" and ("phpinfo()" in content or "PHP Version" in content):
                    is_sensitive = True
                    severity = "medium"
                    description = f"phpinfo() page is exposed at '{path}'. This reveals server configuration, extensions, and paths."
                elif path in ("robots.txt",) and response.status_code == 200:
                    is_sensitive = True
                    severity = "info"
                    description = f"robots.txt is accessible. Check for Disallow entries that reveal hidden paths."
                elif "swagger" in path.lower() and ("paths" in content or "swagger" in content):
                    is_sensitive = True
                    severity = "medium"
                    description = f"API documentation (Swagger/OpenAPI) is publicly accessible at '{path}'."
                elif path in ("admin/", "administrator/", "admin.php") and response.status_code == 200:
                    is_sensitive = True
                    severity = "medium"
                    description = f"Admin panel may be accessible at '{path}'. Ensure strong authentication is enforced."
                elif path.endswith(".sql") and ("CREATE TABLE" in content or "INSERT INTO" in content):
                    is_sensitive = True
                    severity = "critical"
                    description = f"Database dump '{path}' is publicly accessible, exposing all data."
                elif path.startswith("backup") and len(content) > 100:
                    is_sensitive = True
                    severity = "high"
                    description = f"Backup file '{path}' may be exposed."
                elif response.status_code == 200 and len(content) > 50:
                    is_sensitive = True
                
                if is_sensitive:
                    return self.add_finding(
                        title=f"Sensitive File Exposed: {path}",
                        description=description,
                        severity=severity,
                        cwe_id="CWE-548" if severity in ("critical", "high") else "CWE-200",
                        url=url,
                        evidence={
                            "status_code": response.status_code,
                            "content_preview": content[:500],
                            "content_length": len(response.content),
                        },
                        remediation=f"Remove or restrict access to '{path}'. Use .htaccess/nginx rules, or move sensitive files outside the web root.",
                        tool_source="sensitive_file_scan",
                    )
                    
        except Exception:
            pass
        
        return None
    
    async def _check_cors(self, url: str) -> List[Dict[str, Any]]:
        """Check for CORS misconfigurations."""
        findings = []
        
        try:
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                # Test with malicious Origin header
                malicious_origins = [
                    "https://evil.com",
                    "http://evil.com",
                    "null",
                    "https://attacker-site.github.io",
                ]
                
                for origin in malicious_origins:
                    response = await client.get(
                        url,
                        headers={"Origin": origin},
                    )
                    
                    acao = response.headers.get("access-control-allow-origin", "")
                    acac = response.headers.get("access-control-allow-credentials", "")
                    
                    if acao == origin or acao == "*":
                        if acac.lower() == "true":
                            findings.append(self.add_finding(
                                title="Dangerous CORS Configuration with Credentials",
                                description=f"The server reflects arbitrary Origin headers ('{origin}') and allows credentials. This allows attackers to make authenticated cross-origin requests.",
                                severity="critical",
                                cwe_id="CWE-942",
                                url=url,
                                evidence={
                                    "test_origin": origin,
                                    "access-control-allow-origin": acao,
                                    "access-control-allow-credentials": acac,
                                },
                                remediation="Implement a strict allowlist of trusted origins. Never reflect arbitrary origins when Access-Control-Allow-Credentials: true.",
                                tool_source="cors_check",
                            ))
                            break
                        elif acao == "*":
                            findings.append(self.add_finding(
                                title="Wildcard CORS Configuration",
                                description="The server allows any origin via wildcard (*). While this prevents credential theft, it allows cross-origin data access.",
                                severity="medium",
                                cwe_id="CWE-942",
                                url=url,
                                evidence={"access-control-allow-origin": acao},
                                remediation="Replace wildcard with specific allowed origins: Access-Control-Allow-Origin: https://trusted-domain.com",
                                tool_source="cors_check",
                            ))
                            break
                
                logger.info(f"CORS check complete: {len(findings)} findings")
                
        except Exception as e:
            logger.warning(f"CORS check failed: {e}")
        
        return findings
    
    async def _run_nikto(self, url: str) -> List[Dict[str, Any]]:
        """Run Nikto web scanner."""
        findings = []
        
        try:
            rc, stdout, stderr = self.run_tool("nikto", [
                "-h", url,
                "-Cgidirs", "all",
                "-o", f"{self.workspace_dir}/nikto_output.txt",
                "-Format", "txt",
            ], timeout=600)
            
            self.save_raw_output(stdout or "", "nikto")
            
            if stdout:
                findings.extend(self._parse_nikto_output(stdout, url))
            
            logger.info(f"Nikto scan complete: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Nikto scan failed: {e}")
        
        return findings
    
    def _parse_nikto_output(self, output: str, base_url: str) -> List[Dict[str, Any]]:
        """Parse Nikto output into findings."""
        findings = []
        
        # Nikto output patterns
        patterns = [
            (r"OSVDB-\d+:\s*(.+)", "medium", "CWE-200"),
            (r"(X-Frame-Options|X-XSS-Protection|X-Content-Type-Options) header .+", "low", "CWE-693"),
            (r"Server\s+(.+?)\s+may leak inodes", "low", "CWE-200"),
            (r"(\S+)\s+(discloses|reveals|leaks)\s+(.+)", "medium", "CWE-200"),
            (r"(Directory indexing|indexing is enabled)", "medium", "CWE-548"),
            (r"(\S+)\s+(vulnerability|injection|bypass|traversal)", "high", "CWE-74"),
            (r"(Default|default) (file|page|document|credential)", "medium", "CWE-276"),
            (r"(No|no) (anti-CSRF|CSRF|clickjacking) token", "medium", "CWE-352"),
        ]
        
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("-") or line.startswith("+"):
                continue
            
            for pattern, severity, cwe in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(self.add_finding(
                        title=f"Nikto: {line[:100]}",
                        description=line,
                        severity=severity,
                        cwe_id=cwe,
                        url=base_url,
                        evidence={"nikto_output": line},
                        tool_source="nikto",
                    ))
                    break
        
        return findings
    
    async def _run_nuclei(self, url: str) -> List[Dict[str, Any]]:
        """Run Nuclei vulnerability scanner."""
        findings = []
        
        try:
            rc, stdout, stderr = self.run_tool("nuclei", [
                "-u", url,
                "-t", "cves,misconfiguration,exposed-panels,takeover,default-logins",
                "-json",
                "-o", f"{self.workspace_dir}/nuclei_output.json",
                "-timeout", "15",
                "-max-host-error", "30",
            ], timeout=600)
            
            self.save_raw_output(stdout or stderr or "", "nuclei")
            
            # Parse JSON output line by line
            output_file = f"{self.workspace_dir}/nuclei_output.json"
            try:
                with open(output_file, "r") as f:
                    for line in f:
                        if line.strip():
                            try:
                                data = json.loads(line)
                                finding = self._parse_nuclei_finding(data, url)
                                if finding:
                                    findings.append(finding)
                            except json.JSONDecodeError:
                                pass
            except FileNotFoundError:
                pass
            
            logger.info(f"Nuclei scan complete: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Nuclei scan failed: {e}")
        
        return findings
    
    def _parse_nuclei_finding(self, data: Dict, base_url: str) -> Optional[Dict[str, Any]]:
        """Parse a single Nuclei finding."""
        severity = (data.get("info", {}).get("severity", "info") or "info").lower()
        name = data.get("info", {}).get("name", "Unknown")
        matched = data.get("matched-at", base_url)
        template_id = data.get("template-id", "")
        
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
            "unknown": "info",
        }
        
        cvss = None
        classification = data.get("info", {}).get("classification", {})
        if classification:
            cvss = classification.get("cvss-score")
        
        return self.add_finding(
            title=f"Nuclei: {name}",
            description=data.get("info", {}).get("description", name),
            severity=severity_map.get(severity, "info"),
            cwe_id=f"CWE-{classification.get('cwe-id', [''])[0]}" if classification.get("cwe-id") else None,
            cvss_score=float(cvss) if cvss else None,
            url=matched,
            evidence={
                "template_id": template_id,
                "curl_command": data.get("curl-command", ""),
                "matcher_name": data.get("matcher-name", ""),
                "extracted_results": data.get("extracted-results", []),
            },
            tool_source="nuclei",
        )
    
    async def _run_wapiti(self, url: str) -> List[Dict[str, Any]]:
        """Run Wapiti vulnerability scanner."""
        findings = []
        
        try:
            rc, stdout, stderr = self.run_tool("wapiti", [
                "-u", url,
                "-f", "json",
                "-o", f"{self.workspace_dir}/wapiti_output.json",
                "--flush-session",
                "--timeout", "15",
                "--max-links-per-page", "50",
            ], timeout=600)
            
            self.save_raw_output(stdout or stderr or "", "wapiti")
            
            # Parse JSON output
            output_file = f"{self.workspace_dir}/wapiti_output.json"
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    findings.extend(self._parse_wapiti_output(data, url))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            
            logger.info(f"Wapiti scan complete: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Wapiti scan failed: {e}")
        
        return findings
    
    def _parse_wapiti_output(self, data: Dict, base_url: str) -> List[Dict[str, Any]]:
        """Parse Wapiti JSON output into findings."""
        findings = []
        
        vulns = data.get("vulnerabilities", {})
        for vuln_type, instances in vulns.items():
            for instance in instances:
                # Map Wapiti vuln types to severity and CWE
                vuln_map = {
                    "SQL Injection": ("critical", "CWE-89"),
                    "Blind SQL Injection": ("critical", "CWE-89"),
                    "Cross Site Scripting": ("high", "CWE-79"),
                    "Stored Cross Site Scripting": ("critical", "CWE-79"),
                    "File Handling": ("high", "CWE-22"),
                    "CRLF Injection": ("medium", "CWE-93"),
                    "Command Execution": ("critical", "CWE-78"),
                    "XXE": ("high", "CWE-611"),
                    "SSRF": ("high", "CWE-918"),
                    "Open Redirect": ("medium", "CWE-601"),
                    "Weak Credentials": ("high", "CWE-798"),
                }
                
                severity, cwe = vuln_map.get(vuln_type, ("medium", "CWE-200"))
                
                findings.append(self.add_finding(
                    title=f"Wapiti: {vuln_type}",
                    description=instance.get("description", vuln_type),
                    severity=severity,
                    cwe_id=cwe,
                    url=instance.get("path", base_url),
                    parameter=instance.get("parameter", ""),
                    evidence={
                        "method": instance.get("method", ""),
                        "parameter": instance.get("parameter", ""),
                        "curl_command": instance.get("curl_command", ""),
                    },
                    code_snippet=instance.get("info", ""),
                    tool_source="wapiti",
                ))
        
        return findings