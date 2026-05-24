# ============================================
# SentinelAI - Network Scanner
# ============================================
"""
Deep network scanning using Nmap NSE scripts.
Checks for exposed databases, admin panels, default credentials, and known vulnerabilities.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from scanner.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# Known vulnerable services and their default credentials
DEFAULT_CREDS = {
    "ftp": [
        ("anonymous", "anonymous"),
        ("ftp", "ftp"),
        ("admin", "admin"),
    ],
    "ssh": [
        ("root", "root"),
        ("admin", "admin"),
        ("user", "user"),
    ],
    "telnet": [
        ("root", "root"),
        ("admin", "admin"),
    ],
    "mysql": [
        ("root", "root"),
        ("root", ""),
        ("mysql", "mysql"),
    ],
    "postgresql": [
        ("postgres", "postgres"),
        ("postgres", ""),
        ("pgsql", "pgsql"),
    ],
    "mongodb": [
        ("root", "root"),
    ],
    "redis": [
        (None, None),  # Redis often has no auth
    ],
    "elasticsearch": [
        (None, None),  # ES often has no auth by default
    ],
    "rdp": [
        ("Administrator", "Administrator"),
        ("admin", "admin"),
    ],
}

# Exposed admin panels to check
ADMIN_PANELS = {
    8080: ["/manager/html", "/host-manager/html", "/console"],  # Tomcat, JBoss
    4848: ["/common/index.jsf"],  # GlassFish
    8161: ["/admin"],  # ActiveMQ
    9200: ["/_cluster/health", "/_cat/indices"],  # Elasticsearch
    5601: ["/app/kibana"],  # Kibana
    3000: ["/login"],  # Grafana
    9090: ["/graph"],  # Prometheus
    9000: ["/sessions/new"],  # Portainer (older), SonarQube
    8983: ["/solr"],  # Solr
    15672: ["/"],  # RabbitMQ Management
    5984: ["/_utils"],  # CouchDB
    27017: ["/"],  # MongoDB (if HTTP interface enabled)
    6379: ["/"],  # Redis (if HTTP interface enabled)
    5432: ["/"],  # PostgreSQL (if HTTP interface enabled)
    3306: ["/"],  # MySQL (if HTTP interface enabled)
}

# Service to vulnerability mapping
SERVICE_VULNS = {
    "vsftpd 2.3.4": {
        "name": "vsftpd 2.3.4 Backdoor",
        "severity": "critical",
        "cwe": "CWE-78",
        "description": "vsftpd 2.3.4 contains a backdoor that opens a shell on port 6200.",
    },
    "proftpd 1.3.3": {
        "name": "ProFTPD mod_copy Vulnerability",
        "severity": "critical",
        "cwe": "CWE-22",
        "description": "ProFTPD 1.3.3x allows unauthorized file copying via mod_copy.",
    },
    "openssh 4.": {
        "name": "OpenSSH Username Enumeration",
        "severity": "medium",
        "cwe": "CWE-200",
        "description": "Older OpenSSH versions allow username enumeration via timing attacks.",
    },
    "mysql 5.": {
        "name": "MySQL Authentication Bypass (CVE-2012-2122)",
        "severity": "critical",
        "cwe": "CWE-287",
        "description": "MySQL/MariaDB authentication bypass vulnerability.",
    },
    "microsoft-ds": {
        "name": "SMB Service Exposed",
        "severity": "high",
        "cwe": "CWE-284",
        "description": "SMB service is exposed. Vulnerable to EternalBlue and similar exploits.",
    },
    "ms-wbt-server": {
        "name": "RDP Service Exposed",
        "severity": "high",
        "cwe": "CWE-284",
        "description": "Remote Desktop Protocol is exposed. Vulnerable to brute force and BlueKeep.",
    },
}


class NetworkScanner(BaseScanner):
    """
    Deep network scanner.
    Performs comprehensive port scanning with NSE vulnerability detection.
    """
    
    module_name = "network"
    module_description = "Deep network scanning with vulnerability detection"
    
    async def run(self) -> List[Dict[str, Any]]:
        """Run deep network scanning."""
        findings = []
        
        parsed = urlparse(self.target if self.target.startswith("http") else f"http://{self.target}")
        hostname = parsed.hostname or self.target
        
        # Run comprehensive Nmap scan with NSE scripts
        nmap_findings = await self._run_nmap_deep(hostname)
        findings.extend(nmap_findings)
        
        # Check for exposed admin panels on discovered services
        admin_findings = await self._check_admin_panels(hostname)
        findings.extend(admin_findings)
        
        return findings
    
    async def _run_nmap_deep(self, hostname: str) -> List[Dict[str, Any]]:
        """Run comprehensive Nmap scan with NSE vulnerability scripts."""
        findings = []
        
        try:
            # Full port scan with service detection and NSE scripts
            rc, stdout, stderr = self.run_tool("nmap", [
                "-sV",           # Service version detection
                "-sC",           # Default NSE scripts
                "--script", "vuln,auth,default",  # Vulnerability and auth scripts
                "-p-",           # All ports
                "-T4",           # Aggressive timing
                "--max-retries", "2",
                "--max-rtt-timeout", "500ms",
                "-oX", f"{self.workspace_dir}/nmap_deep.xml",
                "-oN", f"{self.workspace_dir}/nmap_deep.txt",
                hostname,
            ], timeout=1800)  # 30 minute timeout for full port scan
            
            self.save_raw_output(stdout or stderr or "", "nmap_deep")
            
            if stdout:
                findings.extend(self._parse_nmap_output(stdout, hostname))
            
            logger.info(f"Nmap deep scan: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Nmap deep scan failed: {e}")
        
        return findings
    
    def _parse_nmap_output(self, output: str, hostname: str) -> List[Dict[str, Any]]:
        """Parse Nmap output for findings."""
        findings = []
        
        # Parse open ports and services
        port_pattern = r'(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)'
        
        open_ports = []
        for match in re.finditer(port_pattern, output):
            port_num = int(match.group(1))
            proto = match.group(2)
            state = match.group(3)
            service = match.group(4)
            version = match.group(5).strip()
            
            open_ports.append({
                "port": port_num,
                "protocol": proto,
                "service": service,
                "version": version,
            })
            
            # Check for exposed databases
            db_findings = self._check_exposed_database(port_num, service, version, hostname)
            findings.extend(db_findings)
            
            # Check for known vulnerable versions
            vuln_findings = self._check_known_vulns(service, version, hostname, port_num)
            findings.extend(vuln_findings)
            
            # Check for services with default credentials
            cred_findings = self._check_default_creds(service, hostname, port_num)
            findings.extend(cred_findings)
        
        # Check for missing firewall (many open ports)
        if len(open_ports) > 20:
            findings.append(self.add_finding(
                title="Excessive Open Ports - Firewall May Be Missing",
                description=f"Found {len(open_ports)} open ports on {hostname}. A large number of open ports increases the attack surface significantly.",
                severity="medium",
                cwe_id="CWE-284",
                url=f"{hostname}",
                evidence={"open_ports_count": len(open_ports), "open_ports": [p["port"] for p in open_ports[:20]]},
                remediation="Implement a host-based firewall (iptables, ufw, Windows Firewall). Only expose services that are necessary. Use a DMZ for public-facing services.",
                tool_source="nmap",
            ))
        
        # Parse NSE script results
        nse_findings = self._parse_nse_results(output, hostname)
        findings.extend(nse_findings)
        
        return findings
    
    def _check_exposed_database(self, port: int, service: str, version: str,
                                 hostname: str) -> List[Dict[str, Any]]:
        """Check for exposed database services."""
        findings = []
        
        exposed_dbs = {
            3306: ("MySQL", "critical", "CWE-284"),
            5432: ("PostgreSQL", "critical", "CWE-284"),
            27017: ("MongoDB", "critical", "CWE-284"),
            27018: ("MongoDB", "critical", "CWE-284"),
            6379: ("Redis", "critical", "CWE-284"),
            6380: ("Redis", "critical", "CWE-284"),
            9200: ("Elasticsearch", "critical", "CWE-284"),
            5984: ("CouchDB", "high", "CWE-284"),
            9042: ("Cassandra", "high", "CWE-284"),
            7474: ("Neo4j", "high", "CWE-284"),
            1521: ("Oracle", "critical", "CWE-284"),
            1433: ("MSSQL", "critical", "CWE-284"),
            50000: ("DB2", "critical", "CWE-284"),
        }
        
        if port in exposed_dbs:
            db_name, severity, cwe = exposed_dbs[port]
            findings.append(self.add_finding(
                title=f"Exposed {db_name} Database on Port {port}",
                description=f"{db_name} database is directly accessible on port {port}. Databases should never be exposed to the public internet.",
                severity=severity,
                cwe_id=cwe,
                url=f"{hostname}:{port}",
                evidence={"service": service, "version": version, "port": port},
                remediation=f"1. Restrict access to port {port} using a firewall\n2. Bind the database to localhost (127.0.0.1) only\n3. Use a VPN or SSH tunnel for remote access\n4. Enable authentication and use strong credentials",
                tool_source="nmap",
            ))
        
        return findings
    
    def _check_known_vulns(self, service: str, version: str, hostname: str,
                           port: int) -> List[Dict[str, Any]]:
        """Check for known vulnerable service versions."""
        findings = []
        
        service_version = f"{service} {version}".lower()
        
        for vuln_pattern, vuln_info in SERVICE_VULNS.items():
            if vuln_pattern.lower() in service_version:
                findings.append(self.add_finding(
                    title=vuln_info["name"],
                    description=f"{vuln_info['description']} Detected: {service} {version} on port {port}.",
                    severity=vuln_info["severity"],
                    cwe_id=vuln_info["cwe"],
                    url=f"{hostname}:{port}",
                    evidence={"service": service, "version": version, "port": port},
                    remediation="Update the service to the latest stable version. Apply security patches immediately.",
                    tool_source="nmap_nse",
                ))
        
        # Check for outdated services (heuristic)
        outdated_services = {
            "apache": [("2.2.", None), ("2.4.1", "2.4.57")],
            "nginx": [("1.10.", None), ("1.12.", None), ("1.14.", "1.24")],
            "openssh": [("4.", None), ("5.", None), ("6.0", "9.3")],
            "mysql": [("5.0.", None), ("5.1.", None), ("5.5.", None)],
            "vsftpd": [("2.3.4", None)],
        }
        
        for svc_name, versions in outdated_services.items():
            if svc_name in service.lower():
                for old_ver, min_ver in versions:
                    if version.startswith(old_ver):
                        findings.append(self.add_finding(
                            title=f"Potentially Outdated {service.title()} Version",
                            description=f"Detected {service} version {version}. This version may be outdated and contain known security vulnerabilities.",
                            severity="medium",
                            cwe_id="CWE-1104",
                            url=f"{hostname}:{port}",
                            evidence={"service": service, "version": version},
                            remediation=f"Upgrade {service} to the latest stable version{f' (minimum {min_ver})' if min_ver else ''}.",
                            tool_source="nmap",
                        ))
                        break
        
        return findings
    
    def _check_default_creds(self, service: str, hostname: str, port: int) -> List[Dict[str, Any]]:
        """Check for services with known default credentials."""
        findings = []
        
        service_lower = service.lower()
        
        # Map service names to credential keys
        service_map = {
            "ftp": "ftp",
            "ssh": "ssh",
            "telnet": "telnet",
            "mysql": "mysql",
            "postgresql": "postgresql",
            "mongodb": "mongodb",
            "redis": "redis",
            "ms-wbt-server": "rdp",
            "microsoft-ds": "smb",
        }
        
        matched_service = None
        for svc_key, cred_key in service_map.items():
            if svc_key in service_lower:
                matched_service = cred_key
                break
        
        if matched_service and matched_service in DEFAULT_CREDS:
            creds = DEFAULT_CREDS[matched_service]
            creds_str = ", ".join([f"{u}/{p}" if u else "no auth" for u, p in creds[:3]])
            
            findings.append(self.add_finding(
                title=f"Potential Default Credentials on {service.title()}",
                description=f"The {service.title()} service on port {port} may have default or weak credentials. Common credentials include: {creds_str}.",
                severity="high",
                cwe_id="CWE-798",
                url=f"{hostname}:{port}",
                evidence={"service": service, "known_default_creds": creds[:3]},
                remediation="Change all default passwords immediately. Use strong, unique passwords. Implement key-based authentication where possible (SSH). Disable password authentication for services that support alternatives.",
                tool_source="nmap",
            ))
        
        return findings
    
    def _parse_nse_results(self, output: str, hostname: str) -> List[Dict[str, Any]]:
        """Parse NSE script results from Nmap output."""
        findings = []
        
        # Common NSE vulnerability patterns
        vuln_patterns = [
            (r"(VULNERABLE).*?(CVE-\d{4}-\d+)", "NSE Vulnerability Detected", "critical"),
            (r"State:\s*VULNERABLE", "NSE Vulnerability Detected", "high"),
            (r"(SQL injection|XSS|command injection|directory traversal)", "Web Vulnerability", "critical"),
        ]
        
        for pattern, title_prefix, severity in vuln_patterns:
            for match in re.finditer(pattern, output, re.IGNORECASE):
                findings.append(self.add_finding(
                    title=f"{title_prefix}: {match.group(0)[:80]}",
                    description=match.group(0),
                    severity=severity,
                    cwe_id="CWE-200",
                    url=hostname,
                    evidence={"nse_match": match.group(0)},
                    tool_source="nmap_nse",
                ))
        
        return findings
    
    async def _check_admin_panels(self, hostname: str) -> List[Dict[str, Any]]:
        """Check for exposed admin panels on discovered services."""
        findings = []
        
        import httpx
        
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            for port, paths in ADMIN_PANELS.items():
                for path in paths:
                    try:
                        url = f"http://{hostname}:{port}{path}"
                        response = await client.get(url)
                        
                        if response.status_code in (200, 401):
                            # Check if it's actually an admin panel
                            indicators = ["login", "admin", "dashboard", "console", "management", "tomcat", "grafana"]
                            body_lower = response.text.lower()
                            
                            if any(indicator in body_lower for indicator in indicators):
                                findings.append(self.add_finding(
                                    title=f"Exposed Admin Panel on Port {port}",
                                    description=f"An administrative interface was found at {url}. Administrative interfaces should not be publicly accessible.",
                                    severity="high",
                                    cwe_id="CWE-284",
                                    url=url,
                                    evidence={
                                        "status_code": response.status_code,
                                        "page_title": self._extract_title(response.text),
                                    },
                                    remediation="1. Restrict access to admin panels by IP\n2. Use VPN or jump host for administrative access\n3. Implement strong authentication (MFA)\n4. Consider using a non-standard port or path",
                                    tool_source="admin_panel_scan",
                                ))
                                break  # One finding per port is enough
                                
                    except Exception:
                        pass
        
        return findings
    
    @staticmethod
    def _extract_title(html: str) -> str:
        """Extract title from HTML."""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""