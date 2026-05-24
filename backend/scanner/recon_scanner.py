# ============================================
# SentinelAI - Reconnaissance Scanner
# ============================================
"""
Reconnaissance module using Nmap, Amass, Subfinder, httpx, and WhatWeb.
Discovers subdomains, open ports, services, and tech stack fingerprinting.
"""

import json
import logging
import re
import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from scanner.base_scanner import BaseScanner

logger = logging.getLogger(__name__)


class ReconScanner(BaseScanner):
    """
    Reconnaissance scanner module.
    Performs subdomain enumeration, port scanning, and tech detection.
    """
    
    module_name = "recon"
    module_description = "Subdomain enumeration, port scanning, and technology fingerprinting"
    
    async def run(self) -> List[Dict[str, Any]]:
        """Run reconnaissance scanning."""
        findings = []
        parsed = urlparse(self.target if self.target.startswith("http") else f"http://{self.target}")
        hostname = parsed.hostname or self.target
        
        # Skip if no valid hostname
        if not hostname:
            logger.warning(f"No valid hostname found in target: {self.target}")
            return findings
        
        # Run subdomain enumeration
        subdomains = await self._enumerate_subdomains(hostname)
        
        # Run port scan on main target
        ports = await self._port_scan(hostname)
        
        # Run tech fingerprinting
        tech = await self._detect_tech(self.target)
        
        # Check DNS records
        dns_records = await self._check_dns(hostname)
        
        # Probe subdomains
        alive_subdomains = await self._probe_subdomains(subdomains)
        
        # Generate findings from results
        findings.extend(self._analyze_results(hostname, subdomains, alive_subdomains, ports, tech, dns_records))
        
        # Store recon data for other modules
        self.config["recon_results"] = {
            "subdomains": subdomains,
            "alive_subdomains": alive_subdomains,
            "ports": ports,
            "technologies": tech,
            "dns_records": dns_records,
        }
        
        return findings
    
    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using subfinder and amass."""
        subdomains = set()
        
        # Run subfinder
        try:
            rc, stdout, stderr = self.run_tool("subfinder", [
                "-d", domain,
                "-silent",
                "-o", f"{self.workspace_dir}/subdomains_subfinder.txt",
            ], timeout=300)
            
            output_file = f"{self.workspace_dir}/subdomains_subfinder.txt"
            if rc == 0:
                with open(output_file, "r") as f:
                    found = [line.strip() for line in f if line.strip()]
                    subdomains.update(found)
                    logger.info(f"Subfinder found {len(found)} subdomains for {domain}")
        except Exception as e:
            logger.warning(f"Subfinder failed: {e}")
        
        # Run amass
        try:
            rc, stdout, stderr = self.run_tool("amass", [
                "enum", "-passive",
                "-d", domain,
                "-o", f"{self.workspace_dir}/subdomains_amass.txt",
            ], timeout=300)
            
            output_file = f"{self.workspace_dir}/subdomains_amass.txt"
            if rc == 0:
                with open(output_file, "r") as f:
                    found = [line.strip() for line in f if line.strip()]
                    subdomains.update(found)
                    logger.info(f"Amass found {len(found)} subdomains for {domain}")
        except Exception as e:
            logger.warning(f"Amass failed: {e}")
        
        return sorted(list(subdomains))
    
    async def _port_scan(self, hostname: str) -> List[Dict[str, Any]]:
        """Run Nmap port scan."""
        ports = []
        
        try:
            rc, stdout, stderr = self.run_tool("nmap", [
                "-sV", "-sC",
                "--top-ports", "1000",
                "-T4",
                "-oX", f"{self.workspace_dir}/nmap_output.xml",
                "-oN", f"{self.workspace_dir}/nmap_output.txt",
                hostname,
            ], timeout=600)
            
            if rc == 0:
                ports = self._parse_nmap_output(stdout)
                logger.info(f"Nmap found {len(ports)} open ports on {hostname}")
            
            self.save_raw_output(stdout or "", "nmap")
        except Exception as e:
            logger.warning(f"Nmap scan failed: {e}")
        
        return ports
    
    def _parse_nmap_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Nmap output to extract open ports and services."""
        ports = []
        # Parse nmap -oN format
        port_pattern = r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)'
        
        for match in re.finditer(port_pattern, output):
            port_num, proto, state, service, version = match.groups()
            ports.append({
                "port": int(port_num),
                "protocol": proto,
                "state": state,
                "service": service,
                "version": version.strip(),
            })
        
        return ports
    
    async def _detect_tech(self, url: str) -> List[Dict[str, Any]]:
        """Detect technology stack using WhatWeb and httpx."""
        tech = []
        
        # Run WhatWeb
        try:
            rc, stdout, stderr = self.run_tool("whatweb", [
                url,
                "--color=never",
                "--log-json", f"{self.workspace_dir}/whatweb.json",
            ], timeout=120)
            
            # Parse WhatWeb JSON output
            try:
                import json
                with open(f"{self.workspace_dir}/whatweb.json", "r") as f:
                    whatweb_data = json.load(f)
                    for entry in whatweb_data:
                        plugins = entry.get("plugins", {})
                        for plugin_name, plugin_data in plugins.items():
                            if plugin_name in ("IP", "HTTPServer", "Title", "Country", "X-Powered-By"):
                                continue
                            tech.append({
                                "name": plugin_name,
                                "category": self._categorize_tech(plugin_name),
                                "version": plugin_data[0].get("version", ["unknown"])[0] if isinstance(plugin_data, list) else "unknown",
                                "source": "whatweb",
                            })
            except Exception:
                # Fallback: parse text output
                for match in re.finditer(r'\[([^\]]+)\]', stdout or ""):
                    tech_name = match.group(1)
                    if tech_name not in ("200 OK", "301 Moved Permanently", "302 Found"):
                        tech.append({
                            "name": tech_name,
                            "category": "unknown",
                            "version": "unknown",
                            "source": "whatweb",
                        })
            
            logger.info(f"WhatWeb detected {len(tech)} technologies")
        except Exception as e:
            logger.warning(f"WhatWeb failed: {e}")
        
        # Run httpx for additional fingerprinting
        try:
            rc, stdout, stderr = self.run_tool("httpx", [
                "-u", url,
                "-tech-detect",
                "-json",
                "-o", f"{self.workspace_dir}/httpx.json",
            ], timeout=60)
            
            try:
                with open(f"{self.workspace_dir}/httpx.json", "r") as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            tech_detect = data.get("tech", [])
                            for t in tech_detect:
                                if not any(existing["name"] == t for existing in tech):
                                    tech.append({
                                        "name": t,
                                        "category": "web_framework",
                                        "version": "unknown",
                                        "source": "httpx",
                                    })
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"httpx failed: {e}")
        
        return tech
    
    def _categorize_tech(self, name: str) -> str:
        """Categorize a technology name."""
        categories = {
            "WordPress": "cms", "Drupal": "cms", "Joomla": "cms",
            "Apache": "web_server", "Nginx": "web_server", "IIS": "web_server",
            "PHP": "language", "Python": "language", "Ruby": "language",
            "JavaScript": "language", "Node.js": "runtime",
            "React": "frontend", "Angular": "frontend", "Vue": "frontend",
            "jQuery": "frontend",
            "MySQL": "database", "PostgreSQL": "database", "MongoDB": "database",
            "Bootstrap": "frontend", "Cloudflare": "cdn",
        }
        return categories.get(name, "unknown")
    
    async def _check_dns(self, domain: str) -> Dict[str, List[str]]:
        """Check DNS records."""
        import subprocess
        records = {}
        record_types = ["A", "MX", "TXT", "NS", "SOA", "SPF", "DMARC"]
        
        for rtype in record_types:
            try:
                result = subprocess.run(
                    ["dig", "+short", rtype, domain],
                    capture_output=True, text=True, timeout=30
                )
                if result.stdout.strip():
                    records[rtype] = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
            except Exception:
                pass
        
        return records
    
    async def _probe_subdomains(self, subdomains: List[str]) -> List[str]:
        """Probe discovered subdomains for alive services using httpx."""
        alive = []
        
        if not subdomains:
            return alive
        
        # Write subdomains to file
        subdomains_file = f"{self.workspace_dir}/subdomains_all.txt"
        with open(subdomains_file, "w") as f:
            for sub in subdomains:
                f.write(f"{sub}\n")
        
        try:
            rc, stdout, stderr = self.run_tool("httpx", [
                "-l", subdomains_file,
                "-status-code",
                "-title",
                "-tech-detect",
                "-json",
                "-o", f"{self.workspace_dir}/httpx_subdomains.json",
            ], timeout=300)
            
            # Parse results
            try:
                with open(f"{self.workspace_dir}/httpx_subdomains.json", "r") as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            url = data.get("url", "")
                            status = data.get("status_code", 0)
                            if status and status < 500:
                                alive.append(url)
            except Exception:
                # Fallback: parse stdout
                for line in (stdout or "").split("\n"):
                    if line.strip().startswith("http"):
                        alive.append(line.strip())
            
            logger.info(f"Found {len(alive)} alive subdomains out of {len(subdomains)}")
        except Exception as e:
            logger.warning(f"httpx subdomain probing failed: {e}")
        
        return alive
    
    def _analyze_results(self, hostname: str, subdomains: List[str],
                         alive: List[str], ports: List[Dict], tech: List[Dict],
                         dns: Dict) -> List[Dict[str, Any]]:
        """Analyze recon results and generate findings."""
        findings = []
        
        # Check for open sensitive ports
        sensitive_ports = {
            21: ("FTP", "Anonymous FTP access or weak credentials"),
            23: ("Telnet", "Unencrypted Telnet - clear text credential transmission"),
            25: ("SMTP", "Open SMTP relay potential"),
            53: ("DNS", "DNS zone transfer potential"),
            110: ("POP3", "Unencrypted email access"),
            143: ("IMAP", "Unencrypted email access"),
            445: ("SMB", "SMB file sharing - potential for EternalBlue or similar"),
            1433: ("MSSQL", "Exposed MS SQL Server"),
            1521: ("Oracle", "Exposed Oracle Database"),
            3306: ("MySQL", "Exposed MySQL Database"),
            3389: ("RDP", "Exposed Remote Desktop - brute force risk"),
            5432: ("PostgreSQL", "Exposed PostgreSQL Database"),
            6379: ("Redis", "Exposed Redis - no auth by default"),
            9200: ("Elasticsearch", "Exposed Elasticsearch - data exposure risk"),
            27017: ("MongoDB", "Exposed MongoDB - no auth by default"),
            11211: ("Memcached", "Exposed Memcached - DDoS amplification risk"),
        }
        
        for port_info in ports:
            port_num = port_info["port"]
            if port_num in sensitive_ports:
                service_name, risk = sensitive_ports[port_num]
                findings.append(self.add_finding(
                    title=f"Exposed {service_name} Service on Port {port_num}",
                    description=f"The server has {service_name} service exposed on port {port_num}. {risk}.",
                    severity="high" if port_num in (3389, 445, 6379, 9200, 27017) else "medium",
                    cwe_id="CWE-284",
                    url=f"{hostname}:{port_num}",
                    evidence={"port_scan": port_info},
                    remediation=f"Restrict access to port {port_num} using a firewall. Only allow connections from trusted IPs. Consider using a VPN or bastion host for administrative access.",
                    tool_source="nmap",
                ))
        
        # Check for missing SPF
        if dns.get("TXT"):
            has_spf = any("v=spf1" in record for record in dns["TXT"])
            if not has_spf:
                findings.append(self.add_finding(
                    title="Missing SPF Record",
                    description="No SPF (Sender Policy Framework) record found in DNS. This allows attackers to spoof emails from your domain.",
                    severity="medium",
                    cwe_id="CWE-290",
                    evidence={"dns_records": dns},
                    remediation="Add an SPF record to your DNS: v=spf1 include:_spf.google.com ~all (adjust for your email provider)",
                    tool_source="dns",
                ))
        
        # Check for DNS zone transfer (if AXFR was attempted during amass)
        
        # Check for wildcard DNS
        if len(subdomains) > 100:
            findings.append(self.add_finding(
                title="Large Subdomain Enumeration Result",
                description=f"Found {len(subdomains)} subdomains. Large attack surface increases the risk of forgotten or unmaintained services being compromised.",
                severity="info",
                evidence={"subdomain_count": len(subdomains), "alive_count": len(alive)},
                remediation="Regularly audit and decommission unused subdomains. Implement a subdomain takeover monitoring program.",
                tool_source="subfinder",
            ))
        
        # Check for outdated software versions in tech detection
        outdated_software = {
            "Apache": [("2.4", "2.4.57"), ("2.2", None)],
            "Nginx": [("1.18", "1.24")],
            "PHP": [("5.", None), ("7.0", None), ("7.1", None), ("7.2", None), ("7.3", "7.4")],
            "WordPress": [],
        }
        
        for t in tech:
            name = t.get("name", "")
            version = t.get("version", "")
            if name in outdated_software and version:
                for vuln_ver, fixed_ver in outdated_software[name]:
                    if version.startswith(vuln_ver):
                        findings.append(self.add_finding(
                            title=f"Potentially Outdated {name} Version",
                            description=f"Detected {name} version {version}. This version may be outdated and contain known vulnerabilities.",
                            severity="medium",
                            cwe_id="CWE-1104",
                            evidence={"detected_tech": t},
                            remediation=f"Upgrade {name} to the latest stable version{f' (fixed in {fixed_ver})' if fixed_ver else ''}.",
                            tool_source="whatweb",
                        ))
                        break
        
        return findings