# ============================================
# SentinelAI - SSL/TLS Scanner
# ============================================
"""
SSL/TLS analysis using testssl.sh and SSLyze.
Checks certificate validity, cipher strength, protocol versions, and known vulnerabilities.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from scanner.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# Known SSL/TLS vulnerability patterns
VULNERABILITY_PATTERNS = {
    "heartbleed": {
        "name": "Heartbleed (CVE-2014-0160)",
        "severity": "critical",
        "cwe": "CWE-119",
        "description": "The Heartbleed vulnerability allows remote attackers to extract sensitive memory contents from the server, including private keys and passwords.",
    },
    "ccs": {
        "name": "CCS Injection (CVE-2014-0224)",
        "severity": "high",
        "cwe": "CWE-345",
        "description": "OpenSSL ChangeCipherSpec injection vulnerability allows man-in-the-middle attacks.",
    },
    "ticketbleed": {
        "name": "Ticketbleed (CVE-2016-9244)",
        "severity": "high",
        "cwe": "CWE-200",
        "description": "F5 Ticketbleed vulnerability leaks up to 31 bytes of uninitialized memory.",
    },
    "robot": {
        "name": "ROBOT Attack",
        "severity": "high",
        "cwe": "CWE-203",
        "description": "Return Of Bleichenbacher's Oracle Threat - allows decryption of RSA ciphertexts and signing with server's key.",
    },
    "crime": {
        "name": "CRIME",
        "severity": "medium",
        "cwe": "CWE-200",
        "description": "Compression Ratio Info-leak Made Easy - SSL compression can leak information.",
    },
    "breach": {
        "name": "BREACH",
        "severity": "medium",
        "cwe": "CWE-200",
        "description": "Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext - HTTP compression can leak secrets.",
    },
    "poodle": {
        "name": "POODLE",
        "severity": "high",
        "cwe": "CWE-310",
        "description": "Padding Oracle On Downgraded Legacy Encryption - SSL 3.0 vulnerability allowing plaintext extraction.",
    },
    "drown": {
        "name": "DROWN",
        "severity": "critical",
        "cwe": "CWE-310",
        "description": "Decrypting RSA with Obsolete and Weakened eNcryption - cross-protocol attack using SSLv2.",
    },
    "logjam": {
        "name": "Logjam",
        "severity": "high",
        "cwe": "CWE-310",
        "description": "Downgrade attack forcing use of weak 512-bit export-grade Diffie-Hellman keys.",
    },
    "freak": {
        "name": "FREAK",
        "severity": "high",
        "cwe": "CWE-310",
        "description": "Factoring RSA Export Keys - downgrade attack to export-grade RSA.",
    },
    "sweet32": {
        "name": "SWEET32",
        "severity": "low",
        "cwe": "CWE-310",
        "description": "64-bit block cipher birthday attack - 3DES vulnerabilities.",
    },
    "lucky13": {
        "name": "LUCKY13",
        "severity": "medium",
        "cwe": "CWE-310",
        "description": "Timing attack against CBC-mode ciphers in TLS.",
    },
    "beast": {
        "name": "BEAST",
        "severity": "medium",
        "cwe": "CWE-310",
        "description": "Browser Exploit Against SSL/TLS - CBC IV vulnerability in TLS 1.0.",
    },
    "rc4": {
        "name": "RC4 Cipher Support",
        "severity": "medium",
        "cwe": "CWE-327",
        "description": "RC4 stream cipher is broken and should not be used.",
    },
}


class SSLScanner(BaseScanner):
    """
    SSL/TLS security scanner.
    Analyzes certificates, protocols, ciphers, and known vulnerabilities.
    """
    
    module_name = "ssl"
    module_description = "SSL/TLS certificate and configuration analysis"
    
    async def run(self) -> List[Dict[str, Any]]:
        """Run SSL/TLS scanning."""
        findings = []
        
        # Extract hostname from target
        parsed = urlparse(self.target if self.target.startswith("http") else f"https://{self.target}")
        hostname = parsed.hostname or self.target
        
        # Run testssl.sh
        testssl_findings = await self._run_testssl(hostname)
        findings.extend(testssl_findings)
        
        # Run SSLyze for additional checks
        sslyze_findings = await self._run_sslyze(hostname)
        findings.extend(sslyze_findings)
        
        return findings
    
    async def _run_testssl(self, hostname: str) -> List[Dict[str, Any]]:
        """Run testssl.sh comprehensive SSL/TLS test."""
        findings = []
        port = self._get_port()
        
        try:
            rc, stdout, stderr = self.run_tool("testssl", [
                "--jsonfile", f"{self.workspace_dir}/testssl_output.json",
                "--full",
                "--warnings", "batch",
                f"{hostname}:{port}" if port != 443 else hostname,
            ], timeout=600)
            
            self.save_raw_output(stdout or stderr or "", "testssl")
            
            # Parse JSON output
            output_file = f"{self.workspace_dir}/testssl_output.json"
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    for scan_result in data:
                        finding = self._parse_testssl_result(scan_result, hostname)
                        if finding:
                            findings.append(finding)
            except (FileNotFoundError, json.JSONDecodeError):
                # Fallback: parse text output
                findings.extend(self._parse_testssl_text_output(stdout or "", hostname))
            
            logger.info(f"testssl.sh complete: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"testssl.sh failed: {e}")
        
        return findings
    
    def _parse_testssl_result(self, result: Dict, hostname: str) -> Optional[Dict[str, Any]]:
        """Parse a single testssl.sh JSON result."""
        severity = result.get("severity", "INFO").lower()
        id_val = result.get("id", "").lower()
        finding_text = result.get("finding", "")
        
        # Skip informational results
        if severity in ("ok", "info", "debug"):
            return None
        
        # Map severity
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "warn": "medium",
        }
        mapped_severity = severity_map.get(severity, "info")
        
        # Check for known vulnerabilities
        for vuln_key, vuln_info in VULNERABILITY_PATTERNS.items():
            if vuln_key in id_val or vuln_key in finding_text.lower():
                return self.add_finding(
                    title=vuln_info["name"],
                    description=f"{vuln_info['description']}\n\ntestssl.sh finding: {finding_text}",
                    severity=vuln_info["severity"],
                    cwe_id=vuln_info["cwe"],
                    url=f"https://{hostname}",
                    evidence={"testssl_result": result},
                    remediation=f"Update server configuration to disable the vulnerable feature. See: https://www.cve.org/CVERecord?id={vuln_info['name'].split('(')[1].replace(')', '') if '(' in vuln_info['name'] else ''}",
                    tool_source="testssl.sh",
                )
        
        # Check for specific issues
        if "certificate" in id_val:
            return self._parse_certificate_issue(result, hostname, mapped_severity)
        elif "protocol" in id_val:
            return self._parse_protocol_issue(result, hostname, mapped_severity)
        elif "cipher" in id_val:
            return self._parse_cipher_issue(result, hostname, mapped_severity)
        
        # Generic finding
        return self.add_finding(
            title=f"SSL/TLS: {result.get('headline', id_val)}",
            description=finding_text,
            severity=mapped_severity,
            cwe_id="CWE-319",
            url=f"https://{hostname}",
            evidence={"testssl_result": result},
            tool_source="testssl.sh",
        )
    
    def _parse_testssl_text_output(self, output: str, hostname: str) -> List[Dict[str, Any]]:
        """Parse testssl.sh text output as fallback."""
        findings = []
        
        # Parse vulnerability checks
        vuln_checks = [
            (r"Heartbleed\s*.*VULNERABLE", "heartbleed"),
            (r"CCS\s*.*VULNERABLE", "ccs"),
            (r"Ticketbleed\s*.*VULNERABLE", "ticketbleed"),
            (r"ROBOT\s*.*VULNERABLE", "robot"),
            (r"CRIME\s*.*VULNERABLE", "crime"),
            (r"BREACH\s*.*VULNERABLE", "breach"),
            (r"POODLE\s*.*VULNERABLE", "poodle"),
            (r"DROWN\s*.*VULNERABLE", "drown"),
            (r"LOGJAM\s*.*VULNERABLE", "logjam"),
            (r"FREAK\s*.*VULNERABLE", "freak"),
            (r"SWEET32\s*.*VULNERABLE", "sweet32"),
            (r"LUCKY13\s*.*VULNERABLE", "lucky13"),
            (r"BEAST\s*.*VULNERABLE", "beast"),
        ]
        
        for pattern, vuln_key in vuln_checks:
            if re.search(pattern, output, re.IGNORECASE):
                vuln_info = VULNERABILITY_PATTERNS.get(vuln_key)
                if vuln_info:
                    findings.append(self.add_finding(
                        title=vuln_info["name"],
                        description=vuln_info["description"],
                        severity=vuln_info["severity"],
                        cwe_id=vuln_info["cwe"],
                        url=f"https://{hostname}",
                        tool_source="testssl.sh",
                    ))
        
        # Check certificate expiry
        expiry_match = re.search(r"Not valid after\s*:\s*(.+)", output)
        if expiry_match:
            expiry_str = expiry_match.group(1).strip()
            try:
                from datetime import datetime
                # Try to parse various date formats
                expiry_date = None
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%b %d %H:%M:%S %Y %Z"]:
                    try:
                        expiry_date = datetime.strptime(expiry_str, fmt)
                        break
                    except ValueError:
                        continue
                
                if expiry_date and expiry_date < datetime.now(timezone.utc):
                    findings.append(self.add_finding(
                        title="Expired SSL/TLS Certificate",
                        description=f"The SSL certificate expired on {expiry_str}. Connections will be rejected by browsers.",
                        severity="critical",
                        cwe_id="CWE-298",
                        url=f"https://{hostname}",
                        evidence={"expiry_date": expiry_str},
                        remediation="Renew the SSL certificate immediately. Set up automated renewal with Let's Encrypt or your certificate provider.",
                        tool_source="testssl.sh",
                    ))
                elif expiry_date and (expiry_date - datetime.now(timezone.utc)).days < 30:
                    findings.append(self.add_finding(
                        title="SSL Certificate Expiring Soon",
                        description=f"The SSL certificate expires on {expiry_str} (less than 30 days).",
                        severity="medium",
                        cwe_id="CWE-298",
                        url=f"https://{hostname}",
                        evidence={"expiry_date": expiry_str, "days_remaining": (expiry_date - datetime.now(timezone.utc)).days},
                        remediation="Renew the SSL certificate before expiration to avoid service disruption.",
                        tool_source="testssl.sh",
                    ))
            except Exception:
                pass
        
        # Check protocol versions
        weak_protocols = {
            "SSLv2": "critical",
            "SSLv3": "critical",
            "TLS 1.0": "high",
            "TLS 1.1": "medium",
        }
        
        for protocol, severity in weak_protocols.items():
            if f"{protocol}" in output and "offered" in output.lower():
                # Check if it's actually offered
                lines = output.split("\n")
                for line in lines:
                    if protocol in line and ("offered" in line.lower() or "yes" in line.lower()):
                        if "not" not in line.lower() or "not offered" in line.lower():
                            if "not offered" not in line.lower():
                                findings.append(self.add_finding(
                                    title=f"Weak Protocol Enabled: {protocol}",
                                    description=f"{protocol} is enabled. This protocol has known vulnerabilities and should be disabled.",
                                    severity=severity,
                                    cwe_id="CWE-326",
                                    url=f"https://{hostname}",
                                    remediation=f"Disable {protocol} in your web server configuration. Only allow TLS 1.2 and TLS 1.3.",
                                    tool_source="testssl.sh",
                                ))
                        break
        
        return findings
    
    def _parse_certificate_issue(self, result: Dict, hostname: str, severity: str) -> Dict[str, Any]:
        """Parse certificate-related testssl finding."""
        finding_text = result.get("finding", "")
        id_val = result.get("id", "")
        
        title = f"Certificate Issue: {result.get('headline', id_val)}"
        cwe = "CWE-298"
        remediation = "Review and fix the certificate configuration."
        
        if "expired" in finding_text.lower():
            title = "Expired SSL/TLS Certificate"
            severity = "critical"
            remediation = "Renew the SSL certificate immediately."
        elif "self-signed" in finding_text.lower() or "self signed" in finding_text.lower():
            title = "Self-Signed Certificate"
            severity = "high"
            cwe = "CWE-295"
            remediation = "Replace the self-signed certificate with a certificate from a trusted CA (e.g., Let's Encrypt, DigiCert)."
        elif "chain" in finding_text.lower() and ("incomplete" in finding_text.lower() or "issue" in finding_text.lower()):
            title = "Incomplete Certificate Chain"
            severity = "medium"
            remediation = "Install all intermediate certificates on the server. Include the full chain in the server configuration."
        elif "hostname" in finding_text.lower() or "mismatch" in finding_text.lower():
            title = "Certificate Hostname Mismatch"
            severity = "high"
            cwe = "CWE-297"
            remediation = "Ensure the certificate covers all domains/subdomains being served. Use a wildcard or SAN certificate."
        elif "weak" in finding_text.lower() and "signature" in finding_text.lower():
            title = "Weak Certificate Signature Algorithm"
            severity = "medium"
            cwe = "CWE-327"
            remediation = "Replace certificates using SHA-1 or MD5 with SHA-256 signed certificates."
        
        return self.add_finding(
            title=title,
            description=finding_text,
            severity=severity,
            cwe_id=cwe,
            url=f"https://{hostname}",
            evidence={"testssl_result": result},
            remediation=remediation,
            tool_source="testssl.sh",
        )
    
    def _parse_protocol_issue(self, result: Dict, hostname: str, severity: str) -> Dict[str, Any]:
        """Parse protocol-related testssl finding."""
        finding_text = result.get("finding", "")
        id_val = result.get("id", "")
        
        protocol = ""
        for p in ["SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]:
            if p.lower() in id_val.lower():
                protocol = p
                break
        
        return self.add_finding(
            title=f"Protocol Issue: {protocol or result.get('headline', id_val)}",
            description=finding_text,
            severity=severity,
            cwe_id="CWE-326",
            url=f"https://{hostname}",
            evidence={"testssl_result": result},
            remediation=f"Disable deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1). Only enable TLS 1.2 and TLS 1.3.",
            tool_source="testssl.sh",
        )
    
    def _parse_cipher_issue(self, result: Dict, hostname: str, severity: str) -> Dict[str, Any]:
        """Parse cipher-related testssl finding."""
        finding_text = result.get("finding", "")
        id_val = result.get("id", "")
        
        return self.add_finding(
            title=f"Cipher Issue: {result.get('headline', id_val)}",
            description=finding_text,
            severity=severity,
            cwe_id="CWE-326",
            url=f"https://{hostname}",
            evidence={"testssl_result": result},
            remediation="Disable weak ciphers (RC4, DES, 3DES, export ciphers). Only allow AEAD ciphers with PFS (AES-GCM, ChaCha20-Poly1305).",
            tool_source="testssl.sh",
        )
    
    async def _run_sslyze(self, hostname: str) -> List[Dict[str, Any]]:
        """Run SSLyze for additional SSL/TLS checks."""
        findings = []
        port = self._get_port()
        
        try:
            rc, stdout, stderr = self.run_tool("sslyze", [
                "--json_out", f"{self.workspace_dir}/sslyze_output.json",
                "--certinfo",
                "--elliptic_curves",
                "--http_headers",
                f"{hostname}:{port}" if port != 443 else hostname,
            ], timeout=300)
            
            self.save_raw_output(stdout or stderr or "", "sslyze")
            
            # Parse JSON output
            output_file = f"{self.workspace_dir}/sslyze_output.json"
            try:
                with open(output_file, "r") as f:
                    data = json.load(f)
                    findings.extend(self._parse_sslyze_output(data, hostname))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            
            logger.info(f"SSLyze complete: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"SSLyze failed: {e}")
        
        return findings
    
    def _parse_sslyze_output(self, data: Dict, hostname: str) -> List[Dict[str, Any]]:
        """Parse SSLyze JSON output."""
        findings = []
        
        server_scan = data.get("server_scan_results", [])
        if not server_scan:
            return findings
        
        for scan_result in server_scan:
            scan_commands = scan_result.get("scan_commands_results", {})
            
            # Check certificate info
            cert_info = scan_commands.get("certificate_info", {})
            if cert_info:
                cert_deployments = cert_info.get("certificate_deployments", [])
                for deployment in cert_deployments:
                    # Check trust stores
                    for path_result in deployment.get("path_validation_results", []):
                        if not path_result.get("verify_string") == "ok":
                            findings.append(self.add_finding(
                                title="Certificate Not Trusted",
                                description=f"Certificate is not trusted by {path_result.get('trust_store', {}).get('name', 'unknown trust store')}: {path_result.get('verify_string', '')}",
                                severity="high",
                                cwe_id="CWE-295",
                                url=f"https://{hostname}",
                                tool_source="sslyze",
                            ))
                    
                    # Check OCSP must-staple
                    leaf_cert = deployment.get("received_certificate_chain", [{}])[0]
                    if leaf_cert:
                        extensions = leaf_cert.get("extensions", {})
                        has_ocsp_must_staple = extensions.get("ocsp_must_staple", False)
                        ocsp_response = deployment.get("ocsp_response", {})
                        if has_ocsp_must_staple and not ocsp_response:
                            findings.append(self.add_finding(
                                title="OCSP Must-Staple Not Enforced",
                                description="Certificate has OCSP Must-Staple extension but no OCSP response was stapled.",
                                severity="medium",
                                cwe_id="CWE-299",
                                url=f"https://{hostname}",
                                tool_source="sslyze",
                            ))
            
            # Check elliptic curves
            curves = scan_commands.get("elliptic_curves", {})
            if curves:
                supported_curves = curves.get("supported_curves", [])
                weak_curves = [c for c in supported_curves if c.get("name", "") in ("secp160k1", "secp160r1", "secp192k1", "secp192r1")]
                if weak_curves:
                    findings.append(self.add_finding(
                        title="Weak Elliptic Curves Supported",
                        description=f"Weak elliptic curves are supported: {[c.get('name') for c in weak_curves]}. These provide insufficient key strength.",
                        severity="medium",
                        cwe_id="CWE-326",
                        url=f"https://{hostname}",
                        tool_source="sslyze",
                    ))
        
        return findings
    
    def _get_port(self) -> int:
        """Extract port from target or use default."""
        parsed = urlparse(self.target if self.target.startswith("http") else f"https://{self.target}")
        return parsed.port or (443 if parsed.scheme == "https" else 80)