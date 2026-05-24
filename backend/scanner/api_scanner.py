# ============================================
# SentinelAI - API Security Scanner
# ============================================
"""
API security testing using Nuclei API templates and custom fuzzing.
Tests for OWASP API Top 10: BOLA, BFLA, broken auth, rate limiting, SSRF, etc.
"""

import json
import logging
import random
import string
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from scanner.base_scanner import BaseScanner

logger = logging.getLogger(__name__)

# OWASP API Top 10 test configurations
API_TESTS = {
    "bola": {
        "name": "Broken Object Level Authorization (BOLA/IDOR)",
        "description": "Testing for IDOR by manipulating resource IDs in API endpoints",
        "severity": "critical",
        "cwe": "CWE-639",
    },
    "broken_auth": {
        "name": "Broken Authentication",
        "description": "Testing for weak authentication mechanisms",
        "severity": "critical",
        "cwe": "CWE-287",
    },
    "bfla": {
        "name": "Broken Function Level Authorization (BFLA)",
        "description": "Testing for unauthorized function access",
        "severity": "high",
        "cwe": "CWE-285",
    },
    "excessive_data": {
        "name": "Excessive Data Exposure",
        "description": "Testing for over-exposure of sensitive data in API responses",
        "severity": "high",
        "cwe": "CWE-200",
    },
    "mass_assignment": {
        "name": "Mass Assignment",
        "description": "Testing for mass assignment vulnerabilities",
        "severity": "high",
        "cwe": "CWE-915",
    },
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Testing for SSRF in API parameters",
        "severity": "critical",
        "cwe": "CWE-918",
    },
    "rate_limiting": {
        "name": "Missing Rate Limiting",
        "description": "Testing for rate limiting on authentication and sensitive endpoints",
        "severity": "medium",
        "cwe": "CWE-770",
    },
    "verbose_errors": {
        "name": "Verbose Error Messages",
        "description": "Testing for stack traces and sensitive info in error responses",
        "severity": "medium",
        "cwe": "CWE-209",
    },
    "injection": {
        "name": "Injection Vulnerabilities",
        "description": "Testing for SQL injection, command injection, and NoSQL injection",
        "severity": "critical",
        "cwe": "CWE-89",
    },
}

# Common API paths to test
COMMON_API_PATHS = [
    "/api/", "/api/v1/", "/api/v2/",
    "/api/users", "/api/user", "/api/profile",
    "/api/admin", "/api/admin/users",
    "/api/auth", "/api/login", "/api/register",
    "/api/products", "/api/orders", "/api/items",
    "/api/search", "/api/query",
    "/api/upload", "/api/files",
    "/api/config", "/api/settings",
    "/api/health", "/api/status",
    "/graphql",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/v1/", "/v2/",
]

# Sensitive keywords in responses
SENSITIVE_KEYWORDS = [
    "password", "secret", "token", "api_key", "apikey",
    "credit_card", "ssn", "social_security",
    "internal", "private", "confidential",
    "admin", "root", "system",
    "connection_string", "database_url",
]


class APIScanner(BaseScanner):
    """
    API security scanner.
    Tests for OWASP API Top 10 vulnerabilities and common API security issues.
    """
    
    module_name = "api_security"
    module_description = "API security testing (OWASP API Top 10)"
    
    async def run(self) -> List[Dict[str, Any]]:
        """Run API security scanning."""
        findings = []
        base_url = self.target if self.target.startswith("http") else f"http://{self.target}"
        
        # Parse OpenAPI spec if provided
        spec = self.config.get("spec_content") or self.config.get("spec_url")
        endpoints = []
        if spec:
            endpoints = self._parse_openapi_spec(spec)
        
        # If no spec or no endpoints found, use common paths
        if not endpoints:
            endpoints = self._discover_endpoints(base_url)
        
        # Run Nuclei API templates
        nuclei_findings = await self._run_nuclei_api(base_url)
        findings.extend(nuclei_findings)
        
        # Run custom API tests
        custom_findings = await self._run_custom_tests(base_url, endpoints)
        findings.extend(custom_findings)
        
        return findings
    
    def _parse_openapi_spec(self, spec: Any) -> List[Dict[str, str]]:
        """Parse OpenAPI/Swagger specification."""
        endpoints = []
        
        try:
            if isinstance(spec, str):
                spec = json.loads(spec) if spec.strip().startswith("{") else yaml.safe_load(spec)
            
            if not isinstance(spec, dict):
                return endpoints
            
            paths = spec.get("paths", {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.lower() in ("get", "post", "put", "delete", "patch"):
                        endpoints.append({
                            "path": path,
                            "method": method.upper(),
                            "parameters": details.get("parameters", []),
                        })
        except Exception as e:
            logger.warning(f"Failed to parse OpenAPI spec: {e}")
        
        return endpoints
    
    def _discover_endpoints(self, base_url: str) -> List[Dict[str, str]]:
        """Discover API endpoints by checking common paths."""
        endpoints = []
        for path in COMMON_API_PATHS:
            endpoints.append({"path": path, "method": "GET", "parameters": []})
        return endpoints
    
    async def _run_nuclei_api(self, base_url: str) -> List[Dict[str, Any]]:
        """Run Nuclei with API-specific templates."""
        findings = []
        
        try:
            rc, stdout, stderr = self.run_tool("nuclei", [
                "-u", base_url,
                "-t", "exposures/apis",
                "-json",
                "-o", f"{self.workspace_dir}/nuclei_api_output.json",
                "-timeout", "15",
            ], timeout=600)
            
            self.save_raw_output(stdout or stderr or "", "nuclei_api")
            
            # Parse JSON output
            output_file = f"{self.workspace_dir}/nuclei_api_output.json"
            try:
                with open(output_file, "r") as f:
                    for line in f:
                        if line.strip():
                            data = json.loads(line)
                            findings.append(self._parse_nuclei_api_finding(data, base_url))
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            
            logger.info(f"Nuclei API: {len(findings)} findings")
            
        except Exception as e:
            logger.warning(f"Nuclei API scan failed: {e}")
        
        return findings
    
    def _parse_nuclei_api_finding(self, data: Dict, base_url: str) -> Dict[str, Any]:
        """Parse a Nuclei API finding."""
        severity = (data.get("info", {}).get("severity", "info") or "info").lower()
        
        return self.add_finding(
            title=f"Nuclei API: {data.get('info', {}).get('name', 'API Issue')}",
            description=data.get("info", {}).get("description", ""),
            severity=severity,
            cwe_id=None,
            url=data.get("matched-at", base_url),
            evidence={
                "template_id": data.get("template-id", ""),
                "curl_command": data.get("curl-command", ""),
            },
            tool_source="nuclei_api",
        )
    
    async def _run_custom_tests(self, base_url: str, endpoints: List[Dict]) -> List[Dict[str, Any]]:
        """Run custom API security tests."""
        findings = []
        
        # Get auth token if provided
        auth_token = self.config.get("auth_token")
        headers = {"Content-Type": "application/json"}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        
        # Merge custom headers
        custom_headers = self.config.get("custom_headers", {})
        headers.update(custom_headers)
        
        async with httpx.AsyncClient(verify=False, timeout=30.0, follow_redirects=False) as client:
            # Test for verbose errors
            error_findings = await self._test_verbose_errors(client, base_url, endpoints, headers)
            findings.extend(error_findings)
            
            # Test for rate limiting
            rate_limit_findings = await self._test_rate_limiting(client, base_url, endpoints, headers)
            findings.extend(rate_limit_findings)
            
            # Test for BOLA/IDOR
            bola_findings = await self._test_bola(client, base_url, endpoints, headers)
            findings.extend(bola_findings)
            
            # Test for SSRF
            ssrf_findings = await self._test_ssrf(client, base_url, endpoints, headers)
            findings.extend(ssrf_findings)
            
            # Test for injection
            injection_findings = await self._test_injection(client, base_url, endpoints, headers)
            findings.extend(injection_findings)
            
            # Test for authentication bypass
            auth_findings = await self._test_auth_bypass(client, base_url, endpoints, headers)
            findings.extend(auth_findings)
            
            # Test for excessive data exposure
            data_findings = await self._test_data_exposure(client, base_url, endpoints, headers)
            findings.extend(data_findings)
        
        return findings
    
    async def _test_verbose_errors(self, client: httpx.AsyncClient, base_url: str,
                                   endpoints: List[Dict], headers: Dict) -> List[Dict[str, Any]]:
        """Test for verbose error messages that leak stack traces."""
        findings = []
        
        # Send malformed requests to trigger errors
        test_endpoints = [e for e in endpoints[:10] if e["method"] == "GET"]
        
        for endpoint in test_endpoints:
            url = urljoin(base_url, endpoint["path"])
            
            try:
                # Send invalid parameter
                response = await client.get(url, params={"error": "true", "debug": "1"}, headers=headers)
                
                response_text = response.text.lower()
                if any(keyword in response_text for keyword in ["stack trace", "traceback", "at ", "file \"", "line ", "<b>", "exception"]):
                    if len(response.text) > 200 and ("error" in response_text or "exception" in response_text):
                        findings.append(self.add_finding(
                            title=API_TESTS["verbose_errors"]["name"],
                            description=f"The API at {url} returns verbose error messages that may contain stack traces, file paths, or internal implementation details.",
                            severity=API_TESTS["verbose_errors"]["severity"],
                            cwe_id=API_TESTS["verbose_errors"]["cwe"],
                            url=url,
                            evidence={
                                "status_code": response.status_code,
                                "response_preview": response.text[:500],
                            },
                            remediation="Configure the API to return generic error messages to clients. Log detailed errors server-side only. Disable debug mode in production.",
                            tool_source="api_fuzzer",
                        ))
                        break  # One finding is enough
                        
            except Exception:
                pass
        
        return findings
    
    async def _test_rate_limiting(self, client: httpx.AsyncClient, base_url: str,
                                  endpoints: List[Dict], headers: Dict) -> List[Dict[str, Any]]:
        """Test for missing rate limiting on sensitive endpoints."""
        findings = []
        
        # Test auth endpoints specifically
        auth_paths = ["/api/auth/login", "/api/login", "/api/auth", "/auth", "/login"]
        test_urls = [urljoin(base_url, p) for p in auth_paths]
        
        for url in test_urls:
            try:
                # Send 5 rapid requests
                responses = []
                for _ in range(5):
                    response = await client.post(
                        url,
                        json={"username": "test", "password": "test123"},
                        headers=headers,
                    )
                    responses.append(response)
                
                # Check if all requests succeeded (no rate limiting)
                success_count = sum(1 for r in responses if r.status_code in (200, 401, 403))
                
                # Check for rate limit headers
                has_rate_limit = any(
                    h in responses[0].headers for h in ["x-ratelimit-limit", "x-rate-limit", "retry-after"]
                )
                
                if success_count >= 5 and not has_rate_limit:
                    findings.append(self.add_finding(
                        title=API_TESTS["rate_limiting"]["name"],
                        description=f"The endpoint {url} does not implement rate limiting. 5 consecutive requests were accepted without throttling. This enables brute force attacks.",
                        severity=API_TESTS["rate_limiting"]["severity"],
                        cwe_id=API_TESTS["rate_limiting"]["cwe"],
                        url=url,
                        evidence={
                            "requests_sent": 5,
                            "responses": [r.status_code for r in responses],
                            "rate_limit_headers": dict(responses[0].headers) if has_rate_limit else None,
                        },
                        remediation="Implement rate limiting on all API endpoints, especially authentication endpoints. Use sliding window or token bucket algorithms. Return 429 status when limit exceeded.",
                        tool_source="api_fuzzer",
                    ))
                    break
                    
            except Exception:
                pass
        
        return findings
    
    async def _test_bola(self, client: httpx.AsyncClient, base_url: str,
                         endpoints: List[Dict], headers: Dict) -> List[Dict[str, Any]]:
        """Test for Broken Object Level Authorization (BOLA/IDOR)."""
        findings = []
        
        # Look for endpoints with numeric IDs
        id_patterns = [r"/\d+", r"/[a-f0-9]{24}", r"/[0-9a-f-]{36}"]
        
        test_endpoints = [e for e in endpoints if any(p in e["path"] for p in ["/users", "/user", "/profile", "/items", "/products", "/orders"])]
        
        for endpoint in test_endpoints:
            url = urljoin(base_url, endpoint["path"])
            
            try:
                # Try accessing different IDs
                test_ids = ["1", "2", "3", str(random.randint(100, 999999))]
                successful_access = []
                
                for test_id in test_ids:
                    test_url = f"{url}/{test_id}"
                    response = await client.get(test_url, headers=headers)
                    if response.status_code == 200:
                        successful_access.append(test_id)
                
                if len(successful_access) >= 3:
                    findings.append(self.add_finding(
                        title=API_TESTS["bola"]["name"],
                        description=f"The API endpoint {url}/{{id}} returned valid data for multiple different IDs ({successful_access[:5]}). This suggests missing authorization checks on object access.",
                        severity=API_TESTS["bola"]["severity"],
                        cwe_id=API_TESTS["bola"]["cwe"],
                        url=url,
                        evidence={
                            "accessible_ids": successful_access[:10],
                            "tested_ids": test_ids,
                        },
                        remediation="Implement proper authorization checks for every API endpoint that accesses objects. Verify the authenticated user has permission to access the requested resource ID. Use indirect reference maps (GUIDs) instead of sequential IDs.",
                        tool_source="api_fuzzer",
                    ))
                    break
                    
            except Exception:
                pass
        
        return findings
    
    async def _test_ssrf(self, client: httpx.AsyncClient, base_url: str,
                         endpoints: List[Dict], headers: Dict) -> List[Dict[str, Any]]:
        """Test for Server-Side Request Forgery (SSRF)."""
        findings = []
        
        # Look for endpoints that might accept URLs
        url_params = ["url", "uri", "path", "link", "redirect", "callback", "endpoint", "target", "src"]
        
        post_endpoints = [e for e in endpoints[:15] if e["method"] in ("POST", "PUT", "PATCH")]
        get_endpoints = [e for e in endpoints[:15] if e["method"] == "GET"]
        
        # Test POST endpoints with URL parameters
        for endpoint in post_endpoints:
            url = urljoin(base_url, endpoint["path"])
            
            for param in url_params:
                try:
                    test_payloads = [
                        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
                        "http://localhost:22",  # Local SSH
                        "http://127.0.0.1:8080",  # Local service
                        "file:///etc/passwd",  # File read
                    ]
                    
                    for payload in test_payloads:
                        response = await client.post(
                            url,
                            json={param: payload},
                            headers=headers,
                            timeout=10.0,
                        )
                        
                        # Check for signs of SSRF
                        if response.status_code == 200:
                            body = response.text.lower()
                            if any(indicator in body for indicator in ["ami-id", "instance-id", "root", "ssh", "amazon"]):
                                findings.append(self.add_finding(
                                    title=API_TESTS["ssrf"]["name"],
                                    description=f"The API at {url} appears vulnerable to SSRF. A request to {payload} through the '{param}' parameter returned data from the internal resource.",
                                    severity=API_TESTS["ssrf"]["severity"],
                                    cwe_id=API_TESTS["ssrf"]["cwe"],
                                    url=url,
                                    parameter=param,
                                    evidence={
                                        "payload": payload,
                                        "response_preview": response.text[:500],
                                    },
                                    remediation="Validate and sanitize all URL inputs. Use an allowlist of permitted domains. Disable URL schemas like file://, gopher://, and ftp://. Implement network segmentation.",
                                    tool_source="api_fuzzer",
                                ))
                                return findings
                                
                except Exception:
                    pass
        
        return findings
    
    async def _test_injection(self, client: httpx.AsyncClient, base_url: str,
                              endpoints: List[Dict], headers: Dict) -> List[Dict[str, Any]]:
        """Test for injection vulnerabilities in API parameters."""
        findings = []
        
        # SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT null,null,null--",
            "1 AND 1=1",
            "1' AND 1=1--",
            "\" OR \"1\"=\"1",
        ]
        
        post_endpoints = [e for e in endpoints[:10] if e["method"] in ("POST", "PUT")]
        
        for endpoint in post_endpoints:
            url = urljoin(base_url, endpoint["path"])
            
            try:
                # Send SQLi payloads in JSON body
                for payload in sql_payloads:
                    response = await client.post(
                        url,
                        json={"search": payload, "query": payload, "id": payload},
                        headers=headers,
                        timeout=10.0,
                    )
                    
                    error_indicators = [
                        "sql syntax", "mysql_fetch", "pg_query", "sqlite_query",
                        "ORA-", "SQL Server", "ODBC", "syntax error",
                        "unterminated", "unknown column",
                    ]
                    
                    response_lower = response.text.lower()
                    if any(indicator in response_lower for indicator in error_indicators):
                        findings.append(self.add_finding(
                            title=API_TESTS["injection"]["name"],
                            description=f"The API at {url} appears vulnerable to SQL injection. The payload '{payload[:30]}...' triggered a database error in the response.",
                            severity=API_TESTS["injection"]["severity"],
                            cwe_id=API_TESTS["injection"]["cwe"],
                            url=url,
                            evidence={
                                "payload": payload,
                                "response_preview": response.text[:500],
                                "status_code": response.status_code,
                            },
                            remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL queries. Implement input validation and ORM frameworks.",
                            tool_source="api_fuzzer",
                        ))
                        return findings
                        
            except Exception:
                pass
        
        return findings
    
    async def _test_auth_bypass(self, client: httpx.AsyncClient, base_url: str,
                                endpoints: List[Dict], headers: Dict) -> List[Dict[str, Any]]:
        """Test for authentication bypass on sensitive endpoints."""
        findings = []
        
        # Test admin/sensitive endpoints without auth
        sensitive_patterns = ["/admin", "/api/admin", "/api/users", "/api/config", "/api/settings", "/api/keys"]
        
        for pattern in sensitive_patterns:
            url = urljoin(base_url, pattern)
            
            try:
                # Request without auth headers
                no_auth_headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
                response = await client.get(url, headers=no_auth_headers)
                
                if response.status_code == 200:
                    findings.append(self.add_finding(
                        title=API_TESTS["broken_auth"]["name"],
                        description=f"The endpoint {url} is accessible without authentication. This endpoint should require valid credentials.",
                        severity=API_TESTS["broken_auth"]["severity"],
                        cwe_id=API_TESTS["broken_auth"]["cwe"],
                        url=url,
                        evidence={
                            "status_code": response.status_code,
                            "response_size": len(response.text),
                        },
                        remediation="Enforce authentication on all sensitive API endpoints. Implement proper authorization middleware. Return 401 for unauthenticated requests and 403 for unauthorized access.",
                        tool_source="api_fuzzer",
                    ))
                    break
                    
            except Exception:
                pass
        
        return findings
    
    async def _test_data_exposure(self, client: httpx.AsyncClient, base_url: str,
                                  endpoints: List[Dict], headers: Dict) -> List[Dict[str, Any]]:
        """Test for excessive data exposure in API responses."""
        findings = []
        
        # Test endpoints that return user data
        user_endpoints = [e for e in endpoints if any(p in e["path"] for p in ["/users", "/user", "/profile", "/account"])]
        
        for endpoint in user_endpoints[:5]:
            url = urljoin(base_url, endpoint["path"])
            
            try:
                response = await client.get(url, headers=headers)
                
                if response.status_code == 200:
                    response_text = response.text.lower()
                    
                    # Check for sensitive data
                    found_sensitive = []
                    for keyword in SENSITIVE_KEYWORDS:
                        if keyword in response_text:
                            found_sensitive.append(keyword)
                    
                    if len(found_sensitive) >= 3:
                        findings.append(self.add_finding(
                            title=API_TESTS["excessive_data"]["name"],
                            description=f"The API at {url} returns responses containing sensitive fields: {', '.join(found_sensitive[:10])}. APIs should not expose sensitive data unnecessarily.",
                            severity=API_TESTS["excessive_data"]["severity"],
                            cwe_id=API_TESTS["excessive_data"]["cwe"],
                            url=url,
                            evidence={
                                "sensitive_fields_found": found_sensitive[:20],
                                "response_preview": response.text[:500],
                            },
                            remediation="Implement response filtering to only return necessary fields. Use Data Transfer Objects (DTOs) to control API output. Never expose passwords, secrets, or internal identifiers.",
                            tool_source="api_fuzzer",
                        ))
                        break
                        
            except Exception:
                pass
        
        return findings