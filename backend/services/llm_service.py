# ============================================
# SentinelAI - LLM Service
# ============================================
"""
LLM integration service for SentinelAI.
Supports multiple providers: DeepSeek, OpenAI, Anthropic, Groq, Ollama.
Handles result correlation, remediation advice, executive summaries, and code review.
"""

import json
import logging
import asyncio
from typing import Optional, List, Dict, Any
from datetime import datetime

from config import settings
from utils.crypto_utils import decrypt_text

logger = logging.getLogger(__name__)


# SentinelAI system prompt - establishes the AI as a security expert
SENTINELAI_SYSTEM_PROMPT = """You are SentinelAI, an expert penetration tester and security auditor with 20+ years of experience in cybersecurity. You specialize in:

- Web application security (OWASP Top 10, WASC)
- API security (OWASP API Top 10)
- Source code analysis (SAST)
- Infrastructure and cloud security
- Network penetration testing
- Vulnerability assessment and risk analysis
- Secure code review and remediation

Your analysis is thorough, precise, and actionable. You provide:
1. Accurate vulnerability classification with CWE/CVE references
2. Realistic risk assessment considering business context
3. Step-by-step remediation instructions with secure code examples
4. Attack chain analysis showing how vulnerabilities can be chained

Always respond in valid JSON format as specified in the user's request."""


class LLMService:
    """Service for LLM interactions across multiple providers."""
    
    def __init__(self, provider: Optional[str] = None, api_key: Optional[str] = None,
                 model: Optional[str] = None, base_url: Optional[str] = None):
        self.provider = provider or settings.LLM_PROVIDER
        self.api_key = api_key or settings.LLM_API_KEY
        self.model = model or settings.LLM_MODEL
        self.base_url = base_url or settings.LLM_BASE_URL
        
        if not self.api_key and self.provider != "ollama":
            logger.warning(f"No API key configured for LLM provider: {self.provider}")
    
    async def _call_llm(self, messages: List[Dict[str, str]], max_tokens: Optional[int] = None,
                        temperature: Optional[float] = None) -> str:
        """Make an LLM API call with retry logic."""
        max_retries = settings.LLM_MAX_RETRIES
        retry_delay = settings.LLM_RETRY_DELAY
        
        for attempt in range(max_retries):
            try:
                if self.provider == "deepseek":
                    return await self._call_deepseek(messages, max_tokens, temperature)
                elif self.provider == "openai":
                    return await self._call_openai(messages, max_tokens, temperature)
                elif self.provider == "anthropic":
                    return await self._call_anthropic(messages, max_tokens, temperature)
                elif self.provider == "groq":
                    return await self._call_groq(messages, max_tokens, temperature)
                elif self.provider == "ollama":
                    return await self._call_ollama(messages, max_tokens, temperature)
                else:
                    raise ValueError(f"Unsupported LLM provider: {self.provider}")
                    
            except Exception as e:
                logger.warning(f"LLM call attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay * (2 ** attempt))
                else:
                    logger.error(f"All LLM call attempts failed: {e}")
                    raise
        
        return ""
    
    async def _call_deepseek(self, messages: List[Dict[str, str]], max_tokens: Optional[int] = None,
                             temperature: Optional[float] = None) -> str:
        """Call DeepSeek API."""
        import httpx
        
        url = self.base_url or "https://api.deepseek.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model or "deepseek-chat",
            "messages": messages,
            "max_tokens": max_tokens or settings.LLM_MAX_TOKENS,
            "temperature": settings.LLM_TEMPERATURE if temperature is None else temperature,  # Bug #14 fixed: temperature=0.0 was falsy
            "response_format": {"type": "json_object"},
        }
        
        async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
    
    async def _call_openai(self, messages: List[Dict[str, str]], max_tokens: Optional[int] = None,
                           temperature: Optional[float] = None) -> str:
        """Call OpenAI API."""
        import httpx
        
        url = self.base_url or "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model or "gpt-4",
            "messages": messages,
            "max_tokens": max_tokens or settings.LLM_MAX_TOKENS,
            "temperature": settings.LLM_TEMPERATURE if temperature is None else temperature,  # Bug #14 fixed: temperature=0.0 was falsy
            "response_format": {"type": "json_object"},
        }
        
        async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
    
    async def _call_anthropic(self, messages: List[Dict[str, str]], max_tokens: Optional[int] = None,
                              temperature: Optional[float] = None) -> str:
        """Call Anthropic Claude API."""
        import httpx
        
        url = self.base_url or "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        
        # Convert messages to Anthropic format
        system_msg = ""
        anthropic_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_msg = msg["content"]
            else:
                anthropic_messages.append({"role": msg["role"], "content": msg["content"]})
        
        payload = {
            "model": self.model or "claude-3-sonnet-20240229",
            "max_tokens": max_tokens or settings.LLM_MAX_TOKENS,
            "temperature": settings.LLM_TEMPERATURE if temperature is None else temperature,  # Bug #14 fixed: temperature=0.0 was falsy
            "system": system_msg,
            "messages": anthropic_messages,
        }
        
        async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data["content"][0]["text"]
    
    async def _call_groq(self, messages: List[Dict[str, str]], max_tokens: Optional[int] = None,
                         temperature: Optional[float] = None) -> str:
        """Call Groq API."""
        import httpx
        
        url = self.base_url or "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model or "mixtral-8x7b-32768",
            "messages": messages,
            "max_tokens": max_tokens or settings.LLM_MAX_TOKENS,
            "temperature": settings.LLM_TEMPERATURE if temperature is None else temperature,  # Bug #14 fixed: temperature=0.0 was falsy
        }
        
        async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
    
    async def _call_ollama(self, messages: List[Dict[str, str]], max_tokens: Optional[int] = None,
                           temperature: Optional[float] = None) -> str:
        """Call local Ollama API."""
        import httpx
        
        url = self.base_url or "http://localhost:11434/api/chat"
        payload = {
            "model": self.model or "deepseek-coder",
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": settings.LLM_TEMPERATURE if temperature is None else temperature,  # Bug #14 fixed: temperature=0.0 was falsy
                "num_predict": max_tokens or settings.LLM_MAX_TOKENS,
            },
        }
        
        async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return data["message"]["content"]
    
    # --- Analysis Methods ---
    
    async def correlate_findings(self, all_findings: List[Dict[str, Any]], target: str) -> Dict[str, Any]:
        """
        Correlate findings from all modules to identify attack chains and reduce false positives.
        
        Returns:
            Dict with correlated_findings, attack_chains, risk_score, grade, executive_summary
        """
        findings_json = json.dumps(all_findings, indent=2, default=str)[:15000]  # Limit context
        
        messages = [
            {"role": "system", "content": SENTINELAI_SYSTEM_PROMPT},
            {"role": "user", "content": f"""As SentinelAI, analyze and correlate the following security scan findings for target: {target}

Here are ALL findings from all scanning modules:
{findings_json}

Perform the following analysis:
1. **Deduplicate**: Merge findings that represent the same vulnerability found by multiple tools
2. **Attack Chains**: Identify chains where multiple vulnerabilities can be combined for greater impact (e.g., exposed admin panel + default credentials = full system compromise)
3. **Re-score Severity**: Adjust severity based on context (e.g., a SQL injection in a public-facing search is more critical than one behind authentication)
4. **Risk Score**: Calculate an overall risk score (0-100)
5. **Grade**: Assign a letter grade (A-F)
6. **Executive Summary**: Write a non-technical paragraph for business stakeholders
7. **Compliance Notes**: Note relevant compliance implications (GDPR, PCI-DSS, HIPAA, SOC2)

Return ONLY valid JSON in this exact format:
{{
    "risk_score": <number 0-100>,
    "grade": "<A|B|C|D|F>",
    "executive_summary": "<paragraph>",
    "compliance_notes": {{
        "gdpr": "<note>",
        "pci_dss": "<note>",
        "hipaa": "<note>",
        "soc2": "<note>"
    }},
    "attack_chains": [
        {{
            "name": "<chain name>",
            "description": "<how vulnerabilities chain together>",
            "combined_severity": "<critical|high|medium|low>",
            "finding_ids": ["<id1>", "<id2>"],
            "attack_steps": ["<step 1>", "<step 2>", "<step 3>"]
        }}
    ],
    "correlated_findings": [
        {{
            "original_ids": ["<id1>", "<id2>"],
            "adjusted_severity": "<severity>",
            "reasoning": "<why severity was adjusted>"
        }}
    ]
}}"""}
        ]
        
        try:
            response = await self._call_llm(messages, max_tokens=4096, temperature=0.1)
            return json.loads(response)
        except Exception as e:
            logger.error(f"LLM correlation failed: {e}")
            return {
                "risk_score": 50,
                "grade": "C",
                "executive_summary": "Security scan completed. Manual review recommended due to analysis service unavailability.",
                "compliance_notes": {},
                "attack_chains": [],
                "correlated_findings": [],
            }
    
    async def generate_remediation(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate detailed remediation advice for a single finding.
        
        Returns:
            Dict with summary, steps, code_fix, references
        """
        finding_json = json.dumps(finding, indent=2, default=str)
        
        messages = [
            {"role": "system", "content": SENTINELAI_SYSTEM_PROMPT},
            {"role": "user", "content": f"""Provide detailed remediation for this security finding:

{finding_json}

Provide:
1. **Plain English Explanation**: What is this vulnerability and why is it dangerous (business impact)
2. **Step-by-Step Fix Instructions**: Numbered steps to remediate
3. **Secure Code Example**: Before/after code showing the fix (if applicable)
4. **References**: OWASP, CWE, CVE links

Return ONLY valid JSON:
{{
    "summary": "<explanation>",
    "business_impact": "<impact>",
    "steps": ["<step 1>", "<step 2>", "<step 3>"],
    "code_fix": {{
        "before": "<vulnerable code>",
        "after": "<fixed code>"
    }},
    "references": ["https://owasp.org/...", "https://cwe.mitre.org/..."]
}}"""}
        ]
        
        try:
            response = await self._call_llm(messages, max_tokens=4096, temperature=0.1)
            return json.loads(response)
        except Exception as e:
            logger.error(f"LLM remediation generation failed: {e}")
            return {
                "summary": f"Remediation advice unavailable. This is a {finding.get('severity', 'unknown')} severity issue requiring attention.",
                "business_impact": "Unknown - please consult a security professional.",
                "steps": ["Review the finding details", "Consult OWASP guidelines for this vulnerability type", "Implement security controls as recommended by your security team"],
                "code_fix": {"before": "", "after": ""},
                "references": [f"https://cwe.mitre.org/data/definitions/{finding.get('cwe_id', '').replace('CWE-', '')}.html"] if finding.get('cwe_id') else [],
            }
    
    async def review_code_chunk(self, code_chunk: str, language: str, filename: str) -> List[Dict[str, Any]]:
        """
        Perform AI-powered code review on a single code chunk.
        
        Returns:
            List of findings with title, description, severity, explanation
        """
        messages = [
            {"role": "system", "content": SENTINELAI_SYSTEM_PROMPT},
            {"role": "user", "content": f"""Perform a deep security code review of the following {language} code from file: {filename}

```{language}
{code_chunk}
```

Analyze for:
1. **Logic Flaws**: Business logic vulnerabilities, authorization bypasses
2. **Input Validation**: Missing or insufficient validation/sanitization
3. **Authentication Issues**: Weak auth, session management flaws
4. **Authorization Issues**: IDOR, BOLA, missing access controls
5. **Injection Vulnerabilities**: SQLi, XSS, Command Injection, XXE, SSRF
6. **Cryptographic Issues**: Weak hashing, insecure randomness, hardcoded secrets
7. **Race Conditions**: TOCTOU, concurrent access issues
8. **Mass Assignment**: Unsafe object property assignment
9. **Insecure Deserialization**: Unsafe parsing of serialized data
10. **Secure Coding**: Best practice violations

For each finding, provide:
- Title and detailed description
- Severity (critical/high/medium/low/info)
- CWE ID
- Line numbers in the code
- Explanation of why it's a vulnerability
- Fix suggestion with code example

Return ONLY valid JSON array:
[
    {{
        "title": "<finding title>",
        "description": "<detailed description>",
        "severity": "<critical|high|medium|low|info>",
        "cwe_id": "CWE-XXX",
        "line_start": <number>,
        "line_end": <number>,
        "explanation": "<why this is a vulnerability>",
        "fix_suggestion": "<how to fix>",
        "fix_code": "<code example>",
        "confidence": <0.0-1.0>
    }}
]

If no findings, return empty array []."""}
        ]
        
        try:
            response = await self._call_llm(messages, max_tokens=4096, temperature=0.1)
            findings = json.loads(response)
            if not isinstance(findings, list):
                findings = findings.get("findings", [])
            return findings
        except Exception as e:
            logger.error(f"AI code review failed for {filename}: {e}")
            return []
    
    async def generate_executive_summary(self, scan_data: Dict[str, Any]) -> str:
        """
        Generate a non-technical executive summary.
        
        Returns:
            Executive summary paragraph
        """
        scan_json = json.dumps(scan_data, indent=2, default=str)[:10000]
        
        messages = [
            {"role": "system", "content": SENTINELAI_SYSTEM_PROMPT},
            {"role": "user", "content": f"""Write a non-technical executive summary for business stakeholders based on this security scan:

{scan_json}

Requirements:
- Maximum 300 words
- Written for non-technical executives (CEO, CTO, board members)
- Include: overall risk posture, top 3-5 critical issues, business impact, recommended actions with priority
- Be direct and actionable
- Include estimated remediation effort

Return as a single paragraph (plain text, not JSON)."""}
        ]
        
        try:
            response = await self._call_llm(messages, max_tokens=2048, temperature=0.3)
            return response.strip()
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            return "Security assessment completed. The system identified security findings requiring review. Please examine the detailed report for specific vulnerabilities and remediation guidance."
    
    @staticmethod
    def chunk_code(code: str, max_tokens: int = 3000, overlap_tokens: int = 200) -> List[Dict[str, Any]]:
        """
        Split code into chunks for processing, with overlap to maintain context.
        
        Returns:
            List of dicts with code, start_line, end_line
        """
        lines = code.split("\n")
        # Rough estimate: 1 token ≈ 4 characters
        chars_per_chunk = max_tokens * 4
        overlap_chars = overlap_tokens * 4
        
        chunks = []
        current_chunk_lines = []
        current_chunk_chars = 0
        start_line = 1
        
        for i, line in enumerate(lines):
            line_chars = len(line) + 1  # +1 for newline
            
            if current_chunk_chars + line_chars > chars_per_chunk and current_chunk_lines:
                # Save chunk
                chunks.append({
                    "code": "\n".join(current_chunk_lines),
                    "start_line": start_line,
                    "end_line": i,
                })
                
                # Start new chunk with overlap
                overlap_lines = []
                overlap_chars_count = 0
                for prev_line in reversed(current_chunk_lines):
                    overlap_chars_count += len(prev_line) + 1
                    overlap_lines.insert(0, prev_line)
                    if overlap_chars_count >= overlap_chars:
                        break
                
                current_chunk_lines = overlap_lines + [line]
                current_chunk_chars = sum(len(l) + 1 for l in current_chunk_lines)
                start_line = i - len(overlap_lines) + 1
            else:
                current_chunk_lines.append(line)
                current_chunk_chars += line_chars
        
        # Add remaining lines
        if current_chunk_lines:
            chunks.append({
                "code": "\n".join(current_chunk_lines),
                "start_line": start_line,
                "end_line": len(lines),
            })
        
        return chunks