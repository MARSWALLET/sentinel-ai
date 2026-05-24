# ============================================
# SentinelAI - Base Scanner
# ============================================
"""
Abstract base class for all scanner modules.
Provides common functionality for running CLI tools, parsing output, and managing findings.
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from config import settings, TOOL_PATHS

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """
    Abstract base class for all security scanner modules.
    
    Each scanner module inherits from this class and implements:
    - module_name: Unique identifier for the module
    - run(): Main scan logic that returns a list of findings
    """
    
    # Override in subclass
    module_name: str = "base"
    module_description: str = "Base scanner module"
    
    def __init__(self, target: str, config: Dict[str, Any], workspace_dir: Optional[str] = None,
                 scan_id: Optional[str] = None):
        """
        Initialize scanner.
        
        Args:
            target: The scan target (URL, file path, etc.)
            config: Scan configuration dict
            workspace_dir: Directory for temporary files
            scan_id: Parent scan ID for logging
        """
        self.target = target
        self.config = config or {}
        self.scan_id = scan_id or "unknown"
        self.workspace_dir = workspace_dir or f"{settings.SCAN_WORKSPACE_DIR}/{self.scan_id}"
        self.findings: List[Dict[str, Any]] = []
        self.start_time: Optional[float] = None
        self.duration: float = 0.0
        self.status: str = "pending"  # pending, running, complete, failed
        self.error_message: Optional[str] = None
        
        # Bug #33 fixed: workspace was created eagerly for every scanner
        # instance (even those that fail before running). Creation is now
        # deferred to execute() just before run() is called, avoiding leftover
        # empty directories for every instantiated-but-unused scanner.
    
    @abstractmethod
    async def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner module.
        
        Returns:
            List of finding dictionaries
        """
        pass
    
    async def execute(self) -> Dict[str, Any]:
        """
        Execute the scanner with timing and error handling.
        
        Returns:
            Dict with findings, status, duration, and error info
        """
        self.start_time = time.time()
        self.status = "running"
        # Bug #33 fixed: create workspace lazily here (not in __init__) so
        # directories are only created when a scan actually starts.
        os.makedirs(self.workspace_dir, exist_ok=True)
        
        try:
            logger.info(f"[{self.scan_id}] Starting {self.module_name} scanner on: {self.target}")
            self.findings = await self.run()
            self.status = "complete"
            logger.info(f"[{self.scan_id}] {self.module_name} complete: {len(self.findings)} findings")
            
        except asyncio.TimeoutError:
            self.status = "failed"
            self.error_message = f"Module timeout after {settings.MODULE_TIMEOUT}s"
            logger.error(f"[{self.scan_id}] {self.module_name} timed out")
            
        except Exception as e:
            self.status = "failed"
            self.error_message = str(e)
            logger.exception(f"[{self.scan_id}] {self.module_name} failed: {e}")
        
        finally:
            self.duration = time.time() - self.start_time
        
        return {
            "module": self.module_name,
            "status": self.status,
            "duration_seconds": round(self.duration, 2),
            "findings_count": len(self.findings),
            "findings": self.findings,
            "error": self.error_message,
        }
    
    def run_tool(self, tool_name: str, args: List[str], timeout: Optional[int] = None,
                 cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
        """
        Execute a CLI security tool and capture output.
        
        Args:
            tool_name: Name of the tool (must be in TOOL_PATHS)
            args: Command line arguments
            timeout: Timeout in seconds (default from settings)
            cwd: Working directory
            env: Additional environment variables
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        tool_path = TOOL_PATHS.get(tool_name)
        if not tool_path:
            raise ValueError(f"Tool '{tool_name}' not found in TOOL_PATHS")
        
        if not os.path.exists(tool_path):
            logger.warning(f"Tool binary not found: {tool_path}")
            return -1, "", f"Tool binary not found: {tool_path}"
        
        cmd = [tool_path] + args
        timeout = timeout or settings.MODULE_TIMEOUT
        
        # Merge environment
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        
        logger.debug(f"Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd or self.workspace_dir,
                env=run_env,
            )
            return result.returncode, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Tool timed out after {timeout}s: {tool_name}")
            # Bug #18 fixed: asyncio.TimeoutError raised from a synchronous
            # method is incorrect — asyncio.wait_for() will not catch it when
            # called from sync code, and it confuses the caller. Use the
            # standard built-in TimeoutError which is the correct exception for
            # synchronous timeout scenarios.
            raise TimeoutError(f"Tool {tool_name} timed out after {timeout}s")
        except Exception as e:
            logger.error(f"Failed to run tool {tool_name}: {e}")
            return -1, "", str(e)
    
    def add_finding(self, title: str, description: str, severity: str,
                    cwe_id: Optional[str] = None, cvss_score: Optional[float] = None,
                    url: Optional[str] = None, file_path: Optional[str] = None,
                    line_number: Optional[int] = None, parameter: Optional[str] = None,
                    evidence: Optional[Dict] = None, code_snippet: Optional[str] = None,
                    remediation: Optional[str] = None, tool_source: Optional[str] = None,
                    **kwargs) -> Dict[str, Any]:
        """
        Add a standardized finding.
        
        Args:
            title: Finding title
            description: Detailed description
            severity: critical/high/medium/low/info
            cwe_id: CWE identifier (e.g., "CWE-89")
            cvss_score: CVSS score (0-10)
            url: Affected URL
            file_path: Affected file path
            line_number: Line number in file
            parameter: Affected parameter
            evidence: Raw evidence dict
            code_snippet: Code snippet
            remediation: Remediation advice
            tool_source: Tool that found this
            **kwargs: Additional fields
            
        Returns:
            The finding dict
        """
        finding = {
            "module": self.module_name,
            "title": title,
            "description": description,
            "severity": severity,
            "cwe_id": cwe_id,
            "cvss_score": cvss_score,
            "url": url,
            "file_path": file_path,
            "line_number": line_number,
            "parameter": parameter,
            "evidence": evidence or {},
            "code_snippet": code_snippet,
            "remediation": remediation,
            "tool_source": tool_source or self.module_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "scan_id": self.scan_id,
            **kwargs,
        }
        
        self.findings.append(finding)
        return finding
    
    def parse_json_output(self, output: str) -> Optional[Dict]:
        """Parse JSON output from a tool, handling common formats."""
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            # Try to extract JSON from mixed output
            json_match = re.search(r'\{.*\}', output, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except json.JSONDecodeError:
                    pass
            logger.warning("Failed to parse JSON output")
            return None
    
    def severity_from_cvss(self, cvss_score: float) -> str:
        """Convert CVSS score to severity string."""
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        elif cvss_score > 0:
            return "low"
        return "info"
    
    def save_raw_output(self, output: str, suffix: str = "output") -> str:
        """Save raw tool output to file for debugging."""
        output_path = f"{self.workspace_dir}/{self.module_name}_{suffix}.txt"
        with open(output_path, "w") as f:
            f.write(output)
        return output_path
    
    @property
    def is_failed(self) -> bool:
        """Check if scanner failed."""
        return self.status == "failed"
    
    @property
    def is_complete(self) -> bool:
        """Check if scanner completed successfully."""
        return self.status == "complete"