# ============================================
# SentinelAI - Scan Orchestrator
# ============================================
"""
Main pipeline controller that orchestrates scanning modules.
Manages module execution order, parallel execution, and result aggregation.
"""

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Type

from config import settings

# Import all scanner modules
from scanner.recon_scanner import ReconScanner
from scanner.web_scanner import WebScanner
from scanner.ssl_scanner import SSLScanner
from scanner.sast_scanner import SASTScanner
from scanner.secrets_scanner import SecretsScanner
from scanner.dependency_scanner import DependencyScanner
from scanner.api_scanner import APIScanner
from scanner.infra_scanner import InfraScanner
from scanner.network_scanner import NetworkScanner
from scanner.ai_reviewer import AIReviewer

logger = logging.getLogger(__name__)

# Module registry - maps module names to scanner classes
MODULE_REGISTRY = {
    "recon": ReconScanner,
    "web": WebScanner,
    "ssl": SSLScanner,
    "sast": SASTScanner,
    "secrets": SecretsScanner,
    "dependencies": DependencyScanner,
    "api_security": APIScanner,
    "infrastructure": InfraScanner,
    "network": NetworkScanner,
    "ai_review": AIReviewer,
}

# Module execution phases for different input types
URL_SCAN_PHASES = [
    # Phase 1: Parallel reconnaissance + SSL
    ["recon", "ssl"],
    # Phase 2: Parallel web + API + network (depends on recon)
    ["web", "api_security", "network"],
]

CODE_SCAN_PHASES = [
    # Phase 1: Parallel static analysis
    ["sast", "secrets", "dependencies", "infrastructure"],
    # Phase 2: AI review (depends on all static findings)
    ["ai_review"],
]

API_SCAN_PHASES = [
    # Single phase: API security scanning
    ["api_security"],
]


class ScanOrchestrator:
    """
    Orchestrates multi-phase security scanning.
    
    For URL scans:
        Phase 1 (parallel): recon, ssl
        Phase 2 (parallel): web, api_security, network (uses recon results)
        Phase 3 (sequential): ai_review, correlation
    
    For code scans:
        Phase 1 (parallel): sast, secrets, dependencies, infrastructure
        Phase 2 (sequential): ai_review
    """
    
    def __init__(self, scan_id: str, target: str, input_type: str,
                 modules: List[str], config: Dict[str, Any]):
        """
        Initialize orchestrator.
        
        Args:
            scan_id: The scan ID
            target: Scan target
            input_type: Type of input (url/github/upload/paste/api_endpoint)
            modules: List of module names to run
            config: Scan configuration
        """
        self.scan_id = scan_id
        self.target = target
        self.input_type = input_type
        self.modules = modules
        self.config = config
        self.all_findings: List[Dict[str, Any]] = []
        self.module_results: Dict[str, Dict[str, Any]] = {}
        self.phases: List[List[str]] = []
        
        # Determine execution phases based on input type
        self._setup_phases()
    
    def _setup_phases(self):
        """Set up execution phases based on input type."""
        if self.input_type in ("url",):
            base_phases = URL_SCAN_PHASES
        elif self.input_type in ("github", "upload", "paste"):
            base_phases = CODE_SCAN_PHASES
        elif self.input_type == "api_endpoint":
            base_phases = API_SCAN_PHASES
        else:
            base_phases = []
        
        # Filter phases to only include requested modules
        self.phases = []
        for phase in base_phases:
            filtered = [m for m in phase if m in self.modules]
            if filtered:
                self.phases.append(filtered)
        
        # Add any requested modules not in phases (append-only modules)
        all_phased = set()
        for phase in self.phases:
            all_phased.update(phase)
        
        extra = [m for m in self.modules if m not in all_phased and m in MODULE_REGISTRY]
        if extra:
            self.phases.append(extra)
        
        logger.info(f"[{self.scan_id}] Execution phases: {self.phases}")
    
    async def run(self) -> Dict[str, Any]:
        """
        Execute the full scan pipeline.
        
        Returns:
            Dict with all findings, module results, and execution summary
        """
        start_time = time.time()
        total_modules = sum(len(p) for p in self.phases)
        completed_modules = 0
        
        logger.info(f"[{self.scan_id}] Starting scan pipeline: {self.input_type} -> {self.target}")
        logger.info(f"[{self.scan_id}] Modules: {self.modules}")
        logger.info(f"[{self.scan_id}] Phases: {len(self.phases)}, Total modules: {total_modules}")
        
        # Execute phases sequentially, modules within each phase in parallel
        for phase_idx, phase_modules in enumerate(self.phases):
            logger.info(f"[{self.scan_id}] Starting phase {phase_idx + 1}/{len(self.phases)}: {phase_modules}")
            
            # Create scanner instances for this phase
            scanners = []
            for module_name in phase_modules:
                scanner_class = MODULE_REGISTRY.get(module_name)
                if not scanner_class:
                    logger.error(f"Unknown module: {module_name}")
                    continue
                
                # Pass relevant config to scanner
                scanner_config = self.config.copy()
                
                # For phase 2 URL scans, pass recon results
                if module_name in ("web", "api_security", "network") and "recon" in self.module_results:
                    scanner_config["recon_results"] = self.module_results["recon"]
                
                scanner = scanner_class(
                    target=self.target,
                    config=scanner_config,
                    scan_id=self.scan_id,
                )
                scanners.append((module_name, scanner))
            
            # Run scanners in parallel
            tasks = [scanner.execute() for _, scanner in scanners]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for (module_name, scanner), result in zip(scanners, results):
                completed_modules += 1
                
                if isinstance(result, Exception):
                    logger.error(f"[{self.scan_id}] Module {module_name} raised exception: {result}")
                    self.module_results[module_name] = {
                        "module": module_name,
                        "status": "failed",
                        "error": str(result),
                        "findings": [],
                    }
                else:
                    self.module_results[module_name] = result
                    if result.get("findings"):
                        self.all_findings.extend(result["findings"])
                    
                    progress = (completed_modules / total_modules) * 100
                    logger.info(f"[{self.scan_id}] Progress: {progress:.0f}% - {module_name} done ({result.get('findings_count', 0)} findings)")
            
            logger.info(f"[{self.scan_id}] Phase {phase_idx + 1} complete")
        
        duration = time.time() - start_time
        
        # Build summary
        failed_modules = [m for m, r in self.module_results.items() if r.get("status") == "failed"]
        
        summary = {
            "scan_id": self.scan_id,
            "target": self.target,
            "input_type": self.input_type,
            "duration_seconds": round(duration, 2),
            "total_findings": len(self.all_findings),
            "modules_executed": list(self.module_results.keys()),
            "failed_modules": failed_modules,
            "module_results": self.module_results,
            "findings": self.all_findings,
        }
        
        logger.info(f"[{self.scan_id}] Pipeline complete: {len(self.all_findings)} findings in {duration:.1f}s")
        
        return summary
    
    @staticmethod
    def get_available_modules() -> Dict[str, str]:
        """Get list of available scanner modules with descriptions."""
        return {
            name: cls.module_description
            for name, cls in MODULE_REGISTRY.items()
        }
    
    @staticmethod
    def get_default_modules(input_type: str) -> List[str]:
        """Get default modules for an input type."""
        defaults = {
            "url": ["recon", "web", "ssl", "network"],
            "github": ["sast", "secrets", "dependencies", "infrastructure", "ai_review"],
            "upload": ["sast", "secrets", "dependencies", "infrastructure", "ai_review"],
            "paste": ["sast", "ai_review"],
            "api_endpoint": ["api_security"],
        }
        return defaults.get(input_type, ["sast", "secrets"])