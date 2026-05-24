# ============================================
# SentinelAI - AI Code Reviewer
# ============================================
"""
AI-powered code review using DeepSeek LLM.
Performs deep manual-style code review with chunking for large codebases.
"""

import logging
import os
from typing import Any, Dict, List, Optional

from scanner.base_scanner import BaseScanner
from services.llm_service import LLMService
from utils.file_utils import detect_languages

logger = logging.getLogger(__name__)

# Maximum file size for AI review (100KB)
MAX_FILE_SIZE = 100 * 1024

# Extensions to review
REVIEW_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".java", ".go", ".php",
    ".c", ".cpp", ".h", ".cs", ".swift", ".kt", ".rs",
    ".sql", ".sh", ".yaml", ".yml", ".tf", ".dockerfile",
}

# Extensions to skip
SKIP_EXTENSIONS = {
    ".min.js", ".min.css", ".map", ".lock", ".sum",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".pyc", ".pyo", ".class",
}

# Security-sensitive files to always review
SENSITIVE_FILES = [
    "auth", "authentication", "login", "password", "session", "token",
    "crypto", "encrypt", "decrypt", "hash", "cipher",
    "payment", "billing", "credit", "card",
    "admin", "role", "permission", "acl",
    "api", "webhook", "callback", "oauth",
    "config", "settings", "env",
    "middleware", "decorator", "filter",
    "upload", "file", "import", "export",
]


class AIReviewer(BaseScanner):
    """
    AI-powered code review module.
    Uses LLM to perform deep security code review with intelligent chunking.
    """
    
    module_name = "ai_review"
    module_description = "AI-powered deep code review for security vulnerabilities"
    
    async def run(self) -> List[Dict[str, Any]]:
        """Run AI code review."""
        findings = []
        target_dir = self.config.get("file_path", self.target)
        
        if not os.path.isdir(target_dir):
            # Single file
            if os.path.isfile(target_dir):
                file_findings = await self._review_file(target_dir, os.path.basename(target_dir))
                findings.extend(file_findings)
            return findings
        
        # Detect languages
        languages = detect_languages(target_dir)
        logger.info(f"AI review - detected languages: {languages}")
        
        # Collect files to review
        files_to_review = self._collect_files(target_dir)
        logger.info(f"AI review - {len(files_to_review)} files to review")
        
        # Review files (limit to 50 most important files)
        prioritized_files = self._prioritize_files(files_to_review)
        
        # Initialize LLM service
        llm_service = LLMService()
        
        # Review each file
        for file_info in prioritized_files[:50]:
            try:
                file_findings = await self._review_single_file(
                    file_info["path"],
                    file_info["relative_path"],
                    file_info["language"],
                    llm_service,
                )
                findings.extend(file_findings)
            except Exception as e:
                logger.warning(f"AI review failed for {file_info['relative_path']}: {e}")
        
        logger.info(f"AI code review complete: {len(findings)} findings")
        return findings
    
    def _collect_files(self, target_dir: str) -> List[Dict[str, Any]]:
        """Collect all reviewable files."""
        files = []
        
        for root, dirs, filenames in os.walk(target_dir):
            # Skip unwanted directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in (
                "node_modules", "vendor", "__pycache__", "dist", "build",
                ".git", ".svn", ".hg", "target", "bin", "obj",
            )]
            
            for filename in filenames:
                file_path = os.path.join(root, filename)
                
                # Check extension
                ext = os.path.splitext(filename)[1].lower()
                if ext in SKIP_EXTENSIONS:
                    continue
                if ext not in REVIEW_EXTENSIONS and not any(filename.endswith(e) for e in REVIEW_EXTENSIONS):
                    continue
                
                # Check file size
                try:
                    size = os.path.getsize(file_path)
                    if size > MAX_FILE_SIZE:
                        continue
                    if size == 0:
                        continue
                except OSError:
                    continue
                
                rel_path = os.path.relpath(file_path, target_dir)
                
                # Detect language
                language = self._detect_file_language(filename)
                
                files.append({
                    "path": file_path,
                    "relative_path": rel_path,
                    "language": language,
                    "size": size,
                })
        
        return files
    
    def _prioritize_files(self, files: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize files for review based on security sensitivity."""
        
        def priority_score(file_info):
            score = 0
            name_lower = os.path.basename(file_info["relative_path"]).lower()
            path_lower = file_info["relative_path"].lower()
            
            # Security-sensitive filenames get higher priority
            for keyword in SENSITIVE_FILES:
                if keyword in name_lower:
                    score += 50
                if keyword in path_lower:
                    score += 20
            
            # Smaller files are easier for the LLM
            score -= file_info["size"] / 10000
            
            return score
        
        return sorted(files, key=priority_score, reverse=True)
    
    async def _review_single_file(self, file_path: str, relative_path: str,
                                   language: str, llm_service: LLMService) -> List[Dict[str, Any]]:
        """Review a single file with the LLM."""
        findings = []
        
        # Read file
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
        except Exception:
            return findings
        
        # Skip files that are too short
        if len(code) < 50:
            return findings
        
        # Use chunking for large files
        chunks = LLMService.chunk_code(code, max_tokens=3000, overlap_tokens=200)
        
        all_findings = []
        for chunk in chunks:
            chunk_findings = await llm_service.review_code_chunk(
                code_chunk=chunk["code"],
                language=language,
                filename=relative_path,
            )
            
            # Adjust line numbers
            for finding in chunk_findings:
                if "line_start" in finding:
                    finding["line_start"] = finding.get("line_start", 0) + chunk["start_line"]
                if "line_end" in finding:
                    finding["line_end"] = finding.get("line_end", 0) + chunk["start_line"]
            
            all_findings.extend(chunk_findings)
        
        # Convert to standardized findings
        for finding in all_findings:
            findings.append(self.add_finding(
                title=f"AI Review: {finding.get('title', 'Security Issue')}",
                description=finding.get("description", ""),
                severity=finding.get("severity", "medium").lower(),
                cwe_id=finding.get("cwe_id"),
                file_path=relative_path,
                line_number=finding.get("line_start", 0),
                code_snippet=finding.get("fix_code", "")[:500],
                evidence={
                    "explanation": finding.get("explanation", ""),
                    "confidence": finding.get("confidence", 0.5),
                    "fix_suggestion": finding.get("fix_suggestion", ""),
                },
                ai_explanation=finding.get("explanation", ""),
                ai_confidence=finding.get("confidence", 0.5),
                remediation=finding.get("fix_suggestion", ""),
                tool_source="ai_reviewer",
            ))
        
        return findings
    
    async def _review_file(self, file_path: str, filename: str) -> List[Dict[str, Any]]:
        """Review a single file (wrapper)."""
        llm_service = LLMService()
        language = self._detect_file_language(filename)
        return await self._review_single_file(file_path, filename, language, llm_service)
    
    @staticmethod
    def _detect_file_language(filename: str) -> str:
        """Detect programming language from filename."""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".rb": "ruby",
            ".java": "java",
            ".go": "go",
            ".php": "php",
            ".c": "c",
            ".cpp": "cpp",
            ".h": "c",
            ".cs": "csharp",
            ".swift": "swift",
            ".kt": "kotlin",
            ".rs": "rust",
            ".sql": "sql",
            ".sh": "bash",
            ".yaml": "yaml",
            ".yml": "yaml",
            ".tf": "terraform",
            ".dockerfile": "dockerfile",
        }
        
        ext = os.path.splitext(filename)[1].lower()
        return ext_map.get(ext, "unknown")