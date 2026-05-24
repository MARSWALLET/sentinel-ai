# ============================================
# SentinelAI - File Utilities
# ============================================
"""
File handling utilities for extracting archives, detecting languages, and managing workspaces.
"""

import logging
import mimetypes
import os
import tarfile
import zipfile
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Language detection by file extension
LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".pyw": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".rb": "ruby",
    ".erb": "ruby",
    ".java": "java",
    ".class": "java",
    ".go": "go",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rs": "rust",
    ".scala": "scala",
    ".sc": "scala",
    ".r": "r",
    ".lua": "lua",
    ".pl": "perl",
    ".pm": "perl",
    ".t": "perl",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "zsh",
    ".ps1": "powershell",
    ".sql": "sql",
    ".dart": "dart",
    ".elm": "elm",
    ".ex": "elixir",
    ".exs": "elixir",
    ".fs": "fsharp",
    ".fsx": "fsharp",
    ".hs": "haskell",
    ".lhs": "haskell",
    ".jl": "julia",
    ".ml": "ocaml",
    ".nim": "nim",
    ".clj": "clojure",
    ".cljs": "clojure",
    ".groovy": "groovy",
    ".gvy": "groovy",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".dockerfile": "dockerfile",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "ini",
    ".conf": "config",
    ".gradle": "gradle",
    ".sbt": "scala",
    ".vue": "vue",
    ".svelte": "svelte",
}

# Package manifest files
PACKAGE_MANIFESTS = {
    "python": ["requirements.txt", "Pipfile", "pyproject.toml", "setup.py", "setup.cfg"],
    "javascript": ["package.json"],
    "typescript": ["package.json", "tsconfig.json"],
    "ruby": ["Gemfile"],
    "java": ["pom.xml", "build.gradle", "gradlew"],
    "go": ["go.mod"],
    "php": ["composer.json"],
    "rust": ["Cargo.toml"],
    "csharp": ["*.csproj", "*.sln"],
    "scala": ["build.sbt"],
    "dart": ["pubspec.yaml"],
    "elixir": ["mix.exs"],
}


def detect_languages(directory: str) -> List[str]:
    """
    Detect programming languages used in a directory.
    
    Args:
        directory: Directory to analyze
        
    Returns:
        List of detected language names
    """
    languages = set()
    file_counts = {}
    
    try:
        for root, dirs, files in os.walk(directory):
            # Skip unwanted directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in (
                "node_modules", "vendor", "__pycache__", "dist", "build",
                "target", ".git", ".svn", ".hg",
            )]
            
            for filename in files:
                # Check by extension
                ext = os.path.splitext(filename)[1].lower()
                if ext in LANGUAGE_EXTENSIONS:
                    lang = LANGUAGE_EXTENSIONS[ext]
                    file_counts[lang] = file_counts.get(lang, 0) + 1
                
                # Check by manifest files
                for lang, manifests in PACKAGE_MANIFESTS.items():
                    if filename in manifests:
                        languages.add(lang)
        
        # Add languages with more than 3 files
        for lang, count in file_counts.items():
            if count >= 3:
                languages.add(lang)
        
        logger.info(f"Detected languages in {directory}: {sorted(languages)}")
        
    except Exception as e:
        logger.error(f"Language detection failed: {e}")
    
    return sorted(list(languages))


def detect_language_from_content(content: str, filename: str = "") -> str:
    """
    Detect programming language from file content.
    
    Args:
        content: File content
        filename: Optional filename for extension-based detection
        
    Returns:
        Language name
    """
    # First check by extension
    ext = os.path.splitext(filename)[1].lower()
    if ext in LANGUAGE_EXTENSIONS:
        return LANGUAGE_EXTENSIONS[ext]
    
    # Heuristic content-based detection
    content_lower = content.lower()
    
    indicators = {
        "python": ["def ", "import ", "from ", "__init__", "self.", "None", "True", "False"],
        "javascript": ["const ", "let ", "var ", "function ", "=>", "require(", "module.exports"],
        "typescript": ["interface ", "type ", "implements", "readonly", ": string", ": number", "as "],
        "java": ["public class", "private ", "protected ", "import java.", "System.out"],
        "ruby": ["def ", "end\n", "require '", "module ", "class <<", "attr_"],
        "go": ["package ", "func ", "import (", "defer ", "chan ", "go func"],
        "php": ["<?php", "echo ", "$", "function ", "namespace ", "use "],
        "rust": ["fn ", "let mut", "impl ", "match ", "use ", "cargo"],
        "c": ["#include", "printf(", "malloc(", "void ", "struct ", "typedef"],
        "cpp": ["#include", "std::", "cout <<", "class ", "template<", "namespace "],
        "csharp": ["using ", "namespace ", "public class", "private ", "async ", "await "],
        "sql": ["SELECT ", "INSERT ", "UPDATE ", "DELETE ", "CREATE TABLE", "JOIN ", "WHERE "],
    }
    
    scores = {}
    for lang, lang_indicators in indicators.items():
        # Bug #32 fixed: was checking 'content' (original case) while content_lower
        # was computed but unused. Use content_lower consistently so case-insensitive
        # matching works (e.g. SQL keywords in lowercase SQL files).
        score = sum(1 for indicator in lang_indicators if indicator.lower() in content_lower)
        if score > 0:
            scores[lang] = score
    
    if scores:
        return max(scores, key=scores.get)
    
    return "unknown"


def extract_archive(archive_path: str, extract_dir: str) -> bool:
    """
    Extract an archive file.
    
    Args:
        archive_path: Path to archive file
        extract_dir: Directory to extract to
        
    Returns:
        True if extraction was successful
    """
    os.makedirs(extract_dir, exist_ok=True)
    
    try:
        if archive_path.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as z:
                # Bug #15 fixed: Zip Slip — validate every member path before
                # extraction so a malicious archive cannot escape extract_dir.
                import os.path as _osp
                for member in z.namelist():
                    target_path = _osp.realpath(_osp.join(extract_dir, member))
                    if not target_path.startswith(_osp.realpath(extract_dir) + os.sep):
                        raise ValueError(f"Zip Slip detected: {member} would escape {extract_dir}")
                z.extractall(extract_dir)
            logger.info(f"Extracted ZIP: {archive_path}")
            return True
        
        elif archive_path.endswith(".tar.gz") or archive_path.endswith(".tgz"):
            with tarfile.open(archive_path, "r:gz") as t:
                # Bug #15 fixed: validate tar members against extract_dir.
                import os.path as _osp
                real_extract = _osp.realpath(extract_dir)
                for member in t.getmembers():
                    target_path = _osp.realpath(_osp.join(extract_dir, member.name))
                    if not target_path.startswith(real_extract + os.sep):
                        raise ValueError(f"Tar Slip detected: {member.name} would escape {extract_dir}")
                t.extractall(extract_dir)
            logger.info(f"Extracted TAR.GZ: {archive_path}")
            return True
        
        elif archive_path.endswith(".tar"):
            with tarfile.open(archive_path, "r") as t:
                import os.path as _osp
                real_extract = _osp.realpath(extract_dir)
                for member in t.getmembers():
                    target_path = _osp.realpath(_osp.join(extract_dir, member.name))
                    if not target_path.startswith(real_extract + os.sep):
                        raise ValueError(f"Tar Slip detected: {member.name} would escape {extract_dir}")
                t.extractall(extract_dir)
            logger.info(f"Extracted TAR: {archive_path}")
            return True
        
        elif archive_path.endswith(".tar.bz2"):
            with tarfile.open(archive_path, "r:bz2") as t:
                import os.path as _osp
                real_extract = _osp.realpath(extract_dir)
                for member in t.getmembers():
                    target_path = _osp.realpath(_osp.join(extract_dir, member.name))
                    if not target_path.startswith(real_extract + os.sep):
                        raise ValueError(f"Tar Slip detected: {member.name} would escape {extract_dir}")
                t.extractall(extract_dir)
            logger.info(f"Extracted TAR.BZ2: {archive_path}")
            return True
        
        elif archive_path.endswith(".rar"):
            # Try unrar or rar
            import subprocess
            result = subprocess.run(
                ["unrar", "x", "-o+", archive_path, extract_dir],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                logger.info(f"Extracted RAR: {archive_path}")
                return True
        
        elif archive_path.endswith(".7z"):
            import subprocess
            result = subprocess.run(
                ["7z", "x", archive_path, f"-o{extract_dir}"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                logger.info(f"Extracted 7Z: {archive_path}")
                return True
        
        logger.warning(f"Unsupported archive format: {archive_path}")
        return False
        
    except Exception as e:
        logger.error(f"Archive extraction failed: {e}")
        return False


def get_file_mime_type(file_path: str) -> str:
    """
    Get MIME type of a file.
    
    Args:
        file_path: Path to file
        
    Returns:
        MIME type string
    """
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type or "application/octet-stream"


def is_binary_file(file_path: str) -> bool:
    """
    Check if a file is binary.
    
    Args:
        file_path: Path to file
        
    Returns:
        True if file is binary
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if b"\0" in chunk:
                return True
    except Exception:
        return True
    return False


def get_directory_size(directory: str) -> int:
    """
    Get total size of a directory in bytes.
    
    Args:
        directory: Directory path
        
    Returns:
        Size in bytes
    """
    total_size = 0
    
    try:
        for dirpath, dirnames, filenames in os.walk(directory):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if not os.path.islink(fp):
                    total_size += os.path.getsize(fp)
    except Exception:
        pass
    
    return total_size


def count_lines_of_code(directory: str) -> Dict[str, int]:
    """
    Count lines of code per language.
    
    Args:
        directory: Directory to analyze
        
    Returns:
        Dict of language -> line count
    """
    loc = {}
    
    try:
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in (
                "node_modules", "vendor", "__pycache__", "dist", "build",
            )]
            
            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in LANGUAGE_EXTENSIONS:
                    continue
                
                lang = LANGUAGE_EXTENSIONS[ext]
                file_path = os.path.join(root, filename)
                
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = sum(1 for _ in f)
                        loc[lang] = loc.get(lang, 0) + lines
                except Exception:
                    pass
    except Exception:
        pass
    
    return loc