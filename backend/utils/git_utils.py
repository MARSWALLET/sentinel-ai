# ============================================
# SentinelAI - Git Utilities
# ============================================
"""
Git utilities for cloning repositories and analyzing commit history.
"""

import logging
import os
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


async def clone_repository(repo_url: str, clone_dir: str, branch: str = "main",
                           github_token: Optional[str] = None) -> bool:
    """
    Clone a Git repository.
    
    Args:
        repo_url: Git repository URL
        clone_dir: Directory to clone into
        branch: Branch to clone (default: main)
        github_token: GitHub personal access token for private repos
        
    Returns:
        True if clone was successful
    """
    # Clean up if directory exists
    if os.path.exists(clone_dir):
        import shutil
        shutil.rmtree(clone_dir, ignore_errors=True)
    
    os.makedirs(clone_dir, exist_ok=True)
    
    # Bug #17 fixed: never embed the token in the clone URL because the full
    # command line (including the URL) is visible in /proc/<pid>/cmdline and
    # in 'ps aux', exposing the token to any process on the same host.
    # Instead supply credentials via the GIT_ASKPASS mechanism using a
    # helper script that echoes the token without it ever touching argv.
    clone_url = repo_url
    git_env: dict = {}
    
    if github_token:
        import stat
        import tempfile
        # Write a tiny credential helper script to a temp file.
        helper_content = f"#!/bin/sh\necho '{github_token}'\n"
        helper_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", delete=False, prefix="git_askpass_"
        )
        helper_file.write(helper_content)
        helper_file.close()
        os.chmod(helper_file.name, stat.S_IRWXU)  # readable/executable only by owner
        git_env["GIT_ASKPASS"] = helper_file.name
        git_env["GIT_USERNAME"] = "x-token"
        # For HTTPS repos, Git will call GIT_ASKPASS for the password prompt.
        # Keep the URL clean — no credentials embedded.
    
    # Try to clone
    branches_to_try = [branch, "main", "master", "develop"]
    
    for try_branch in branches_to_try:
        try:
            logger.info(f"Cloning {repo_url} (branch: {try_branch}) to {clone_dir}")
            
            run_env = os.environ.copy()
            run_env.update(git_env)
            
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", try_branch, clone_url, "."],
                cwd=clone_dir,
                capture_output=True,
                text=True,
                timeout=300,
                env=run_env,
            )
            
            if result.returncode == 0:
                logger.info(f"Successfully cloned {repo_url} (branch: {try_branch})")
                return True
            
            # If branch not found, try next
            if "Remote branch" in result.stderr and "not found" in result.stderr:
                continue
            
            logger.warning(f"Git clone failed: {result.stderr}")
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Git clone timed out for branch {try_branch}")
        except Exception as e:
            logger.error(f"Git clone error: {e}")
    
    # If all branch-specific clones failed, try without branch
    try:
        run_env = os.environ.copy()
        run_env.update(git_env)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", clone_url, "."],
            cwd=clone_dir,
            capture_output=True,
            text=True,
            timeout=300,
            env=run_env,
        )
        
        if result.returncode == 0:
            logger.info(f"Successfully cloned {repo_url} (default branch)")
            return True
        
        logger.error(f"Git clone failed: {result.stderr}")
        
    except Exception as e:
        logger.error(f"Git clone error: {e}")
    
    # Clean up the helper script
    if github_token and git_env.get("GIT_ASKPASS"):
        try:
            os.unlink(git_env["GIT_ASKPASS"])
        except OSError:
            pass
    
    return False


async def analyze_commit_history(repo_dir: str) -> dict:
    """
    Analyze git commit history for security issues.
    
    Args:
        repo_dir: Path to git repository
        
    Returns:
        Dict with commit analysis results
    """
    results = {
        "total_commits": 0,
        "authors": [],
        "suspicious_commits": [],
    }
    
    try:
        # Get total commits
        result = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        if result.returncode == 0:
            results["total_commits"] = int(result.stdout.strip())
        
        # Get authors
        result = subprocess.run(
            ["git", "log", "--format=%an <%ae>", "--all"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        if result.returncode == 0:
            authors = set(result.stdout.strip().split("\n"))
            results["authors"] = list(authors)[:50]  # Limit to 50
        
        # Look for suspicious commit messages
        result = subprocess.run(
            ["git", "log", "--all", "--format=%H|%s"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        if result.returncode == 0:
            suspicious_keywords = [
                "password", "secret", "key", "token", "credential",
                "remove", "delete", "fix", "revert", "oops",
                "accident", "mistake", "backup", "temp",
            ]
            
            for line in result.stdout.strip().split("\n"):
                if "|" not in line:
                    continue
                commit_hash, message = line.split("|", 1)
                message_lower = message.lower()
                
                if any(kw in message_lower for kw in suspicious_keywords):
                    results["suspicious_commits"].append({
                        "commit": commit_hash,
                        "message": message,
                    })
        
        # Check for .git directory exposure
        git_dir = os.path.join(repo_dir, ".git")
        if os.path.exists(git_dir):
            # Check if the repo itself has .git exposed (it would in a web root)
            pass
        
        logger.info(f"Commit analysis: {results['total_commits']} commits, {len(results['suspicious_commits'])} suspicious")
        
    except Exception as e:
        logger.warning(f"Commit history analysis failed: {e}")
    
    return results


def get_repo_info(repo_dir: str) -> dict:
    """
    Get repository information.
    
    Args:
        repo_dir: Path to git repository
        
    Returns:
        Dict with repo info
    """
    info = {
        "is_git_repo": False,
        "branch": "",
        "last_commit": "",
        "remote_url": "",
    }
    
    try:
        # Check if git repo
        if not os.path.exists(os.path.join(repo_dir, ".git")):
            return info
        
        info["is_git_repo"] = True
        
        # Get current branch
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            info["branch"] = result.stdout.strip()
        
        # Get last commit
        result = subprocess.run(
            ["git", "log", "-1", "--format=%H|%an|%ae|%ai|%s"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            parts = result.stdout.strip().split("|", 4)
            if len(parts) == 5:
                info["last_commit"] = {
                    "hash": parts[0],
                    "author": parts[1],
                    "email": parts[2],
                    "date": parts[3],
                    "message": parts[4],
                }
        
        # Get remote URL
        result = subprocess.run(
            ["git", "remote", "-v"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if "(fetch)" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        info["remote_url"] = parts[1]
                        break
        
    except Exception as e:
        logger.warning(f"Repo info extraction failed: {e}")
    
    return info