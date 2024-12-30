#!/usr/bin/env python3

import os
import sys
import time
import base64
import atexit
import gc
import html
import urllib.parse
import subprocess
import warnings
import random
import json
import logging
import asyncio
import argparse
from importlib.metadata import version as get_version, PackageNotFoundError
import platform
import aiofiles
import re
import aiohttp
from packaging.version import parse as parse_version
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from colorama import init, Fore, Style
from tqdm.asyncio import tqdm_asyncio

init(autoreset=True)

MAX_CONCURRENT_WORKERS = 30
DEFAULT_WORKERS = 8
PAYLOADS_BATCH_SIZE = 15
URLS_BATCH_SIZE = 5
MAX_WORKERS_PER_BATCH = 8
DEFAULT_RATE_LIMIT = 12
DEFAULT_TIMEOUT = 8
DEFAULT_ALERT_TIMEOUT = 6
CONNECTIONS_PER_WORKER = 3
MIN_RATE_LIMIT = 1
MAX_RATE_LIMIT = 100
ERROR_LOG_FILE = "logs/errors.log"

# Telegram Configuration
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""
TELEGRAM_NOTIFICATIONS_ENABLED = False

VERSION = "0.0.1"
GITHUB_REPOSITORY: str = "Cybersecurity-Ethical-Hacker/xssuccessor"
GITHUB_URL: str = f"https://github.com/{GITHUB_REPOSITORY}"

class DOMXSSScanner:
    def __init__(self):
        # Enhanced DOM source and sink patterns
        self.dom_patterns = {
            'sources': [
                # URL-based sources
                r'location\s*\.\s*(href|search|hash|pathname)',
                r'document\s*\.\s*(URL|documentURI|baseURI|referrer)',
                r'window\s*\.\s*(name|location)',
                r'document\.write\s*\(',
                # Parameter-based sources
                r'URLSearchParams',
                r'new\s+URL\s*\(',
                r'\.searchParams',
                # Storage-based sources
                r'localStorage',
                r'sessionStorage',
                r'document\.cookie',
                # Fragment-based sources
                r'location\.hash',
                # Form-based sources
                r'FormData',
                r'\.elements',
                r'\.value'
            ],
            'sinks': [
                # HTML injection sinks
                r'\.innerHTML\s*[=\+]=',
                r'\.outerHTML\s*[=\+]=',
                r'\.insertAdjacentHTML',
                r'\.insertAdjacentElement',
                r'\.insertBefore',
                r'\.insertAfter',
                # Script execution sinks
                r'eval\s*\(',
                r'Function\s*\(',
                r'setTimeout\s*\(',
                r'setInterval\s*\(',
                r'document\.write\s*\(',
                r'document\.writeln\s*\(',
                # Element creation sinks
                r'createElement\s*\(\s*[\'"]script[\'"]',
                r'\.src\s*[=\+]=',
                r'\.setAttribute\s*\(\s*[\'"]on\w+[\'"]',
                # URL-based sinks
                r'location\s*[=\+]=',
                r'\.href\s*[=\+]='
            ],
            'dom_mutations': [
                r'\.appendChild\s*\(',
                r'\.replaceChild\s*\(',
                r'\.replaceWith\s*\(',
                r'\.insertBefore\s*\(',
                r'\.after\s*\(',
                r'\.before\s*\('
            ],
            'event_handlers': [
                r'addEventListener\s*\(',
                r'on\w+\s*=',
                r'\.onload\s*=',
                r'\.onerror\s*=',
                r'\.onmouseover\s*='
            ]
        }

    async def analyze_dom_content(self, content: str) -> Dict[str, List[str]]:
        """
        Perform detailed DOM analysis of the content.
        Returns a dictionary with found patterns and their contexts.
        """
        results = {
            'sources': [],
            'sinks': [],
            'mutations': [],
            'events': []
        }

        # Extract all script content
        script_tags = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL)
        inline_handlers = re.findall(r'on\w+\s*=\s*["\']([^"\']+)["\']', content)
        js_content = '\n'.join(script_tags + inline_handlers)

        # Analyze JavaScript content
        for category, patterns in self.dom_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    context = js_content[max(0, match.start()-20):min(len(js_content), match.end()+20)]
                    if category == 'sources':
                        results['sources'].append(context.strip())
                    elif category == 'sinks':
                        results['sinks'].append(context.strip())
                    elif category == 'dom_mutations':
                        results['mutations'].append(context.strip())
                    elif category == 'event_handlers':
                        results['events'].append(context.strip())

        return results

    async def check_dom_vulnerability(self, content: str, payload: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Analyze if the content is vulnerable to DOM-based XSS.
        Returns a tuple of (is_vulnerable, details).
        """
        dom_analysis = await self.analyze_dom_content(content)
        
        # Check for source-to-sink flows
        has_sources = len(dom_analysis['sources']) > 0
        has_sinks = len(dom_analysis['sinks']) > 0
        has_mutations = len(dom_analysis['mutations']) > 0
        has_events = len(dom_analysis['events']) > 0

        # Enhanced payload-specific checks
        payload_lower = payload.lower()
        relevant_sinks = []
        
        if 'script' in payload_lower:
            relevant_sinks.extend([s for s in dom_analysis['sinks'] 
                                 if 'createElement' in s or 'innerHTML' in s])
        
        if 'on' in payload_lower and '=' in payload_lower:
            relevant_sinks.extend([s for s in dom_analysis['sinks'] 
                                 if 'setAttribute' in s or 'innerHTML' in s])

        if 'javascript:' in payload_lower:
            relevant_sinks.extend([s for s in dom_analysis['sinks'] 
                                 if 'location' in s or 'href' in s])

        is_vulnerable = (
            (has_sources and has_sinks) or
            (has_sources and has_mutations) or
            (has_events and has_sinks) or
            len(relevant_sinks) > 0
        )

        return is_vulnerable, {
            'analysis': dom_analysis,
            'relevant_sinks': relevant_sinks,
            'payload_type': 'dom',
            'confidence': 'high' if (has_sources and has_sinks) else 'medium'
        }

    async def quick_dom_check(self, response_text: str) -> bool:
        """
        Quick check for DOM-based XSS potential,
        plus detection of createElement, appendChild, on[a-zA-Z]+=, etc.
        """
        # Check for suspicious DOM-manipulating functions
        if re.search(r'createElement\s*\(\s*[\'"](?:script|iframe|svg)[\'"]', response_text, re.IGNORECASE):
            return True
        if re.search(r'appendChild\s*\(', response_text, re.IGNORECASE):
            return True
        if re.search(r'insertAdjacentHTML\s*\(', response_text, re.IGNORECASE):
            return True
        # Check for on-event attributes
        if re.search(r'on[a-zA-Z]+\s*=\s*', response_text, re.IGNORECASE):
            return True

        script_tags = re.findall(r'<script[^>]*>(.*?)</script>', response_text, re.DOTALL)
        for script in script_tags:
            has_param_access = re.search(r'URLSearchParams|params\.get|location\.search', script, re.IGNORECASE)
            has_dom_mod = re.search(r'innerHTML\s*=|document\.write|eval', script, re.IGNORECASE)

            if has_param_access and has_dom_mod:
                return True

            if re.search(r'getElementById\([^)]+\)\.innerHTML\s*=', script, re.IGNORECASE):
                return True

            if 'window.onload' in script and 'innerHTML' in script:
                return True
        return False

class ReflectionAnalyzer:
    def __init__(self):
        self.encoding_patterns = {
            'html': [
                (r'&[a-zA-Z]+;', html.unescape),
                (r'&#x[0-9a-fA-F]+;', lambda x: chr(int(x[3:-1], 16))),
                (r'&#[0-9]+;', lambda x: chr(int(x[2:-1])))
            ],
            'url': [
                (r'%[0-9a-fA-F]{2}', urllib.parse.unquote),
                (r'\+', lambda x: ' ')
            ],
            'js': [
                (r'\\x[0-9a-fA-F]{2}', lambda x: bytes.fromhex(x[2:]).decode()),
                (r'\\u[0-9a-fA-F]{4}', lambda x: chr(int(x[2:], 16))),
                (r'\\"', lambda x: '"'),
                (r"\\'", lambda x: "'")
            ]
        }

    def normalize_content(self, content: str) -> str:
        """Normalize content by handling different encodings."""
        normalized = content
        for encoding_type, patterns in self.encoding_patterns.items():
            for pattern, decoder in patterns:
                try:
                    matches = re.finditer(pattern, normalized)
                    for match in matches:
                        try:
                            decoded = decoder(match.group(0))
                            normalized = normalized.replace(match.group(0), decoded)
                        except:
                            continue
                except:
                    continue
        return normalized

    async def analyze_reflection(self, content: str, payload: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Analyze if and how the payload is reflected in the content.
        Returns a tuple of (is_reflected, details).
        """
        normalized_content = self.normalize_content(content)
        normalized_payload = self.normalize_content(payload)

        # Check for direct reflection
        direct_reflection = payload in content
        normalized_reflection = normalized_payload in normalized_content

        # Check for specific reflection contexts
        reflections = []
        if direct_reflection or normalized_reflection:
            # Find all occurrences
            for match in re.finditer(re.escape(normalized_payload), normalized_content):
                start_pos = max(0, match.start() - 50)
                end_pos = min(len(normalized_content), match.end() + 50)
                context = normalized_content[start_pos:end_pos]
                
                # Determine the reflection context
                if re.search(r'<script[^>]*>', context):
                    reflections.append(('script', context))
                elif re.search(r'<[^>]*=[\'"]*', context):
                    reflections.append(('attribute', context))
                elif re.search(r'javascript:', context):
                    reflections.append(('javascript', context))
                else:
                    reflections.append(('html', context))

        is_reflected = len(reflections) > 0 or direct_reflection or normalized_reflection

        return is_reflected, {
            'direct_reflection': direct_reflection,
            'normalized_reflection': normalized_reflection,
            'reflection_contexts': reflections,
            'payload_type': 'reflected',
            'confidence': 'high' if direct_reflection else 'medium'
        }

class VulnerabilityVerifier:
    def __init__(self, dom_scanner: DOMXSSScanner, reflection_analyzer: ReflectionAnalyzer):
        self.dom_scanner = dom_scanner
        self.reflection_analyzer = reflection_analyzer

    async def verify_vulnerability(self, page: Page, content: str, payload: str, url: str) -> Dict[str, Any]:
        """
        Comprehensive verification of XSS vulnerability with certificate error handling.
        Returns detailed analysis results.
        """
        # Configure page to ignore certificate errors
        context = page.context
        await context.clear_cookies()
        
        # Set extra headers to handle SSL
        await context.set_extra_http_headers({
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })
        
        # Check for DOM-based vulnerability
        dom_vulnerable, dom_details = await self.dom_scanner.check_dom_vulnerability(content, payload)
        
        # Check for reflection-based vulnerability
        is_reflected, reflection_details = await self.reflection_analyzer.analyze_reflection(content, payload)

        # Determine the vulnerability type
        vuln_types = []
        if dom_vulnerable:
            vuln_types.append('dom')
        if is_reflected:
            vuln_types.append('reflected')

        vuln_type = 'hybrid' if len(vuln_types) > 1 else (vuln_types[0] if vuln_types else 'none')
        
        # Enhanced alert detection with context tracking
        alert_details = await self._check_for_alert(page, url)

        return {
            'vulnerable': bool(vuln_types) and alert_details['alert_triggered'],
            'vulnerability_type': vuln_type,
            'dom_analysis': dom_details,
            'reflection_analysis': reflection_details,
            'alert_details': alert_details,
            'url': url,
            'payload': payload
        }

    async def _check_for_alert(self, page: Page, url: str) -> Dict[str, Any]:
        """
        Enhanced alert detection with better context tracking.
        """
        alert_triggered = False
        alert_text = None
        execution_context = None

        async def handle_dialog(dialog):
            nonlocal alert_triggered, alert_text, execution_context
            alert_triggered = True
            alert_text = dialog.message
            try:
                execution_context = await page.evaluate('() => document.currentScript?.src || "inline"')
            except:
                execution_context = "unknown"
            await dialog.accept()

        try:
            page.on("dialog", handle_dialog)
            await page.goto(url, wait_until='networkidle')
            await page.wait_for_timeout(3000)  # Adjust timeout as needed

            # Check for DOM modifications
            dom_modified = await page.evaluate("""() => {
                return {
                    innerHTML_modified: window._domModified || false,
                    script_executed: window._scriptExecuted || false,
                    event_triggered: window._eventTriggered || false
                }
            }""")

            return {
                'alert_triggered': alert_triggered,
                'alert_text': alert_text,
                'execution_context': execution_context,
                'dom_modifications': dom_modified
            }

        finally:
            page.remove_listener("dialog", handle_dialog)

class CustomStderr:
    def __init__(self, error_log_path):
        self.error_log = open(error_log_path, 'a')
        self.stderr = sys.stderr
        self.isatty = getattr(sys.stderr, 'isatty', lambda: False)

    def write(self, message):
        if any(pattern in message for pattern in [
            'Event loop is closed',
            'Task was destroyed but it is pending',
            'Exception ignored in:',
            'task: <Task cancelled',
            'BaseSubprocessTransport.__del__',
            'transport was deleted'
        ]):
            self.error_log.write(message)
            self.error_log.flush()
        else:
            self.stderr.write(message)
            self.stderr.flush()

    def flush(self):
        self.error_log.flush()
        self.stderr.flush()

    def close(self):
        self.error_log.close()

    def isatty(self):
        return self.stderr.isatty()

    def fileno(self):
        return self.stderr.fileno()

def cleanup_stderr():
    try:
        if hasattr(sys.stderr, 'close'):
            sys.stderr.close()
    except:
        pass

atexit.register(cleanup_stderr)

warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", category=ResourceWarning)
warnings.filterwarnings("ignore", message="Event loop is closed")
warnings.filterwarnings("ignore", message=".*Task .* was destroyed but it is pending!.*")

def custom_exception_handler(loop, context):
    if isinstance(context.get('exception'), RuntimeError):
        if 'Event loop is closed' in str(context.get('message', '')):
            return
    if isinstance(context.get('exception'), asyncio.CancelledError):
        return
    msg = context.get('message')
    if not any(ignore in str(msg) for ignore in [
        'Event loop is closed',
        'Task was destroyed but it is pending',
        'task: <Task cancelled',
        'transport was deleted'
    ]):
        pass

def cleanup_loop():
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.stop()
        if not loop.is_closed():
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()
    except:
        pass

def cleanup_resources():
    gc.collect()

atexit.register(cleanup_resources)
atexit.register(cleanup_loop)

loop = asyncio.new_event_loop()
loop.set_exception_handler(custom_exception_handler)
asyncio.set_event_loop(loop)

def log_error(message: str, exc: Optional[Exception] = None) -> None:
    if exc:
        logging.error(message, exc_info=True)
    else:
        logging.error(message)

def get_playwright_version() -> str:
    try:
        import playwright
        version = getattr(playwright, '__version__', None)
        if not version:
            try:
                version = get_version('playwright')
            except PackageNotFoundError:
                version = "unknown"
        if version == "0.0.0":
            version = "0.0.0 (Normal on some Linux distributions)"
        return version
    except Exception as e:
        return f"error retrieving version: {e}"

def check_playwright_version() -> str:
    playwright_version = get_playwright_version()
    try:
        if playwright_version == "0.0.0" or playwright_version == "0.0.0 (Normal on some Linux distributions)":
            return playwright_version
        required_version = '1.35.0'
        if parse_version(playwright_version) < parse_version(required_version):
            print(f"{Fore.RED}Error: This tool requires Playwright >= {required_version}")
            print(f"Current version: {playwright_version}")
            print(f"Please upgrade: pip install -U playwright{Style.RESET_ALL}")
            sys.exit(1)
    except Exception as e:
        if "not installed" in str(e):
            print(f"{Fore.RED}Error: Playwright is not installed")
            print("Please install: pip install playwright>=1.35.0")
            print(f"Then run: playwright install chromium{Style.RESET_ALL}")
            sys.exit(1)
        else:
            print(f"{Fore.RED}Error checking Playwright version: {e}{Style.RESET_ALL}")
            sys.exit(1)
    return playwright_version

class TimeoutFilter(logging.Filter):
    TIMEOUT_PATTERNS = [
        "Timeout",
        "TimeoutError",
        "Page.goto: Timeout",
        "page.goto: Timeout",
        "Call log:",
        "navigating to",
        "Error checking reflection",
        "Error closing browser",
        "Connection closed"
    ]
    def filter(self, record: logging.LogRecord) -> bool:
        return not any(pattern in str(record.msg) for pattern in self.TIMEOUT_PATTERNS)

class VersionManager:
    def __init__(self, file_path: str) -> None:
        self.file_path = Path(file_path)
        self.version_pattern = re.compile(r'VERSION\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']')

    def get_current_version(self) -> str:
        try:
            content = self.file_path.read_text()
            match = self.version_pattern.search(content)
            if match:
                return match.group(1)
            raise ValueError("VERSION variable not found in file")
        except Exception as e:
            log_error(f"Error reading version: {e}")
            return "0.0.1"

    def update_version(self, new_version: str) -> bool:
        try:
            content = self.file_path.read_text()
            updated_content = self.version_pattern.sub(f'VERSION = "{new_version}"', content)
            self.file_path.write_text(updated_content)
            return True
        except Exception as e:
            log_error(f"Error updating version: {e}")
            return False

class Updater:
    def __init__(self) -> None:
        self.current_version: str = VERSION
        self.repo_path: Path = Path(__file__).parent
        self.is_git_repo: bool = self._check_git_repo()
        self.default_branch: Optional[str] = self._detect_default_branch()

    def _check_git_repo(self) -> bool:
        try:
            subprocess.run(
                ['git', 'rev-parse', '--git-dir'],
                cwd=self.repo_path,
                capture_output=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
        except Exception as e:
            return False

    def _detect_default_branch(self) -> Optional[str]:
        if not self.is_git_repo:
            return None
        try:
            result = subprocess.run(
                ['git', 'remote', 'show', 'origin'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            for line in result.stdout.split('\n'):
                if 'HEAD branch:' in line:
                    return line.split(':')[1].strip()
        except:
            pass
        return 'main'

class AutoUpdater(Updater):
    def _check_git_repo(self) -> bool:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                subprocess.run(
                    ['git', 'rev-parse', '--git-dir'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
            return True
        except:
            return False

    def _get_local_version(self) -> str:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            result = subprocess.run(
                ['git', 'describe', '--tags', '--abbrev=0'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2,
                env=env,
                cwd=self.repo_path
            )
            if result.returncode == 0:
                return result.stdout.strip().lstrip('v')
            return self.current_version
        except:
            return self.current_version

    def _detect_default_branch(self) -> Optional[str]:
        if not self.is_git_repo:
            return None
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
                return result.stdout.strip() or 'main'
        except:
            return 'main'

    def _get_remote_changes(self) -> Tuple[bool, str]:
        if not self.default_branch:
            return False, "Check skipped"
        env = os.environ.copy()
        env["GIT_ASKPASS"] = "echo"
        env["GIT_TERMINAL_PROMPT"] = "0"
        local_version = self._get_local_version()
        try:
            with open(os.devnull, 'w') as devnull:
                fetch_result = subprocess.run(
                    ['git', 'fetch', '--tags', 'origin'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
                if fetch_result.returncode != 0:
                    return False, "Check skipped"
                result = subprocess.run(
                    ['git', 'describe', '--tags', '--abbrev=0', f'origin/{self.default_branch}'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
                if result.returncode != 0:
                    return False, "Check skipped"
                remote_tag = result.stdout.strip()
                if not remote_tag:
                    return False, "Check skipped"
                remote_version = remote_tag.lstrip('v')
                if self._compare_versions(remote_version, local_version):
                    return True, remote_version
                else:
                    return False, local_version
        except subprocess.TimeoutExpired:
            return False, "Check skipped"
        except Exception as e:
            return False, "Check skipped"

    def _run_git_command(self, command: List[str]) -> Optional[str]:
        if not self.is_git_repo:
            return None
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
            return result.stdout.strip()
        except:
            return None

    def _perform_update(self) -> Dict[str, Any]:
        if not self.default_branch:
            return {
                'status': 'error',
                'message': 'No default branch detected'
            }
        if not self._run_git_command(['git', 'reset', '--hard', f'origin/{self.default_branch}']):
            return {
                'status': 'error',
                'message': 'Update failed'
            }
        pull_output = self._run_git_command(['git', 'pull', '--force', 'origin', self.default_branch])
        if not pull_output:
            return {
                'status': 'error',
                'message': 'Pull failed'
            }
        current_tag = self._run_git_command(['git', 'describe', '--tags', '--abbrev=0']) or self.current_version
        return {
            'status': 'success',
            'message': 'Update successful',
            'version': current_tag.lstrip('v'),
            'changes': pull_output,
            'updated': True
        }

    def _compare_versions(self, v1: str, v2: str) -> bool:
        def to_ints(v: str):
            return list(map(int, v.split('.')))
        result = to_ints(v1) > to_ints(v2)
        return result

    def check_and_update(self) -> Dict[str, Any]:
        if not self.is_git_repo:
            return {
                'status': 'error',
                'message': 'Not a git repository'
            }
        has_changes, info = self._get_remote_changes()
        if info == "Check skipped":
            return {
                'status': 'success',
                'message': 'Check skipped',
                'version': self.current_version,
                'updated': False
            }
        elif not has_changes:
            return {
                'status': 'success',
                'message': 'Already at latest version',
                'version': self.current_version,
                'updated': False
            }
        update_result = self._perform_update()
        return update_result

class VersionInfo:
    def __init__(self, current: str, update_available: str):
        self.current = current
        self.update_available = update_available

class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return metavar
        else:
            parts = []
            if hasattr(self, '_usage_mode'):
                return action.option_strings[0]
            if action.nargs == 0:
                parts.extend(action.option_strings)
            else:
                parts.extend(action.option_strings)
            return ', '.join(parts)

    def _expand_help(self, action: argparse.Action) -> str:
        params = dict(vars(action), prog=self._prog)
        for name in list(params):
            if params[name] is argparse.SUPPRESS:
                del params[name]
            elif hasattr(params[name], '__name__'):
                params[name] = params[name].__name__
        if params.get('help') == 'show this help message and exit':
            return 'Show this help message and exit'
        return self._get_help_string(action) % params

    def _format_usage(self, usage: Optional[str], actions: List[argparse.Action],
                     groups: List[argparse._ArgumentGroup], prefix: Optional[str]) -> str:
        if prefix is None:
            prefix = 'usage: '
        self._usage_mode = True
        action_usage = []
        action_usage.append("[-h HELP]")
        action_usage.append("[-d DOMAIN | -l URL_LIST]")
        for action in actions:
            if action.option_strings:
                if action.option_strings[0] not in ['-h', '-d', '-l']:
                    msg = self._format_action_invocation(action)
                    upper_dest = action.dest.upper()
                    action_usage.append(f"[{msg} {upper_dest}]")
        usage = ' '.join([x for x in action_usage if x])
        delattr(self, '_usage_mode')
        return f"{prefix}{self._prog} {usage}\n\n"

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        args = sys.argv[1:]
        if len(args) == 0:
            self.print_help()
            sys.exit(2)
        if '-u' in args or '--update' in args:
            if len(args) == 1:
                return
        self.print_help()
        print(f"\n{Fore.RED}Error: {message}{Style.RESET_ALL}")
        if "one of the arguments -d/--domain -l/--url-list" in message:
            print(f"\n{Fore.RED}❌ One of the arguments is required -d/--domain or -l/--url-list{Style.RESET_ALL}")
        elif "Please provide a full URL with scheme" in message:
            print(f"\n{Fore.RED}❌ Error: Invalid URL format.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}🧩 URL must start with http:// or https://{Style.RESET_ALL}")
            print(f"{Fore.CYAN}🔗 Example of a valid URL: https://example.com/page?param1=value&param2=test{Style.RESET_ALL}")
        elif "at least one query parameter" in message:
            print(f"\n{Fore.RED}❌ Error: Invalid URL format.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}🧩 URL must include at least one query parameter.{Style.RESET_ALL}")
            print(f"{Fore.CYAN}🔗 Example of a valid URL: https://example.com/page?param1=value&param2=test{Style.RESET_ALL}")
        elif "unrecognized arguments" in message:
            print(f"{Fore.YELLOW}Use -h or --help to see available options{Style.RESET_ALL}")
        sys.exit(2)

def validate_url(url: str) -> bool:
    """
    Validate URL for parameter presence in both normal queries and after fragments.
    Now accepts both empty parameters and parameters with values.
    """
    try:
        decoded_url = urllib.parse.unquote(url)
        if not decoded_url.startswith(('http://', 'https://')):
            return False
        if '?' not in decoded_url:
            return False
        query_part = ""
        if '#' in decoded_url and '?' in decoded_url.split('#')[1]:
            query_part = decoded_url.split('#')[1].split('?')[1]
        else:
            query_part = decoded_url.split('?')[1]
        params = query_part.split('&')
        for param in params:
            if param and '=' in param:
                param_name = param.split('=')[0]
                if param_name:
                    return True
        return False
    except Exception:
        return False

def parse_arguments() -> argparse.Namespace:
    parser = CustomArgumentParser(
        formatter_class=lambda prog: CustomHelpFormatter(prog, max_help_position=80)
    )
    parser.add_argument('-u', '--update',
                      action='store_true',
                      help='Check for updates and automatically install the latest version')
    mutex_group = parser.add_mutually_exclusive_group(required=False)
    mutex_group.add_argument('-d', '--domain',
                           help='Specify the domain with parameter(s) to scan (required unless -l is used)')
    mutex_group.add_argument('-l', '--url-list',
                           help='Provide a file containing a list of URLs with parameters to scan')
    parser.add_argument('-p', '--payloads', default='xss_payloads.txt',
                       help='Custom file containing payloads')
    parser.add_argument('-o', '--output',
                       help='Specify the output file name (supports .txt or .json)')
    parser.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS,
                       help=f'Maximum number of concurrent workers')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT,
                       help=f'Total request timeout in seconds')
    parser.add_argument('-a', '--alert-timeout', type=int, default=DEFAULT_ALERT_TIMEOUT,
                       help=f'Specify the alert timeout in seconds')
    parser.add_argument('-j', '--json', action='store_true',
                       help='Output results in JSON format')
    parser.add_argument('-H', '--header', action='append',
                       help='Custom headers can be specified multiple times. Format: "Header: Value"')
    parser.add_argument('-b', '--batch-size', type=int, default=PAYLOADS_BATCH_SIZE,
                       help=f'Define the number of requests per batch (default: {PAYLOADS_BATCH_SIZE})')
    parser.add_argument('-r', '--rate-limit', type=int, default=DEFAULT_RATE_LIMIT,
                       help=f'Maximum number of requests per second (default: {DEFAULT_RATE_LIMIT})')
    args = parser.parse_args()

    if not args.update and not (args.domain or args.url_list):
        parser.error("One of the arguments -d/--domain -l/--url-list is required")

    if not args.update:
        if args.workers < 1 or args.workers > MAX_CONCURRENT_WORKERS:
            parser.error(f"Workers must be between 1 and {MAX_CONCURRENT_WORKERS}")
        if args.timeout < 1 or args.timeout > 60:
            parser.error("Timeout must be between 1 and 60 seconds")
        if args.alert_timeout < 1 or args.alert_timeout > 30:
            parser.error("Alert timeout must be between 1 and 30 seconds")
        if args.batch_size < 1 or args.batch_size > 1000:
            parser.error("Batch size must be between 1 and 1000")
        if args.rate_limit < 1 or args.rate_limit > 100:
            parser.error("Rate limit must be between 1 and 100 requests per second")
        if args.domain:
            if not validate_url(args.domain):
                parser.error("\n\nPlease provide a valid URL with parameters. Examples:\n" +
                           "- http://testhtml5.vulnweb.com/#/redir?url=\n" +
                           "- http://testhtml5.vulnweb.com/%23/redir?url=value\n" +
                           "- https://example.com/page?param1=value")
    return args

class GitHandler:
    @staticmethod
    def check_git() -> Tuple[bool, str]:
        try:
            result = subprocess.run(
                ['git', '--version'],
                capture_output=True,
                text=True,
                check=True,
                env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},
                stdin=subprocess.DEVNULL
            )
            return True, result.stdout.strip()
        except FileNotFoundError:
            return False, "Git is not installed"
        except subprocess.CalledProcessError as e:
            return False, f"Git error: {e.stderr.strip()}"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def check_repo_status() -> Tuple[bool, str]:
        try:
            subprocess.run(
                ['git', 'rev-parse', '--git-dir'],
                capture_output=True,
                check=True,
                env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},
                stdin=subprocess.DEVNULL
            )
            return True, "Repository OK"
        except subprocess.CalledProcessError:
            return False, "Update: Repository not initialized"
        except Exception as e:
            return False, f"Update: Repository connection error"

    @staticmethod
    def get_installation_instructions() -> str:
        system = platform.system().lower()
        if system == "windows":
            return """
Git is not installed. To install Git on Windows:

1. Download the official Git installer:
   https://git-scm.com/download/windows

2. Or install with winget:
   winget install --id Git.Git -e --source winget

3. Or install with Chocolatey:
   choco install git

After installation, restart your terminal/command prompt.
"""
        elif system == "darwin":
            return """
Git is not installed. To install Git on macOS:

1. Install with Homebrew (recommended):
   brew install git

2. Install Xcode Command Line Tools (alternative):
   xcode-select --install

After installation, restart your terminal.
"""
        elif system == "linux":
            try:
                with open('/etc/os-release') as f:
                    distro = f.read().lower()
                if 'ubuntu' in distro or 'debian' in distro or 'kali' in distro:
                    return """
Git is not installed. To install Git:

1. Update package list:
   sudo apt update

2. Install git:
   sudo apt install git

After installation, restart your terminal.
"""
                elif 'fedora' in distro or 'rhel' in distro or 'centos' in distro:
                    return """
Git is not installed. To install Git:

1. Install git:
   sudo dnf install git  (Fedora)
   sudo yum install git  (RHEL/CentOS)

After installation, restart your terminal.
"""
                elif 'arch' in distro:
                    return """
Git is not installed. To install Git:

1. Install git:
   sudo pacman -S git

After installation, restart your terminal.
"""
            except:
                pass
            return """
Git is not installed. To install Git on Linux:
Common commands:
- Ubuntu/Debian/Kali: sudo apt install git
- Fedora: sudo dnf install git
- Arch: sudo pacman -S git

After installation, restart your terminal.
"""
        return """
Git is not installed. Please install Git for your operating system:
https://git-scm.com/downloads
"""

    def ensure_git_available(self) -> bool:
        is_installed, message = self.check_git()
        if not is_installed:
            print(f"\n{Fore.RED}Error: {message}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Installation Instructions:{Style.RESET_ALL}")
            print(self.get_installation_instructions())
            return False
        return True

class Config:
    def __init__(self, args: argparse.Namespace, playwright_version: str) -> None:
        self.github_url = "https://github.com/Cybersecurity-Ethical-Hacker/xssuccessor"
        self.github_repository = "Cybersecurity-Ethical-Hacker/xssuccessor"
        updater = AutoUpdater()
        self.current_version = updater._get_local_version()
        self.domain: Optional[str] = args.domain
        self.url_list: Optional[str] = args.url_list
        self.json_output: bool = args.json
        self.timeout: int = args.timeout
        self.alert_timeout: int = args.alert_timeout
        self.max_workers: int = args.workers
        self.batch_size: int = min(args.batch_size, PAYLOADS_BATCH_SIZE)
        self.rate_limit: int = args.rate_limit
        self.playwright_version: str = playwright_version

        git_handler = GitHandler()
        repo_status, repo_message = git_handler.check_repo_status()
        self.version_info: VersionInfo = self._check_version()

        self.custom_headers_present = False
        custom_headers = {}
        if args.header:
            self.custom_headers_present = True
            for header in args.header:
                if ':' in header:
                    key, value = header.split(':', 1)
                    custom_headers[key.strip()] = value.strip()
                else:
                    print(f"{Fore.RED}Invalid header format: {header}. Headers must be in 'HeaderName: HeaderValue' format.{Style.RESET_ALL}")
                    sys.exit(1)
        self.headers = HeaderManager.get_headers(custom_headers)

        self._setup_directories(args)
        self._setup_files(args)

    def _check_version(self) -> VersionInfo:
        try:
            git_handler = GitHandler()
            repo_status, repo_message = git_handler.check_repo_status()
            if not repo_status:
                return VersionInfo(
                    current=VERSION,
                    update_available='Unknown (No Repository)'
                )
            updater = AutoUpdater()
            local_version = updater._get_local_version()
            has_changes, info = updater._get_remote_changes()
            if info == "Check skipped":
                return VersionInfo(
                    current=local_version,
                    update_available='Check skipped'
                )
            elif has_changes:
                return VersionInfo(
                    current=local_version,
                    update_available='Yes'
                )
            return VersionInfo(
                current=local_version,
                update_available='No'
            )
        except Exception as e:
            log_error(f"Update check: {str(e)}")
            return VersionInfo(
                current=VERSION,
                update_available='Check Failed'
            )

    def _setup_directories(self, args: argparse.Namespace) -> None:
        if self.domain:
            parsed_url = urlparse(self.domain)
            base_name = parsed_url.netloc.split(':')[0]
        elif self.url_list:
            base_name = Path(self.url_list).stem
        else:
            base_name = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.base_dir = Path(f"scans/{base_name}")
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _setup_files(self, args: argparse.Namespace) -> None:
        self.payload_file = Path(args.payloads)
        if not self.payload_file.exists():
            print(f"{Fore.RED}\nError: Payload file not found: {self.payload_file}{Style.RESET_ALL}")
            sys.exit(1)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if args.output:
            output_path = Path(args.output)
            if self.json_output and output_path.suffix.lower() != '.json':
                self.output_file = output_path.parent / f"{output_path.stem}_{timestamp}.json"
            else:
                self.output_file = output_path.parent / f"{output_path.stem}_{timestamp}{output_path.suffix if output_path.suffix else '.txt'}"
        else:
            if self.json_output:
                self.output_file = self.base_dir / f"xss_results_{timestamp}.json"
            else:
                self.output_file = self.base_dir / f"xss_results_{timestamp}.txt"

class XSSScanner:
    async def send_telegram_notification(self, message: str) -> None:
        if not TELEGRAM_NOTIFICATIONS_ENABLED or not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            return
        try:
            telegram_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            message = (message.replace('<', '&lt;')
                            .replace('>', '&gt;')
                            .replace('&', '&amp;')
                            .replace('"', '&quot;')
                            .replace("'", '&#39;'))
            params = {
                'chat_id': TELEGRAM_CHAT_ID,
                'text': message,
                'parse_mode': 'HTML'
            }
            async with self.http_session.post(telegram_url, json=params) as response:
                if response.status != 200:
                    error_msg = await response.text()
                    log_error(f"Telegram notification error: {error_msg}")
        except Exception as e:
            log_error(f"Telegram notification error: {str(e)}")

    def _extract_payload_from_url(self, url: str) -> Optional[str]:
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param_values in params.values():
                for value in param_values:
                    if any(payload in value for payload in self.payloads):
                        return value
            return None
        except Exception:
            return None

    SVG_PATTERNS = [
        re.compile(r'<\s*svg[^>]*>(.*?)</\s*svg\s*>', re.I | re.S),
        re.compile(r'<\s*svg[^>]*onload\s*=', re.I),
        re.compile(r'<\s*svg[^>]*on\w+\s*=', re.I)
    ]
    JS_PATTERNS = [
        re.compile(r'javascript:.*alert', re.I),
        re.compile(r'javascript:.*confirm', re.I),
        re.compile(r'javascript:.*prompt', re.I),
        re.compile(r'javascript:.*eval', re.I),
        re.compile(r'data:text/html.*base64', re.I)
    ]
    EVENT_PATTERNS = [
        re.compile(r'on\w+\s*=\s*(["\']|&quot;|&#39;)?(\w|\+|\s|\\|&#x|%|!|\^|\(|\)|{|}|\[|\])*?(alert|confirm|prompt|eval)', re.I),
        re.compile(r'on\w+\s*=\s*(["\']|&quot;|&#39;)?(\w|\+|\s|\\|&#x|%|!|\^|\(|\)|{|}|\[|\])*?(location|document|window|this)', re.I)
    ]

    def __init__(self, config: Config) -> None:
        self.config: Config = config
        self.ERROR_LOG_FILE = "logs/errors.log"
        self.stats: Dict[str, int] = {
            'total_urls': 0,
            'parameters_tested': 0,
            'payloads_tested': 0,
            'successful_payloads': 0,
            'failed_payloads': 0,
            'errors': 0
        }
        # Initialize the enhanced detection components
        self.dom_scanner = DOMXSSScanner()
        self.reflection_analyzer = ReflectionAnalyzer()
        self.vulnerability_verifier = VulnerabilityVerifier(
            dom_scanner=self.dom_scanner,
            reflection_analyzer=self.reflection_analyzer
        )
        self.error_types: Dict[str, int] = {}
        self.start_time: Optional[float] = None
        self.output_lock: asyncio.Lock = asyncio.Lock()
        self.stats_lock: asyncio.Lock = asyncio.Lock()
        self.tested_parameters: set = set()
        self.tested_parameters_lock = asyncio.Lock()
        self.results: List[str] = []
        self.json_results: List[Dict[str, Any]] = []
        self.total_tests: int = 0
        self.urls: List[str] = []
        self.payloads: List[str] = []
        self.interrupted: bool = False
        self.running: bool = True
        self.rate_limiter = RateLimiter(config.rate_limit)
        self.progress_bar: Optional[tqdm_asyncio] = None
        self.browser: Optional[Browser] = None
        self.context_pool: asyncio.Queue = asyncio.Queue()
        self.http_session: Optional[aiohttp.ClientSession] = None

    async def initialize_http_session(self) -> None:
        connector = aiohttp.TCPConnector(
            limit=self.config.max_workers * CONNECTIONS_PER_WORKER,
            ttl_dns_cache=300,
            force_close=True,
            enable_cleanup_closed=True,
            ssl=False,
            use_dns_cache=True,
            resolver=aiohttp.AsyncResolver(nameservers=['8.8.8.8', '1.1.1.1']),
        )
        timeout = aiohttp.ClientTimeout(
            total=self.config.timeout,
            connect=self.config.timeout / 2,
            sock_connect=self.config.timeout / 2,
            sock_read=self.config.timeout
        )
        self.http_session = aiohttp.ClientSession(
            connector=connector,
            headers=self.config.headers,
            timeout=timeout
        )

    async def close_http_session(self) -> None:
        if self.http_session:
            await self.http_session.close()

    async def initialize_browser(self) -> None:
        try:
            playwright_obj = await async_playwright().start()
            self.browser = await playwright_obj.chromium.launch(
                headless=True,
                args=['--disable-web-security', '--ignore-certificate-errors']
            )
            for _ in range(self.config.max_workers):
                context = await self.browser.new_context(
                    bypass_csp=True,
                    ignore_https_errors=True
                )
                page = await context.new_page()
                await self.context_pool.put((context, page))
        except Exception as e:
            log_error(f"Failed to initialize browser: {str(e)}")
            raise

    async def acquire_context(self) -> Tuple[BrowserContext, Page]:
        return await self.context_pool.get()

    async def release_context(self, context: BrowserContext, page: Page) -> None:
        await self.context_pool.put((context, page))

    def get_parameter_context(self, url: str, param: str) -> str:
        parsed = urlparse(url)
        normalized_path = parsed.path.rstrip('/')
        return f"{parsed.netloc}{normalized_path}:{param.lower()}"

    async def should_test_parameter(self, url: str, param: str) -> bool:
        context = self.get_parameter_context(url, param)
        async with self.tested_parameters_lock:
            if context not in self.tested_parameters:
                self.tested_parameters.add(context)
                return True
            return False

    def inject_payload(self, url: str, payload: str) -> List[Tuple[str, str]]:
        if '?' not in url:
            return []
        base_url, query = url.split('?', 1)
        injected_urls = []
        param_pairs = query.split('&')
        for pair in param_pairs:
            if '=' not in pair:
                continue
            param_name = pair.split('=', 1)[0]
            new_pairs = []
            for original_pair in param_pairs:
                if original_pair.startswith(f"{param_name}="):
                    new_pairs.append(f"{param_name}={payload}")
                else:
                    original_param_name, original_value = original_pair.split('=', 1)
                    new_pairs.append(f"{original_param_name}={original_value}")
            new_url = f"{base_url}?{'&'.join(new_pairs)}"
            injected_urls.append((new_url, param_name))
        return injected_urls

    # REFINE COMPLEX REFLECTION CHECK
    async def _check_complex_reflection(self, content: str, payload: str) -> bool:
        """
        Enhanced reflection check that safely handles escape sequences and various injection patterns.
        Returns True if a reflection is detected, False otherwise.
        """
        # Check for direct variations first
        encoded_variations = self._get_encoded_variations(payload)
        if any(var in content for var in encoded_variations):
            return True

        # Fuzzy check ignoring whitespace and newlines
        fuzzy_payload = payload.replace('\n', '').replace('\r', '').replace(' ', '')
        fuzzy_content = content.replace('\n', '').replace('\r', '').replace(' ', '')
        if fuzzy_payload in fuzzy_content:
            return True

        # Handle escape sequences safely
        if re.search(r'(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|&#x[0-9a-fA-F]+;)', payload, re.IGNORECASE):
            try:
                def decode_hex(match):
                    try:
                        hex_str = match.group(1)
                        if hex_str.startswith('\\x'):
                            hex_val = hex_str[2:]
                            if len(hex_val) == 2 and all(c in '0123456789abcdefABCDEF' for c in hex_val):
                                return bytes.fromhex(hex_val).decode('utf-8', errors='ignore')
                        elif hex_str.startswith('\\u'):
                            hex_val = hex_str[2:]
                            if len(hex_val) == 4 and all(c in '0123456789abcdefABCDEF' for c in hex_val):
                                return chr(int(hex_val, 16))
                        elif hex_str.startswith('&#x'):
                            hex_val = hex_str[3:].rstrip(';')
                            if all(c in '0123456789abcdefABCDEF' for c in hex_val):
                                return chr(int(hex_val, 16))
                        return match.group(0)  # Return original if can't decode
                    except:
                        return match.group(0)  # Return original on any error

                escaped_payload = re.sub(
                    r'((?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|&#x[0-9a-fA-F]+;))',
                    decode_hex,
                    payload
                )
                if escaped_payload in content:
                    return True
            except Exception:
                pass  # Silently continue if decoding fails

        # Detect partial merges like <SvgOnLoad=, <DivOnError=, etc.
        if re.search(r'<\w+on(?:load|error|click|mouseover)\s*=', content, re.IGNORECASE):
            return True

        # SVG pattern checks
        if 'svg' in payload.lower():
            if any(pattern.search(content) for pattern in self.SVG_PATTERNS):
                return True

        # JavaScript protocol checks
        if 'javascript:' in payload.lower():
            if any(pattern.search(content) for pattern in self.JS_PATTERNS):
                return True

        # Event handler pattern checks
        if any(evt in payload.lower() for evt in ['onload', 'onerror', 'onmouseover', 'onclick']):
            if any(pattern.search(content) for pattern in self.EVENT_PATTERNS):
                return True

        # Data URI scheme checks
        if 'data:' in payload.lower():
            data_patterns = [
                re.compile(r'data:text/html.*,', re.IGNORECASE),
                re.compile(r'data:image/svg.*,', re.IGNORECASE),
                re.compile(r'data:application/x-.*,', re.IGNORECASE)
            ]
            if any(pattern.search(content) for pattern in data_patterns):
                return True

        # Expression checks
        if 'expression' in payload.lower():
            expr_patterns = [
                re.compile(r'expression\s*\(', re.IGNORECASE),
                re.compile(r'expr\s*\(', re.IGNORECASE)
            ]
            if any(pattern.search(content) for pattern in expr_patterns):
                return True

        # Template literal and concatenation checks
        if any(char in payload for char in ['`', '+', '${']): 
            concat_patterns = [
                re.compile(r'\$\{.*\}', re.DOTALL),
                re.compile(r'["\'][\s+]*\+[\s+]*["\']'),
                re.compile(r'`[^`]*\$\{[^}]*\}[^`]*`')
            ]
            if any(pattern.search(content) for pattern in concat_patterns):
                return True

        # Constructor checks
        if 'constructor' in payload:
            constructor_patterns = [
                re.compile(r'constructor\s*\('),
                re.compile(r'constructor\s*\['),
                re.compile(r'\[constructor\]')
            ]
            if any(pattern.search(content) for pattern in constructor_patterns):
                return True

        return False

    def _get_encoded_variations(self, payload: str) -> List[str]:
        variations = []
        variations.append(urllib.parse.quote(payload))
        variations.append(urllib.parse.quote_plus(payload))
        variations.append(html.escape(payload))
        variations.append(html.escape(payload, quote=False))
        variations.append(urllib.parse.quote(urllib.parse.quote(payload)))
        variations.append(html.escape(html.escape(payload)))
        variations.append(payload.encode('unicode-escape').decode())
        variations.append(base64.b64encode(payload.encode()).decode())
        variations.append(''.join([f'&#{ord(c)};' for c in payload]))
        variations.append(''.join([f'&#x{ord(c):x};' for c in payload]))
        return variations

    async def validate_alert(self, page: Page, url: str, potential_dom: bool = False) -> Tuple[bool, Optional[str], str]:
        """
        Enhanced XSS validation with balanced DOM vs Reflected detection.
        Returns: (is_vulnerable, alert_text, vulnerability_type)
        """
        alert_triggered = False
        alert_text = None
        xss_type = "none"
        
        try:
            # Set up monitoring script before navigation
            await page.add_init_script("""
                window._xssMonitor = {
                    domModified: false,
                    scriptExecuted: false,
                    eventTriggered: false,
                    urlParamAccessed: false,
                    innerHTMLModified: false,
                    documentWriteUsed: false,
                    evaluationOccurred: false,
                    directWrite: false,
                    clientSideFlow: false,
                    source: null,
                    lastSourceAccess: 0,
                    lastDomModification: 0
                };

                // Monitor URL parameter access
                const originalURLSearchParams = window.URLSearchParams;
                window.URLSearchParams = new Proxy(originalURLSearchParams, {
                    construct: function(target, args) {
                        window._xssMonitor.urlParamAccessed = true;
                        window._xssMonitor.clientSideFlow = true;
                        window._xssMonitor.source = 'urlParams';
                        window._xssMonitor.lastSourceAccess = Date.now();
                        return new target(...args);
                    }
                });

                // Monitor DOM mutations
                new MutationObserver((mutations) => {
                    for (const mutation of mutations) {
                        if (mutation.type === 'childList' || mutation.type === 'characterData') {
                            window._xssMonitor.domModified = true;
                            window._xssMonitor.lastDomModification = Date.now();
                            
                            // Check if modification happened through script
                            const stack = new Error().stack || '';
                            if (stack.includes('eval') || stack.includes('setTimeout') || 
                                stack.includes('setInterval') || stack.includes('Function')) {
                                window._xssMonitor.clientSideFlow = true;
                            }
                            
                            // Check for script elements
                            if (mutation.target.nodeName === 'SCRIPT' || 
                                [...(mutation.addedNodes || [])].some(node => node.nodeName === 'SCRIPT')) {
                                window._xssMonitor.scriptExecuted = true;
                            }
                        }
                    }
                }).observe(document, {
                    childList: true,
                    characterData: true,
                    subtree: true,
                    characterDataOldValue: true
                });

                // Monitor innerHTML modifications
                const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
                Object.defineProperty(Element.prototype, 'innerHTML', {
                    set: function(value) {
                        window._xssMonitor.innerHTMLModified = true;
                        window._xssMonitor.domModified = true;
                        window._xssMonitor.lastDomModification = Date.now();
                        
                        // Check if modification is from client-side code
                        const stack = new Error().stack || '';
                        window._xssMonitor.clientSideFlow = stack.includes('onload') || 
                                                           stack.includes('setTimeout') || 
                                                           stack.includes('addEventListener');
                        
                        return originalInnerHTMLDescriptor.set.call(this, value);
                    },
                    get: originalInnerHTMLDescriptor.get
                });

                // Monitor document.write
                const originalWrite = document.write;
                document.write = function() {
                    window._xssMonitor.documentWriteUsed = true;
                    window._xssMonitor.directWrite = true;
                    window._xssMonitor.source = 'documentWrite';
                    return originalWrite.apply(this, arguments);
                };

                // Monitor script execution
                const originalSetTimeout = window.setTimeout;
                window.setTimeout = function() {
                    window._xssMonitor.scriptExecuted = true;
                    window._xssMonitor.clientSideFlow = true;
                    window._xssMonitor.source = 'setTimeout';
                    return originalSetTimeout.apply(this, arguments);
                };

                // Monitor eval
                const originalEval = window.eval;
                window.eval = function() {
                    window._xssMonitor.evaluationOccurred = true;
                    window._xssMonitor.clientSideFlow = true;
                    window._xssMonitor.source = 'eval';
                    return originalEval.apply(this, arguments);
                };

                // Monitor location/URL access
                let locationDescriptor = Object.getOwnPropertyDescriptor(window, 'location');
                Object.defineProperty(window, 'location', {
                    get: function() {
                        window._xssMonitor.urlParamAccessed = true;
                        window._xssMonitor.lastSourceAccess = Date.now();
                        window._xssMonitor.source = 'location';
                        return locationDescriptor.get.call(this);
                    }
                });
            """)

            # Set up dialog handler
            async def handle_dialog(dialog):
                nonlocal alert_triggered, alert_text
                alert_triggered = True
                alert_text = dialog.message
                await dialog.accept()

            page.on("dialog", handle_dialog)
            
            try:
                # Navigate and wait for load
                await page.goto(url, timeout=self.config.timeout * 1000, wait_until='domcontentloaded')
                await page.wait_for_timeout(self.config.alert_timeout * 1000)

                # Check execution context and determine XSS type
                monitor_status = await page.evaluate("() => window._xssMonitor")
                
                if alert_triggered:
                    # Determine XSS type based on execution flow
                    if monitor_status.get('clientSideFlow') and monitor_status.get('urlParamAccessed'):
                        # Clear DOM-based XSS indicators:
                        # 1. URL parameter access followed by DOM modification
                        # 2. Client-side flow (setTimeout, eval, etc.)
                        # 3. Time gap between source access and DOM modification
                        time_gap = monitor_status.get('lastDomModification', 0) - monitor_status.get('lastSourceAccess', 0)
                        if time_gap > 0 and time_gap < 1000:  # Within 1 second
                            xss_type = "dom"
                        else:
                            xss_type = "reflected"
                    else:
                        # If no clear client-side flow, likely reflected
                        xss_type = "reflected"
                elif monitor_status.get('domModified'):
                    # Check for DOM XSS without alert
                    if monitor_status.get('clientSideFlow') and monitor_status.get('urlParamAccessed'):
                        alert_triggered = True
                        alert_text = "DOM Modification Detected"
                        xss_type = "dom"

                # Log detection details for debugging
                if alert_triggered:
                    logging.debug(f"XSS Detection - Type: {xss_type}")
                    logging.debug(f"Monitor Status: {json.dumps(monitor_status, indent=2)}")

                return alert_triggered, alert_text, xss_type

            except TimeoutError:
                logging.debug(f"Page load timeout for URL: {url}")
                return False, None, "none"
                
            except Exception as e:
                logging.error(f"Page navigation error: {str(e)}")
                return False, None, "none"

        except Exception as e:
            logging.error(f"Validation error: {str(e)}")
            return False, None, "none"

        finally:
            try:
                page.remove_listener("dialog", handle_dialog)
            except Exception:
                pass

    async def record_vulnerability(self, domain: str, param: str, payload: str,
                                 url: str, alert_text: str, xss_type: str,
                                 reflection_details: Optional[Dict] = None,
                                 dom_details: Optional[Dict] = None) -> None:
        async with self.output_lock:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Enhanced result with detailed analysis
            result = {
                "timestamp": timestamp,
                "domain": domain,
                "parameter": param,
                "payload": payload,
                "url": url,
                "alert_text": alert_text,
                "type": xss_type,
                "analysis": {
                    "reflection": reflection_details,
                    "dom": dom_details
                }
            }

            # Create detailed notification message
            notification_message = (
                f"🎯 XSS Vulnerability Found!\n\n"
                f"🔍 Type: {xss_type.capitalize()}\n"
                f"🌐 Domain: {domain}\n"
                f"📝 Parameter: {param}\n"
                f"💉 Payload: {payload}\n"
                f"🔗 URL: {url}\n"
                f"⚠️ Alert Text: {alert_text}\n"
                f"🕒 Time: {timestamp}\n"
            )

            if reflection_details:
                notification_message += "✓ Reflection detected in content\n"
                if reflection_details.get('reflection_contexts'):
                    contexts = reflection_details['reflection_contexts']
                    notification_message += f"✓ Found in contexts: {', '.join(c[0] for c in contexts)}\n"

            if dom_details:
                notification_message += "✓ DOM vulnerability detected\n"
                if dom_details.get('sources'):
                    notification_message += f"✓ DOM Sources found: {len(dom_details['sources'])}\n"
                if dom_details.get('sinks'):
                    notification_message += f"✓ DOM Sinks found: {len(dom_details['sinks'])}\n"
                if dom_details.get('events'):
                    notification_message += f"✓ Event handlers found\n"

            await self.send_telegram_notification(notification_message)

            if self.config.json_output:
                self.json_results.append(result)
            else:
                # Format the results for text output
                self.results.extend([
                    "=" * 50,
                    "XSS Vulnerability Found:",
                    "-" * 25,
                    f"Type: {xss_type.capitalize()}",
                    f"Domain: {domain}",
                    f"Parameter: {param}",
                    f"Payload: {payload}",
                    f"URL: {url}",
                    f"Alert Text: {alert_text}",
                    f"Timestamp: {timestamp}",
                    "",
                    "Analysis Details:",
                    "-" * 17
                ])

                if reflection_details:
                    self.results.extend([
                        "Reflection Analysis:",
                        f"• Direct Reflection: {'Yes' if reflection_details.get('direct_reflection') else 'No'}",
                        f"• Normalized Reflection: {'Yes' if reflection_details.get('normalized_reflection') else 'No'}"
                    ])
                    if reflection_details.get('reflection_contexts'):
                        self.results.append("• Found in contexts:")
                        for context_type, context in reflection_details['reflection_contexts']:
                            self.results.append(f"  - {context_type}")

                if dom_details:
                    self.results.extend([
                        "",
                        "DOM Analysis:",
                        f"• Sources Found: {len(dom_details.get('sources', []))}",
                        f"• Sinks Found: {len(dom_details.get('sinks', []))}",
                        f"• DOM Mutations: {len(dom_details.get('mutations', []))}"
                    ])
                    if dom_details.get('confidence'):
                        self.results.append(f"• Confidence: {dom_details['confidence']}")

                self.results.extend(["", "=" * 50, ""])

    async def process_parameter_payloads(self, url: str, param: str, progress_bar: tqdm_asyncio) -> None:
        domain = url.split('/')[2]
        try:
            for payload in self.payloads:
                if not self.running:
                    break

                await self.rate_limiter.acquire()

                base_url = url.split('?')[0]
                param_pairs = url.split('?')[1].split('&')
                new_pairs = []
                for pair in param_pairs:
                    if '=' in pair:
                        current_param = pair.split('=')[0]
                        if current_param == param:
                            new_pairs.append(f"{param}={payload}")
                        else:
                            new_pairs.append(pair)
                    else:
                        new_pairs.append(pair)

                test_url = f"{base_url}?{'&'.join(new_pairs)}"
                async with self.stats_lock:
                    self.stats['payloads_tested'] += 1

                try:
                    async with self.http_session.get(test_url) as response:
                        if response.status != 200:
                            if progress_bar:
                                progress_bar.update(1)
                            continue

                        response_text = await response.text()

                        # Simple reflection check
                        is_reflected_simple = (payload in response_text)
                        # Complex reflection check
                        is_reflected_advanced = await self._check_complex_reflection(response_text, payload)
                        is_reflected = is_reflected_simple or is_reflected_advanced

                        # DOM pattern check
                        potential_dom = await self.dom_scanner.quick_dom_check(response_text)

                        # Skip only if BOTH reflection and DOM checks fail
                        if not is_reflected and not potential_dom:
                            async with self.stats_lock:
                                self.stats['failed_payloads'] += 1
                            if progress_bar:
                                progress_bar.update(1)
                            continue

                        # Otherwise proceed with browser test
                        context, page = await self.acquire_context()
                        try:
                            alert_triggered, alert_text, xss_type = await self.validate_alert(
                                page,
                                test_url,
                                potential_dom=potential_dom
                            )

                            if alert_triggered:
                                async with self.stats_lock:
                                    self.stats['successful_payloads'] += 1

                                payload_number = self.payload_index_map.get(payload, 0)
                                type_label = "DOM Based" if xss_type == "dom" else "Reflected"
                                domain_field = f"{domain:<25}"
                                param_field = f"{param:<10}"
                                type_field = f"{type_label:<10}"

                                message = (
                                    f"{Fore.GREEN}🎯 XSS Found!{Style.RESET_ALL}  "
                                    f"Domain: {Fore.YELLOW}{domain_field}{Style.RESET_ALL}  |  "
                                    f"Parameter: {Fore.YELLOW}{param_field}{Style.RESET_ALL}  |  "
                                    f"Type: {Fore.YELLOW}{type_field}{Style.RESET_ALL}  |  "
                                    f"Payload: {Fore.YELLOW}#{payload_number}{Style.RESET_ALL}"
                                )
                                if progress_bar:
                                    progress_bar.write(message)

                                await self.record_vulnerability(
                                    domain=domain,
                                    param=param,
                                    payload=payload,
                                    url=test_url,
                                    alert_text=alert_text,
                                    xss_type=type_label
                                )

                                remaining_payloads = len(self.payloads) - (self.payloads.index(payload) + 1)
                                if progress_bar:
                                    progress_bar.update(1 + remaining_payloads)
                                break
                            else:
                                async with self.stats_lock:
                                    self.stats['failed_payloads'] += 1
                                if progress_bar:
                                    progress_bar.update(1)

                        finally:
                            await self.release_context(context, page)

                except Exception as e:
                    async with self.stats_lock:
                        self.stats['errors'] += 1
                        self.error_types[type(e).__name__] = self.error_types.get(type(e).__name__, 0) + 1
                    if progress_bar:
                        progress_bar.update(1)
                    with open(self.ERROR_LOG_FILE, 'a', encoding='utf-8') as f:
                        f.write(f"Error processing {test_url}: {str(e)}\n")

        except Exception as e:
            log_error(f"Error in parameter payload processing: {str(e)}")
            if progress_bar:
                remaining = len(self.payloads)
                progress_bar.update(remaining)

    async def process_batch(self, batch_urls: List[str], progress_bar: tqdm_asyncio) -> None:
        try:
            semaphore = asyncio.Semaphore(MAX_WORKERS_PER_BATCH)
            tasks = []

            async def process_with_semaphore(url: str, param: str) -> None:
                try:
                    async with semaphore:
                        await self.process_parameter_payloads(url, param, progress_bar)
                        await asyncio.sleep(0.1)
                except Exception as e:
                    log_error(f"Error processing URL {url} with parameter {param}: {str(e)}")
                    if progress_bar:
                        progress_bar.update(1)

            for url in batch_urls:
                if not self.running:
                    break
                try:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    for param in params:
                        if await self.should_test_parameter(url, param):
                            task = asyncio.create_task(process_with_semaphore(url, param))
                            tasks.append(task)
                    while tasks:
                        current_tasks, tasks = tasks[:MAX_WORKERS_PER_BATCH], tasks[MAX_WORKERS_PER_BATCH:]
                        if current_tasks:
                            await asyncio.gather(*current_tasks, return_exceptions=True)
                        await asyncio.sleep(0.2)
                except Exception as e:
                    log_error(f"Error processing batch URL {url}: {str(e)}")
                    continue
        except Exception as e:
            log_error(f"Error in process_batch: {str(e)}")

    def banner(self) -> None:
        banner_width = 91
        def center_text(text: str, width: int = banner_width) -> str:
            return text.center(width)
        banner = f"""
{Fore.CYAN}██╗  ██╗███████╗███████╗██║   ██║ ██████╗ ██████╗███████╗███████╗███████╗ ██████╗ ██████╗ 
╚██╗██╔╝██╔════╝██╔════╝██║   ██║██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗
 ╚███╔╝ ███████╗███████╗██║   ██║██║     ██║     █████╗  ███████╗███████╗██║   ██║██████╔╝
 ██╔██╗ ╚════██║╚════██║██║   ██║██║     ██║     ██╔══╝  ╚════██║╚════██║██║   ██║██╔══██╗
██╔╝ ██╗███████║███████║╚██████╔╝╚██████╗╚██████╗███████╗███████║███████║╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝╚═════╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
{center_text(f"{Fore.CYAN}By Dimitris Chatzidimitris{Style.RESET_ALL}")}
{center_text(f"{Fore.CYAN}Email: dimitris.chatzidimitris@gmail.com{Style.RESET_ALL}")}
{center_text(f"{Fore.CYAN}Async-Powered / 100% Valid Results / Bypasses Cloud/WAF{Style.RESET_ALL}")}\n

{Fore.CYAN}🔧Configuration:{Style.RESET_ALL}
- Version: {Fore.GREEN}{self.config.current_version}{Style.RESET_ALL}
- Update Available: {Fore.GREEN}{self.config.version_info.update_available}{Style.RESET_ALL}
- Max Workers: {Fore.GREEN}{self.config.max_workers}{Style.RESET_ALL}
- Payloads Batch Size: {Fore.GREEN}{self.config.batch_size}{Style.RESET_ALL}
- Rate Limit: {Fore.GREEN}{self.config.rate_limit} req/s{Style.RESET_ALL}
- Page Timeout: {Fore.GREEN}{self.config.timeout}s{Style.RESET_ALL}
- Alert Timeout: {Fore.GREEN}{self.config.alert_timeout}s{Style.RESET_ALL}
- Playwright Version: {Fore.GREEN}{self.config.playwright_version}{Style.RESET_ALL}
- Payloads File: {Fore.GREEN}{self.config.payload_file}{Style.RESET_ALL}
- Custom Headers: {Fore.GREEN}{'Yes' if self.config.custom_headers_present else 'Default'}{Style.RESET_ALL}
- Output Format: {Fore.GREEN}{'JSON' if self.config.json_output else 'Text'}{Style.RESET_ALL}
- Output File: {Fore.GREEN}{str(self.config.output_file.resolve())}{Style.RESET_ALL}

"""
        print(banner)

    async def check_reflection(self, url: str, payload: str) -> bool:
        try:
            async with self.http_session.get(url) as response:
                if response.status != 200:
                    return False
                content = await response.text()
                if payload in content:
                    return True
                if await self._check_complex_reflection(content, payload):
                    return True
                return False
        except Exception as e:
            async with self.stats_lock:
                self.stats['errors'] += 1
                self.error_types[type(e).__name__] = self.error_types.get(type(e).__name__, 0) + 1
            return False

    async def run(self) -> None:
        self.banner()
        await self.load_files()
        self.start_time = time.time()

        try:
            await self.initialize_http_session()
            await self.initialize_browser()

            async def warm_up_connection(url: str) -> None:
                try:
                    async with self.http_session.head(url, timeout=2):
                        pass
                except Exception:
                    pass

            first_batch = self.urls[:min(3, len(self.urls))]
            await asyncio.gather(*[warm_up_connection(url) for url in first_batch])

            total_urls = len(self.urls)
            self.progress_bar = tqdm_asyncio(
                total=self.total_tests,
                desc="Progress",
                bar_format=(
                    "Progress: {percentage:3.0f}%|{bar}| "
                    f"[URLs: {{n_fmt}}/{total_urls}] "
                    "[{n_fmt}/{total_fmt} Tests] "
                    "[Time:{elapsed:<6} - Est:{remaining:<6}]"
                ),
                colour="cyan",
                dynamic_ncols=True,
                unit="test"
            )

            for i in range(0, total_urls, URLS_BATCH_SIZE):
                if not self.running:
                    break
                batch_urls = self.urls[i:i + URLS_BATCH_SIZE]
                current_batch_end = min(i + URLS_BATCH_SIZE, total_urls)
                self.progress_bar.bar_format = (
                    "Progress: {percentage:3.0f}%|{bar}| "
                    f"[URLs: {i+1}-{current_batch_end}/{total_urls}] "
                    "[{n_fmt}/{total_fmt} Tests] "
                    "[Time:{elapsed} - Est:{remaining}]"
                )
                try:
                    await self.process_batch(batch_urls, self.progress_bar)
                except Exception as e:
                    log_error(f"Error processing batch {i+1}-{current_batch_end}: {str(e)}")
                    continue
                await asyncio.sleep(0.5)
            await asyncio.sleep(0)

        except Exception as e:
            log_error(f"Error in run method: {str(e)}")
        finally:
            await self.cleanup()

    async def cleanup(self) -> None:
        try:
            if self.progress_bar:
                try:
                    remaining = self.progress_bar.total - self.progress_bar.n
                    if remaining > 0:
                        self.progress_bar.update(remaining)
                    self.progress_bar.refresh()
                    self.progress_bar.close()
                except:
                    pass
                self.progress_bar = None

            if hasattr(self, 'rate_limiter'):
                self.rate_limiter.reset()

            if self.stats['successful_payloads'] > 0:
                await self.save_results()

            if hasattr(self, 'context_pool') and self.context_pool is not None:
                while not self.context_pool.empty():
                    try:
                        context, page = await self.context_pool.get_nowait()
                        if page:
                            await page.close()
                        if context:
                            await context.close()
                    except Exception:
                        pass

            if hasattr(self, 'browser') and self.browser:
                try:
                    await asyncio.wait_for(self.browser.close(), timeout=2.0)
                except:
                    pass

            if hasattr(self, 'http_session') and self.http_session and not self.http_session.closed:
                try:
                    await asyncio.wait_for(self.http_session.close(), timeout=1.0)
                    await asyncio.sleep(0.1)
                except:
                    pass

            if not self.interrupted:
                self.print_final_stats()
        except Exception as e:
            log_error(f"Error during cleanup: {str(e)}")
        finally:
            if hasattr(self, 'context_pool'):
                self.context_pool = None
            if hasattr(self, 'browser'):
                self.browser = None
            if hasattr(self, 'http_session'):
                self.http_session = None
            warnings.filterwarnings("ignore",
                                  category=ResourceWarning,
                                  message="unclosed.*<aiohttp.client.ClientSession.*>")

    async def save_results(self) -> None:
        try:
            if self.config.json_output:
                async with aiofiles.open(self.config.output_file, 'w') as f:
                    await f.write(json.dumps(self.json_results, indent=2))
            else:
                async with aiofiles.open(self.config.output_file, 'w') as f:
                    await f.write('\n'.join(self.results))
        except Exception as e:
            print(f"\n{Fore.RED}Error saving results: {str(e)}{Style.RESET_ALL}")
            log_error(f"Error saving results: {str(e)}")

    def print_final_stats(self) -> None:
        if self.start_time:
            duration = time.time() - self.start_time
            minutes, seconds = divmod(int(duration), 60)
            print(f"\n{Fore.CYAN}🏁 Scan Complete! Summary:{Style.RESET_ALL}")
            print("="*30)
            print(f"Duration: {Fore.GREEN}{minutes}m {seconds}s{Style.RESET_ALL}")
            print(f"URLs tested: {Fore.GREEN}{self.stats['total_urls']}{Style.RESET_ALL}")
            print(f"Parameters tested: {Fore.GREEN}{self.stats['parameters_tested']}{Style.RESET_ALL}")
            print(f"Payloads tested: {Fore.GREEN}{self.stats['payloads_tested']}{Style.RESET_ALL}")
            print(f"Successful payloads: {Fore.GREEN}{self.stats['successful_payloads']}{Style.RESET_ALL}")
            print(f"Failed/skipped payloads: {Fore.YELLOW}{self.stats['failed_payloads']}{Style.RESET_ALL}")
            print(f"Errors encountered: {Fore.RED if self.stats['errors'] > 0 else Fore.GREEN}{self.stats['errors']}{Style.RESET_ALL}")
            if self.stats['errors'] > 0 and self.error_types:
                for err_type, count in self.error_types.items():
                    pass
            print("="*30)
            if self.stats['successful_payloads'] > 0:
                print(f"\n{Fore.CYAN}📝 Results saved to:{Style.RESET_ALL} {Fore.GREEN}{self.config.output_file.resolve()}{Style.RESET_ALL}")

    def stop(self) -> None:
        self.running = False
        self.interrupted = True

    def get_url_signature(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            if '#' in url and '?' in url.split('#')[1]:
                fragment_parts = url.split('#')[1].split('?')
                query = fragment_parts[1]
            else:
                query = parsed.query
            params = []
            if query:
                for param in query.split('&'):
                    if '=' in param:
                        name = param.split('=')[0]
                        if name:
                            params.append(f"{name}=")
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if params:
                return f"{base}?{'&'.join(params)}"
            return base
        except Exception as e:
            logging.error(f"Error generating URL signature: {str(e)}")
            return url

    async def load_files(self) -> None:
        try:
            print(f"{Fore.YELLOW}📦 Loading URLs...{Style.RESET_ALL}")

            if self.config.url_list:
                async with aiofiles.open(self.config.url_list, 'r') as f:
                    all_urls = [line.strip() for line in await f.readlines() if line.strip()]
                    valid_urls = []
                    seen_signatures = set()
                    skipped_same_params = 0

                    for url in all_urls:
                        if not validate_url(url):
                            continue
                        signature = self.get_url_signature(url)
                        if signature not in seen_signatures:
                            seen_signatures.add(signature)
                            valid_urls.append(url)
                        else:
                            skipped_same_params += 1

                    if not valid_urls:
                        print(f"\n{Fore.RED}❌ Error: No valid URLs found in the input file.{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}🧩 URLs must include parameters. Examples:{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}- http://testhtml5.vulnweb.com/#/redir?url={Style.RESET_ALL}")
                        print(f"{Fore.CYAN}- http://testhtml5.vulnweb.com/%23/redir?url=value{Style.RESET_ALL}")
                        sys.exit(2)

                    print(f"{Fore.CYAN}📝 URL Processing Results:{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}✓ Total URLs: {len(all_urls)}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}✓ Unique parameter combinations: {len(valid_urls)}{Style.RESET_ALL}")
                    if skipped_same_params > 0:
                        print(f"{Fore.GREEN}ℹ Skipped URLs (same parameters): {skipped_same_params}{Style.RESET_ALL}")
                    self.urls = valid_urls
            elif self.config.domain:
                self.urls = [self.config.domain]

            async with aiofiles.open(self.config.payload_file, 'r') as f:
                self.payloads = list(dict.fromkeys([line.strip() for line in await f.readlines() if line.strip()]))
                self.payload_index_map = {payload: idx + 1 for idx, payload in enumerate(self.payloads)}

            self.stats['total_urls'] = len(self.urls)
            total_parameters = 0
            for url in self.urls:
                decoded_url = urllib.parse.unquote(url)
                query_part = ""
                if '#' in decoded_url and '?' in decoded_url.split('#')[1]:
                    fragment_parts = decoded_url.split('#')[1]
                    query_part = fragment_parts.split('?')[1]
                elif '?' in decoded_url:
                    query_part = decoded_url.split('?')[1]
                params = []
                for param in query_part.split('&'):
                    if param and '=' in param:
                        param_name = param.split('=')[0]
                        if param_name:
                            params.append(param_name)
                total_parameters += len(params)

            self.stats['parameters_tested'] = total_parameters
            self.total_tests = total_parameters * len(self.payloads)

            print(f"{Fore.CYAN}🔗 Loaded {len(self.urls)} URLs and {len(self.payloads)} payloads{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}🔍 Starting the scan...{Style.RESET_ALL}\n")

        except FileNotFoundError as e:
            print(f"{Fore.RED}📂 Error: Could not find file: {e.filename}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}❌ An unexpected error occurred while loading files: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

async def async_main() -> None:
    scanner = None
    try:
        playwright_version = check_playwright_version()
        args = parse_arguments()
        if args.update:
            git_handler = GitHandler()
            if not git_handler.ensure_git_available():
                print(f"\n{Fore.RED}Cannot perform update without Git installed.{Style.RESET_ALL}")
                return
            print(f"\n{Fore.CYAN}Checking for updates...{Style.RESET_ALL}")
            updater = AutoUpdater()
            update_result = updater.check_and_update()
            if update_result.get('status') == 'error':
                print(f"{Fore.RED}Update check failed: {update_result.get('message')}{Style.RESET_ALL}")
                return
            elif update_result.get('updated'):
                print(f"{Fore.GREEN}Tool updated successfully to the latest version!{Style.RESET_ALL}")
                if update_result.get('changes'):
                    print(f"\nUpdated files:\n{update_result.get('changes')}")
                print(f"{Fore.YELLOW}Please restart the tool to use the new version.{Style.RESET_ALL}")
                return
            elif update_result.get('message') == 'Check skipped':
                print(f"{Fore.YELLOW}Check skipped{Style.RESET_ALL}")
                return
            else:
                print(f"{Fore.GREEN}Already running the latest version.{Style.RESET_ALL}")
                return
        config = Config(args, playwright_version)
        setup_logging(config)
        scanner = XSSScanner(config)
        await scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}🚫 Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Unhandled exception: {str(e)}", exc_info=True)
    finally:
        pass

def setup_logging(config: Config) -> None:
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    detailed_formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
    console_formatter = logging.Formatter('%(message)s')

    file_handler = logging.FileHandler(logs_dir / 'xss_scanner.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    file_handler.addFilter(lambda record: record.levelno < logging.ERROR)

    error_handler = logging.FileHandler(logs_dir / 'errors.log')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(console_formatter)
    console_handler.addFilter(TimeoutFilter())

    root_logger.addHandler(file_handler)
    root_logger.addHandler(error_handler)
    root_logger.addHandler(console_handler)

class HeaderManager:
    @staticmethod
    def get_default_headers() -> Dict[str, str]:
        chrome_versions = ["122.0.6261.112", "122.0.6261.94", "122.0.6261.69"]
        viewport_widths = [1366, 1440, 1536, 1920, 2560]
        device_memories = [2, 4, 8, 16]
        languages = [
            'en-US,en;q=0.9',
            'en-US,en;q=0.9,es;q=0.8',
            'en-GB,en;q=0.9,en-US;q=0.8',
            'en-US,en;q=0.9,fr;q=0.8'
        ]
        chrome_version = random.choice(chrome_versions)
        viewport = random.choice(viewport_widths)
        memory = random.choice(device_memories)
        language = random.choice(languages)
        base_headers = {
            'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': language,
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Ch-Ua': f'"Chromium";v="{chrome_version}", "Google Chrome";v="{chrome_version}", "Not(A:Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Ch-Ua-Platform-Version': '"15.0.0"',
            'Sec-Ch-Ua-Full-Version-List': f'"Chromium";v="{chrome_version}", "Google Chrome";v="{chrome_version}", "Not(A:Brand";v="24.0.0.0"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'Connection': 'keep-alive',
            'DNT': '1',
            'Viewport-Width': str(viewport),
            'Device-Memory': f'{memory}',
            'Priority': 'u=0, i',
            'Permissions-Policy': 'interest-cohort=()',
        }
        return base_headers

    @staticmethod
    def merge_headers(default_headers: Dict[str, str], custom_headers: Dict[str, str] = None) -> Dict[str, str]:
        if not custom_headers:
            return default_headers
        merged = default_headers.copy()
        custom_headers = {k.title(): v for k, v in custom_headers.items()}
        merged.update(custom_headers)
        return merged

    @staticmethod
    def get_headers(custom_headers: Dict[str, str] = None) -> Dict[str, str]:
        default_headers = HeaderManager.get_default_headers()
        return HeaderManager.merge_headers(default_headers, custom_headers)

class RateLimiter:
    def __init__(self, rate_limit: int):
        self.rate_limit = rate_limit
        self.tokens = rate_limit
        self.last_update = time.time()
        self.lock = asyncio.Lock()
        self._sleep_time = 1.0 / rate_limit if rate_limit > 0 else 0

    async def acquire(self):
        async with self.lock:
            now = time.time()
            time_passed = now - self.last_update
            self.tokens = min(self.rate_limit, self.tokens + time_passed * self.rate_limit)
            self.last_update = now
            if self.tokens < 1:
                sleep_time = self._sleep_time
                await asyncio.sleep(sleep_time)
                self.tokens = 1
            self.tokens -= 1

    def reset(self):
        self.tokens = self.rate_limit
        self.last_update = time.time()

def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}🚫 Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Unhandled exception: {str(e)}", exc_info=True)
        sys.exit(1)
    finally:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.stop()
            if not loop.is_closed():
                loop.close()
        except:
            pass
        cleanup_stderr()

if __name__ == "__main__":
    main()
