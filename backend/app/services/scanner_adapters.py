import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from app.core.config import get_settings


MAX_OUTPUT_BYTES = 1_000_000
MAX_SCAN_SECONDS = 60
MAX_SOURCE_FILES = 1200
MAX_SOURCE_FILE_BYTES = 1_000_000
MAX_SOURCE_TOTAL_BYTES = 20_000_000
EXCLUDED_DIRS = {".git", ".venv", "venv", "env", "node_modules", "dist", "build", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "coverage", ".next", ".codex-tmp", "site-packages"}
SECRET_TEXT = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+|((?:token|password|secret|api[_-]?key)\s*[=:]\s*)[^\s,;]+")
USERINFO_URL = re.compile(r"(https?://)[^/@\s]+:[^/@\s]+@")


@dataclass
class CommandResult:
    returncode: int | None
    output: str
    error: str | None = None
    timed_out: bool = False
    truncated: bool = False


@dataclass
class AdapterResult:
    status: str = "completed"
    availability: dict[str, str] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    summary: str = ""


CommandRunner = Callable[..., CommandResult]


def sanitize_output(value: str, limit: int = 4000) -> str:
    safe = USERINFO_URL.sub(r"\1[REDACTED]@", value)
    safe = SECRET_TEXT.sub(lambda match: (match.group(1) or match.group(2) or "") + "[REDACTED]", safe)
    return safe[:limit]


def run_bounded(args: list[str], *, cwd: Path, timeout: int = MAX_SCAN_SECONDS, output_limit: int = MAX_OUTPUT_BYTES) -> CommandResult:
    """Run a scanner without a shell, polling wall time and output size."""
    started = time.monotonic()
    with tempfile.TemporaryFile(mode="w+b") as output:
        try:
            process = subprocess.Popen(args, cwd=str(cwd), stdout=output, stderr=subprocess.STDOUT, shell=False)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return CommandResult(None, "", error=f"Scanner could not start ({exc.__class__.__name__}).")
        timed_out = False
        truncated = False
        while process.poll() is None:
            output.flush()
            if os.fstat(output.fileno()).st_size > output_limit:
                truncated = True
                process.kill()
                break
            if time.monotonic() - started > timeout:
                timed_out = True
                process.kill()
                break
            time.sleep(0.05)
        try:
            returncode = process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            returncode = process.wait()
        output.flush()
        if os.fstat(output.fileno()).st_size > output_limit:
            truncated = True
        output.seek(0)
        text = output.read(output_limit).decode("utf-8", errors="replace")
    return CommandResult(returncode, sanitize_output(text, output_limit), timed_out=timed_out, truncated=truncated)


def _walk(root: Path, extensions: set[str], *, max_files: int = MAX_SOURCE_FILES):
    found: list[Path] = []
    warnings: list[str] = []
    total = 0
    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        dirs[:] = [name for name in dirs if name not in EXCLUDED_DIRS and not (current / name).is_symlink()]
        for name in files:
            path = current / name
            if path.is_symlink() or path.suffix.lower() not in extensions:
                continue
            try:
                size = path.stat(follow_symlinks=False).st_size
            except OSError:
                warnings.append(f"Skipped unreadable file: {path.relative_to(root).as_posix()[:240]}.")
                continue
            if size > MAX_SOURCE_FILE_BYTES:
                warnings.append(f"Skipped oversized file: {path.relative_to(root).as_posix()[:240]}.")
                continue
            if len(found) >= max_files or total + size > MAX_SOURCE_TOTAL_BYTES:
                warnings.append("Source scan reached its file-count or total-size limit; results are partial.")
                return found, warnings, False
            found.append(path)
            total += size
    return found, warnings, True


def _json_from_output(output: str):
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        start = output.find("{")
        if start >= 0:
            try:
                return json.loads(output[start:])
            except json.JSONDecodeError:
                pass
    return None


def _temporary_directory(prefix: str):
    configured = get_settings().scan_temp_dir or os.environ.get("FAILPROOF_SCAN_TEMP_DIR")
    directory = Path(configured).expanduser().resolve() if configured else None
    if directory is not None and not directory.is_dir():
        raise OSError("Configured scanner temporary directory is not available.")
    return tempfile.TemporaryDirectory(prefix=prefix, dir=str(directory) if directory else None)


def scan_static(root: Path, *, runner: CommandRunner = run_bounded, module_available: Callable[[str], bool] | None = None) -> AdapterResult:
    available = module_available or (lambda module: importlib.util.find_spec(module) is not None)
    result = AdapterResult(availability={"bandit": "available" if available("bandit") else "unavailable", "semgrep": "optional_not_configured"})
    if result.availability["bandit"] == "unavailable":
        result.status = "blocked"
        result.errors.append("Bandit is not installed. Install backend/requirements-security.txt to run static analysis.")
        result.summary = "Static analysis was blocked because Bandit is unavailable."
        return result
    files, warnings, complete_walk = _walk(root, {".py"})
    result.warnings.extend(warnings)
    if not files:
        result.status = "completed" if complete_walk else "completed_with_errors"
        result.summary = "No eligible Python source files were found in the registered directory."
        return result
    with _temporary_directory(prefix="failproof-bandit-") as temporary:
        staging = Path(temporary)
        relative_map: dict[str, str] = {}
        for original in files:
            relative = original.relative_to(root)
            staged = staging / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(original.read_bytes())
            relative_map[str(staged).replace("\\", "/")] = relative.as_posix()
        command = runner([sys.executable, "-m", "bandit", "-r", str(staging), "-f", "json", "-q"], cwd=staging, timeout=MAX_SCAN_SECONDS, output_limit=MAX_OUTPUT_BYTES)
    if command.timed_out:
        result.status = "failed"
        result.errors.append("Bandit exceeded the 60 second execution limit.")
        result.summary = "Static analysis failed because the scanner timed out."
        return result
    if command.truncated:
        result.status = "completed_with_errors"
        result.errors.append("Bandit output exceeded the 1 MB capture limit; results may be incomplete.")
    parsed = _json_from_output(command.output)
    if not isinstance(parsed, dict) or not isinstance(parsed.get("results"), list):
        result.status = "failed"
        result.errors.append("Bandit returned output that could not be parsed as its JSON report.")
        result.summary = "Static analysis failed while parsing the scanner report."
        return result
    if command.returncode not in (0, 1):
        result.status = "completed_with_errors"
        result.errors.append("Bandit exited with an error after producing a report.")
    for item in parsed["results"]:
        filename = str(item.get("filename", "" )).replace("\\", "/")
        relative = relative_map.get(filename)
        if relative is None:
            try:
                relative = Path(filename).relative_to(Path(tempfile.gettempdir())).as_posix()
            except ValueError:
                relative = Path(filename).name
        result.findings.append({
            "title": sanitize_output(str(item.get("issue_text") or "Bandit security signal"), 300),
            "description": sanitize_output(str(item.get("issue_text") or "Bandit reported a static-analysis signal."), 4000),
            "category": "static-analysis",
            "severity": str(item.get("issue_severity", "unknown")).lower(),
            "confidence": str(item.get("issue_confidence", "unknown")).lower(),
            "status": "suspected",
            "source": "bandit",
            "scanner": "Bandit",
            "rule_id": str(item.get("test_id", "unknown"))[:200],
            "affected_resource": relative[:1000],
            "relative_path": relative[:1000],
            "line_number": item.get("line_number") if isinstance(item.get("line_number"), int) else None,
            "cwe_id": (item.get("issue_cwe") or {}).get("id") if isinstance(item.get("issue_cwe"), dict) else None,
            "cve_id": None,
            "remediation": "Review the cited source and Bandit rule guidance; this static warning is a signal, not proof of exploitability.",
            "references": [str(item["more_info"])[:1000]] if item.get("more_info") else [],
            "evidence_type": "scanner",
            "details": {"test_id": item.get("test_id"), "code": sanitize_output(str(item.get("code", "")), 2000), "issue_severity": item.get("issue_severity"), "issue_confidence": item.get("issue_confidence")},
            "actual_result": "Bandit reported this rule at the recorded file and line.",
        })
    if warnings or not complete_walk:
        result.status = "completed_with_errors"
    result.summary = f"Bandit analyzed {len(files)} Python files and reported {len(result.findings)} finding(s)."
    return result


def _manifest_files(root: Path):
    requirements: list[Path] = []
    locks: list[Path] = []
    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        dirs[:] = [name for name in dirs if name not in EXCLUDED_DIRS and not (current / name).is_symlink()]
        for name in files:
            path = current / name
            if path.is_symlink():
                continue
            if re.fullmatch(r"requirements(?:[-_.][A-Za-z0-9_.-]+)?\.txt", name, re.I):
                requirements.append(path)
            elif name == "package-lock.json" and (current / "package.json").is_file():
                locks.append(path)
            if len(requirements) > 20 or len(locks) > 20:
                return requirements[:20], locks[:20], False
    return requirements, locks, True


def _pip_findings(parsed: object):
    found: list[dict] = []
    dependencies = parsed.get("dependencies", []) if isinstance(parsed, dict) else parsed if isinstance(parsed, list) else []
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            continue
        name = str(dependency.get("name", "unknown"))[:200]
        version = str(dependency.get("version", "unknown"))[:100]
        for vulnerability in dependency.get("vulns", []):
            if not isinstance(vulnerability, dict):
                continue
            advisory = str(vulnerability.get("id", ""))[:200]
            aliases = vulnerability.get("aliases", []) if isinstance(vulnerability.get("aliases"), list) else []
            cve = next((str(alias) for alias in aliases if re.fullmatch(r"CVE-\d{4}-\d+", str(alias))), None)
            fixes = [str(item)[:100] for item in vulnerability.get("fix_versions", []) if isinstance(item, str)]
            found.append({"title": f"Vulnerable Python dependency: {name}"[:300], "description": str(vulnerability.get("description") or f"pip-audit matched {name} {version} to advisory {advisory}.")[:4000], "category": "dependency", "severity": "unknown", "confidence": "high", "status": "confirmed", "source": "pip-audit", "scanner": "pip-audit", "rule_id": advisory or "unknown", "affected_resource": f"{name} {version}", "cwe_id": None, "cve_id": cve, "remediation": f"Upgrade {name} to a version reported as fixed by the advisory: {', '.join(fixes)}." if fixes else f"Review advisory {advisory} and choose a fixed compatible version.", "references": [str(value)[:1000] for value in vulnerability.get("aliases", []) if str(value).startswith(("https://", "http://"))], "evidence_type": "advisory", "details": {"package": name, "installed_version": version, "advisory_id": advisory, "fix_versions": fixes, "aliases": [str(value)[:200] for value in aliases[:20]]}, "actual_result": f"pip-audit reported {name} {version} as affected by {advisory}."})
    return found


def _npm_findings(parsed: object, lock_data: dict):
    found: list[dict] = []
    vulnerabilities = parsed.get("vulnerabilities", {}) if isinstance(parsed, dict) else {}
    packages = lock_data.get("packages", {}) if isinstance(lock_data, dict) else {}
    for name, vulnerability in vulnerabilities.items():
        if not isinstance(vulnerability, dict):
            continue
        nodes = vulnerability.get("nodes") or [f"node_modules/{name}"]
        installed = next((packages.get(node, {}).get("version") for node in nodes if isinstance(packages.get(node), dict) and packages[node].get("version")), "unknown")
        vias = vulnerability.get("via", [])
        if not isinstance(vias, list):
            vias = []
        for via in vias:
            if not isinstance(via, dict):
                continue
            advisory = str(via.get("source") or via.get("name") or name)[:200]
            cve = next((str(item) for item in via.get("cve", []) if re.fullmatch(r"CVE-\d{4}-\d+", str(item))), None) if isinstance(via.get("cve"), list) else None
            fixed = vulnerability.get("fixAvailable")
            fix_version = fixed.get("version") if isinstance(fixed, dict) else None
            urls = []
            if isinstance(via.get("url"), str) and via["url"].startswith(("http://", "https://")):
                urls.append(via["url"][:1000])
            found.append({"title": str(via.get("title") or f"Vulnerable JavaScript dependency: {name}")[:300], "description": str(via.get("title") or f"npm audit reports {name} {installed} as affected.")[:4000], "category": "dependency", "severity": str(vulnerability.get("severity", "unknown")).lower(), "confidence": "high", "status": "confirmed", "source": "npm-audit", "scanner": "npm audit", "rule_id": advisory, "affected_resource": f"{name} {installed}", "cwe_id": str(via.get("cwe", [None])[0])[:32] if isinstance(via.get("cwe"), list) and via.get("cwe") else None, "cve_id": cve, "remediation": f"npm reports a fix is available at version {fix_version}. Review transitive impact before applying." if fix_version else "Review the advisory and upgrade to a version npm reports as fixed; inspect the lockfile impact first.", "references": urls, "evidence_type": "advisory", "details": {"package": name, "installed_version": installed, "affected_range": str(vulnerability.get("range", ""))[:500], "advisory_id": advisory, "fix_available": fixed if isinstance(fixed, (dict, bool)) else None}, "actual_result": f"npm audit matched {name} {installed} to advisory {advisory}."})
    return found


def scan_dependencies(root: Path, *, runner: CommandRunner = run_bounded, module_available: Callable[[str], bool] | None = None, npm_available: Callable[[], bool] | None = None) -> AdapterResult:
    available = module_available or (lambda module: importlib.util.find_spec(module) is not None)
    has_npm = npm_available or (lambda: shutil.which("npm") is not None)
    requirements, locks, manifest_scan_complete = _manifest_files(root)
    result = AdapterResult(availability={"pip-audit": "not_applicable" if not requirements else "available" if available("pip_audit") else "unavailable", "npm-audit": "not_applicable" if not locks else "available" if has_npm() else "unavailable"})
    if not requirements and not locks:
        result.status = "blocked"
        result.errors.append("No supported requirements*.txt or package-lock.json manifests were found in the registered source directory.")
        result.summary = "Dependency analysis was blocked because no supported lock or requirements manifest was available."
        return result
    had_error = not manifest_scan_complete
    if not manifest_scan_complete:
        result.errors.append("Manifest discovery exceeded the 20-file limit; results are partial.")
    completed = 0
    if requirements and result.availability["pip-audit"] == "unavailable":
        result.errors.append("pip-audit is not installed. Install backend/requirements-security.txt to audit Python requirements.")
        had_error = True
    elif requirements:
        for manifest in requirements:
            command = runner([sys.executable, "-m", "pip_audit", "--requirement", str(manifest), "--format", "json", "--progress-spinner", "off"], cwd=manifest.parent, timeout=MAX_SCAN_SECONDS, output_limit=MAX_OUTPUT_BYTES)
            parsed = _json_from_output(command.output)
            if command.timed_out:
                result.errors.append(f"pip-audit timed out while checking {manifest.relative_to(root).as_posix()}.")
                had_error = True
            elif command.truncated:
                result.errors.append(f"pip-audit output exceeded the 1 MB limit for {manifest.relative_to(root).as_posix()}.")
                had_error = True
            elif not isinstance(parsed, (dict, list)):
                result.errors.append(f"pip-audit could not return a parseable report for {manifest.relative_to(root).as_posix()}: {sanitize_output(command.output) or command.error or 'no output'}")
                result.availability["pip-audit"] = "advisory_service_or_execution_error"
                had_error = True
            elif command.returncode not in (0, 1):
                result.errors.append(f"pip-audit exited with status {command.returncode} for {manifest.relative_to(root).as_posix()}.")
                had_error = True
            else:
                for issue in _pip_findings(parsed):
                    issue["relative_path"] = manifest.relative_to(root).as_posix()
                    result.findings.append(issue)
                completed += 1
    if locks and result.availability["npm-audit"] == "unavailable":
        result.errors.append("npm is unavailable; JavaScript dependency audit could not run.")
        had_error = True
    elif locks:
        for lockfile in locks:
            try:
                lock_data = json.loads(lockfile.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                result.errors.append(f"Could not parse {lockfile.relative_to(root).as_posix()} to identify installed versions.")
                result.availability["npm-audit"] = "lockfile_parse_error"
                had_error = True
                continue
            command = runner(["npm", "audit", "--json"], cwd=lockfile.parent, timeout=MAX_SCAN_SECONDS, output_limit=MAX_OUTPUT_BYTES)
            parsed = _json_from_output(command.output)
            if command.timed_out:
                result.errors.append(f"npm audit timed out for {lockfile.parent.relative_to(root).as_posix()}.")
                had_error = True
            elif command.truncated:
                result.errors.append(f"npm audit output exceeded the 1 MB limit for {lockfile.parent.relative_to(root).as_posix()}.")
                had_error = True
            elif not isinstance(parsed, dict) or "metadata" not in parsed:
                message = sanitize_output(command.output or command.error or "No report returned.", 500)
                result.errors.append(f"npm audit did not produce a complete advisory report for {lockfile.parent.relative_to(root).as_posix()}: {message}")
                result.availability["npm-audit"] = "advisory_service_or_execution_error"
                had_error = True
            elif command.returncode not in (0, 1):
                result.errors.append(f"npm audit exited with status {command.returncode}; advisory results may be incomplete.")
                had_error = True
            else:
                for issue in _npm_findings(parsed, lock_data):
                    issue["relative_path"] = lockfile.relative_to(root).as_posix()
                    result.findings.append(issue)
                completed += 1
    if completed == 0:
        result.status = "blocked" if not result.findings else "completed_with_errors"
    elif had_error:
        result.status = "completed_with_errors"
    result.summary = f"Dependency analysis completed for {completed} manifest(s) and reported {len(result.findings)} advisory match(es)."
    return result

