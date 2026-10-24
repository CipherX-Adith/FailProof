import json
import subprocess
import sys

results = []
for requirement in ("requirements.txt", "requirements-security.txt"):
    run = subprocess.run([sys.executable, "-m", "pip_audit", "--requirement", requirement, "--format", "json", "--progress-spinner", "off"], capture_output=True, text=True, timeout=120)
    report = json.loads(run.stdout)
    findings = {}
    for dependency in report.get("dependencies", []):
        for vulnerability in dependency.get("vulns", []):
            key = (dependency.get("name"), dependency.get("version"), vulnerability.get("id"))
            findings[key] = {"package": key[0], "installed": key[1], "id": key[2], "aliases": vulnerability.get("aliases", []), "fixed": vulnerability.get("fix_versions", [])}
    results.append({"requirement": requirement, "exit_code": run.returncode, "unique_advisories": len(findings), "findings": list(findings.values()), "unresolved": report.get("fixes", [])})
print(json.dumps(results, separators=(",", ":")))
