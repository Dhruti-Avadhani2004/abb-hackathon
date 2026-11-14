
import subprocess
import os

repo_path = r"sgc-gatekeeper-testbed"
output_file = r"scanner_output\trivy_output_offline.json"
cache_dir = r"trivy-cache"

os.makedirs("scanner_output", exist_ok=True)

trivy_exe = os.path.join(
    os.environ["LOCALAPPDATA"],
    "Microsoft",
    "WinGet",
    "Packages",
    "AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe",
    "trivy.exe"
)

command = [
    trivy_exe,
    "--cache-dir", cache_dir,
    "fs",
    "--scanners", "vuln,misconfig,secret",
    "--skip-db-update",
    "--skip-java-db-update",
    "--skip-check-update",
    "--offline-scan",
    "--skip-version-check",
    "--disable-telemetry",
    "--format", "json",
    "--output", output_file,
    repo_path
]

result = subprocess.run(
    command,
    capture_output=True,
    text=True
)

print(result.stdout)

if result.stderr:
    print(result.stderr)

print(f"Trivy scan completed. Output saved to {output_file}")
print(f"Exit code: {result.returncode}")
