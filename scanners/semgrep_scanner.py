
# import os
# import shutil
# import subprocess
# from pathlib import Path

# import yaml

# # ==========================================
# # PATHS
# # ==========================================

# BASE_DIR = Path(__file__).resolve().parent.parent

# TARGET_DIR = BASE_DIR / "sgc-gatekeeper-testbed"
# RULES_DIR = BASE_DIR / "semgrep-rules"

# OUTPUT_DIR = BASE_DIR / "scanner_output"
# CONFIG_DIR = OUTPUT_DIR / "semgrep-configs"
# OUTPUT_FILE = OUTPUT_DIR / "semgrep_output.txt"

# # ==========================================
# # VALIDATE ENVIRONMENT
# # ==========================================

# if not TARGET_DIR.is_dir():
#     raise SystemExit(f"Target repository not found: {TARGET_DIR}")

# if not RULES_DIR.is_dir():
#     raise SystemExit(f"Local Semgrep rules not found: {RULES_DIR}")

# if shutil.which("semgrep") is None:
#     raise SystemExit("Semgrep is not installed in the active environment.")

# OUTPUT_DIR.mkdir(exist_ok=True)

# # ==========================================
# # PREPARE LOCAL RULES
# # ==========================================

# print("[1] Preparing local Semgrep rules...")

# if CONFIG_DIR.exists():
#     shutil.rmtree(CONFIG_DIR)

# CONFIG_DIR.mkdir()

# valid_count = 0

# excluded_dirs = {
#     ".github",
#     ".git",
#     "scripts",
#     "stats",
#     "__pycache__"
# }

# for file_path in RULES_DIR.rglob("*"):

#     if not file_path.is_file():
#         continue

#     if file_path.suffix.lower() not in (".yaml", ".yml"):
#         continue

#     relative_path = file_path.relative_to(RULES_DIR)

#     if any(part in excluded_dirs for part in relative_path.parts):
#         continue

#     try:
#         with open(
#             file_path,
#             "r",
#             encoding="utf-8",
#             errors="replace"
#         ) as file:
#             config = yaml.safe_load(file)

#         if not isinstance(config, dict):
#             continue

#         rules = config.get("rules")

#         if not isinstance(rules, list) or not rules:
#             continue

#         if not all(isinstance(rule, dict) for rule in rules):
#             continue

#         destination = CONFIG_DIR / relative_path
#         destination.parent.mkdir(parents=True, exist_ok=True)

#         shutil.copy2(file_path, destination)

#         valid_count += 1

#     except (yaml.YAMLError, OSError) as error:
#         print(f"Skipping {relative_path}: {error}")

# print(f"Loaded {valid_count} local rule configuration files.")

# if valid_count == 0:
#     raise SystemExit("No valid local rules found.")

# # ==========================================
# # RUN OFFLINE SCAN
# # ==========================================

# print("\n[2] Running offline Semgrep scan...")

# command = [
#     "semgrep",
#     "scan",
#     "--config", str(CONFIG_DIR),
#     "--metrics=off",
#     "--no-git-ignore",
#     "--jobs", "1",
#     str(TARGET_DIR)
# ]

# env = os.environ.copy()

# env["PYTHONUTF8"] = "1"
# env["PYTHONIOENCODING"] = "utf-8"
# env["SEMGREP_SEND_METRICS"] = "off"

# with open(OUTPUT_FILE, "w", encoding="utf-8") as output:

#     result = subprocess.run(
#         command,
#         stdout=output,
#         stderr=subprocess.STDOUT,
#         text=True,
#         encoding="utf-8",
#         errors="replace",
#         env=env
#     )

# # ==========================================
# # RESULTS
# # ==========================================

# print("\n[3] Semgrep execution finished.")

# print(f"Target repository : {TARGET_DIR}")
# print(f"Local rules       : {valid_count}")
# print(f"Output file       : {OUTPUT_FILE}")
# print(f"Exit code         : {result.returncode}")

# if result.returncode == 0:
#     print("Scan completed successfully.")

# elif result.returncode == 1:
#     print("Scan completed with findings or a scan condition.")

# else:
#     print("Semgrep reported an execution error.")

# print("\nCheck semgrep_output.txt for the detailed results.")


import os
import shutil
import subprocess
from pathlib import Path

import yaml

# ==========================================
# PATHS
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent

TARGET_DIR = BASE_DIR / "sgc-gatekeeper-testbed"
RULES_DIR = BASE_DIR / "semgrep-rules"

OUTPUT_DIR = BASE_DIR / "scanner_output"
CONFIG_DIR = OUTPUT_DIR / "semgrep-configs"

OUTPUT_FILE = OUTPUT_DIR / "semgrep_output.txt"
JSON_OUTPUT_FILE = OUTPUT_DIR / "semgrep_output.json"

# ==========================================
# VALIDATE ENVIRONMENT
# ==========================================

if not TARGET_DIR.is_dir():
    raise SystemExit(f"Target repository not found: {TARGET_DIR}")

if not RULES_DIR.is_dir():
    raise SystemExit(f"Local Semgrep rules not found: {RULES_DIR}")

if shutil.which("semgrep") is None:
    raise SystemExit("Semgrep is not installed in the active environment.")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ==========================================
# PREPARE LOCAL RULES
# ==========================================

print("[1] Preparing local Semgrep rules...")

if CONFIG_DIR.exists():
    shutil.rmtree(CONFIG_DIR)

CONFIG_DIR.mkdir()

valid_count = 0

excluded_dirs = {
    ".github",
    ".git",
    "scripts",
    "stats",
    "__pycache__"
}

for file_path in RULES_DIR.rglob("*"):

    if not file_path.is_file():
        continue

    if file_path.suffix.lower() not in (".yaml", ".yml"):
        continue

    relative_path = file_path.relative_to(RULES_DIR)

    if any(part in excluded_dirs for part in relative_path.parts):
        continue

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as file:
            config = yaml.safe_load(file)

        if not isinstance(config, dict):
            continue

        rules = config.get("rules")

        if not isinstance(rules, list) or not rules:
            continue

        if not all(isinstance(rule, dict) for rule in rules):
            continue

        destination = CONFIG_DIR / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)

        shutil.copy2(file_path, destination)

        valid_count += 1

    except (yaml.YAMLError, OSError) as error:
        print(f"Skipping {relative_path}: {error}")

print(f"Loaded {valid_count} local rule configuration files.")

if valid_count == 0:
    raise SystemExit("No valid local rules found.")

# ==========================================
# RUN OFFLINE SCAN
# ==========================================

print("\n[2] Running offline Semgrep scan...")

command = [
    "semgrep",
    "scan",
    "--config", str(CONFIG_DIR),
    "--metrics=off",
    "--no-git-ignore",
    "--jobs", "1",
    "--json-output", str(JSON_OUTPUT_FILE),
    str(TARGET_DIR)
]

env = os.environ.copy()

env["PYTHONUTF8"] = "1"
env["PYTHONIOENCODING"] = "utf-8"
env["SEMGREP_SEND_METRICS"] = "off"

# Remove stale reports before starting
for report_file in (OUTPUT_FILE, JSON_OUTPUT_FILE):
    if report_file.exists():
        report_file.unlink()

with open(OUTPUT_FILE, "w", encoding="utf-8") as output:

    result = subprocess.run(
        command,
        stdout=output,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env
    )

# ==========================================
# RESULTS
# ==========================================

print("\n[3] Semgrep execution finished.")

print(f"Target repository : {TARGET_DIR}")
print(f"Local rules       : {valid_count}")
print(f"Text report       : {OUTPUT_FILE}")
print(f"JSON report       : {JSON_OUTPUT_FILE}")
print(f"Exit code         : {result.returncode}")

if result.returncode == 0:
    print("Scan completed successfully.")

elif result.returncode == 1:
    print("Scan completed with findings or a scan condition.")

else:
    print("Semgrep reported an execution error.")

if JSON_OUTPUT_FILE.exists():
    print("JSON report generated successfully.")
else:
    print("WARNING: JSON report was not generated.")

print("\nCheck semgrep_output.txt and semgrep_output.json for results.")
