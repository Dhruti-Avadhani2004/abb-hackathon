
# import subprocess
# from pathlib import Path
# from datetime import datetime
# import shutil

# BASE_DIR = Path(__file__).resolve().parent.parent

# TARGET_DIR = BASE_DIR / "sgc-gatekeeper-testbed"
# OUTPUT_DIR = BASE_DIR / "scanner_output"

# TEXT_REPORT = OUTPUT_DIR / "dotnet_output.txt"


# def main():
#     OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

#     print("Starting .NET NuGet vulnerability scan...")
#     print(f"Target: {TARGET_DIR}")

#     if not TARGET_DIR.exists():
#         print("Target directory not found.")
#         return

#     dotnet_path = shutil.which("dotnet")

#     if not dotnet_path:
#         print(".NET CLI not found. Check installation and PATH.")
#         return

#     project_files = list(TARGET_DIR.rglob("*.csproj"))
#     project_files += list(TARGET_DIR.rglob("*.fsproj"))

#     if not project_files:
#         print("\n===== .NET Vulnerability Scan Summary =====")
#         print("Status: SKIPPED")
#         print("Reason: No .NET project files found.")
#         print("NuGet vulnerability scan was not performed.")
#         print("===========================================")
#         return

#     start_time = datetime.now()

#     all_output = []
#     scan_success = True

#     for project in project_files:
#         print(f"\nScanning project: {project}")

#         command = [
#             dotnet_path,
#             "list",
#             str(project),
#             "package",
#             "--vulnerable"
#         ]

#         try:
#             result = subprocess.run(
#                 command,
#                 capture_output=True,
#                 text=True,
#                 encoding="utf-8",
#                 errors="replace",
#                 cwd=str(BASE_DIR)
#             )

#             all_output.append(f"\nProject: {project}\n")
#             all_output.append(result.stdout)
#             all_output.append(result.stderr)

#             if result.returncode != 0:
#                 scan_success = False

#         except Exception as error:
#             scan_success = False
#             all_output.append(f"Execution error: {error}\n")

#     end_time = datetime.now()
#     duration = (end_time - start_time).total_seconds()

#     with open(TEXT_REPORT, "w", encoding="utf-8") as report:
#         report.write("".join(all_output))

#     print("\n===== .NET Vulnerability Scan Summary =====")
#     print(f"Status: {'SUCCESS' if scan_success else 'FAILED'}")
#     print(f"Projects scanned: {len(project_files)}")
#     print(f"Duration: {duration:.2f} seconds")
#     print(f"Text Report: {TEXT_REPORT}")
#     print("===========================================")


# if __name__ == "__main__":
#     main()



import subprocess
from pathlib import Path
from datetime import datetime
import shutil

BASE_DIR = Path(__file__).resolve().parent.parent

TARGET_DIR = BASE_DIR / "sgc-gatekeeper-testbed"
OUTPUT_DIR = BASE_DIR / "scanner_output"

TEXT_REPORT = OUTPUT_DIR / "dotnet_output.txt"


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Starting offline .NET NuGet vulnerability scan...")
    print(f"Target: {TARGET_DIR}")

    if not TARGET_DIR.exists():
        print("Target directory not found.")
        return

    dotnet_path = shutil.which("dotnet")

    if not dotnet_path:
        print(".NET CLI not found. Check installation and PATH.")
        return

    project_files = list(TARGET_DIR.rglob("*.csproj"))
    project_files += list(TARGET_DIR.rglob("*.fsproj"))

    if not project_files:
        print("\n===== .NET Vulnerability Scan Summary =====")
        print("Status: SKIPPED")
        print("Reason: No .NET project files found.")
        print("===========================================")
        return

    start_time = datetime.now()

    all_output = []
    scan_success = True

    for project in project_files:
        print(f"\nScanning project: {project}")

        command = [
            dotnet_path,
            "package",
            "list",
            "--project",
            str(project),
            "--vulnerable",
            "--no-restore"
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(BASE_DIR)
            )

            all_output.append(f"\nProject: {project}\n")
            all_output.append(result.stdout)
            all_output.append(result.stderr)

            if result.returncode != 0:
                scan_success = False
                print("Project vulnerability scan failed.")
                print(result.stderr)

        except Exception as error:
            scan_success = False
            all_output.append(f"Execution error: {error}\n")
            print(f"Execution error: {error}")

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    with open(TEXT_REPORT, "w", encoding="utf-8") as report:
        report.write("".join(all_output))

    print("\n===== .NET Vulnerability Scan Summary =====")
    print(f"Status: {'SUCCESS' if scan_success else 'FAILED'}")
    print("Offline mode: Enabled (--no-restore)")
    print(f"Projects scanned: {len(project_files)}")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Text Report: {TEXT_REPORT}")
    print("===========================================")


if __name__ == "__main__":
    main()
