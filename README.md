# ABB Hackathon — Complete Ubuntu Offline Security Scanner Setup

**Technical setup documentation | Ubuntu Server 22.04.5 LTS | November 2026**

This document explains how we migrated the ABB Hackathon security scanning framework from Windows to Ubuntu Server, installed and configured the security tools, prepared their dependencies for offline operation, integrated them into our Python orchestrator, and generated consolidated security assessment reports.

It documents the environment we actually built, including the installation problems we encountered and how we resolved them.

The final system uses **eight security scanning tools**, a Python orchestration layer, and a report generator. You have confirmed that the completed setup runs offline.

## 1. Project objective

Our objective was to build a unified security scanning framework capable of assessing vulnerable application repositories without requiring an internet connection during the scanning process.

Instead of running separate security tools manually and interpreting their outputs individually, we developed a Python-based orchestration system that executes the scanners, saves their results, and produces a consolidated security assessment.

The framework covers:

| Tool             | Primary responsibility                            |
| ---------------- | ------------------------------------------------- |
| Semgrep          | Static application security testing (SAST)        |
| Trivy            | Vulnerability, secret, and configuration scanning |
| Syft             | Software Bill of Materials (SBOM) generation      |
| Gitleaks         | Secret detection                                  |
| ScanCode Toolkit | License, copyright, and package inventory         |
| Bandit           | Python-specific security analysis                 |
| .NET SDK         | NuGet dependency vulnerability assessment         |
| ESLint           | JavaScript security and code-quality analysis     |

The framework was developed initially on Windows, then migrated to Ubuntu Server, which became our actual execution and submission environment.

## 2. Ubuntu virtual machine environment

We used **Ubuntu Server 22.04.5 LTS** running inside Oracle VirtualBox on a Windows host.

The virtual machine had the following resources:

| Component             | Configuration                                 |
| --------------------- | --------------------------------------------- |
| Operating system      | Ubuntu Server 22.04.5 LTS                     |
| Virtualization        | Oracle VirtualBox                             |
| Host operating system | Windows                                       |
| Virtual CPUs          | 1                                             |
| RAM                   | 2 GB                                          |
| Swap                  | 4 GB                                          |
| Python                | Python 3.10 for the orchestration environment |
| SSH                   | Ubuntu port 22 forwarded to Windows port 2222 |
| Working directory     | `/home/kali/workspace/abb-hackathon`          |

### Why swap was necessary

Some of our security scanners, particularly ScanCode Toolkit and Semgrep, can consume substantial memory.

With only 2 GB of RAM, the VM was vulnerable to memory exhaustion during large scans. We therefore configured 4 GB of swap and avoided running the scanners simultaneously.

The key optimization was **sequential execution**.

This allowed us to run the framework on a relatively small virtual machine rather than requiring a more powerful server.

### SSH access from Windows

We configured VirtualBox NAT port forwarding so the Windows host could access the Ubuntu SSH service:

| Windows host     | Ubuntu guest |
| ---------------- | ------------ |
| `127.0.0.1:2222` | Port `22`    |

We accessed the server using:

```
ssh -p 2222 kali@127.0.0.1
```

This also allowed us to transfer scanner results and project files using SCP.

Importantly, SSH access through the host does not mean the VM needs internet access. The scanning framework can run without external connectivity.

## 3. Project directory structure

Our working directory was:

```
/home/kali/workspace/abb-hackathon/
```

The project was organized approximately as follows:

```
abb-hackathon/
│
├── main.py
├── scan_config.py
├── report_generator.py
│
├── scanners/
│   ├── semgrep_scanner.py
│   ├── trivy_scanner.py
│   ├── syft_scanner.py
│   ├── gitleaks_scanner.py
│   ├── scancode_scanner.py
│   ├── bandit_scanner.py
│   ├── dotnet_scanner.py
│   └── eslint_scanner.py
│
├── scanner_output/
│   ├── semgrep_output.json
│   ├── trivy_output_offline.json
│   ├── sbom_cyclonedx.json
│   ├── sbom_spdx.json
│   ├── gitleaks_output.txt
│   ├── scancode_output.json
│   ├── bandit_output.json
│   ├── dotnet_output.txt
│   └── eslint_output.json
│
├── security_report/
│   ├── final_security_assessment.md
│   ├── consolidated_findings.json
│   └── risk_register.csv
│
├── sgc-gatekeeper-testbed/
│   └── dotnet-aspgoat/
│
├── tools/
│   └── scancode/
│       └── linux/
│           └── scancode-toolkit-v32.5.0/
│
└── venv/
```

The output directory also contains text reports, additional JSON reports, and other scanner-generated files.

## 4. Python environment and orchestration

We used a Python virtual environment to isolate the orchestration dependencies from Ubuntu's system Python installation.

The activation sequence was:

```
cd ~/workspace/abb-hackathon
source venv/bin/activate
```

We verified that the Python packages required by the scanner wrappers were installed and that Linux-compatible scanner executables were available.

The central configuration file was `scan_config.py`:

```
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent

TARGET_DIR = Path(
    os.environ.get(
        "SCAN_TARGET",
        str(BASE_DIR / "sgc-gatekeeper-testbed")
    )
).resolve()

OUTPUT_DIR = BASE_DIR / "scanner_output"
```

### Why we introduced `SCAN_TARGET`

Initially, the scanners were tied to a fixed testbed directory.

We wanted to scan different repositories without modifying every scanner script whenever the target changed.

We therefore used an environment variable:

```
export SCAN_TARGET="/home/kali/workspace/abb-hackathon/sgc-gatekeeper-testbed/dotnet-aspgoat"
```

The scanner wrappers read the target from the shared configuration.

This provided three advantages:

1. We could switch repositories without editing scanner code.
2. All scanners could use the same target path.
3. The framework could assess multiple vulnerable applications using the same orchestration workflow.

The `SCAN_TARGET` variable is set for the current shell session. A new terminal must export it again unless it has been configured persistently.

### Main orchestration file

Our `main.py` executes the scanners in sequence:

```
from scanners import semgrep_scanner
print("\nStatic Analysis completed!")

from scanners import trivy_scanner
print("\nDependencies, configuration and licenses scan completed!")

from scanners import syft_scanner
syft_scanner.main()
print("\nSoftware Bill of Materials (SBOM) generation completed!")

from scanners import gitleaks_scanner
gitleaks_scanner.main()
print("\nSecrets scanning completed!")

from scanners import scancode_scanner
scancode_scanner.main()
print("\nLicense, copyright and package inventory scan completed!")

from scanners import bandit_scanner
bandit_scanner.main()
print("\nPython-specific security scanning completed!")

from scanners import dotnet_scanner
dotnet_scanner.main()
print("\n.NET NuGet vulnerability scanning completed!")

from scanners import eslint_scanner
eslint_scanner.main()
print("\nJavaScript security and code-quality scanning completed!")
```

Semgrep and Trivy run through their module import behavior, while the remaining scanners are invoked through their `main()` functions.

After the scanners complete, the report generator is run separately:

```
python main.py && python report_generator.py
```

This separation makes it possible to regenerate consolidated reports from existing scanner outputs without rerunning all eight scanners.

---

## 5. Semgrep — Offline static application security testing

**Semgrep**

Version used: **1.185.0**

Purpose: Identify insecure code patterns through static analysis.

### 5.1 Installation and preparation

We installed Semgrep into our Python environment and verified that its CLI worked on Ubuntu.

The significant challenge was making Semgrep operate without fetching rules from its online registry.

Normally, Semgrep can use online configurations such as:

```
semgrep --config auto
```

That approach is not suitable for a strictly offline execution environment because the configuration may require network access.

Instead, we prepared a **local collection of Semgrep YAML rules** while internet access was available.

The rule files were then made accessible to the Linux scanner wrapper.

### 5.2 Offline configuration

Our offline Semgrep workflow used local YAML rules, with options including:

```
semgrep scan \
  --config /path/to/local/semgrep-rules \
  --metrics=off \
  --no-git-ignore \
  --jobs 1 \
  --json \
  --output scanner_output/semgrep_output.json \
  "$SCAN_TARGET"
```

Here, `/path/to/local/semgrep-rules` represents the local rule directory configured in the project. It is not a path that needs to be downloaded at scan time.

The important flags were:

| Option                       | Reason                                                              |
| ---------------------------- | ------------------------------------------------------------------- |
| `--config <local-directory>` | Load rules from local files                                         |
| `--metrics=off`              | Disable metrics transmission                                        |
| `--jobs 1`                   | Limit resource usage on the single-core VM                          |
| `--no-git-ignore`            | Avoid automatically excluding files solely because Git ignores them |
| `--json`                     | Generate machine-readable findings                                  |
| `--output`                   | Save results for consolidation                                      |

We also maintained text output for human-readable inspection.

### 5.3 Issues encountered

During the original Windows development, Semgrep encountered an encoding problem:

```
'charmap' codec can't decode byte ...
```

We investigated UTF-8 environment settings and output handling.

On Ubuntu, the Linux-native environment eliminated the Windows-specific terminal encoding problem from our workflow.

We also had to account for Semgrep's memory consumption. Using one job helped keep execution within the VM's available resources.

### 5.4 Verified results

In our earlier testbed validation, Semgrep reported:

Rules executed

# 1,000

Findings

# 30

Targets scanned

# 9

Our prepared rule collection contained approximately 2,116 YAML rule files, although the actual number of applicable rules executed depended on the target.

The primary output was:

```
scanner_output/semgrep_output.json
```

**Offline mechanism:** Semgrep loads its rules and target source code locally, without contacting the Semgrep rule registry during scanning.

---

## 6. Trivy — Offline vulnerability and configuration scanning

**Trivy**

Version used: **0.76.2**

Purpose: Detect known vulnerabilities, exposed secrets, and configuration issues.

### 6.1 Installation

We installed the Linux Trivy executable and made it available at:

```
/usr/local/bin/trivy
```

We verified the installation using:

```
trivy --version
```

### 6.2 Preparing the vulnerability database

Trivy ordinarily downloads vulnerability data from external sources.

That is a problem in an air-gapped or offline environment.

To solve it, we downloaded the required vulnerability database **while the machine still had internet access**.

Our database was stored under:

```
/home/kali/trivy-cache/db/trivy.db
```

The database could then be reused across scans.

A representative database preparation command is:

```
trivy --cache-dir /home/kali/trivy-cache image --download-db-only
```

This is an online preparation step. The database must already be available before an offline scan begins.

### 6.3 Offline execution flags

The Trivy wrapper used the following important flags:

```
--skip-db-update
--skip-java-db-update
--skip-check-update
--offline-scan
--skip-version-check
--disable-telemetry
```

Their purposes were:

| Flag                    | Function                                         |
| ----------------------- | ------------------------------------------------ |
| `--skip-db-update`      | Prevent updating the vulnerability database      |
| `--skip-java-db-update` | Prevent updating the Java vulnerability database |
| `--skip-check-update`   | Prevent updating checks                          |
| `--offline-scan`        | Use offline scanning behavior                    |
| `--skip-version-check`  | Avoid version-check requests                     |
| `--disable-telemetry`   | Disable telemetry                                |

A representative filesystem scan is:

```
trivy fs \
  --cache-dir /home/kali/trivy-cache \
  --offline-scan \
  --skip-db-update \
  --skip-java-db-update \
  --skip-check-update \
  --skip-version-check \
  --disable-telemetry \
  --format json \
  --output scanner_output/trivy_output_offline.json \
  "$SCAN_TARGET"
```

The exact set of scanners and configuration options in the Python wrapper determines which categories of findings are included.

### 6.4 Offline database considerations

There is an important distinction between **offline execution** and **up-to-date vulnerability intelligence**.

Our offline workflow means Trivy does not need to contact the internet during a scan.

However, it can only detect vulnerabilities known to its locally cached database.

Therefore, the database must be refreshed periodically during a separate online preparation process if current vulnerability coverage is required.

For Java-specific vulnerability detection, the Java database also needs to have been prepared if that analysis is enabled.

### 6.5 Results

Our earlier testbed scan reported:

- **58 vulnerabilities**
- **4 secret findings**
- **0 configuration findings** in that particular run

The scanner produced JSON outputs including:

```
scanner_output/trivy_output.json
scanner_output/trivy_output_offline.json
```

The offline JSON output was one of the supported inputs to our consolidated report generator.

**Offline mechanism:** Local vulnerability databases, disabled updates, offline scanning mode, and disabled network-related checks.

---

## 7. Syft — Offline Software Bill of Materials generation

**Syft**

Linux version verified: **1.57.1**

Purpose: Identify software components and generate SBOMs.

### 7.1 Installation

We installed the Linux Syft binary at:

```
/usr/local/bin/syft
```

We verified it with:

```
syft version
```

Syft performs software inventory by examining files and package metadata.

Unlike vulnerability scanners that require a current advisory database, generating an SBOM primarily depends on the files and metadata available locally.

### 7.2 SBOM formats

Our framework generated two standard formats:

**CycloneDX JSON**

```
syft "$SCAN_TARGET" \
  -o cyclonedx-json=./scanner_output/sbom_cyclonedx.json
```

**SPDX JSON**

```
syft "$SCAN_TARGET" \
  -o spdx-json=./scanner_output/sbom_spdx.json
```

Both outputs were saved in the common `scanner_output` directory.

### 7.3 Warning encountered

During development, Syft displayed a warning similar to:

```
WARN no explicit name and version provided for directory source,
deriving artifact ID from the given path
```

This warning did not indicate that SBOM generation had failed.

It meant Syft was deriving the scanned directory's identity rather than receiving an explicit project name and version.

Both SBOM formats were generated successfully.

### 7.4 Why we included Syft

Syft provides an inventory of application dependencies and components.

That information is useful for:

- Understanding the application's software supply chain.
- Identifying third-party components.
- Supporting dependency vulnerability analysis.
- Producing standardized SBOM artifacts for submission and auditing.

**Offline mechanism:** Generate component inventories from local source files, manifests, and package metadata.

---

## 8. Gitleaks — Offline secrets scanning

**Gitleaks**

Purpose: Detect hardcoded credentials, API keys, tokens, and other potentially sensitive strings.

### 8.1 Installation and integration

We installed the Linux Gitleaks executable and integrated it into:

```
scanners/gitleaks_scanner.py
```

The scanner was called from `main.py` using:

```
from scanners import gitleaks_scanner
gitleaks_scanner.main()
```

### 8.2 Offline operation

Gitleaks performs local analysis using its detection rules.

For an offline source-code scan, the target files and detection configuration must be available locally.

A representative command is:

```
gitleaks dir "$SCAN_TARGET" \
  --report-format json \
  --report-path scanner_output/gitleaks_output.json
```

The precise command syntax and flags depend on the installed Gitleaks version and the Python wrapper.

Gitleaks can also inspect Git history when run in Git scanning mode. That differs from scanning only the current working directory.

### 8.3 Results and handling

During our testbed validation, Gitleaks detected **5 findings**.

The scanner generated outputs including:

```
scanner_output/gitleaks_output.json
scanner_output/gitleaks_output.txt
```

One important security consideration is that Gitleaks reports may contain portions of detected secrets.

We therefore need to treat those reports as potentially sensitive and review or redact them before publishing them to a public repository.

**Offline mechanism:** Local detection rules and local repository or directory analysis.

---

## 9. ScanCode Toolkit — License, copyright, and package inventory

**ScanCode Toolkit**

Version used: **32.5.0**

Purpose: Identify licenses, copyright notices, and package metadata.

### 9.1 Why ScanCode required special handling

ScanCode Toolkit was one of the more demanding tools in our setup.

Our initial Windows development used a Windows-specific executable:

```
scancode.bat
```

That executable could not simply be reused on Ubuntu.

We therefore prepared the Linux-compatible ScanCode Toolkit distribution and configured the Linux scanner wrapper to use it.

The installed toolkit directory was:

```
/home/kali/workspace/abb-hackathon/tools/scancode/linux/scancode-toolkit-v32.5.0
```

### 9.2 Installation preparation

We used the Linux toolkit with its required Python dependencies.

The installation and initialization steps needed to be completed while dependency packages were available.

After setup, the toolkit could perform local license and copyright detection without downloading additional rule databases during each scan.

### 9.3 Resource limitations

ScanCode was especially important to optimize because our Ubuntu VM had:

- 2 GB RAM
- 1 CPU core
- 4 GB swap

We configured the scan to use a single process:

```
--processes 1
```

A representative ScanCode command is:

```
./scancode \
  --license \
  --copyright \
  --package \
  --processes 1 \
  --json /home/kali/workspace/abb-hackathon/scanner_output/scancode_output.json \
  "$SCAN_TARGET"
```

This command is shown from inside the Linux ScanCode Toolkit directory.

The actual wrapper also applied exclusions for directories that would unnecessarily increase scanning time.

These included:

```
node_modules/
.git/
.venv/
venv/
__pycache__/
```

### 9.4 Why the exclusions mattered

Without exclusions, ScanCode could spend a large amount of time analyzing installed dependencies, virtual environments, and Git metadata.

That would increase memory consumption and scan duration, while producing substantial output unrelated to the application's own source code.

The exclusions helped us keep the scan practical on the VM.

There is a tradeoff: excluding `node_modules` also means ScanCode does not directly inventory every installed JavaScript dependency in that directory. Other tools, such as Syft, complement this analysis.

### 9.5 Results

ScanCode completed successfully in our Ubuntu environment.

One recorded execution took approximately **90.83 seconds**.

Its primary machine-readable output was:

```
scanner_output/scancode_output.json
```

We also maintained a text log.

**Offline mechanism:** Preinstalled toolkit, local detection rules, local files, and single-process execution.

---

## 10. Bandit — Python-specific security analysis

**Bandit**

Version used: **1.9.4**

Purpose: Identify insecure programming patterns in Python source code.

### 10.1 Installation

We installed Bandit into the Python environment and integrated it into:

```
scanners/bandit_scanner.py
```

The tool was invoked from the orchestrator using:

```
from scanners import bandit_scanner
bandit_scanner.main()
```

### 10.2 Offline execution

Bandit performs local static analysis of Python code using its installed checks.

A representative command is:

```
bandit -r "$SCAN_TARGET" \
  -f json \
  -o scanner_output/bandit_output.json
```

A separate text-format execution can produce:

```
scanner_output/bandit_output.txt
```

Our wrapper handled output generation and summarized findings by severity.

Bandit does not need to download vulnerability advisory data to perform its normal static checks.

### 10.3 Verified findings

In our earlier Python testbed validation, Bandit reported:

High

# 3

Medium

# 2

Low

# 4

**Total: 9 findings**, with a recorded scan duration of approximately 5.25 seconds.

When we later ran the framework against AspGoat, which is primarily a .NET application, a separate run reported zero Python findings.

That is expected: Bandit is a language-specific scanner and should not be interpreted as a C# security assessment.

**Offline mechanism:** Locally installed Python security checks operating on local source code.

---

## 11. .NET SDK — Offline NuGet vulnerability scanning

**.NET SDK**

Version used: **8.0.134**

Purpose: Assess NuGet package dependencies for known vulnerabilities.

### 11.1 Why we needed a .NET-specific scanner

One of our target repositories was **AspGoat**, a deliberately vulnerable ASP.NET application.

The repository was located at:

```
/home/kali/workspace/abb-hackathon/sgc-gatekeeper-testbed/dotnet-aspgoat
```

Its project file was:

```
AspGoat.csproj
```

Although Semgrep and Trivy can analyze aspects of a .NET application, we also wanted a dedicated NuGet dependency vulnerability check.

We installed .NET SDK 8.0.134 and verified it using:

```
dotnet --version
```

### 11.2 NuGet vulnerability command

The scanner used the .NET CLI's package vulnerability functionality:

```
dotnet list AspGoat.csproj package \
  --vulnerable \
  --include-transitive
```

This requests vulnerability information for both direct and transitive NuGet dependencies.

The wrapper was implemented in:

```
scanners/dotnet_scanner.py
```

### 11.3 The first issue: unsupported `--no-restore`

Initially, we attempted to use:

```
--no-restore
```

with the package-listing command.

The installed .NET SDK did not accept that flag in the way we had used it.

We removed the unsupported argument from the scanner command.

This was a CLI compatibility issue, not a problem with AspGoat's source code.

### 11.4 The second issue: missing project assets

After removing the flag, the scanner reported:

```
No assets file was found for AspGoat.csproj.
Please run restore before running this command.
```

The underlying issue was that the project did not yet have the dependency assets generated by NuGet restore.

The .NET tooling uses:

```
obj/project.assets.json
```

to understand the project's resolved dependency graph.

Without that file, the vulnerability command could not enumerate the packages correctly.

### 11.5 Resolving the problem

We prepared the project dependencies using:

```
cd ~/workspace/abb-hackathon/sgc-gatekeeper-testbed/dotnet-aspgoat

dotnet restore AspGoat.csproj
```

We then checked for the generated assets file:

```
ls -lh obj/project.assets.json
```

After preparing the project, we returned to the framework directory:

```
cd ~/workspace/abb-hackathon
```

And reran the scanner:

```
python -m scanners.dotnet_scanner
```

### 11.6 Successful result

The scanner subsequently produced:

```
.NET SDK: 8.0.134

Scanning project:
.../dotnet-aspgoat/AspGoat.csproj

Completed: AspGoat.csproj

===== .NET Vulnerability Scan Summary =====
Status: SUCCESS
.NET SDK: 8.0.134
Restore disabled: YES (--no-restore)
Projects scanned: 1
Duration: 14.52 seconds
Text Report: .../scanner_output/dotnet_output.txt
```

This confirmed that the Python wrapper completed successfully and wrote the report.

The `Restore disabled: YES (--no-restore)` summary text remained in the wrapper even after the unsupported argument was removed. Therefore, that line should be treated as a status label from our script, not proof that the command itself used `--no-restore`.

### 11.7 Important distinction about offline NuGet scanning

NuGet vulnerability scanning is different from ordinary source-code static analysis.

It relies on vulnerability advisory information supplied by configured package sources or their available caches.

For a fully offline workflow, two things must be prepared in advance:

1. **Dependency resolution data**, including `project.assets.json` and the packages required by the project.
2. **Vulnerability advisory information**, available locally through the relevant NuGet tooling or package-source configuration.

A successful command alone does not establish that current advisory data was consulted.

You have subsequently confirmed that your complete workflow operates offline. That confirms the execution behavior of your environment, but the report contents are still needed to establish how much NuGet vulnerability coverage was available.

**Offline mechanism:** Prepared project assets, locally available dependencies, and no requirement for a fresh online restore during the tested scan.

---

## 12. ESLint — Offline JavaScript security analysis

**ESLint**

Node.js version: **22.23.5**

npm version: **10.9.9**

Purpose: Identify JavaScript security patterns and code-quality problems.

### 12.1 Node.js installation problems

The original Ubuntu Node.js installation was too old for our intended ESLint setup.

We encountered a package conflict involving:

```
libnode-dev
```

while upgrading Node.js.

After resolving the package conflict, we successfully installed and verified:

```
Node.js v22.23.5
npm 10.9.9
```

We checked these using:

```
node --version
npm --version
```

### 12.2 Preparing dependencies

During the original Windows development, we had created an ESLint configuration and installed the required packages.

The relevant files included:

```
eslint.config.mjs
package.json
package-lock.json
```

We transferred these into the Ubuntu testbed and installed the dependencies while connectivity was available.

We used:

```
npm ci
```

This installs the dependencies defined by the lockfile.

After installation, the executable was available under:

```
node_modules/.bin/eslint
```

### 12.3 Offline execution

Once the dependencies were installed, we could execute ESLint locally without downloading packages:

```
npx --no-install eslint broken_gate.js
```

The important option is:

```
--no-install
```

This prevents `npx` from installing a missing package automatically.

The Python scanner wrapper invoked the local ESLint executable and generated JSON and text reports.

### 12.4 Initial validation

We tested ESLint against the intentionally vulnerable JavaScript file:

```
broken_gate.js
```

It reported:

```
5 problems (3 errors, 2 warnings)
```

Among the security-related findings were:

```
security/detect-child-process
security/detect-eval-with-expression
```

This matched the findings obtained during the Windows development stage.

That consistency was useful because it showed the Ubuntu ESLint setup was applying the intended security rules.

### 12.5 AspGoat integration problem

When we switched the target to AspGoat, ESLint initially failed:

```
FileNotFoundError:
ESLint executable not found:
.../dotnet-aspgoat/node_modules/.bin/eslint
```

This happened because our wrapper expected ESLint to be installed inside the target repository.

However, the existing ESLint installation was located in the parent testbed.

Instead of reinstalling the dependencies or rewriting the scanner, we created a Linux symbolic link.

From inside the AspGoat directory:

```
ln -s ../node_modules node_modules
```

This linked AspGoat's `node_modules` path to the existing installation in the parent directory.

We then reran:

```
cd ~/workspace/abb-hackathon

python -m scanners.eslint_scanner
```

The scan completed successfully.

### 12.6 AspGoat ESLint results

**AspGoat JavaScript scan** (SUCCESS)

Files scanned

# 23

Errors

# 477

Warnings

# 293

Execution time: 10.37 seconds

The findings came from real AspGoat JavaScript files under directories including:

```
wwwroot/js/
wwwroot/LLM-js/
```

The most frequent rules were:

| Rule                                   | Count |
| -------------------------------------- | ----- |
| `security/detect-object-injection`     | 274   |
| `no-undef`                             | 247   |
| `no-unused-vars`                       | 119   |
| `no-func-assign`                       | 36    |
| `no-extra-boolean-cast`                | 36    |
| `no-cond-assign`                       | 18    |
| `security/detect-non-literal-regexp`   | 18    |
| `no-constant-condition`                | 18    |
| `no-unsanitized/property`              | 3     |
| `security/detect-eval-with-expression` | 1     |

### 12.7 Interpreting the findings

The scan was technically successful, but the findings require interpretation.

For example, the `no-undef` rule can produce false positives when a browser-oriented project uses globals such as `window`, `document`, or jQuery without declaring them in ESLint's configuration.

Similarly, `security/detect-object-injection` is useful for identifying potentially unsafe dynamic property access but can generate many findings that are not exploitable vulnerabilities.

We therefore distinguished between:

- Security-related lint rules.
- General code-quality rules.
- Findings requiring manual verification.

We discussed reviewing `eslint.config.mjs` to improve browser-global handling. The conversation does not establish that we subsequently made that change, so the 477 errors and 293 warnings should be treated as the recorded results of the existing configuration.

The scanner generated:

```
scanner_output/eslint_output.json
scanner_output/eslint_output.txt
```

**Offline mechanism:** Local Node.js installation, locally installed npm dependencies, local ESLint configuration, and direct execution without package downloads.

---

## 13. Consolidated security report generation

Running eight independent scanners is useful, but manually reviewing every JSON and text file would be inefficient.

We therefore built a separate Python reporting component:

```
report_generator.py
```

Its responsibility is to read the scanner outputs and consolidate them into a unified security assessment.

### 13.1 Supported inputs

The report generator supports inputs including:

| Scanner  | Input file                                         |
| -------- | -------------------------------------------------- |
| Semgrep  | `semgrep_output.json`                              |
| Trivy    | `trivy_output_offline.json` or `trivy_output.json` |
| Syft     | `sbom_cyclonedx.json`, `sbom_spdx.json`            |
| Gitleaks | `gitleaks_output.json`                             |
| ScanCode | `scancode_output.json`                             |
| Bandit   | `bandit_output.json`                               |
| .NET     | `dotnet_output.txt`                                |
| ESLint   | `eslint_output.json`                               |

The generator can handle missing inputs, but a missing report must not be interpreted as proof that the scanner found no vulnerabilities.

### 13.2 Output artifacts

The reporting component produces three principal artifacts.

**1. Final security assessment**

```
security_report/final_security_assessment.md
```

A human-readable Markdown report summarizing the assessment, findings, and security posture.

**2. Consolidated findings**

```
security_report/consolidated_findings.json
```

A machine-readable representation of findings from the supported scanners.

**3. Risk register**

```
security_report/risk_register.csv
```

A structured file that can be opened in Excel or imported into another reporting system.

### 13.3 Execution

After completing the scans:

```
cd ~/workspace/abb-hackathon
source venv/bin/activate

python report_generator.py
```

We deliberately kept reporting separate from scanning.

This allowed us to rerun the report generator without spending additional time executing Semgrep, Trivy, or ScanCode.

### 13.4 Handling multiple repositories

Our framework uses a common output directory:

```
scanner_output/
```

This makes integration straightforward, but it introduces a limitation.

If we scan repository A and then repository B without clearing or archiving the outputs, reports from the two repositories can become mixed.

This is especially relevant when a language-specific scanner does not produce a new report for the second repository.

For accurate multi-repository assessments, the outputs must be separated by target.

For example:

```
results/
├── aspgoat/
│   ├── scanner_output/
│   └── security_report/
├── pygoat/
│   ├── scanner_output/
│   └── security_report/
└── other-testbed/
    ├── scanner_output/
    └── security_report/
```

Our existing framework does not automatically implement that structure. It is a recommended way to preserve results when running multiple testbeds.

---

## 14. Complete offline scanning workflow

Once all installations, dependencies, local rules, databases, and project assets have been prepared, the execution workflow is straightforward.

**Target repository**

Selected using SCAN_TARGET

**Python orchestrator — main.py**

Sequential scanner execution

Semgrep — SAST

Trivy — vulnerabilities

Syft — SBOM

Gitleaks — secrets

ScanCode — licenses

Bandit — Python

NuGet — .NET

ESLint — JavaScript

**scanner_output/**

Individual JSON and text reports

**report_generator.py**

Parse and consolidate scanner results

**security_report/**

Final security assessment

Consolidated JSON findings

CSV risk register

### 14.1 Select the target

```
cd ~/workspace/abb-hackathon
source venv/bin/activate

export SCAN_TARGET="/home/kali/workspace/abb-hackathon/sgc-gatekeeper-testbed/dotnet-aspgoat"
```

Verify:

```
echo "$SCAN_TARGET"
```

### 14.2 Run the framework

```
python main.py
```

Once all scanners complete:

```
python report_generator.py
```

Alternatively:

```
python main.py && python report_generator.py
```

The second command executes the report generator only if `main.py` exits successfully.

### 14.3 Verify generated files

```
ls -lh scanner_output/
ls -lh security_report/
```

We can also inspect the final report:

```
cat security_report/final_security_assessment.md
```

### 14.4 Run scanners individually

During debugging, we used individual scanner commands to isolate problems:

```
python -m scanners.dotnet_scanner
```

```
python -m scanners.eslint_scanner
```

This was particularly useful when the main orchestrator stopped at a scanner failure.

Rather than rerunning the entire pipeline, we could fix and test the failing scanner independently.

---

## 15. How we achieved offline operation

Our approach was not simply to disconnect Ubuntu from the internet and hope the tools continued working.

We separated the environment into two phases.

### Phase A — Online preparation

During the preparation stage, we installed and downloaded everything the scanners would need.

| Component | What we prepared                                         |
| --------- | -------------------------------------------------------- |
| Ubuntu    | Required system packages and utilities                   |
| Python    | Virtual environment and installed Python dependencies    |
| Semgrep   | CLI and local YAML rule collection                       |
| Trivy     | Linux executable and vulnerability database              |
| Syft      | Linux executable                                         |
| Gitleaks  | Linux executable and detection configuration             |
| ScanCode  | Linux toolkit and required dependencies                  |
| Bandit    | Python package and its security checks                   |
| .NET      | SDK, restored project assets, locally available packages |
| ESLint    | Node.js, npm dependencies, plugins, and configuration    |
| Testbeds  | Local copies of the repositories to scan                 |

This preparation is essential.

An offline scanner cannot retrieve a missing executable, package, rule file, or vulnerability database after network access has been disabled.

### Phase B — Offline execution

Once preparation was complete, we executed the tools against local repositories.

The scanners used their locally available dependencies and data.

The resulting reports were written to the Ubuntu filesystem.

**What our offline setup provides**

A repeatable local scanning workflow, with no requirement to download tools or application dependencies during the tested scan.

### 15.1 Offline does not mean every scanner works identically

There are three distinct offline models in our framework:

| Offline model               | Tools                                       | Explanation                                                                     |
| --------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------- |
| Local rules                 | Semgrep, Bandit, ESLint, Gitleaks, ScanCode | Analyze code using installed detection rules                                    |
| Local database or inventory | Trivy, Syft                                 | Use cached vulnerability data or inspect local component metadata               |
| Prepared dependency graph   | .NET SDK                                    | Use previously resolved project dependencies and available advisory information |

These distinctions matter when explaining the architecture to judges.

For example, Semgrep can continue detecting insecure code patterns using its local rules, while Trivy's ability to identify newly disclosed vulnerabilities depends on the freshness of its cached database.

### 15.2 Verifying offline execution

You confirmed that the completed setup works offline.

A useful way to document that verification for submission is to record the following evidence:

1. Disable the Ubuntu VM's external network connectivity.
2. Verify that external connectivity is unavailable.
3. Execute the scanners against a locally available testbed.
4. Confirm that the scanner processes finish without requiring downloads.
5. Verify the generated report files.
6. Preserve terminal logs showing successful execution.

One caveat: because the original .NET scanner output does not show the underlying advisory data source, its report should be inspected before claiming that NuGet vulnerability intelligence is complete.

Similarly, a scanner's successful exit does not necessarily mean it detected every possible vulnerability.

The defensible claim is that **the framework was tested and runs offline using prepared local resources**.

---

## 16. Problems encountered and how we solved them

The Ubuntu migration involved several practical engineering challenges.

| Problem                                           | Cause                                          | Resolution                                                 |
| ------------------------------------------------- | ---------------------------------------------- | ---------------------------------------------------------- |
| Windows scanner commands incompatible with Ubuntu | Windows-specific executables and paths         | Installed Linux-compatible tools and updated scanner paths |
| Semgrep encoding error during Windows development | Windows character encoding behavior            | Used UTF-8 handling and migrated to Linux                  |
| Semgrep resource usage                            | Limited VM CPU and RAM                         | Single-job execution                                       |
| Trivy attempted database updates                  | Default online behavior                        | Local cache and offline flags                              |
| ScanCode resource pressure                        | Large toolkit and scan workload                | 4 GB swap, single process, directory exclusions            |
| Old Node.js installation                          | Ubuntu package version and dependency conflict | Upgraded to Node.js 22 and resolved `libnode-dev` conflict |
| ESLint executable missing in AspGoat              | Dependencies installed in parent testbed       | Created `node_modules` symlink                             |
| .NET rejected `--no-restore`                      | Unsupported command argument                   | Removed the flag                                           |
| .NET could not find assets                        | Missing `project.assets.json`                  | Prepared dependencies with `dotnet restore`                |
| Multiple target repositories                      | Hardcoded scanner target paths                 | Introduced `SCAN_TARGET`                                   |
| Large files and slow transfer                     | Many small dependency and toolkit files        | Used SCP and considered archive/Git-based transfer         |

These problems were not vulnerabilities in the target applications. They were **environmental and integration issues** that had to be resolved to make the scanner framework reliable.

---

## 17. Results and validation

The following are recorded results from our development and validation sessions. They are not all from the same target repository, so they should not be combined into one vulnerability total.

| Scanner  | Recorded validation result                              |
| -------- | ------------------------------------------------------- |
| Semgrep  | 1,000 rules executed, 30 findings on an earlier testbed |
| Trivy    | 58 vulnerabilities and 4 secrets on an earlier testbed  |
| Syft     | CycloneDX and SPDX SBOMs generated                      |
| Gitleaks | 5 findings in a recorded testbed scan                   |
| ScanCode | Completed successfully; one run took 90.83 seconds      |
| Bandit   | 9 findings on the Python testbed; another run found 0   |
| .NET SDK | AspGoat project scanned successfully in 14.52 seconds   |
| ESLint   | AspGoat: 23 files, 477 errors, 293 warnings             |

The most important outcome is not the total number of findings.

It is that the framework successfully integrated different classes of security tools into a common workflow, including tools with different languages, dependencies, report formats, and offline requirements.

---

## 18. Current limitations

Although the framework is operational, the following limitations should be acknowledged in a technical submission.

**Vulnerability intelligence freshness:** Trivy and NuGet vulnerability analysis depend on the locally available advisory information. An offline environment cannot automatically learn about newly disclosed vulnerabilities.

**Scanner applicability:** Not every tool applies to every repository. For example, Bandit is specific to Python, and ESLint analyzes JavaScript rather than C#.

**False positives:** Static analysis tools can flag suspicious patterns that are not exploitable. The large number of ESLint `no-undef` and object-injection findings illustrates why manual triage matters.

**Shared output directory:** Scanning multiple repositories without archiving or clearing earlier outputs can cause stale findings to appear in later reports.

**Limited resources:** A single-core, 2 GB RAM VM is sufficient for the prepared workflow but can be slow on large repositories, especially when ScanCode is involved.

**Environment portability:** Linux virtual environments and binaries cannot be assumed to work on Windows. A Windows copy of the project is a backup of the files, not a directly executable Windows installation.

**Sensitive reports:** Secret-scanning outputs may contain confidential material. Such reports must be reviewed before being committed to a public GitHub repository.

---

## 19. Recommended GitHub repository contents

Since we also discussed pushing the project to a new GitHub repository, it is useful to distinguish between the **source repository** and the **fully provisioned offline environment**.

A GitHub repository should ordinarily contain the scanner wrappers, orchestration code, configuration, dependency manifests, documentation, and safe sample outputs.

The full offline environment additionally requires the installed tools, Python environment, local rule files, databases, and cached packages.

These are not necessarily appropriate to commit directly because they can be large, platform-specific, or sensitive.

For reproducibility, the GitHub repository should document the exact tool versions, installation steps, offline preparation steps, cache locations, and commands used to execute the framework.

That makes it possible for another person to reconstruct the environment without committing every installed dependency.

## 20. Final project summary

Our ABB Hackathon project evolved from a collection of individual security scanner scripts into a unified, offline-capable security assessment framework.

We began by developing and validating the scanners on Windows. We then migrated the framework to Ubuntu Server 22.04.5 LTS running inside VirtualBox.

During migration, we installed Linux-compatible versions of the tools, prepared local Semgrep rules and Trivy vulnerability data, configured the Python environment, resolved ScanCode's resource requirements, installed Node.js and ESLint dependencies, and prepared .NET project assets.

We also introduced the `SCAN_TARGET` environment variable to make the framework reusable across different application repositories without changing the scanner implementations.

The completed architecture integrates eight security tools and generates consolidated assessment artifacts in Markdown, JSON, and CSV formats.

**The final result is a modular security scanning framework that you have verified can execute offline using preinstalled tools, local detection rules, cached vulnerability information, and prepared project dependencies.**

It demonstrates the practical integration of static analysis, dependency assessment, secrets detection, software inventory, license analysis, and multi-language security checks within a resource-constrained Ubuntu environment.

Documentation note: This reconstruction is based on our recorded commands, configuration details, troubleshooting, and scanner outputs. Where the exact original installation command was not preserved, I have provided representative commands rather than presenting them as verbatim execution history.
