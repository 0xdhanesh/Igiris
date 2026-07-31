# Security Scanning & CI/CD Analysis for Igris

## Overview

This document details the security and CI/CD infrastructure implemented in the Igris repository. Each section explains the relevant configuration, associated repository settings, and why each measure matters for code quality and security.

---

## 🔒 Security Implementation

### 1. Secret Scanning with Gitleaks

#### Related configuration files

- `.github/workflows/security.yml` - lines 20–38 (`secret-scan` job)
- `.gitignore` - lines 1–9 (prevention at source)

#### Repository settings

- **Branch protection:** The `main` branch is protected (`protected: true`).
- **Commit verification:** Enforced through signed commits.

#### Workflow configuration

```yaml
jobs:
  secret-scan:
    name: Secret scan
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    permissions:
      contents: read
    steps:
      - name: Check out source
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10
        with:
          persist-credentials: false
          fetch-depth: 0 # Scans the entire commit history

      - name: Scan committed history
        uses: gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e
```

#### Trigger events

- Every push to the `main` and `dev` branches
- Every pull request targeting the `main` and `dev` branches
- Weekly schedule on Tuesdays at 04:17 UTC
- Manual workflow dispatch

#### Why it matters

- **Prevents credential leaks:** Scans for hardcoded API keys, passwords, tokens, and private keys.
- **Scans repository history:** `fetch-depth: 0` ensures the entire commit history is checked, including secrets introduced by earlier commits.
- **Provides pre-merge validation:** Blocks pull requests that expose secrets before they reach `main`.
- **Disables persisted credentials:** `persist-credentials: false` reduces the risk of GitHub token exposure.
- **Pins actions to commit SHAs:** Pinning `gitleaks-action` to a specific SHA reduces supply-chain risk from mutable tags.
- **Keeps findings out of comments:** `GITLEAKS_ENABLE_COMMENTS: "false"` prevents potentially sensitive findings from appearing in pull-request comments.

### 2. Static Application Security Testing (SAST)

#### 2.1 Semgrep

##### Related configuration files

- `.github/workflows/security.yml` - lines 40–67 (`sast` job)

##### Repository settings

Semgrep does not require a dedicated repository setting. It uses the Python environment defined in `pyproject.toml`.

##### Workflow configuration

```yaml
- name: Run Semgrep
  env:
    SEMGREP_SEND_METRICS: "off"
  run: |
    semgrep scan \
      --config p/security-audit \
      --config p/secrets \
      --exclude .venv \
      --exclude frontend/node_modules \
      --exclude frontend/dist \
      --exclude src/igiris/static \
      .
```

##### Trigger events

Semgrep uses the same push, pull-request, weekly, and manual triggers as the security workflow.

##### Why it matters

- **Security audit rules:** `p/security-audit` checks for common OWASP and CWE-related security patterns.
- **Secret detection:** `p/secrets` detects hardcoded credentials, API keys, and tokens.
- **Reduced false positives:** Generated files, dependencies, virtual environments, and built assets are excluded.
- **Metrics disabled:** `SEMGREP_SEND_METRICS: "off"` disables Semgrep metrics collection.
- **Fast feedback:** Runs on pull requests to surface security issues before merge.

#### 2.2 Bandit

##### Related configuration files

- `.github/workflows/security.yml` - lines 40–80 (`sast` job)

##### Workflow configuration

```yaml
- name: Produce complete Bandit report
  continue-on-error: true
  run: bandit -r src/igiris -f json -o bandit-report.json

- name: Block high-severity Bandit findings
  run: bandit -r src/igiris --severity-level high --confidence-level medium

- name: Upload Bandit report
  if: always()
  uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
  with:
    name: bandit-report
    path: bandit-report.json
    if-no-files-found: error
    retention-days: 14
```

##### Why it matters

- **Python-specific analysis:** Detects patterns associated with insecure deserialization, injection, hardcoded credentials, weak cryptography, and other Python security issues.
- **Severity filtering:** Only high-severity findings block the workflow, reducing alert fatigue.
- **Confidence threshold:** `--confidence-level medium` requires medium-or-higher confidence before a high-severity finding blocks the build.
- **Complete reporting:** A full JSON report is uploaded and retained for 14 days.
- **Two-stage execution:** The first command creates an auditable report; the second enforces the blocking threshold.
- **Audit history:** Retained artifacts support reviews, trend analysis, and post-mortems.

### 3. Dependency Auditing

#### Related configuration files

- `.github/workflows/security.yml` - lines 82–112 (`dependencies` job)
- `pyproject.toml` - lines 11–19 (Python dependencies)
- `frontend/package.json` - npm dependencies
- `.github/dependabot.yml` - automated dependency updates

#### Workflow configuration

```yaml
jobs:
  dependencies:
    name: Dependency audit
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - name: Audit Python environment
        run: |
          python -m pip install --upgrade pip==26.2 setuptools==83.0.0
          python -m pip install -e . pip-audit==2.10.1
          python -m pip_audit --local

      - name: Audit frontend dependencies
        working-directory: frontend
        run: |
          npm ci
          npm audit --audit-level=high
```

#### Dependabot configuration

```yaml
updates:
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: weekly
      day: monday
      time: "04:00"
    open-pull-requests-limit: 5
    groups:
      python-dependencies:
        patterns: ["*"]

  - package-ecosystem: npm
    directory: /frontend
    schedule:
      interval: weekly
      day: monday
      time: "04:15"
    open-pull-requests-limit: 5
```

#### Why it matters

- **Known-vulnerability detection:** `pip-audit` and `npm audit` check dependencies against vulnerability advisories.
- **Reproducible tooling:** Pinning `pip`, `setuptools`, and `pip-audit` makes the audit environment more predictable.
- **Installed-environment audit:** `pip_audit --local` audits packages installed in the current Python environment.
- **npm severity threshold:** `--audit-level=high` fails the audit for high- and critical-severity vulnerabilities.
- **Automated updates:** Dependabot opens grouped weekly pull requests for Python and npm dependencies.
- **Pull-request limits:** `open-pull-requests-limit: 5` reduces dependency-update noise.
- **Cross-ecosystem coverage:** Python and JavaScript dependencies are audited separately.

### 4. CodeQL Analysis

#### Related configuration files

- `.github/workflows/codeql.yml` - CodeQL workflow
- `pyproject.toml` - Python project configuration

#### Workflow configuration

```yaml
jobs:
  analyze:
    name: CodeQL ${{ matrix.language }}
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    permissions:
      contents: read
      security-events: write
    strategy:
      fail-fast: false
      matrix:
        language: [python, javascript-typescript]
    steps:
      - name: Initialize CodeQL
        uses: github/codeql-action/init@b7351df727350dca84cb9d725d57dcf5bc82ba26 # v3
        with:
          languages: ${{ matrix.language }}
          build-mode: none

      - name: Analyze source
        uses: github/codeql-action/analyze@b7351df727350dca84cb9d725d57dcf5bc82ba26 # v3
        with:
          category: /language:${{ matrix.language }}
```

#### Trigger events

- Every push to the `main` and `dev` branches
- Every pull request targeting the `main` and `dev` branches
- Weekly schedule on Wednesdays at 04:31 UTC
- Manual workflow dispatch

#### Why it matters

- **Multi-language analysis:** The matrix analyzes both Python and JavaScript/TypeScript.
- **Scoped permissions:** The workflow can read repository contents and write security findings without broader write access.
- **No unnecessary build:** `build-mode: none` is suitable for the interpreted languages analyzed here.
- **Security-tab integration:** Findings appear in the repository's GitHub Security interface.
- **Data-flow analysis:** Detects complex issues such as tainted-data flows, command injection, and path traversal.
- **Extended timeout:** The 30-minute limit allows deeper analysis.
- **Independent matrix results:** `fail-fast: false` ensures one language failure does not cancel the other analysis.

### 5. Workflow Security Audit with Zizmor

#### Related configuration files

- `.github/workflows/security.yml` - lines 114–126 (`workflow-security` job)
- `.github/workflows/*.yml` - all GitHub Actions workflows

#### Workflow configuration

```yaml
workflow-security:
  name: Workflow security
  runs-on: ubuntu-24.04
  timeout-minutes: 10
  steps:
    - name: Install workflow auditor
      run: python3 -m pip install zizmor==1.28.0

    - name: Audit workflow definitions
      run: zizmor .github/workflows
```

#### Why it matters

- **Action pinning validation:** Detects unpinned or weakly pinned GitHub Actions references.
- **Permission-scope validation:** Flags workflows that request unnecessarily broad permissions.
- **CI/CD security checks:** Identifies workflow patterns that could expose credentials or permit privilege escalation.
- **Pinned auditor version:** `zizmor==1.28.0` provides consistent audit behavior.
- **Continuous validation:** Workflow changes are checked for security regressions.

#### Example action pinning

```yaml
- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
- uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
- uses: github/codeql-action/init@b7351df727350dca84cb9d725d57dcf5bc82ba26 # v3
```

### 6. Branch Protection and Access Control

#### Related repository settings

- **Main branch:** Protected (`protected: true`)
- **Commit verification:** Enforced
- **CODEOWNERS file:** `.github/CODEOWNERS`

```text
* @0xdhanesh

/src/igiris/auth.py @0xdhanesh
/src/igiris/api.py @0xdhanesh
/packaging/ @0xdhanesh
/.github/workflows/ @0xdhanesh
```

#### Why it matters

- **Critical-file review:** Authentication and API code require approval from the designated owner.
- **Workflow governance:** Changes to `.github/workflows/` require owner review, helping prevent malicious CI/CD modifications.
- **Packaging governance:** Changes to release and packaging files remain controlled.
- **Protected main branch:** Reduces accidental or unauthorized direct pushes.

---

## 🚀 CI/CD Pipeline

### CI Workflow (`ci.yml`)

#### Trigger events

- Every push to the `main` or `dev` branches
- Every pull request targeting the `main` or `dev` branches
- Manual workflow dispatch

#### Concurrency control

```yaml
concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

#### Why it matters

- Prevents wasted compute on superseded pushes.
- Cancels older in-progress runs when a newer commit is pushed.
- Reduces feedback latency.

#### Job 1: Python Tests Across Multiple Versions

##### Configuration

```yaml
python-tests:
  runs-on: ubuntu-24.04
  timeout-minutes: 15
  strategy:
    fail-fast: false
    matrix:
      python-version: ["3.11", "3.12", "3.13"]
  steps:
    - run: python -m pip install -e '.[dev]'
    - run: python -m pytest -q
    - run: python -m compileall -q src
    - run: python -m pip check
```

##### Why it matters

- **Multi-version testing:** Confirms compatibility with Python 3.11, 3.12, and 3.13.
- **Development dependencies:** `.[dev]` installs test dependencies such as `pytest` and `httpx`.
- **Compilation check:** `compileall` catches syntax errors early.
- **Dependency health:** `pip check` detects incompatible or missing installed dependencies.
- **Parallel execution:** Matrix jobs can run concurrently.
- **Complete results:** `fail-fast: false` allows all Python versions to finish even if one fails.

#### Job 2: Frontend Tests and Build

##### Configuration

```yaml
frontend:
  runs-on: ubuntu-24.04
  timeout-minutes: 15
  steps:
    - run: npm ci
    - run: npm test
    - run: npm run build
    - run: diff -qr frontend/dist src/igiris/static
```

##### Related files

- `frontend/package.json` - npm configuration
- `src/igiris/static/` - packaged frontend assets

##### Why it matters

- **Reproducible installs:** `npm ci` installs exact dependency versions from the lockfile.
- **Test execution:** Detects frontend regressions.
- **Production build verification:** Confirms the frontend builds successfully in CI.
- **Asset synchronization:** `diff` verifies that the packaged frontend matches the source build.
- **Stale-build detection:** Blocks commits that contain outdated or uncommitted generated assets.

#### Job 3: Package Build

##### Configuration

```yaml
package:
  runs-on: ubuntu-24.04
  timeout-minutes: 15
  steps:
    - run: bash -n packaging/install.sh # Syntax check
    - run: python -m build # Build wheel and source distribution
    - run: |
        python -m venv /tmp/igiris-wheel
        /tmp/igiris-wheel/bin/pip install dist/*.whl
        /tmp/igiris-wheel/bin/python -c "import igiris"
        /tmp/igiris-wheel/bin/igiris-set-password --help >/dev/null
    - uses: actions/upload-artifact
      with:
        name: python-packages
        retention-days: 7
```

##### Related files

- `pyproject.toml` - package metadata and build configuration
- `packaging/install.sh` - installation script

##### Why it matters

- **Shell syntax validation:** `bash -n` catches shell-script syntax errors without executing the script.
- **Build validation:** Confirms the Python package can produce a wheel and source distribution.
- **Clean installation test:** Installs the wheel in a fresh virtual environment.
- **Runtime validation:** Confirms the package imports and its installed command is available.
- **Artifact retention:** Keeps package artifacts for seven days for testing and investigation.
- **Release readiness:** Verifies release artifacts before publication.

#### Job 4: Required CI Gate

##### Configuration

```yaml
required:
  name: CI required
  if: always()
  needs: [python-tests, frontend, package]
  steps:
    - run: |
        test "$PYTHON_RESULT" = success
        test "$FRONTEND_RESULT" = success
        test "$PACKAGE_RESULT" = success
```

##### Why it matters

- **All-or-nothing validation:** Python, frontend, and package jobs must all succeed.
- **Clear failure status:** Any failed dependency causes the required CI gate to fail.
- **Branch-protection integration:** The gate can be configured as a required status check for `main`.

### Security Workflow (`security.yml`)

#### Trigger events

- Every push to the `main` or `dev` branches
- Every pull request targeting the `main` or `dev` branches
- Weekly schedule on Tuesdays at 04:17 UTC
- Manual workflow dispatch

#### Concurrency control

```yaml
concurrency:
  group: security-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

#### Required security gate

```yaml
required:
  needs: [secret-scan, sast, dependencies, workflow-security]
  steps:
    - run: |
        test "$SECRET_RESULT" = success
        test "$SAST_RESULT" = success
        test "$DEPENDENCY_RESULT" = success
        test "$WORKFLOW_RESULT" = success
```

#### Why it matters

- **No partial passes:** All four security jobs must succeed.
- **Broad coverage:** Enforces secret scanning, SAST, dependency auditing, and workflow-security checks.
- **Pre-merge enforcement:** Pull requests cannot pass the security gate when any required job fails.
- **Scheduled rescanning:** Weekly runs can surface newly disclosed vulnerabilities in previously merged code.

### CodeQL Workflow (`codeql.yml`)

#### Trigger events

- Every push to the `main` and `dev` branches
- Every pull request targeting the `main` and `dev` branches
- Weekly schedule on Wednesdays at 04:31 UTC
- Manual workflow dispatch

#### Required gate

```yaml
required:
  needs: analyze
  steps:
    - run: test "$CODEQL_RESULT" = success
```

#### Why it matters

- **Continuous SAST:** Complements Semgrep and Bandit with semantic analysis.
- **Trend tracking:** Findings can be tracked over time in GitHub's security interface.
- **Deep data-flow analysis:** Detects complex vulnerabilities that pattern matching may miss.
- **Optimized build mode:** `build-mode: none` suits Python and JavaScript/TypeScript analysis.

### Release Workflow (`release.yml`)

#### Trigger events

- Tag pushes matching the semantic-version pattern `v*.*.*`

#### Build job

```yaml
build:
  runs-on: ubuntu-24.04
  timeout-minutes: 30
  steps:
    - run: npm ci && npm test && npm run build
    - run: diff -qr frontend/dist src/igiris/static
    - run: python -m pip install -e '.[dev]' build==1.3.0
    - run: python -m pytest -q
    - run: python -m build # Creates wheel and source distribution
    - uses: anchore/sbom-action # Generates an SPDX SBOM
    - run: sha256sum -- * > SHA256SUMS
    - uses: actions/upload-artifact
```

#### Publish job

```yaml
publish:
  needs: build
  permissions:
    contents: write
    id-token: write
    attestations: write
  steps:
    - uses: actions/attest-build-provenance
    - run: gh release create "$GITHUB_REF_NAME" dist/* --verify-tag
```

#### Why it matters

- **Complete pre-release validation:** Runs the test and build process before release.
- **SBOM generation:** Produces a Software Bill of Materials for supply-chain transparency.
- **SHA-256 checksums:** Allows users to verify artifact integrity.
- **Build attestations:** Provides provenance information for release artifacts.
- **Tag verification:** `--verify-tag` requires a verifiable release tag.
- **Separated privileges:** The build job remains separate from the privileged publish job.
- **Extended timeout:** Allows enough time for comprehensive release validation.

---

## 📋 Repository Configuration

### Permissions Model

#### Default workflow permissions

```yaml
permissions:
  contents: read
```

#### Why it matters

- **Read-only by default:** Workflows begin with minimal repository access.
- **Explicit escalation:** Only jobs that need additional access request it.
- **Reduced blast radius:** Limits the impact of a compromised workflow or action.

#### Example scoped permissions for CodeQL

```yaml
permissions:
  contents: read
  security-events: write # Writes findings to GitHub's security interface
```

### Dependabot Configuration

#### Python updates

- Weekly on Mondays at 04:00 UTC
- All dependency patterns grouped together
- Maximum of five open pull requests

#### npm updates

- Weekly on Mondays at 04:15 UTC
- All dependency patterns grouped together
- Maximum of five open pull requests

#### GitHub Actions updates

- Weekly on Mondays at 04:30 UTC
- All action updates grouped together
- Maximum of five open pull requests

#### Why it matters

- **Regular updates:** Checks weekly for newer and potentially safer dependency versions.
- **Staggered execution:** Offsets schedules by 15 minutes to reduce contention.
- **Grouped pull requests:** Reduces review overhead by grouping updates per ecosystem.
- **Pull-request limits:** Prevents excessive automated pull-request volume.

### Pull Request Template (`.github/pull_request_template.md`)

#### Enforced sections

```markdown
## Security impact

- [ ] No security boundary changes
- [ ] Security-sensitive change explained below
- [ ] No credentials, private telemetry, or host-specific data included

## Verification

- [ ] Python tests pass
- [ ] Frontend tests pass
- [ ] Frontend production build passes
- [ ] Package build passes
- [ ] Security checks pass
- [ ] Documentation updated where required

## Evidence

List commands run and relevant results.
```

#### Why it matters

- **Security-first review:** Every pull request explicitly addresses its security impact.
- **Credential prevention:** Reminds contributors not to include secrets or private telemetry.
- **Verification evidence:** Contributors document the checks they ran.
- **Traceability:** The evidence section supports audits and post-mortems.

### Issue Templates

#### Available templates

- `bug.yml` - bug report form
- `feature.yml` - feature request form
- `config.yml` - issue routing and instructions

#### Why it matters

- **Structured reporting:** Bug reports include reproduction steps and environment details.
- **Consistent information:** Feature requests include use cases and acceptance criteria.
- **Community guidance:** Templates set expectations for actionable issues.

---

## 🎯 Security and Quality Maturity

**Maturity level:** Production-grade

| Category | Implementation | Benefit |
|---|---|---|
| Secret scanning | Gitleaks with full-history scanning | Prevents credential leaks in commits |
| SAST | Semgrep, Bandit, and CodeQL | Detects code vulnerabilities early |
| Software composition analysis | `pip-audit` and `npm audit` | Identifies vulnerable dependencies |
| Supply-chain security | Action pinning, Zizmor, SBOMs, and attestations | Reduces CI/CD and release compromise risk |
| Dependency management | Dependabot with grouped updates | Automates dependency maintenance |
| Testing | Multi-version Python and Node.js checks | Improves runtime compatibility |
| Artifact validation | Frontend asset diff and wheel installation test | Prevents packaging and deployment errors |
| Enforcement | Required status-check gates | Blocks risky merges |
| Access control | CODEOWNERS and branch protection | Adds governance for critical files |
| Audit trail | Signed commits, PR templates, and retained artifacts | Improves compliance and traceability |

---

## 📊 Scanning Schedule

```text
Monday 04:00 UTC    Dependabot: Python updates
Monday 04:15 UTC    Dependabot: npm updates
Monday 04:30 UTC    Dependabot: GitHub Actions updates
Tuesday 04:17 UTC   Gitleaks and security workflow schedule
Wednesday 04:31 UTC CodeQL analysis schedule
```

Additional execution points:

- Every push to the `main` and `dev` branches for immediate feedback
- Every pull request for pre-merge validation
- Manual workflow dispatch where configured

---

## 🔍 Key Takeaways

- **Defense in depth:** Multiple scanning layers cover secrets, source code, dependencies, workflows, and release artifacts.
- **Pre-merge enforcement:** Required gates prevent merging when mandatory checks fail.
- **Automation:** Dependabot and scheduled workflows reduce manual maintenance.
- **Auditability:** Signed commits, pull-request templates, reports, and retained artifacts improve traceability.
- **Supply-chain security:** Action pinning, SBOMs, checksums, and provenance attestations strengthen CI/CD and releases.
- **Developer experience:** Clear checks, uploaded reports, and concurrency controls improve feedback quality.
- **Continuous improvement:** Scheduled runs can detect newly disclosed issues in previously merged code.

This approach makes security part of the development workflow rather than a separate compliance exercise, helping the project detect issues at multiple stages while maintaining code quality and release confidence.
