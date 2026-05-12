# Workflows

Five entry-point workflows depending on the event. All reusable jobs live at the top level of `.github/workflows/`.

## Entry points

### `check.yml` — PR Label Check

Triggered on every PR targeting `main`. Enforces that the PR carries a `major`, `minor`, or `patch` label before merge. If the check fails, a comment is posted on the PR with instructions.

```
PR opened / labeled / updated
        │
        ├──► check   (label validation → semver dry-run)
        └──► comment (posts PR comment on failure)
```

---

### `pr.yml` — Pull Request

Triggered on every PR targeting `main`. Runs validation in parallel to give fast feedback before merge. Does **not** build or push images.

```
PR opened / updated
        │
        ├──► Style Guide   (golangci-lint)
        ├──► Build         (go build)
        ├──► Tests         (unit + integration)
        └──► Security      (govulncheck + gosec → SARIF)
```

---

### `pre-release.yml` — Pre-Release Image

Triggered on every PR targeting `main`. Builds and pushes a pre-release Docker image to quay.io, tagged as `x.y.z-PRE-<pr-number>`. Also creates a GitHub pre-release with binary artifacts.

```
PR opened / labeled / updated
        │
        ├──► generate-version
        ├──► build-scan-push   (trivy scan → SARIF + multi-platform image push)
        ├──► build-binaries    (linux/amd64 + linux/arm64)
        └──► git-release       (GitHub pre-release with binaries)
```

---

### `main.yml` — Merge to main

Triggered when a PR is merged into `main`. Runs validation in parallel, then the release pipeline. The release only happens if the merged PR carries a `major`, `minor`, or `patch` label — otherwise validation runs but nothing is published.

```
Merge to main
        │
        ├──► Style Guide ──┐
        ├──► Tests ────────┼──► Release
        └──► Security ─────┘

Release:
  1. Detect semver label from merged PR
  2. go build (fast-fail check)
  3. docker build locally → trivy scan → SARIF → GitHub Security tab
  4. docker build + push multi-platform (amd64 + arm64) → :latest + :x.y.z + :sha
  5. Build binaries (linux/amd64 + linux/arm64)
  6. GitHub Release with binaries

  No label → steps 4–6 skipped, scan still runs
```

---

### `stale-issues.yml` — Stale Issues

Runs daily. Marks issues and PRs as stale after 40 days of inactivity and closes them after 5 more days.

---

## Reusable workflows

| File | Tool | Purpose | Blocks pipeline |
|---|---|---|---|
| `style-guide.yml` | golangci-lint | Code style enforcement | Yes |
| `build.yml` | go build | Compilation check | Yes |
| `tests.yml` | go test + integration tests | Unit + integration coverage via Coveralls | Yes |
| `security-analysis.yml` | govulncheck + gosec | Dependency CVEs + source code security | No (report only) |
| `release.yml` | trivy + quay.io + GitHub Release | Image scan, publish, binary release | Yes |

## Security reporting

Three tools report findings to the **Security → Code scanning** tab via SARIF:

| Tool | What it scans | Where |
|---|---|---|
| **gosec** | Go source code — hardcoded secrets, unsafe patterns | `security-analysis.yml` |
| **govulncheck** | Go dependencies — known CVEs (Go Vulnerability Database) | `security-analysis.yml` |
| **trivy** | Container image — OS and library vulnerabilities | `pre-release.yml`, `release.yml` |

None of these block the pipeline. The image scanned by trivy is built locally and never stored as an artifact.

## Concurrency

PR workflows (`check.yml`, `pr.yml`, `pre-release.yml`) cancel any in-progress run for the same PR when a new commit is pushed. The main workflow does not cancel in-progress runs to avoid interrupting a release mid-flight.

## Docker image cache

Docker layer cache is shared across runs via the GitHub Actions cache (`type=gha`). This speeds up both the local scan build and the multi-platform push build, reusing unchanged layers between commits.

## Secrets required

| Secret | Used in |
|---|---|
| `QUAY_USERNAME` | `main.yml`, `pre-release.yml` |
| `QUAY_PASSWORD` | `main.yml`, `pre-release.yml` |

## Image and registry configuration

The image name and registry are configured at the top of `pre-release.yml` and `release.yml`:

```yaml
env:
  REGISTRY: quay.io
  REPOSITORY: fiware
  IMAGE_NAME: vcverifier
```
