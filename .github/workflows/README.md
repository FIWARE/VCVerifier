# Workflows

Three entry-point workflows depending on the event. All reusable jobs live at the top level of `.github/workflows/`.

## Workflows

### `check.yml` — PR Label Check

Triggered on every PR targeting `main`, including when labels are added or removed. Enforces that the PR has a `major`, `minor`, or `patch` label before it can be merged. If the check fails, a comment is posted on the PR with instructions.

```
PR opened / labeled / updated
        │
        ├──► check   (zwaldowski/match-label-action → semver dry-run)
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
        ├──► Tests         (go test -race + Coveralls)
        └──► Security      (govulncheck + gosec → SARIF)
```

---

### `main.yml` — Merge to main

Triggered when a PR is merged into `main`. Runs validation in parallel, then the release pipeline. The release only happens if the merged PR carries a `major`, `minor`, or `patch` label — otherwise no image is pushed.

```
Merge to main
        │
        ├──► Style Guide ──┐
        ├──► Tests ────────┼──► Release
        └──► Security ─────┘

Release (single job):
  1. go build
  2. docker build (single-arch, loaded locally)
  3. trivy scan → SARIF → GitHub Security tab
  4. docker build + push (multi-platform: amd64 + arm64)
  5. GitHub Release (only if PR had major/minor/patch label)

  PR label present (major/minor/patch) → push :x.y.z + GitHub Release
  No label                             → no image pushed
```

---

## Reusable workflows

| File | Tool | Purpose | Blocks pipeline |
|---|---|---|---|
| `style-guide.yml` | golangci-lint | Code style enforcement | Yes |
| `build.yml` | go build | Compilation check | Yes |
| `tests.yml` | go test -race + Coveralls | Unit tests + coverage | Yes |
| `security-analysis.yml` | govulncheck + gosec | Dependency CVEs + source code security | No (report only) |
| `release.yml` | trivy + quay.io push + GitHub Release | Image scan + publish | Yes |

## Security reporting

Three tools report findings to the **Security → Code scanning** tab in GitHub via SARIF:

| Tool | What it scans | Where |
|---|---|---|
| **gosec** | Go source code — hardcoded secrets, SQL injection, unsafe patterns | `security-analysis.yml` |
| **govulncheck** | Go dependencies — known CVEs (Go Vulnerability Database) | `security-analysis.yml` |
| **trivy** | Container image — OS and library vulnerabilities | `release.yml` |

None of these block the pipeline (`continue-on-error: true`). The image scanned by trivy is built locally and never stored as an artifact.

## Secrets required

| Secret | Used in |
|---|---|
| `QUAY_USERNAME` | `main.yml` |
| `QUAY_PASSWORD` | `main.yml` |

## Configuration

The image name and registry are configured at the top of `release.yml`:

```yaml
env:
  REGISTRY: quay.io
  REPOSITORY: fiware
  IMAGE_NAME: vcverifier
```
