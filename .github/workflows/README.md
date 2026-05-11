# Workflows

Three entry-point workflows depending on the event. All reusable jobs live at the top level of `.github/workflows/`.

## Workflows

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

Triggered when a PR is merged into `main`. Runs validation in parallel, then the release pipeline. The release only happens if the merged PR carries a `major`, `minor`, or `patch` label — otherwise the image is published as `latest` only.

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

  PR label present (major/minor/patch) → push :latest + :x.y.z + GitHub Release
  No label                             → push :latest only
```

---

### `manual-release.yml` — Manual Release

Triggered manually from the GitHub Actions UI. Accepts a version string and skips label detection entirely. Useful for hotfixes or re-releasing without creating a new PR.

```
workflow_dispatch (version: x.y.z)
        │
        └──► Release
               │
               ├── go build
               ├── docker build → trivy scan → SARIF
               ├── docker build + push :latest + :x.y.z (multi-platform)
               └── GitHub Release
```

---

## Reusable workflows

| File | Tool | Blocks pipeline |
|---|---|---|
| `style-guide.yml` | golangci-lint | Yes |
| `build.yml` | go build | Yes |
| `tests.yml` | go test -race + Coveralls | Yes |
| `security-analysis.yml` | govulncheck, gosec | No (report only) |
| `release.yml` | trivy + quay.io push + GitHub Release | Yes |

### Security reporting

Both `security-analysis.yml` (source code) and the trivy scan inside `release.yml` (container image) report findings to the **Security → Code scanning** tab in GitHub via SARIF upload. Neither blocks the pipeline (`continue-on-error: true`).

The trivy scan builds the image locally (never pushed to a registry, never stored as an artifact) and scans it in-place before the final multi-platform push.

## Secrets required

| Secret | Used in |
|---|---|
| `QUAY_USERNAME` | `main.yml`, `manual-release.yml` |
| `QUAY_PASSWORD` | `main.yml`, `manual-release.yml` |

## Configuration

The image name and registry are configured at the top of `release.yml`:

```yaml
env:
  REGISTRY: quay.io
  REPOSITORY: fiware
  IMAGE_NAME: vcverifier
```
