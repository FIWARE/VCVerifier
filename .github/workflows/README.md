# Go Workflows

Three entry-point workflows depending on the event. All jobs delegate to reusable workflows in `common/`.

## Workflows

### `pr.yml` — Pull Request

Triggered on every PR targeting `main`. Runs validation in parallel to give fast feedback before merge. Does **not** build or push images.

```
PR opened / updated
        │
        ├──► Style Guide   (golangci-lint)
        ├──► Build         (go build → artifact)
        ├──► Tests         (go test -race)
        └──► Security      (govulncheck + gosec → SARIF)
```

---

### `main.yml` — Merge to main

Triggered when a PR is merged into `main`. Runs the full pipeline including image build and release. The release only happens if the merged PR carries a `major`, `minor`, or `patch` label — otherwise the image is published as `latest` only.

```
Merge to main
        │
        ├──► Style Guide   ──────────────────────────────────┐
        ├──► Build ──► Build Images ──► Image Security        ├──► Release
        ├──► Tests  ──────────────────────────────────────────┤
        └──► Security ───────────────────────────────────────-┘

Release:
  PR label present (major/minor/patch) → push :latest + :x.y.z  + GitHub Release
  No label                             → push :latest only
```

---

### `manual-release.yml` — Manual Release

Triggered manually from the GitHub Actions UI. Accepts a version string and skips label detection entirely. Useful for hotfixes or re-releasing without creating a new PR.

```
workflow_dispatch (version: x.y.z)
        │
        └──► Build ──► Build Images ──► Image Security ──► Release
                                                              │
                                                push :latest + :x.y.z + GitHub Release
```

---

## Common jobs (`common/`)

| File | Tool | Blocks pipeline |
|---|---|---|
| `style-guide.yml` | golangci-lint | Yes |
| `build.yml` | go build | Yes |
| `tests.yml` | go test -race | Yes |
| `security-analysis.yml` | govulncheck, gosec | No (report only) |
| `build-images.yml` | docker buildx (local tar) | Yes |
| `image-security-analysis.yml` | trivy | No (report only) |
| `release.yml` | quay.io push + GitHub Release | Yes |

Security jobs report findings to the **Security** tab in GitHub via SARIF but never fail the pipeline.

## Secrets required

| Secret | Used in |
|---|---|
| `QUAY_USERNAME` | `main.yml`, `manual-release.yml` |
| `QUAY_PASSWORD` | `main.yml`, `manual-release.yml` |

## Configuration

The image name and registry are configured in `common/release.yml`:

```yaml
env:
  REGISTRY: quay.io
  REPOSITORY: fiware
  IMAGE_NAME: my-app
```
