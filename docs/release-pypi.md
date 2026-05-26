# Publishing wpsecscan to PyPI

This guide is the one-time setup + per-release runbook for the PyPI
release pipeline. The workflow at
[`.github/workflows/pypi-publish.yml`](../.github/workflows/pypi-publish.yml)
implements both **TestPyPI dry runs** (for verifying the build) and **real
PyPI publishes** (the user-facing release).

## One-time setup

You only do these three steps once.

### Step 1 — claim the project on PyPI

1. Sign in or sign up at <https://pypi.org/account/login/>.
2. The first publish creates the `wpsecscan` project automatically; you
   don't need to pre-register it. But you DO need an account in good
   standing (e-mail verified, password set, 2FA strongly recommended).

### Step 2 — register the Trusted Publisher

PyPI lets a GitHub Actions workflow publish without storing any API
token in the repo. Setup is per-project + per-workflow + per-environment:

1. Go to <https://pypi.org/manage/account/publishing/>.
2. Click **Add a new pending publisher**.
3. Fill in:
   - **PyPI project name**: `wpsecscan`
   - **Owner**: `bryanflowers`
   - **Repository name**: `wpsecscan`
   - **Workflow name**: `pypi-publish.yml`
   - **Environment name**: `pypi`
4. Save. Repeat with environment name `testpypi` if you also want
   TestPyPI dry runs (recommended).

### Step 3 — create the GitHub Actions environments

1. In the GitHub repo, go to **Settings → Environments**.
2. Create two environments named `pypi` and `testpypi`. No secrets
   needed (Trusted Publisher uses OIDC).
3. Optionally add a **required reviewer** on the `pypi` environment
   so real publishes require a manual approve-and-merge click.

## Per-release runbook

Every release follows the same four steps.

### Step 1 — bump the version

1. Edit `pyproject.toml` and `wpsecscan/__init__.py`:
   ```toml
   version = "X.Y.Z"     # in pyproject.toml
   ```
   ```python
   __version__ = "X.Y.Z"  # in wpsecscan/__init__.py
   ```
2. Update `CHANGELOG.md` — move the `[Unreleased]` heading down and
   insert a new `## [vX.Y.Z] — YYYY-MM-DD` section above it.
3. Commit with `chore(release): vX.Y.Z` and push.

### Step 2 — TestPyPI dry run

Verify the package builds + validates + uploads cleanly:

```bash
gh workflow run pypi-publish.yml -F environment=testpypi
```

Watch the run:

```bash
gh run watch
```

Once green, smoke-install from TestPyPI in a clean venv:

```bash
python -m venv /tmp/wpsec-smoke
source /tmp/wpsec-smoke/bin/activate
pip install -i https://test.pypi.org/simple/ \
            --extra-index-url https://pypi.org/simple/ \
            wpsecscan==X.Y.Z
wpsecscan --version
```

If anything fails (most commonly: PyPI metadata complaint about the
`README.md` content-type, an unfilled author/email field, or a tag
mismatch), fix forward in a new commit + re-run the dry run.

### Step 3 — real publish

Once the TestPyPI dry run is clean:

```bash
gh workflow run pypi-publish.yml -F environment=pypi
```

If you configured a required reviewer on the `pypi` environment, GitHub
will hold the workflow at the **Publish to PyPI (real)** step until you
click **Review deployments** and approve it.

### Step 4 — verify on real PyPI

```bash
python -m venv /tmp/wpsec-real
source /tmp/wpsec-real/bin/activate
pip install wpsecscan==X.Y.Z
wpsecscan --version
```

Also create a GitHub release tag pointing at the version commit:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
gh release create vX.Y.Z --notes-from-tag
```

The existing `release-attestation.yml` workflow will then attach
cosign signatures + SHA256SUMS + the SBOM to the release.

## Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `400 File already exists` | This version was already published | Bump the patch (PyPI is immutable — you can't republish the same version) |
| `403 OIDC token verification failed` | Trusted Publisher mapping is wrong | Re-check the workflow filename + environment name in Step 2; they must match the workflow YAML byte-for-byte |
| `Repository name does not match` | Repo renamed or forked | Update the mapping at <https://pypi.org/manage/project/wpsecscan/settings/publishing/> |
| `README content-type` complaint | Long-description format wrong | Ensure `[project] readme = "README.md"` in pyproject.toml; PyPI infers content-type from the extension |
| `Missing required field 'author'` | Stripped from pyproject during a refactor | Add back `authors = [{ name = "..." }]` under `[project]` |

## Hardening for production

- Enable PyPI 2FA on the account that owns the project.
- Enable the **Require reviews** rule on the `pypi` GitHub
  environment so no single commit can ship a release unattended.
- Pin the `pypa/gh-action-pypi-publish` action to a specific SHA
  instead of a tag once you're past first-publish iteration.
- After the first real publish, snapshot the SHA256 of the released
  `.whl` and `.tar.gz` somewhere offline — Sigstore signatures
  cover this, but a manual hash is a good last-line check.
