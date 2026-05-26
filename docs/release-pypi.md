# Publishing wpsecscan to PyPI

This guide is the one-time setup + per-release runbook for the PyPI
release pipeline. The workflow at
[`.github/workflows/pypi-publish.yml`](../.github/workflows/pypi-publish.yml)
implements both **TestPyPI dry runs** (for verifying the build) and **real
PyPI publishes** (the user-facing release).

## Auth model (as shipped)

Both indexes use **API-token authentication**, stored as repo-level
GitHub Actions secrets. We initially intended to use PyPI Trusted
Publisher OIDC, but the user-side OIDC mapping turned out fragile
during initial onboarding — API tokens were faster to ship and the
secrets are scoped to the `wpsecscan` project only.

| Index    | Secret name           | Issued at                                            |
|----------|-----------------------|------------------------------------------------------|
| TestPyPI | `TEST_PYPI_API_TOKEN` | https://test.pypi.org/manage/account/token/          |
| PyPI     | `PYPI_API_TOKEN`      | https://pypi.org/manage/account/token/               |

Both tokens are also mirrored at
`C:\Users\bryan\migration\HANDOFF.md` for rotation reference.

## One-time setup (already done)

1. Created accounts on both pypi.org and test.pypi.org (separate
   sign-ups, separate credentials, separate token namespaces).
2. Issued an API token on each, scoped to the `wpsecscan` project.
3. Registered both as repo secrets:
   ```
   gh secret set TEST_PYPI_API_TOKEN --repo bryanflowers/wpsecscan --body "<test-token>"
   gh secret set PYPI_API_TOKEN      --repo bryanflowers/wpsecscan --body "<real-token>"
   ```
4. Created GitHub Actions environments `pypi` and `testpypi`. Optional
   but recommended: add a **required reviewer** to the `pypi`
   environment so real releases require a manual approval click.

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

## Token rotation

When a token leaks or expires, issue a new one and update both the
GitHub secret AND the mirror in `C:\Users\bryan\migration\HANDOFF.md`:

```
gh secret set TEST_PYPI_API_TOKEN --repo bryanflowers/wpsecscan --body "<new-test-token>"
gh secret set PYPI_API_TOKEN      --repo bryanflowers/wpsecscan --body "<new-real-token>"
```

## Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `Token-based authentication failed` | Token secret missing, expired, or scoped to a different project | Re-issue at the relevant token page, then `gh secret set` (see Rotation above) |
| `400 File already exists` | This version was already published | Bump the patch (PyPI is immutable — you can't republish the same version) |
| `400 'summary' field must be 512 characters or less` | pyproject.toml `description` is too long | Shorten `description` in pyproject.toml. The README handles the long form |
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
