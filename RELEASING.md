# Releasing

This repository publishes **`prism-ai-human-plus`** to PyPI. The repository name and the
package name are not the same, and PyPI cares about the package name.

A release is a tag push. `.github/workflows/release.yml` does the rest.

## One-time setup on PyPI, per package

**Until this is done the workflow builds fine and fails at the publish step.**
It uses trusted publishing, so there is no API token in this repository's
secrets — PyPI authenticates the workflow itself, by identity.

On PyPI → the project → *Manage* → *Publishing*, add a GitHub publisher:

| field | value |
|---|---|
| Owner | `Particle-Academy` |
| Repository | this repository's name |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

All four must match exactly; PyPI checks every one of them.

For a package that has **never** been published, add it as a *pending*
publisher instead (same form, on the "Publishing" page of your account). PyPI
creates the project on the first successful upload.

## Cutting a release

1. Bump `version` in `pyproject.toml` and commit it to `main`.
2. Wait for **Tests** to go green on that commit. The release refuses to
   publish a commit without a successful `tests.yml` run for that exact SHA.
3. Tag it and push:

   ```
   git tag v0.2.0
   git push origin v0.2.0
   ```

The tag must equal the declared version with a leading `v`. `v0.2.0` against a
`pyproject.toml` that says `0.1.0` is refused before anything is built.

## Why it refuses things

PyPI is append-only. A version number cannot be reused, and a bad upload can
only be yanked, never replaced — so every check here is cheaper than the
mistake it prevents:

- **Tag ≠ declared version** → a release exists that no commit claims.
- **No green Tests for the SHA** → publishing on the assumption of green.
- **`twine check` fails** → a malformed README is rejected by PyPI *after* the
  tag exists, forcing a version bump to fix a typo.

If a tag was pushed before CI finished, that is not a failure of the release —
re-run the workflow once Tests is green.
