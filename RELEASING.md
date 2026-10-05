# Releasing

This repository publishes **`prism-ai-human-plus`** to PyPI. The repository name and the
package name are not the same, and PyPI cares about the package name.

A release is a tag push. `.github/workflows/publish.yml` does the rest.

## One-time setup on PyPI, per package

**Until this is done the workflow builds fine and fails at the publish step.**
It uses trusted publishing, so there is no API token in this repository's
secrets — PyPI authenticates the workflow itself, by identity.

On PyPI → the project → *Manage* → *Publishing*, add a GitHub publisher:

| field | value |
|---|---|
| Owner | `Particle-Academy` |
| Repository | this repository's name |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

All four must match exactly; PyPI checks every one of them. The workflow name
is part of that identity: rename `publish.yml` and publishing stops until the
entry on PyPI is changed to match.

For a package that has **never** been published, add it as a *pending*
publisher instead (same form, on the "Publishing" page of your account). PyPI
creates the project on the first successful upload.

## Cutting a release

1. Bump `version` in `pyproject.toml` and commit it to `main`.
2. Wait for **Tests** to go green on that commit. The release refuses to
   publish a commit without a successful `tests.yml` run for that exact SHA.
3. Tag it and push:

   ```
   git tag -a v0.2.0        # annotated: the message BECOMES the release notes
   git push origin v0.2.0
   ```

   The workflow publishes to PyPI, creates the GitHub release from the tag's
   message, then checks that PyPI serves the version.

   **Every annotation must declare its breaking status**, and the release
   refuses one that does not. Write one of these two lines, whichever is true:

   ```
   BREAKING CHANGE: <what breaks, and what the consumer must do about it>
   ```

   ```
   No breaking changes.
   ```

   A `## Breaking changes` heading with content under it also satisfies the
   check, but **only if you tag with `--cleanup=verbatim` or `-F`**. Under git's
   default cleanup every `#` line in a tag message is treated as a comment and
   **deleted**, so `git tag -a -m '## Breaking changes …'` publishes an
   annotation with the heading silently missing. The two forms above carry no
   `#` to lose, which is why they come first.

   This was asked for in prose before this check existed, and asking did not
   work: of the twenty most recent annotations across ten of these repositories,
   EIGHTEEN never used the word "breaking" at all. One shipped a mandatory
   migration, a changed scope-matching rule and a raised framework floor under
   headings that described each change accurately and labelled none of them
   breaking. A consumer scanning that release page for the word found nothing.

   Prose mentioning "breaking" does not satisfy the check — it matches the
   structural form, so a note that merely discusses breakage still has to say
   which it is. Anyone holding a pinned digest or matching on an error code
   learns it here or not at all.

   The guard runs **before** the upload, so a missing declaration refuses the
   publish rather than merely withholding the release page. You can see the same
   verdict locally before tagging:

   ```
   sh tools/check-release-notes.sh --tag v0.2.0
   ```

   Use `--tag`, not a pipe from `git tag -l --format='%(contents)'`: on a
   lightweight tag that format yields the *commit* message instead, so the check
   would read text the release will never publish and approve it. `--tag`
   refuses that case by name.

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
- **Lightweight tag** → a release with no notes. Refused before the build,
  because once the upload has happened the version cannot be taken back.
- **PyPI never serves the version** → the last job fails even though the
  upload succeeded. An accepted upload is not an installable package.

If a tag was pushed before CI finished, that is not a failure of the release —
re-run the workflow once Tests is green.
