# Publishing

Two paths. The second is the one to use once it is set up.

---

## What is already done

- The repository is live and public, with GitHub's private vulnerability
  reporting on, so the link in [`SECURITY.md`](../SECURITY.md) works.
- The website is live at <https://dimensionwebsolutions.github.io/proofwire/>. It is static files in `site/`, deployed by
  `.github/workflows/pages.yml`; the site's own tests gate the deploy and
  `site/test/` is not published.
- CI runs the full suite on Linux, macOS and Windows, on Node 22 LTS and 24,
  plus a compatibility job that exercises the core on Node 20.11 — the oldest
  version it claims to support.
- Every package carries its own README, LICENSE and repository metadata, so
  each npm page links back to its own subtree rather than the repo root.
- Scoped packages are marked `publishConfig.access=public`, which they need
  in order to publish at all under a free org.
- `npm run release:dry` passes except for authentication.

## What is not, and cannot be from here

Publishing needs npm credentials. Nothing in this repository asks for them and
nothing stores them — that is deliberate. Both paths below put the credential
somewhere you control.

---

## Path 1 — from your machine, once

```bash
npm login                       # opens a browser
node scripts/release.js --dry-run
npm run release
```

### First time only: create the scope

The four `@proofwire/*` packages need an npm org to live in. It is free for
public packages:

**https://www.npmjs.com/org/create** → name it `proofwire`.

Without it those four fail to publish. The unscoped `proofwire` CLI — the one
people actually install — publishes either way.

### What the script does

Preflight, then publish in dependency order:

```
core  →  proxy  →  dashboard  →  server  →  cli
```

Order matters. Publishing the CLI before the proxy leaves a package on the
registry whose dependency does not exist yet: briefly uninstallable, and not
fixable by unpublishing.

Preflight refuses to continue on a failing test run, a dirty working tree,
mismatched versions, or missing auth. A version already on the registry is
skipped, so a re-run after a partial failure resumes rather than erroring.

> **npm is effectively write-once.** `npm unpublish` works for 72 hours, and
> the name is held forever either way. Run the dry run first.

---

## Path 2 — from CI, every time after that

Better for a security product, for three reasons: the artifact is built from a
tagged commit anyone can inspect, npm records **provenance attestations**
linking each tarball to the workflow run that produced it, and no long-lived
credential sits on a laptop.

### Setup, once

1. On npm: **Access Tokens → Generate New Token → Granular Access Token**.
   Scope it to the `proofwire` packages and the `@proofwire` org, with
   *Read and write*. Set an expiry.
2. On GitHub: **Settings → Secrets and variables → Actions → New repository
   secret**, named `NPM_TOKEN`.

### Releasing

```bash
npm version 0.2.1 --workspaces --include-workspace-root
git push && git push --tags
```

The tag triggers `.github/workflows/release.yml`, which re-runs the full suite
on three operating systems, checks the tag matches the manifests, publishes
with provenance, and opens a GitHub release with generated notes.

Try it first with **Actions → Release → Run workflow → dry run: true**.

---

## After the first publish

```bash
npx proofwire@latest --version
npm view proofwire
```

Then the things that are not automatable and are worth doing deliberately:

- [ ] Check the site noticed. The Pages workflow reruns when Release finishes
      and writes the version into `site/release.json`, which reveals the install
      line on the page. It does so only if `npm view proofwire repository.url`
      points at this repository: the CLI's name is unscoped, so without that
      check anyone who registered it first would be advertised here. Then delete
      the *Not on npm yet* note from the root `README.md` (not from
      `packages/cli/README.md`, which ships in the tarball and is correct once
      published).
- [ ] Enable **2FA on the npm account**. A compromised publish account on a
      package that claims to make things tamper-evident is the worst available
      outcome.
- [ ] Turn on **branch protection** for `main`, requiring CI to pass.
- [ ] Add the repository to **GitHub's secret scanning and Dependabot alerts**
      (Settings → Code security).
- [ ] Commission the cryptographic review in
      [`AUDIT-BRIEF.md`](AUDIT-BRIEF.md) — the one remaining blocker for a
      hosted service, and the thing to do before charging anyone.

## The website's address

It is at <https://dimensionwebsolutions.github.io/proofwire/>. Every path on the site is relative, so it works under any
prefix or at a root; moving it changes where it is served from, not the site.

To put it under `proofwire.github.io`:

1. Create a free GitHub organisation named `proofwire`. That is an account
   action, so it has to be you; the handle was unclaimed when this was written.
2. Transfer this repository into it (Settings → General → Danger zone). GitHub
   redirects the repository's own URLs; do not count on the old `github.io`
   address doing the same. Pages is served per repository, so the site moves to
   `proofwire.github.io/proofwire/`.
3. Update everything that names the old owner: `repository` in each
   `package.json`, the `REPO` constant in `site/test/site.test.js`, the links in
   `site/index.html`, `SECURITY.md`, and the README badges. The site tests fail
   on the links they can see. Publish again after changing `repository`: until
   then the site's npm check will, correctly, decline to advertise a package that
   points at the old owner.
4. Optionally add a one-file repository named `proofwire.github.io` whose
   `index.html` redirects to `/proofwire/`, so the bare hostname lands somewhere.
   GitHub serves a hostname's root only from a repository of exactly that name.

A custom domain later is Settings → Pages → Custom domain; nothing in the site
needs to change.

## Versioning

All five packages release at the same version; preflight enforces it. The wire
format is versioned separately (`"v": 1` in every receipt) and will be
migrated rather than broken.
