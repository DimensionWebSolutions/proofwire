# Publishing

Two paths. The second is the one to use once it is set up.

---

## What is already done

- The repository is live and public.
- CI runs the full suite on Linux, macOS and Windows, on Node 22.5 and 24.
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

- [ ] Enable **2FA on the npm account**. A compromised publish account on a
      package that claims to make things tamper-evident is the worst available
      outcome.
- [ ] Turn on **branch protection** for `main`, requiring CI to pass.
- [ ] Add the repository to **GitHub's secret scanning and Dependabot alerts**
      (Settings → Code security).
- [ ] Commission the cryptographic review in
      [`AUDIT-BRIEF.md`](AUDIT-BRIEF.md) — the one remaining blocker for a
      hosted service, and the thing to do before charging anyone.

## Versioning

All five packages release at the same version; preflight enforces it. The wire
format is versioned separately (`"v": 1` in every receipt) and will be
migrated rather than broken.
