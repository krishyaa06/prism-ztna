# Contributing to prism-ztna

Thanks for taking the time to contribute! prism-ztna is a command-line tool by [Prism Protocol](https://github.com/krishyaa06) — Prism ZTNA replaces the VPN with per-request decisions. A small policy language (apps, allow/deny rules, attribute conditions, step-up MFA) is parsed by a Pratt parser and evaluated with deny-overrides and default deny, and every decision explains itself rule by rule. Device posture is scored from disk encryption, EDR, patch age, jailbreak and MDM signals. Sessions use device-bound HS256 tokens with key rotation, posture is re-checked on every request, and traffic is routed through an anycast PoP mesh to outbound-only app connectors. It ships with a hash-chained audit log, a policy linter, an identity-aware HTTP reverse proxy and a CLI.

## Getting started

```bash
git clone https://github.com/krishyaa06/prism-ztna.git
cd prism-ztna
npm start
```

## Before you open a pull request

Make sure everything passes locally:

```bash
npm test
```

## Guidelines

- **Zero dependencies.** Please don't add runtime dependencies — use Node.js built-ins (`node:fs`, `node:path`, `node:test`, …).
- **No build step, no frameworks.** Keep it plain HTML, CSS and JavaScript so it runs straight from GitHub Pages.
- **Everything stays in the browser.** Don't send user data to any server.
- Keep pull requests small and focused — one feature or fix per PR.
- Update the README when you change behaviour, flags or options.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add --json output
fix: handle empty input
docs: clarify install steps
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`. Add a short entry under **[Unreleased]** in [CHANGELOG.md](CHANGELOG.md) for user-facing changes.

## Reporting bugs & ideas

Open an [issue](https://github.com/krishyaa06/prism-ztna/issues) with:

- what you expected vs. what happened
- steps to reproduce
- your OS, browser or Node.js version

**Security issues:** please don't open a public issue — contact the maintainer privately via [GitHub](https://github.com/krishyaa06).

## License

By contributing, you agree that your contributions will be licensed under the project's [license](LICENSE).
