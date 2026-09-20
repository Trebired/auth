# Contributing

Thanks for helping improve `@trebired/auth`.

## Development Setup

```sh
bun install
```

The package is authored in TypeScript and published from `dist`. Generated outputs, package tarballs, temp folders, logs, and caches stay out of Git.

## Common Commands

```sh
bun install --frozen-lockfile
bunx @trebired/code-discipline check
bun run typecheck
bun run build
bun run verify:pack
bun run verify:auth
```

Committed `*.spec.ts` and `*.spec.tsx` files are banned by Code Discipline. `verify:auth` exercises the built package end to end: password policy, sign-in, sessions, two-factor, codes, permissions and the Express middleware.

## Pull Request Checklist

- Add a fixture for every name, count, or rule you change.
- Keep public API changes intentional and documented in `README.md`.
- Run Code Discipline, typecheck, build, and both verification scripts.
- Update `CHANGELOG.md` under the current version or a new version section.
- Do not commit `dist`, package tarballs, temp folders, logs, or caches.

## Code Discipline

- Keep the config at `.trebired/code-discipline/config.ts`.
- Keep `@trebired/code-discipline` in `devDependencies`.
- Do not add rule-level excludes to bypass discipline.
- Keep hardcoded organization strings out of source files.

## Design Principles

- Keep the root entry browser-safe: runtime dependencies are limited to `@trebired/utils` and `@trebired/logger-adapter`'s browser entry, and nothing imports Node builtins or reads files.
- Log through `src/logging.ts`; never call `console` or write to stdout.
- Return a name unchanged when the rules cannot classify it; never guess a garbled form.
- Keep rules data-driven: suffix patterns and exception tables, not per-name code.
