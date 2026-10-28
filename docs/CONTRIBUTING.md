# Contributing

## Branching (Gitflow)

- Work on a `feature/<short-desc>` branch cut from `develop`.
- PR into `develop`; squash-merge.
- Release: cut `release/vX.Y.Z` from `develop`, merge to `main` + `develop`, tag.
- Hotfix: cut `hotfix/*` from `main`, merge to `main` + `develop`.

## CI contract

`make test-strict` must pass locally before opening a PR. CI runs the same thing.
No live network calls in tests.
