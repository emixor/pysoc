# Contributing to PySOC

First of all, **thank you** for taking the time to contribute. 🎉

PySOC is a community project and we welcome contributions of all sizes —
from typo fixes in the docs to entirely new detectors. This document
explains the expectations and the process.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Project philosophy](#project-philosophy)
- [Before you start](#before-you-start)
- [Development workflow](#development-workflow)
- [Pull request checklist](#pull-request-checklist)
- [Reporting bugs](#reporting-bugs)
- [Suggesting features](#suggesting-features)

## Code of Conduct

By participating in this project you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md). Please be kind.

## Project philosophy

Before contributing, please internalise these principles — they explain
*why* the code looks the way it does:

1. **Zero runtime dependencies.** PySOC runs on the Python standard library
   alone. Adding a new runtime dep is a serious decision — open an issue to
   discuss before opening a PR.
2. **TDD.** Tests are written *before* the implementation. The
   `tests/` directory is the spec; the `src/` directory is the
   implementation of that spec. See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).
3. **Immutable models.** `Event` and `Alert` are `frozen=True`. If you
   need to "modify" an event, use `dataclasses.replace`.
4. **ECS-inspired schema.** New event fields should follow the
   [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/)
   naming where possible. If ECS doesn't have a sensible name, document
   why you deviated.
5. **Emit, don't suppress.** Detectors emit alerts with rich context; they
   do not silently filter. Suppression is the analyst's job.
6. **Documented FPs.** Every detector carries a `note` field describing
   common false positives. New detectors must follow this convention.

## Before you start

1. **Open an issue** describing what you want to change. We'll discuss the
   approach and avoid wasted work. (Typo fixes don't need an issue.)
2. **Check the roadmap** in [`docs/ROADMAP.md`](docs/ROADMAP.md) — your
   idea may already be planned, or already rejected with rationale.

## Development workflow

```bash
# 1. Fork and clone
git clone https://github.com/<your-username>/pysoc.git
cd pysoc

# 2. Create a virtual environment and install dev deps
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 3. Create a branch
git checkout -b feature/my-new-detector

# 4. Write tests first. Run them. They should fail.
pytest tests/unit/test_my_new_detector.py

# 5. Implement until tests pass.
pytest tests/unit/test_my_new_detector.py

# 6. Run the full suite + lint.
pytest
ruff check src tests   # if you have ruff installed

# 7. Commit and push. Use conventional-commits-style messages.
git commit -m "feat(detect): add AG-001 admin-group-add detector"
git push -u origin feature/my-new-detector

# 8. Open a pull request. Fill in the template.
```

## Pull request checklist

Before opening a PR, please confirm:

- [ ] An issue exists for the change (or it's a trivial fix).
- [ ] Tests were written first and pass: `pytest`.
- [ ] No new runtime dependencies were added (or an issue was opened to
      discuss the trade-off).
- [ ] New detectors / parsers / reporters follow the existing patterns
      (see [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)).
- [ ] New detectors include a `note` field describing common FPs.
- [ ] Documentation updated:
      - [ ] [`docs/DETECTION_RULES.md`](docs/DETECTION_RULES.md) for new rules
      - [ ] [`CHANGELOG.md`](CHANGELOG.md) under `[Unreleased]`
      - [ ] [`README.md`](README.md) table-of-contents / tables if relevant
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
      `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `perf:`.
- [ ] Branch is up to date with `main`.

## Reporting bugs

Open a GitHub issue with:

1. **PySOC version** (`python -m pysoc --version` or `pip show pysoc`).
2. **Python version** and OS.
3. **Reproduction steps** — ideally a shell script that generates mock
   data and runs the pipeline.
4. **Expected vs actual behaviour.**
5. **Logs / stack trace** (sanitised).

## Suggesting features

Open a GitHub issue with the prefix `[Proposal]` and include:

1. **Use case** — what problem does this solve?
2. **Proposed API** — what would the user code look like?
3. **Trade-offs** — does this break the zero-deps rule? Does it add FPs?
4. **Alternatives considered** — what else did you look at?

We'll discuss and either accept, defer to the roadmap, or politely
decline with rationale.

Thank you again for contributing! 🙏
