# FreeRADIUS Server: Agent Guide

### Purpose and Scope

This file is the repository entry point for automated coding agents. It provides operational context, navigation, and verification guidance.

Human-facing contribution policies and community governance belong in their respective documents, not in this file.

### Repository Orientation

- `README.md`: Project overview, version status, and general guidance.
- `VERSION`: Source-tree version identifier.
- `src/`: Server implementation, libraries, modules, and tests.
- `raddb/`: Server configuration, modules, policies, and examples.
- `doc/antora/modules/`: AsciiDoc documentation sources.
- `scripts/`: Build, development, and supporting utilities.
- `.github/workflows/`: Continuous integration workflows.
- `.github/contributing.md`: Human contributor guidance.
- `CODE_OF_CONDUCT.md`: Community conduct expectations.

The `master` branch contains FreeRADIUS 4 development sources. Do not assume instructions for FreeRADIUS 3 apply unchanged.

### Agent Workflow

1. Identify the relevant version, subsystem, and requested outcome.
2. Inspect existing implementation and documentation before proposing changes.
3. Distinguish observed behavior from assumptions and unverified claims.
4. Prefer minimal, independently reviewable changes.
5. Preserve unrelated behavior and repository state.
6. Validate changes using the applicable build, test, or documentation checks.
7. Report results, evidence, and any checks that could not be completed.

### Building and Testing

The source tree uses an Autoconf-based build system and requires GNU Make 4.0 or newer.

The standard build sequence is:

```sh
./configure
make
```

Install required dependencies according to the documentation for the target platform before building.

Relevant testing areas include:

- `src/tests/unit/`
- `src/tests/modules/`
- `src/tests/unlang/`

Inspect their associated build rules and instructions to determine appropriate test commands. Do not claim tests passed unless executed successfully.

### Documentation Work

Documentation is maintained principally in AsciiDoc under `doc/antora/`.

When editing documentation:

- Verify links against actual repository paths.
- Check that examples and terminology match the intended server version.
- Preserve valid technical information.
- Distinguish compatibility aliases from obsolete syntax.
- Validate affected references and report the method used.

### Deliverables and Accountability

For each completed task, provide:

- The files changed and purpose of each change.
- Relevant implementation decisions.
- Verification performed and observed results.
- Remaining limitations or unresolved issues.

Evaluate contributions by demonstrable correctness, reproducibility, maintainability, and project compatibility.

This file supplies agent-specific operational guidance. It does not replace the project's human-facing documentation or establish a separate community governance process.
