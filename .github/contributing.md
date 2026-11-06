# Contributing to FreeRADIUS

FreeRADIUS benefits from reports, documentation improvements, tests, patches,
and proposals from the community. This guide explains how to contribute and
what maintainers need in order to review a submission.

Contributions are evaluated for their technical merits, evidence,
compatibility, security, maintainability, and relevance. Review does not
guarantee acceptance, and an initial proposal need not arrive with a complete
implementation.

Community behavior is covered by the [Code of Conduct](../CODE_OF_CONDUCT.md).
Repository-specific instructions for coding agents are in
[`AGENTS.md`](../AGENTS.md).

## Choose the appropriate channel

| Purpose | Channel |
| --- | --- |
| Report a reproducible software or documentation defect | [GitHub Issues](https://github.com/FreeRADIUS/freeradius-server/issues) |
| Suggest a feature, behavior change, or documentation improvement | [GitHub Issues](https://github.com/FreeRADIUS/freeradius-server/issues) |
| Propose a concrete source or documentation change | [GitHub Pull Requests](https://github.com/FreeRADIUS/freeradius-server/pulls) |
| Ask for configuration or operational assistance | [FreeRADIUS users' mailing list](https://freeradius.org/support/) |
| Discuss development approaches or substantial design proposals | [FreeRADIUS development mailing list](https://freeradius.org/support/) |
| Report a security vulnerability | [FreeRADIUS security team](mailto:security@freeradius.org) |

Do not publish exploitable security details or credentials in a public issue.
Configuration questions filed as issues may be redirected to the appropriate
support channel or closed. A question submitted to the wrong channel is not,
by itself, a conduct violation.

## Before reporting or changing something

1. Identify the affected FreeRADIUS version or branch. The `master` branch
   contains development sources and may differ from stable releases.
2. Check relevant version-specific documentation, existing issues, and recent
   changes when practical.
3. State the intended outcome and distinguish observed behavior from
   assumptions.
4. Prefer a focused, reproducible report or change over a collection of
   unrelated concerns.

A defect in a supported release is worth reporting even if the latest
development branch behaves differently. Indicate which versions you tested.
Do not assert that an issue is fixed or absent without checking.

## Discussing substantial changes

For new modules, substantial features, or architectural changes, early
discussion with maintainers is encouraged. Their feedback may identify
existing functionality, design constraints, or approaches that reduce
maintenance work.

Discussion is a way to exchange information, **not a prerequisite for
opening a pull request**. A contributor may submit a proposal for review
without obtaining advance permission. Maintainers may ask for revisions,
suggest a different approach, or decline a proposed change, with a technical
explanation where practical.

When pointing to an existing solution or asking someone to use a different
approach, provide the relevant implementation, documentation, issue, or
design constraint whenever available. This makes the feedback actionable
and preserves useful project knowledge.

## Reporting defects

The [defect-reporting guide](../doc/antora/modules/developers/pages/bugs/bugs.adoc)
contains additional instructions. Include the evidence relevant to the
reported problem.

For **runtime defects**, provide:

- The affected version, platform, and relevant configuration context.
- Steps to reproduce the behavior and the expected versus actual result.
- Relevant debug output, test output, or error messages, if available.
- What has already been checked and any known limitations of the report.

For **documentation defects**, provide:

- The affected page URL or repository file path.
- The inaccurate statement, missing content, or broken reference.
- The expected destination or corrected information, with supporting evidence.

A documentation-only defect does not require a running server or daemon
debug output. Review logs and configuration excerpts for credentials,
private information, or other secrets before publishing them.

Use fenced code blocks (three backticks before and after a block) for
terminal output or source excerpts so that GitHub displays them accurately.

## Preparing a pull request

Fork the repository, create a branch for the change, and submit a
[pull request](https://github.com/FreeRADIUS/freeradius-server/pulls)
against the appropriate upstream branch. See the
[GitHub contribution guide](../doc/antora/modules/developers/pages/gitpr.adoc)
for additional instructions.

A useful pull request includes:

- **Purpose:** What problem does the change address, and why?
- **Scope:** What files or behavior change, and what remains unchanged?
- **Evidence:** Reproduction steps, relevant references, or design reasoning.
- **Verification:** Tests and checks actually run, their results, and any
  relevant checks that were not run.
- **Compatibility:** Affected versions, migration implications, or other
  limitations when applicable.

Keep logically independent changes in separate commits or pull requests.
A related set of edits across multiple files may be one logical change.
Avoid unrelated formatting changes that obscure the review.

Documentation-only corrections ordinarily do not require a full runtime
build, but their references, terminology, and examples should be checked
against the relevant version. Do not present a check as passed unless it
was performed.

## Coding and documentation references

- [Coding methods](../doc/antora/modules/developers/pages/coding-methods.adoc)
  describe established implementation practices.
- [Module interface guidance](../doc/antora/modules/developers/pages/module_interface.adoc)
  is relevant when implementing a new module.
- [Developer API reference](https://doc.freeradius.org/) provides generated
  source documentation.
- [Antora documentation sources](../doc/antora/modules/) contain the
  documentation used for the project website.

Follow the surrounding file's conventions, check affected interfaces and
tests, and explain intentional deviations when relevant.

## Testing and continuous integration

The repository uses [GitHub Actions](../.github/workflows/) for continuous
integration. Review the workflows and the relevant build rules to determine
which checks apply to a change.

Test locations include:

- `src/tests/unit/`: unit tests.
- `src/tests/modules/`: module-related tests.
- `src/tests/`: additional protocol, integration, and functional tests.

Add or update tests where practical. Include actual results in the pull
request, and identify missing coverage or tests that could not be run.
A CI failure should be investigated in the context of the change rather
than assumed to prove or disprove its correctness on its own.

## AI-assisted and automated contributions

Contributors may use coding assistants, generators, scripts, and other
automation. The means of drafting a contribution neither establishes
its correctness nor disqualifies it from review.

The person submitting a change remains responsible for understanding it
and for accurately representing its provenance and verification.
Review generated material for compatibility, security, and licensing
concerns. Identify material external sources or automated transformations
when relevant to reproducibility, attribution, or review. Do not
misrepresent tests, authorship, or evidence.

Apply the same technical review criteria to changes regardless of the
tools used to produce them. Inadequately verified changes may be
returned for revision or closed; deliberate misrepresentation or
harassment is addressed under the Code of Conduct.

## Review and participation

Reviewers may request changes, ask for tests, identify duplication,
or explain why a proposal does not fit the project. When possible,
feedback should reference specific code, documentation, behavior,
or constraints and provide a next action.

Maintainer time is limited. Contributors are not guaranteed review
within a particular interval, nor are maintainers required to accept
a submission. Participants are expected to discuss technical
disagreements respectfully and may request clarification without
that request itself being treated as misconduct.
