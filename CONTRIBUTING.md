# Contributing

Contributing to libmtev can be accomplished through a standard Github
PR process.  The process is rather lose, but will be guided by more
tenured committers.  If the contributing community grows, the processes
will be formalized from lessons learned during that growth.

You can use github issues to open bug reports or feature requests or
simply skip that and issue a PR.

### Small changes and bug fixes.

A single commit, with a good commit message, PR'd and peer reviewed.

### Complex changes or significant fixes.

Builds upon the small changes guidance, but should include tests.  Tests
are either C tests or luajit "busted" tests using the built-in `mtevbusted`
test system.  If the tests are testing something new, they should be included
in the single commit.  If they are testing something broken, they should be
a separate commit before the commit including the fix.

### Features

> tl;dr: 2-4 commits: docs, tests, code, docs build. Tests and code might be in a single commit, docs builds can be excluded.

Features should have justification and justification should last.  There is
no better justification for a feature than good documentation.  Documentation
is managed in gitbook in the top-level `docs-md` directory.  Changes in that
directory should be in their own commit.

Documentation is also compiled for display online by running `make docs-html`
in the root; changes from this should either be in their own separate commit
or left to a project maintainer to do outside of the review process as they
are effectively build by-products.

The code of the feature itself should be a single commit.

## Style guidelines.

Attempt to follow the style in the file you are editing.  Code added to a file
should be done under the same license that the file currently holds.  New files
should be licensed using a 3-clause BSD license as is most common throughout
the repository.

## Making a release

 * Fixes with no ABI changes should do in patch releases.
 * New APIs that are insignificant can go in patch releases.
 * New APIs bringing any significant functionality should be in minor releases.
 * Breaking ABI changes (with rare exceptions) should go into a new major release.

We use master for releases.  Make sure the ChangeLog.md is up to date and that the
version in `src/Makefile.in` reflects the new release version.  Commit and push
these in the same commit.  Tag the commit as <major>.<minor>.<patch>.
