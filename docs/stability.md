# Stability

breachgraph is before 1.0, and it follows [Semantic Versioning](https://semver.org/) as it applies
there: a minor release (0.x.0) can change behavior, and a patch release (0.x.y) only fixes bugs.
This page says what you can rely on between releases.

## Pin what you depend on

`amoghnellutla/breachgraph@v0` moves to each new release, so you get new checks and accuracy changes
automatically, which can change what fails your build. For a build that changes only when you
choose, pin an exact version such as `@v0.7.0`, or a commit SHA. The image tags work the same way.

`main` is where work happens and can change many times a day. Only tagged releases are supported.

## What won't change without notice

These change only in a minor release, listed in the changelog under a clear heading:

- exit codes (0 passed, 1 failed, 2 usage error, 3 incomplete);
- action inputs and outputs, CLI commands and flags, and configuration keys;
- fields in `breachgraph.json`, which are added to rather than removed or repurposed;
- baselines and suppressions: a fingerprint that suppressed a finding keeps doing so.

A key or flag being removed is deprecated for at least one minor release first, with a warning.

## What does change between releases

The point of the tool is to get more accurate, so these can change in any minor release: which
findings and paths are reported, their priority and confidence, and rule contents. Anything that
can newly fail a build is called out in the changelog.

Patch releases can also add new detections when they fix a false negative.

## Security fixes

The latest minor release gets security fixes. See [SECURITY.md](../SECURITY.md).
