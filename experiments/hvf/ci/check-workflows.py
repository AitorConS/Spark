#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Source lint for the self-hosted hardware runners.

Every job that asks for a self-hosted runner must live in
hvf-local-validation.yml, which only workflow_dispatch triggers, and must wait
for the protected `hardware-validation` environment. This keeps the
repository's own workflows honest; it cannot stop a branch or pull request
from bringing its own workflow, which only the settings in README.md can.
Line based (no PyYAML on hosted runners): it relies on this repository's
two-space indentation. `runs-on` is read in all its forms: a scalar, a flow
list, a block list or a mapping. A value the lint cannot resolve to labels (an
expression, a runner group) counts as self-hosted.
`--self-test` runs the lint against built-in cases.
"""
import pathlib
import re
import sys
import tempfile

ALLOWED = 'hvf-local-validation.yml'
ENVIRONMENT = 'hardware-validation'


def jobs(text):
    """Yields (name, lines) for each job under the top-level `jobs:` key."""
    inside, name, lines = False, None, []
    for line in text.splitlines():
        if re.match(r'^\S', line):
            if name:
                yield name, lines
            inside, name, lines = line.startswith('jobs:'), None, []
            continue
        if not inside:
            continue
        job = re.match(r'^  ([A-Za-z0-9_-]+):\s*$', line)
        if job:
            if name:
                yield name, lines
            name, lines = job.group(1), []
        elif name:
            lines.append(line)
    if name:
        yield name, lines


def triggers(text):
    block = re.search(r'^on:\s*\n((?:[ \t].*\n|\n)*)', text, re.M)
    inline = re.search(r'^on:\s*(\S.*)$', text, re.M)
    if block:
        return set(re.findall(r'^  ([A-Za-z_]+):', block.group(1), re.M))
    return set(re.findall(r'[A-Za-z_]+', inline.group(1))) if inline else set()


def runs_on(lines):
    """The job's whole `runs-on` value: its line and any deeper continuation."""
    value, inside = [], False
    for line in lines:
        if inside and (re.match(r'^ {5,}\S', line) or not line.strip()):
            value.append(line)
            continue
        key = re.match(r'^    runs-on:(.*)$', line)
        inside = bool(key)
        if key:
            value.append(key.group(1))
    return '\n'.join(re.sub(r'(^|\s)#.*$', '', line) for line in value)


def self_hosted(lines):
    return bool(re.search(r'self-hosted|\$\{\{|\bgroup\s*:', runs_on(lines)))


def check(directory):
    errors = []
    for path in sorted(directory.glob('*.y*ml')):
        text = path.read_text()
        for name, lines in jobs(text):
            body = '\n'.join(lines)
            if not self_hosted(lines):
                continue
            where = f'{path.name}: job {name}'
            if path.name != ALLOWED:
                errors.append(f'{where} uses a self-hosted runner outside {ALLOWED}')
            if not re.search(rf'^    environment:\s*{ENVIRONMENT}\s*$', body, re.M):
                errors.append(f'{where} does not wait for the {ENVIRONMENT} environment')
            if triggers(text) != {'workflow_dispatch'}:
                errors.append(f'{where} is triggered by more than workflow_dispatch')
    return errors


GATED = 'on:\n  workflow_dispatch:\njobs:\n  a:\n'
CASES = [
    # (file name, workflow text, number of errors expected)
    ('ci.yml', 'on: [push]\njobs:\n  a:\n    runs-on: ubuntu-latest\n', 0),
    ('ci.yml', 'on: [push]\njobs:\n  a:\n    # self-hosted\n    runs-on: macos-26 # not self-hosted\n', 0),
    (ALLOWED, GATED + '    runs-on: [self-hosted, Linux]\n    environment: hardware-validation\n', 0),
    (ALLOWED, GATED + '    environment: hardware-validation\n    runs-on:\n      - self-hosted\n      - Linux\n', 0),
    (ALLOWED, GATED + '    runs-on: [self-hosted, Linux]\n', 1),
    (ALLOWED, GATED + '    runs-on:\n      - self-hosted\n      - Linux\n    steps: []\n', 1),
    (ALLOWED, GATED + '    runs-on:\n\n      - Linux\n      - self-hosted\n', 1),
    (ALLOWED, GATED + '    runs-on: [\n      self-hosted,\n      Linux,\n    ]\n', 1),
    (ALLOWED, GATED + '    runs-on:\n      labels: [self-hosted]\n', 1),
    (ALLOWED, GATED + '    runs-on:\n      group: hardware\n', 1),
    (ALLOWED, GATED + '    runs-on: ${{ inputs.runner }}\n', 1),
    ('ci.yml', 'on: [push]\njobs:\n  a:\n    runs-on:\n      - self-hosted\n', 3),
    ('ci.yml', 'on: [push]\njobs:\n  a:\n    runs-on: self-hosted\n', 3),
]


def self_test():
    failures = 0
    for number, (name, text, expected) in enumerate(CASES):
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            (directory / name).write_text(text)
            errors = check(directory)
        if len(errors) != expected:
            failures += 1
            print(f'check-workflows: self-test case {number}: expected {expected} '
                  f'errors, got {errors}', file=sys.stderr)
    if failures:
        return 1
    print(f'check-workflows: self-test passed ({len(CASES)} cases)')
    return 0


def main():
    if sys.argv[1:] == ['--self-test']:
        return self_test()
    root = pathlib.Path(__file__).resolve().parents[3]
    errors = check(root / '.github' / 'workflows')
    for error in errors:
        print(f'check-workflows: {error}', file=sys.stderr)
    if errors:
        return 1
    print('check-workflows: self-hosted jobs are gated')
    return 0


if __name__ == '__main__':
    sys.exit(main())
