#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Source lint for the self-hosted hardware runners.

Every job that asks for a self-hosted runner must live in
hvf-local-validation.yml, which only workflow_dispatch triggers, and must wait
for the protected `hardware-validation` environment. This keeps the
repository's own workflows honest; it cannot stop a branch or pull request
from bringing its own workflow, which only the settings in README.md can.
Line based (no PyYAML on hosted runners): it relies on this repository's
two-space indentation.
"""
import pathlib
import re
import sys

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


def check(directory):
    errors = []
    for path in sorted(directory.glob('*.y*ml')):
        text = path.read_text()
        for name, lines in jobs(text):
            body = '\n'.join(lines)
            if not re.search(r'^    runs-on:.*self-hosted', body, re.M):
                continue
            where = f'{path.name}: job {name}'
            if path.name != ALLOWED:
                errors.append(f'{where} uses a self-hosted runner outside {ALLOWED}')
            if not re.search(rf'^    environment:\s*{ENVIRONMENT}\s*$', body, re.M):
                errors.append(f'{where} does not wait for the {ENVIRONMENT} environment')
            if triggers(text) != {'workflow_dispatch'}:
                errors.append(f'{where} is triggered by more than workflow_dispatch')
    return errors


def main():
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
