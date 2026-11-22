# Continuous Integration

## Automatic Checks

`spark-ci.yml` runs on every push and pull request, using GitHub's macOS 26
ARM64 runner. It installs the pinned Rust toolchain, builds checksum-pinned native
dependencies, installs LLVM for ASan/UBSan/LeakSanitizer, and runs `hosted.sh`:

- Release build of the signed macOS executable.
- Rust unit tests for `hvf-vmm` and Clippy with warnings treated as errors.
- ASan/UBSan device fault tests, including storage error latching, flush ordering,
  snapshot rejection after an I/O failure, and six mutation controls.

These checks do not create a VM. GitHub-hosted macOS runners do not support
[nested virtualization](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
Passing this job is not evidence of a successful guest boot.

Run the same checks locally after building the native dependencies:

```sh
brew install llvm
export GLIB_PREFIX="$PWD/experiments/hvf/build/distribution/native"
sh experiments/hvf/ci/hosted.sh
```

## Hardware Integration

`hvf-local-validation.yml` is manually dispatched with backend `hvf` or `kvm`.
It only runs on provisioned, dedicated self-hosted runners:

| Backend | Runner labels | Coverage |
| --- | --- | --- |
| HVF | `self-hosted`, `macOS`, `ARM64`, `hvf-macos26` | Native/API/security tests, Alpine and Debian boot, snapshots, I/O limits, 100 network lifecycle cycles, fuzzing |
| KVM | `self-hosted`, `Linux`, `X64`, `kvm-validation` | Linux VMM and Firecracker unit/integration suite |

Do not run unreviewed pull-request code on these privileged hosts. The workflow
does not register runners, install services, publish packages, or use signing
credentials. Provisioning a runner is a separate administrator task.

Nothing in a workflow file can enforce that rule. GitHub assigns a job to a
self-hosted runner by its labels, for whatever workflow definition the run
uses: a dispatch of another branch runs that branch's copy of this workflow,
and a pull request runs its own workflows, which can ask for the same labels.
`check-workflows.py` (run by `hosted.sh`) keeps this repository's own jobs in
line: every self-hosted job is in `hvf-local-validation.yml`, which only
`workflow_dispatch` starts, and waits for the `hardware-validation`
environment. What binds the runners must be configured in the repository or
organization settings before any runner is registered:

- **Environment `hardware-validation`**: required reviewers, and deployment
  branches limited to `main`. A run that uses a workflow copy without the
  `environment:` key skips it, so this alone is not enough.
- **Runner scope**: register the runners in an organization runner group
  restricted to this repository and, under "selected workflows", to
  `.github/workflows/hvf-local-validation.yml@refs/heads/main`. That is the
  only setting that refuses jobs from other refs and from pull requests.
  Repository-level runners cannot be restricted this way.
- **Pull requests from forks**: require approval for all outside
  collaborators (Settings > Actions > General), and do not give write access
  to accounts whose dispatches should not reach the hosts.
- **Ephemeral runners**: register each runner with `--ephemeral` (or as a
  just-in-time runner) and recreate the host's runner user between jobs, so a
  job cannot leave state, under the runner's home or through `sudo` on the KVM
  host, for the next one.

HVF requires macOS 26 ARM64, Xcode CLI tools, Rust 1.97.0 with Clippy, Python 3,
and LLVM/libFuzzer (`FUZZ_CC` selects clang). Native libraries and guest tools
are built or downloaded from pinned sources. `HVF_USE_CACHED_GUEST=1` explicitly
reuses prepared local fixtures; the workflow prepares them by default.

KVM requires Linux x86_64, Rust 1.97.0, libseccomp development headers,
passwordless `sudo`, `unshare`, and iproute2. Compilation is unprivileged and
tests use an isolated network namespace. The separate
[KVM boot smoke test](../guests/kvm/README.md) is not part of this job.

`preflight.py` exits 77 and records `available: false` when the requested backend
is unavailable. Availability alone never marks tests as passed. Evidence is
written under `experiments/hvf/build/ci`; a full 24-hour stability campaign must
be invoked separately with `HVF_RUN_24H=1` and a sufficiently long job timeout.
