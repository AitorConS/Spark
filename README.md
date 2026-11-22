# Spark

Spark runs lightweight ARM64 virtual machines on Apple Silicon using Apple's
Hypervisor.framework. Boot Linux or an ELF unikernel, attach disks, configure
networking, and manage the VM through a local HTTP API.

Spark is the VMM behind [Jerboa](https://jerboa.dev) on macOS, where every app
runs in a VM of its own. It is an independent fork of
[Firecracker](https://github.com/firecracker-microvm/firecracker), not an
official AWS release: the executable is still called `firecracker`, and the
original Linux/KVM backend remains available.

## What You Can Do

- Boot ARM64 Linux Image/initramfs or ELF guests with 1-8 vCPUs and up to 8192 MiB of RAM.
- Attach up to four file-backed VirtIO disks, with read-only and copy-on-start modes.
- Use user-mode networking with explicit TCP/UDP forwarding and an MTU of up to
  9000, or connect an external Ethernet switch over a Unix socket.
- Start, stop, pause, resume, and inspect VMs through a private Unix-socket API.
- Save and restore local snapshots, with explicit network reconnection.
- Inspect JSON or Prometheus metrics and configure resource limits.

## Requirements

You need an Apple Silicon Mac running **macOS 26 or later**, with
Hypervisor.framework available. Local validation has been performed on an M5;
other Mac models and OS builds are not yet qualified.

For a source build, install Xcode Command Line Tools, Python 3, and Rust 1.97.0
through rustup. Native dependencies are built in a private directory from
checksum-pinned sources. Go and guest-image tools are downloaded and verified by
the Linux fixture builder. No QEMU or sibling project is required.

## Quick Start

```sh
git clone https://github.com/AitorConS/Spark.git
cd Spark
rustup toolchain install 1.97.0 --profile minimal --component clippy

python3 experiments/hvf/distribution/build-native-deps.py
export GLIB_PREFIX="$PWD/experiments/hvf/build/distribution/native"
sh experiments/hvf/build-native.sh

python3 experiments/hvf/guests/linux/prepare.py
build/macos-arm64/firecracker --no-api --config-file build/linux-guest/config.json
```

The example boots Alpine Linux with a persistent test disk and a small HTTP/UDP
service. In another terminal:

```sh
curl http://127.0.0.1:19000/
curl http://127.0.0.1:19000/shutdown
```

The build signs the executable ad hoc with the Hypervisor entitlement. It does
not install a service or require administrator privileges. Guest preparation
downloads public, checksum-verified assets and preserves an existing test disk.

## Bring Your Own Guest

Use `--no-api --config-file CONFIG.json` to run a configured VM, or start the
API server in a private directory:

```sh
mkdir -m 700 vm-runtime
build/macos-arm64/firecracker --api-sock "$PWD/vm-runtime/firecracker.sock"
```

See the [macOS guide](experiments/hvf/README.md) for complete configuration,
boot protocols, API endpoints, shutdown behavior, security, and snapshots.
The API's `/capabilities` endpoint reports what this backend supports.

## Tests

```sh
brew install llvm
export GLIB_PREFIX="$PWD/experiments/hvf/build/distribution/native"
sh experiments/hvf/ci/hosted.sh       # Build, Rust tests, lint, device fault tests
sh experiments/hvf/test-native.sh    # Real HVF, API, devices, security, Linux boot
```

The second command requires working hardware virtualization and LLVM for the
sanitizer tests (`FUZZ_CC` can select its clang executable).
Automatic CI runs on pushes and pull requests. Real HVF/KVM integration runs
are separate, manually dispatched jobs on dedicated hosts. See the
[CI guide](experiments/hvf/ci/README.md) for setup and coverage.

## Scope and Safety

Network egress and DNS are denied by default; authorize only the destinations
your guest needs. The macOS backend has its own API, Seatbelt policies, and
resource limits: upstream Linux security guarantees and full API compatibility
do not automatically apply.

Snapshots require the same Mac, macOS build, and VMM build. They are not a
cross-machine migration format. Unix-stream restore requires a compatible
interface and an explicitly authorized current switch socket; external switch
state and live connections are not restored. Forced termination is not a clean
guest shutdown.

A snapshot is written only into a directory that no other user can rename
entries in: the parent of `snapshot_path` must be owned by you or root, and
writable by neither group nor others unless it has the sticky bit. A
group-writable parent without it, which earlier builds accepted, now fails
with `snapshot parent directory must be private or sticky`; see
[`experiments/hvf/README.md`](experiments/hvf/README.md).

Spark ships inside Jerboa's macOS releases, built from a pinned commit of this
repository. Builds are signed ad hoc; Developer ID signing and notarization are
not in place yet. Broader hardware qualification, a full 24-hour stability
campaign, and physical power-loss certification remain outside the current
validation.

## Documentation

- [macOS configuration and API](experiments/hvf/README.md)
- [Unix-stream networking](experiments/hvf/UNIX_STREAM.md)
- [Network regression tests](experiments/hvf/NETWORK_REGRESSIONS.md)
- [Packaging and optional notarization](experiments/hvf/distribution/README.md)
- [Storage durability and test boundaries](experiments/hvf/durability/README.md)
- [Fuzzing](experiments/hvf/fuzz/README.md)
- [Linux/KVM quick start](docs/getting-started.md)

## Contributing and License

Bug reports and focused pull requests are welcome. Include your Mac model,
macOS build, build revision, a minimal configuration, and reproduction steps;
remove credentials and private guest data before sharing logs.

Spark builds on the work of the Firecracker contributors. It retains the
[Apache-2.0 license](LICENSE), [NOTICE](NOTICE), and third-party license notices.
See [CONTRIBUTING.md](CONTRIBUTING.md) for the inherited contribution guidelines.
