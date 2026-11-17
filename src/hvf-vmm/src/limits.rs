// SPDX-License-Identifier: Apache-2.0
//! Hard file/descriptor ceilings and externally sampled group CPU/RSS.
use crate::Result;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
#[repr(C)]
struct Timebase {
    numer: u32,
    denom: u32,
}
unsafe extern "C" {
    fn mach_timebase_info(info: *mut Timebase) -> i32;
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Limits {
    pub version: u32,
    pub open_files: u64,
    pub file_size_bytes: u64,
    pub cpu_seconds: u64,
    /// None charges the guest's own size: see Watchdog::new.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rss_mib: Option<u64>,
    pub nice: i32,
    pub disk_bytes_per_second: u64,
    pub disk_operations_per_second: u64,
    pub network_bytes_per_second: u64,
    pub network_packets_per_second: u64,
}
const DEFAULT_RSS_FLOOR_MIB: u64 = 2 * 2048 + 1024;
impl Default for Limits {
    fn default() -> Self {
        Self {
            version: 1,
            open_files: 1024,
            file_size_bytes: 16 << 30,
            cpu_seconds: 86400,
            rss_mib: None,
            nice: 5,
            // Device budgets should permit modern local storage by default;
            // operators can still set lower explicit byte and IOPS limits.
            disk_bytes_per_second: 8 << 30,
            disk_operations_per_second: 250000,
            // Network traffic is unrestricted unless the operator supplies a
            // byte or packet rate. The former defaults throttled local VM
            // links to 64 MiB/s, below even a single host's network capacity.
            network_bytes_per_second: 0,
            network_packets_per_second: 0,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        if !(1 << 20..=1 << 40).contains(&self.disk_bytes_per_second)
            || !(1..=1000000).contains(&self.disk_operations_per_second)
            || (self.network_bytes_per_second != 0
                && !(1 << 20..=1 << 40).contains(&self.network_bytes_per_second))
            || (self.network_packets_per_second != 0
                && !(1..=1000000).contains(&self.network_packets_per_second))
        {
            return Err(
                "I/O limits require disk 1 MiB/s..1 TiB/s and 1..1000000 operations/s; network rates are 0 (unlimited), 1 MiB/s..1 TiB/s, or 1..1000000 packets/s".into(),
            );
        }
        if self.version != 1
            || !(64..=4096).contains(&self.open_files)
            || !(1 << 20..=1 << 40).contains(&self.file_size_bytes)
            || !(1..=31536000).contains(&self.cpu_seconds)
            || self.rss_mib.is_some_and(|rss| !(64..=32768).contains(&rss))
            || !(0..=19).contains(&self.nice)
        {
            return Err("invalid limits v1: open_files 64..4096, file_size_bytes 1 MiB..1 TiB, cpu_seconds 1..31536000, rss_mib 64..32768, nice 0..19".into());
        }
        Ok(())
    }
    pub fn apply(&self) -> Result<()> {
        self.validate()?;
        let mut cpu = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // Finite RLIMIT_CPU stalls HVF on the validated host. Preserve inherited
        // restrictions and reject this setup; never silently remove a host limit.
        if unsafe { libc::getrlimit(libc::RLIMIT_CPU, &mut cpu) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if cpu.rlim_cur != libc::RLIM_INFINITY {
            return Err("HVF_UNSUPPORTED_INHERITED_CPU_LIMIT: finite RLIMIT_CPU is incompatible with this backend; use limits.cpu_seconds with the supervisor".into());
        }
        for (resource, value) in [
            (libc::RLIMIT_NOFILE, self.open_files),
            (libc::RLIMIT_FSIZE, self.file_size_bytes),
            (libc::RLIMIT_CORE, 0),
        ] {
            let limit = libc::rlimit {
                rlim_cur: value,
                rlim_max: value,
            };
            // SAFETY: valid immutable rlimit; only lowers ceilings in the VMM child.
            if unsafe { libc::setrlimit(resource, &limit) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        // SAFETY: changes only this process; descendants inherit the priority.
        if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, self.nice) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}
pub(crate) fn process(pid: u32) -> Option<libc::proc_taskinfo> {
    let mut info = std::mem::MaybeUninit::<libc::proc_taskinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_taskinfo>() as i32;
    // SAFETY: writable buffer, initialized only when libproc returns its full size.
    if unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTASKINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    } == size
    {
        Some(unsafe { info.assume_init() })
    } else {
        None
    }
}
/// A process of the VM, identified across PID reuse by its start time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Member {
    pub pid: i32,
    pub start: (u64, u64),
}
/// What the supervisor can learn about host processes.
pub(crate) trait Processes {
    /// PIDs in process group `pgid`; None when enumeration failed.
    fn group(&self, pgid: i32) -> Option<Vec<i32>>;
    /// PIDs whose parent is `pid`; None when enumeration failed.
    fn children(&self, pid: i32) -> Option<Vec<i32>>;
    /// Start time of a live process.
    fn start(&self, pid: i32) -> Option<(u64, u64)>;
}
/// More than the VMM, broker and authority could ever be.
const MAX_MEMBERS: usize = 64;
/// The VM's processes. Group membership alone is not enough: a member can
/// leave the leader's group with setpgid. So the set also holds every
/// descendant of the leader and of the group (a process cannot change its
/// parent), and every member seen before that is still the same process (one
/// whose parent exited, reparenting it). None when enumeration failed.
pub(crate) fn members(
    table: &impl Processes,
    leader: i32,
    known: &std::collections::BTreeSet<Member>,
) -> Option<std::collections::BTreeSet<Member>> {
    let mut queue = table.group(leader)?;
    queue.push(leader);
    queue.extend(
        known
            .iter()
            .filter(|m| table.start(m.pid) == Some(m.start))
            .map(|m| m.pid),
    );
    let mut seen = std::collections::BTreeSet::new();
    let mut found = std::collections::BTreeSet::new();
    while let Some(pid) = queue.pop() {
        if pid <= 0 || !seen.insert(pid) {
            continue;
        }
        if seen.len() > MAX_MEMBERS {
            return None;
        }
        let Some(start) = table.start(pid) else {
            continue;
        };
        found.insert(Member { pid, start });
        queue.extend(table.children(pid)?);
    }
    Some(found)
}
/// The host's process table, through libproc.
pub(crate) struct Darwin;
impl Darwin {
    fn list(kind: u32, argument: i32) -> Option<Vec<i32>> {
        let mut pids = [0i32; MAX_MEMBERS];
        let size = std::mem::size_of_val(&pids) as i32;
        // SAFETY: writable buffer of `size` bytes; libproc fills at most that.
        let n =
            unsafe { libc::proc_listpids(kind, argument as u32, pids.as_mut_ptr().cast(), size) };
        if n < 0 || n >= size || n % 4 != 0 {
            return None;
        }
        Some(
            pids[..n as usize / 4]
                .iter()
                .copied()
                .filter(|&p| p > 0)
                .collect(),
        )
    }
}
impl Processes for Darwin {
    fn group(&self, pgid: i32) -> Option<Vec<i32>> {
        // PROC_PGRP_ONLY=2 is the public macOS 26 sys/proc_info.h selector.
        Self::list(2, pgid)
    }
    fn children(&self, pid: i32) -> Option<Vec<i32>> {
        // PROC_PPID_ONLY=6, from the same header.
        Self::list(6, pid)
    }
    fn start(&self, pid: i32) -> Option<(u64, u64)> {
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        // SAFETY: writable buffer, initialized only when libproc returns its full size.
        if unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        } != size
        {
            return None;
        }
        let info = unsafe { info.assume_init() };
        (info.pbi_pid == pid as u32).then_some((info.pbi_start_tvsec, info.pbi_start_tvusec))
    }
}
pub(crate) struct Watchdog {
    /// Every process of the VM seen so far: see `members`.
    members: std::collections::BTreeSet<Member>,
    next: Instant,
    budget: u64,
    cpu_budget: u64,
    ticks: std::collections::BTreeMap<i32, u64>,
    pub cpu_ns: u64,
    pub rss_bytes: u64,
    pub samples: u64,
}
impl Watchdog {
    /// HVF charges resident guest mappings in both host and hypervisor
    /// ledgers on macOS: a fully touched guest can report twice its memory.
    /// Without an explicit rss_mib the budget is that plus another GiB for
    /// the VMM, the broker and transient buffers, and never less than what a
    /// 2 GiB guest gets. An explicit value is enforced without adjustment.
    pub fn new(limits: &Limits, memory_mib: u32) -> Self {
        let rss_mib = limits
            .rss_mib
            .unwrap_or_else(|| (2 * u64::from(memory_mib) + 1024).max(DEFAULT_RSS_FLOOR_MIB));
        Self {
            members: Default::default(),
            next: Instant::now(),
            budget: rss_mib << 20,
            cpu_budget: limits.cpu_seconds * 1_000_000_000,
            ticks: Default::default(),
            cpu_ns: 0,
            rss_bytes: 0,
            samples: 0,
        }
    }
    /// Refreshes the record of the VM's processes. The supervisor holds an
    /// unreaped leader Child while calling this.
    fn track(&mut self, leader: u32) -> bool {
        match members(&Darwin, leader as i32, &self.members) {
            Some(members) => {
                self.members = members;
                true
            }
            None => false,
        }
    }
    /// SIGKILL to every recorded process of the VM other than the leader,
    /// including any that left its process group. Each is checked against its
    /// start time first, so a reused PID is never signalled.
    pub fn kill_members(&mut self, leader: u32) {
        self.track(leader);
        for member in &self.members {
            if member.pid != leader as i32 && Darwin.start(member.pid) == Some(member.start) {
                // SAFETY: plain signal to a process verified to be the recorded one.
                unsafe { libc::kill(member.pid, libc::SIGKILL) };
            }
        }
    }
    /// Whether `pid` is a process of the VM as last recorded. Telemetry from
    /// the VMM (such as the broker PID it reports) is checked against this.
    pub fn is_member(&self, pid: u32) -> bool {
        self.members.iter().any(|m| m.pid == pid as i32)
    }
    // The supervisor holds an unreaped group leader Child while calling this.
    // Kernel enumeration finds broker and authority; telemetry is untrusted.
    pub fn poll(&mut self, leader: u32) -> Option<String> {
        if Instant::now() < self.next {
            return None;
        }
        self.next = Instant::now() + Duration::from_millis(100);
        if !self.track(leader) {
            return Some(
                "RESOURCE_MONITOR_UNAVAILABLE: process enumeration failed or overflowed".into(),
            );
        }
        let pids: Vec<i32> = self.members.iter().map(|m| m.pid).collect();
        let mut rss = 0u64;
        let mut ticks = std::collections::BTreeMap::new();
        let mut delta = 0u64;
        let mut timebase = Timebase { numer: 0, denom: 0 };
        if unsafe { mach_timebase_info(&mut timebase) } != 0 || timebase.denom == 0 {
            return Some("RESOURCE_MONITOR_UNAVAILABLE: clock conversion failed".into());
        }
        for &pid in &pids {
            if let Some(info) = process(pid as u32) {
                rss = rss.saturating_add(info.pti_resident_size);
                let current = info.pti_total_user.saturating_add(info.pti_total_system);
                let previous = self.ticks.get(&pid).copied().unwrap_or(0);
                delta = delta.saturating_add(if current >= previous {
                    current - previous
                } else {
                    current
                });
                ticks.insert(pid, current);
            }
        }
        self.ticks = ticks;
        self.cpu_ns = self.cpu_ns.saturating_add(
            (u128::from(delta) * u128::from(timebase.numer) / u128::from(timebase.denom))
                .min(u128::from(u64::MAX)) as u64,
        );
        self.rss_bytes = rss;
        self.samples += 1;
        if self.cpu_ns >= self.cpu_budget {
            return Some(format!(
                "CPU_LIMIT_EXCEEDED: accumulated sampled group CPU {} ns; budget {} ns (reactive 100 ms sampling)",
                self.cpu_ns, self.cpu_budget
            ));
        }
        (rss>self.budget).then(||format!("RSS_LIMIT_EXCEEDED: process group uses {rss} bytes; budget {} bytes (reactive 100 ms sampling)",self.budget))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsafe_limits() {
        let mut limits = Limits::default();
        limits.validate().unwrap();
        limits.nice = -1;
        assert!(limits.validate().is_err());
        limits.nice = 5;
        limits.open_files = 63;
        assert!(limits.validate().is_err());
        assert!(serde_json::from_str::<Limits>(r#"{"unexpected":1}"#).is_err());
    }

    #[test]
    fn network_limits_are_optional_and_independent() {
        let mut limits = Limits::default();
        assert_eq!(limits.network_bytes_per_second, 0);
        assert_eq!(limits.network_packets_per_second, 0);
        limits.validate().unwrap();
        limits.network_bytes_per_second = 1 << 20;
        limits.validate().unwrap();
        limits.network_bytes_per_second = 0;
        limits.network_packets_per_second = 100;
        limits.validate().unwrap();
        limits.network_packets_per_second = 1000001;
        assert!(limits.validate().is_err());
    }

    #[test]
    fn default_rss_covers_maximum_guest_mappings() {
        let limits = Limits::default();
        assert_eq!(Watchdog::new(&limits, 64).budget, (2 * 2048 + 1024) << 20);
        assert_eq!(Watchdog::new(&limits, 2048).budget, (2 * 2048 + 1024) << 20);
        assert_eq!(Watchdog::new(&limits, 8192).budget, (2 * 8192 + 1024) << 20);
        // The default survives the supervisor's hand-off of the config to the VMM.
        let copy: Limits = serde_json::from_str(&serde_json::to_string(&limits).unwrap()).unwrap();
        assert_eq!(copy.rss_mib, None);
        let explicit: Limits = serde_json::from_str(r#"{"rss_mib":64}"#).unwrap();
        explicit.validate().unwrap();
        assert_eq!(Watchdog::new(&explicit, 8192).budget, 64 << 20);
    }

    /// A process table for `members`: pid -> (parent, group, start).
    struct Table(std::collections::BTreeMap<i32, (i32, i32, u64)>);
    impl Processes for Table {
        fn group(&self, pgid: i32) -> Option<Vec<i32>> {
            Some(
                self.0
                    .iter()
                    .filter(|e| e.1.1 == pgid)
                    .map(|e| *e.0)
                    .collect(),
            )
        }
        fn children(&self, pid: i32) -> Option<Vec<i32>> {
            Some(
                self.0
                    .iter()
                    .filter(|e| e.1.0 == pid)
                    .map(|e| *e.0)
                    .collect(),
            )
        }
        fn start(&self, pid: i32) -> Option<(u64, u64)> {
            self.0.get(&pid).map(|e| (e.2, 0))
        }
    }
    fn pids(set: &std::collections::BTreeSet<Member>) -> Vec<i32> {
        set.iter().map(|m| m.pid).collect()
    }
    #[test]
    fn members_survive_leaving_the_group() {
        // Leader 10 (group 10), broker 11 and authority 12; 99 is unrelated.
        let mut table = Table(
            [
                (10, (1, 10, 5)),
                (11, (10, 10, 6)),
                (12, (11, 10, 7)),
                (99, (1, 99, 8)),
            ]
            .into(),
        );
        let known = members(&table, 10, &Default::default()).unwrap();
        assert_eq!(pids(&known), [10, 11, 12]);
        // The broker leaves the group: still the leader's child.
        table.0.insert(11, (10, 11, 6));
        let known = members(&table, 10, &known).unwrap();
        assert_eq!(pids(&known), [10, 11, 12]);
        // Then its parent dies and it is reparented: still recorded.
        table.0.remove(&10);
        table.0.insert(11, (1, 11, 6));
        table.0.insert(12, (11, 11, 7));
        let known = members(&table, 10, &known).unwrap();
        assert_eq!(pids(&known), [11, 12]);
        // A reused PID is a different process and is dropped.
        table.0.insert(12, (1, 12, 50));
        table.0.insert(11, (1, 11, 51));
        assert!(members(&table, 10, &known).unwrap().is_empty());
    }
    #[test]
    fn members_overflow_is_an_error() {
        let table = Table(
            (10..10 + MAX_MEMBERS as i32 + 1)
                .map(|p| (p, (if p == 10 { 1 } else { p - 1 }, 10, 1)))
                .collect(),
        );
        assert!(members(&table, 10, &Default::default()).is_none());
    }

    #[test]
    fn default_disk_budget_is_above_benchmark_scale() {
        let limits = Limits::default();
        assert_eq!(limits.disk_bytes_per_second, 8 << 30);
        assert_eq!(limits.disk_operations_per_second, 250000);
        limits.validate().unwrap();
    }
}
