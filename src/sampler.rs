//! The one-second sampler: watches every Defender/Intune process's CPU, memory and disk I/O
//! with `sysinfo`, keeps a rolling sample ring, and now and then asks `mdatp` for scans,
//! threats and health.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sysinfo::{ProcessesToUpdate, System};

use crate::state::{CpuSample, Group, ProcRow, Snapshot, Store};

/// One sample per second.
const TICK: Duration = Duration::from_secs(1);
/// Ask `mdatp scan list` every minute.
const SCAN_EVERY: u64 = 60;
/// Ask `mdatp threat list` every five minutes.
const THREAT_EVERY: u64 = 300;

/// The executable basenames (or paths) that belong to the watched family, in match order.
const WATCHED: &[(&str, Group)] = &[
    ("telemetryd_v2", Group::Telemetry),
    ("dlp_agent", Group::Dlp),
    ("dlp_processor", Group::Dlp),
    ("mssense", Group::Defender),
    ("wdavdaemon_enterprise", Group::Defender),
    ("wdavdaemon_unprivileged", Group::Defender),
    ("wdavdaemon", Group::Defender),
    ("com.microsoft.wdav.epsext", Group::SysExt),
    ("com.microsoft.wdav.netext", Group::SysExt),
    ("epsext", Group::SysExt),
    ("netext", Group::SysExt),
    ("microsoft defender", Group::Defender),
    ("intunemdm", Group::Intune),
    ("intune", Group::Intune),
    ("company portal", Group::Intune),
    ("single sign on", Group::Intune),
];

/// What a process at `path_or_name` (lowercased) belongs to, if anything.
pub fn group_of(path_or_name: &str) -> Option<(String, Group)> {
    for (needle, group) in WATCHED {
        if path_or_name.contains(needle) {
            let mut name = basename(path_or_name);
            if path_or_name.contains("unprivileged") {
                name.push_str(" (unprivileged)");
            } else if path_or_name.contains("privileged") {
                name.push_str(" (privileged)");
            } else if needle.contains("enterprise") {
                name.push_str(" (EDR)");
            }
            return Some((name, *group));
        }
    }
    None
}

/// The last path component, minus a `.app` suffix when it is a bundle executable.
pub fn basename(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.split(' ').next().unwrap_or(name).to_owned()
}

/// Read what device management has installed every ten minutes.
const MANAGED_EVERY: u64 = 600;

enum Ask {
    Health,
    Scans,
    Threats,
    Managed,
}

pub fn run(store: Arc<Store>, wake: rune::Waker) {
    let Ok(mut sys) = System::new() else { return };
    // The first refresh establishes CPU baselines; discard it.
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut last = Instant::now();
    let mut cpu_seconds = 0.0f64;
    let mut peak = 0.0f32;
    let mut tick = 0u64;
    loop {
        std::thread::sleep(TICK);
        sys.refresh_cpu_usage();
        sys.refresh_processes(ProcessesToUpdate::All, true);
        let dt = last.elapsed().as_secs_f64();
        last = Instant::now();
        tick += 1;

        let mut rows: Vec<ProcRow> = vec![];
        let mut cpu = 0.0f32;
        let mut read = 0.0f32;
        for (pid, proc_) in sys.processes() {
            let exe = proc_.exe().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
            let name = proc_.name().to_string_lossy().to_lowercase();
            let Some((name, group)) = group_of(&format!("{exe} {name}")) else { continue };
            let usage = proc_.disk_usage();
            cpu += proc_.cpu_usage();
            read += usage.read_bytes as f32 / 1_048_576.0;
            rows.push(ProcRow {
                pid: pid.as_u32(),
                name,
                group,
                cpu: proc_.cpu_usage(),
                mem_mb: proc_.memory() as f32 / 1_048_576.0,
                read_mb_s: usage.read_bytes as f32 / 1_048_576.0,
                write_mb_s: usage.written_bytes as f32 / 1_048_576.0,
            });
        }
        cpu_seconds += cpu as f64 * dt / 100.0;
        if cpu > peak {
            peak = cpu;
        }
        let system = sys.global_cpu_usage();
        rows.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(b.mem_mb.total_cmp(&a.mem_mb)));

        let minute = crate::timeline::now_minute();
        store.publish(|snap: &mut Snapshot| {
            snap.timeline.add_cpu(minute, cpu, system);
            snap.proc_rows = Some(rows);
            snap.new_samples.push(CpuSample { cpu, read_mb_s: read, system_cpu: system });
            snap.cpu_seconds = Some(cpu_seconds);
            snap.peak_cpu = Some(peak);
        });
        wake();

        // `mdatp` asks are quick but not instant; do them on their own thread so the
        // sampling cadence stays even.
        if tick == 1 {
            ask(&store, wake.clone(), Ask::Health);
        } else if tick == 2 || tick % MANAGED_EVERY == 0 {
            ask(&store, wake.clone(), Ask::Managed);
        } else if tick % SCAN_EVERY == 0 {
            ask(&store, wake.clone(), Ask::Scans);
        } else if tick % THREAT_EVERY == 0 {
            ask(&store, wake.clone(), Ask::Threats);
        }
    }
}

fn ask(store: &Arc<Store>, wake: rune::Waker, what: Ask) {
    let store = store.clone();
    std::thread::spawn(move || {
        let mdfgatp = crate::mdatp::Mdatp;
        let mut answer = Snapshot::default();
        match what {
            Ask::Health => answer.health = Some(mdfgatp.health()),
            Ask::Scans => answer.scans = Some(mdfgatp.scans()),
            Ask::Threats => answer.threats = Some(mdfgatp.threats()),
            Ask::Managed => answer.managed = crate::managed::read(),
        }
        store.publish(|snap| merge(snap, &mut answer));
        wake();
    });
}

fn merge(snap: &mut Snapshot, answer: &mut Snapshot) {
    if answer.health.is_some() { snap.health = answer.health.take(); }
    if answer.threats.is_some() { snap.threats = answer.threats.take(); }
    if answer.scans.is_some() { snap.scans = answer.scans.take(); }
    if answer.managed.is_some() { snap.managed = answer.managed.take(); }
}
