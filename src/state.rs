//! State and the shared store the monitor threads write and `poll` drains.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::classify::{Kind, KINDS};
use crate::managed::Managed;
use crate::timeline::Timeline;

/// CPU samples kept for the chart: 300 at one per second is the past 5 minutes.
pub const SAMPLES: usize = 300;
/// Feed entries kept.
pub const FEED: usize = 140;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Group {
    Defender,
    SysExt,
    Telemetry,
    Dlp,
    Intune,
}

impl Group {
    pub fn color(self) -> rune::Color {
        use rune::oklch;
        match self {
            Group::Defender => oklch(0.62, 0.14, 250.0),
            Group::SysExt => oklch(0.68, 0.16, 60.0),
            Group::Telemetry => oklch(0.55, 0.15, 270.0),
            Group::Dlp => oklch(0.68, 0.14, 340.0),
            Group::Intune => oklch(0.62, 0.11, 160.0),
        }
    }
}

/// The window's pages, in sidebar order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Overview,
    Explore,
    Performance,
    Privacy,
    Protection,
    Management,
    Activity,
}

impl Page {
    pub const ALL: [Page; 7] = [
        Page::Overview, Page::Explore, Page::Performance, Page::Privacy, Page::Protection, Page::Management, Page::Activity,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Page::Overview => "Overview",
            Page::Explore => "Timeline",
            Page::Management => "Management",
            Page::Performance => "Performance",
            Page::Privacy => "Privacy",
            Page::Protection => "Protection",
            Page::Activity => "Activity log",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CpuSample {
    /// The watched family's CPU, in percent of one core.
    pub cpu: f32,
    /// The family's disk read rate, MB/s, since the last sample.
    pub read_mb_s: f32,
    /// The whole system's CPU, percent, for context.
    pub system_cpu: f32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProcRow {
    pub pid: u32,
    pub name: String,
    pub group: Group,
    pub cpu: f32,
    pub mem_mb: f32,
    pub read_mb_s: f32,
    pub write_mb_s: f32,
}

#[derive(Clone, Debug)]
pub struct FeedEvent {
    /// Wall-clock time, "16:30:20", as the system logged it.
    pub t: String,
    pub kind: Kind,
    pub title: String,
    /// The normalised message, for collapsing repeats.
    pub key: String,
    pub detail: String,
    /// How many log lines collapsed into this entry.
    pub count: u64,
    /// The message itself said "Performance impact".
    pub perf: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Health {
    pub app_version: String,
    pub definitions_version: String,
    /// Minutes since the definitions updated.
    pub definitions_age_min: u64,
    pub passive_mode: bool,
    pub cloud_enabled: bool,
    /// What Defender may upload: "safe", "advanced", "none"…
    pub cloud_sample_submission: String,
    pub full_disk_access: bool,
    pub managed_by: String,
    pub healthy: bool,
    pub engine_version: String,
    pub release_ring: String,
    /// "block", "audit", "disabled".
    pub tamper_protection: String,
    pub behavior_monitoring: String,
    pub network_protection: String,
    pub dlp: String,
    pub troubleshooting_mode: bool,
    pub device_tags: Vec<String>,
    /// Where EDR telemetry goes, e.g. "https://winatp-gw-neu.microsoft.com/".
    pub edr_endpoint: String,
    /// The data region the tenant prefers, e.g. "europe".
    pub edr_geo: String,
    pub org_id: String,
    pub machine_id: String,
    /// Which settings the employer pins (the rest the user may change).
    pub managed_settings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Threat {
    pub name: String,
    pub t: String,
    pub status: String,
}

impl Threat {
    /// A behavior detection flags something a process *did* (like a reverse-shell-shaped
    /// command), not a file. Defender reports these to the tenant as alerts, so the
    /// security team sees them — quarantine alone doesn't make them go away.
    pub fn is_behavior(&self) -> bool {
        self.name.starts_with("Behavior:")
    }
}

#[derive(Clone, Debug)]
pub struct ScanInfo {
    pub kind: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Backfill {
    /// Not started (or not macOS).
    None,
    Running { lines: u64 },
    Done { lines: u64 },
}

/// What the monitor threads leave for `poll`. Every field is "the newest answer":
/// `None` means "nothing new", not "nothing".
#[derive(Default)]
pub struct Snapshot {
    pub proc_rows: Option<Vec<ProcRow>>,
    pub new_samples: Vec<CpuSample>,
    pub cpu_seconds: Option<f64>,
    pub peak_cpu: Option<f32>,
    pub events: Vec<FeedEvent>,
    pub live_tallies: Option<[u64; KINDS]>,
    pub history_tallies: Option<[u64; KINDS]>,
    pub backfill: Option<Backfill>,
    pub health: Option<Option<Health>>,
    pub threats: Option<Vec<Threat>>,
    pub scans: Option<Vec<ScanInfo>>,
    /// Destinations Defender called recently, newest last.
    pub destinations: Vec<String>,
    /// New timeline counts since the last drain.
    pub timeline: Timeline,
    pub managed: Option<Managed>,
}

pub struct Store {
    pub dirty: AtomicBool,
    pub inner: Mutex<Snapshot>,
}

impl Default for Store {
    fn default() -> Self {
        Store { dirty: AtomicBool::new(false), inner: Mutex::new(Snapshot::default()) }
    }
}

impl Store {
    pub fn publish(&self, f: impl FnOnce(&mut Snapshot)) {
        let mut snap = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut snap);
        drop(snap);
        self.dirty.store(true, Ordering::Release);
    }
}

pub type State = StateFull;

pub struct StateFull {
    pub demo: bool,
    pub samples: VecDeque<CpuSample>,
    pub procs: Vec<ProcRow>,
    pub events: VecDeque<FeedEvent>,
    /// Since the app opened.
    pub session: [u64; KINDS],
    /// The past 3 hours, from the backfill's `log show`.
    pub history: [u64; KINDS],
    pub live_seen: bool,
    pub backfill: Backfill,
    pub health: Option<Health>,
    pub threats: Vec<Threat>,
    pub scans: Vec<ScanInfo>,
    /// Destinations Defender called recently, newest last.
    pub destinations: VecDeque<String>,
    /// Watched-family CPU-seconds since the app opened.
    pub cpu_seconds: f64,
    pub peak_cpu: f32,
    pub system_cpu: f32,
    pub live_cpu: f32,
    /// The sidebar page on screen.
    pub page: Page,
    pub timeline: Timeline,
    pub managed: Option<Managed>,
    pub explore: Explore,
    /// The Explore chart row's drawn width, points.
    pub explore_w: f32,
}

/// Window lengths the Explore page offers, in minutes.
pub const SPANS: [(i64, &str); 6] = [(15, "15m"), (60, "1h"), (180, "3h"), (360, "6h"), (720, "12h"), (1440, "24h")];

/// The Explore page's own state: which slice of time, which kinds, what's under the pointer.
#[derive(Clone, Debug, PartialEq)]
pub struct Explore {
    /// Window length in minutes while following the live edge.
    pub span: i64,
    /// A fixed window `[from, to)` once zoomed, brushed or panned; `None` follows now.
    pub fixed: Option<(i64, i64)>,
    pub shown: [bool; KINDS],
    pub perf_only: bool,
    /// The pointer over the plot, as a fraction of its width.
    pub hover: Option<f32>,
    /// A drag in progress: start and current fraction.
    pub brush: Option<(f32, f32)>,
    /// The column picked for details, `[from, to)` minutes.
    pub picked: Option<(i64, i64)>,
}

impl Default for Explore {
    fn default() -> Self {
        Explore { span: 180, fixed: None, shown: [true; KINDS], perf_only: false, hover: None, brush: None, picked: None }
    }
}

impl Explore {
    /// The window `[from, to)` in epoch minutes, given the newest minute there is.
    pub fn window(&self, latest: i64) -> (i64, i64) {
        self.fixed.unwrap_or((latest + 1 - self.span, latest + 1))
    }

    /// Zoom by `factor` (<1 zooms in) around `at`, a fraction of the width; never below
    /// 5 minutes or beyond `limit`.
    pub fn zoom(&mut self, latest: i64, at: f32, factor: f32, limit: (i64, i64)) {
        let (from, to) = self.window(latest);
        let span = (to - from) as f32;
        let new_span = (span * factor).clamp(5.0, (limit.1 - limit.0).max(5) as f32);
        let pivot = from as f32 + span * at.clamp(0.0, 1.0);
        let new_from = (pivot - new_span * at.clamp(0.0, 1.0)).round() as i64;
        self.set(new_from, new_from + new_span.round() as i64, limit);
    }

    /// Move the window by `minutes`, kept inside `limit`.
    pub fn pan(&mut self, latest: i64, minutes: i64, limit: (i64, i64)) {
        let (from, to) = self.window(latest);
        self.set(from + minutes, to + minutes, limit);
    }

    /// Fix the window, clamped inside `limit`; touching the live edge follows it again.
    pub fn set(&mut self, from: i64, to: i64, limit: (i64, i64)) {
        let span = (to - from).max(5).min((limit.1 - limit.0).max(5));
        let to = to.min(limit.1).max(limit.0 + span);
        let from = to - span;
        if to >= limit.1 {
            self.fixed = None;
            self.span = span;
        } else {
            self.fixed = Some((from, to));
        }
    }
}

impl StateFull {
    pub fn new(demo: bool) -> Self {
        StateFull {
            demo,
            samples: VecDeque::with_capacity(SAMPLES),
            procs: vec![],
            events: VecDeque::with_capacity(FEED),
            session: [0; KINDS],
            history: [0; KINDS],
            live_seen: false,
            backfill: Backfill::None,
            health: None,
            threats: vec![],
            scans: vec![],
            destinations: VecDeque::with_capacity(12),
            cpu_seconds: 0.0,
            peak_cpu: 0.0,
            system_cpu: 0.0,
            live_cpu: 0.0,
            page: Page::Overview,
            timeline: Timeline::default(),
            managed: None,
            explore: Explore::default(),
            explore_w: 760.0,
        }
    }

    /// Move what arrived into visible state; true when anything visible changed.
    pub fn absorb(&mut self, snap: &mut Snapshot) -> bool {
        let mut changed = false;
        if let Some(rows) = snap.proc_rows.take() {
            if rows != self.procs {
                self.procs = rows;
                changed = true;
            }
        }
        for sample in snap.new_samples.drain(..) {
            self.live_cpu = sample.cpu;
            self.system_cpu = sample.system_cpu;
            if sample.cpu > self.peak_cpu {
                self.peak_cpu = sample.cpu;
            }
            if self.samples.len() >= SAMPLES {
                self.samples.pop_front();
            }
            self.samples.push_back(sample);
            changed = true;
        }
        if let Some(cpu_seconds) = snap.cpu_seconds.take() {
            if (cpu_seconds - self.cpu_seconds).abs() > f64::EPSILON {
                self.cpu_seconds = cpu_seconds;
                changed = true;
            }
        }
        for event in snap.events.drain(..) {
            self.session[event.kind.index()] += event.count.max(1);
            self.live_seen = true;
            if self.events.len() >= FEED {
                self.events.pop_front();
            }
            self.events.push_back(event);
            changed = true;
        }
        if let Some(tallies) = snap.live_tallies.take() {
            self.session = tallies;
            self.live_seen = true;
            changed = true;
        }
        if let Some(tallies) = snap.history_tallies.take() {
            self.history = tallies;
            changed = true;
        }
        if let Some(backfill) = snap.backfill.take() {
            if self.backfill != backfill {
                self.backfill = backfill;
                changed = true;
            }
        }
        if let Some(health) = snap.health.take() {
            self.health = health;
            changed = true;
        }
        if let Some(threats) = snap.threats.take() {
            self.threats = threats;
            changed = true;
        }
        if let Some(scans) = snap.scans.take() {
            self.scans = scans;
            changed = true;
        }
        if !snap.timeline.is_empty() || snap.timeline.offset_min.is_some() {
            self.timeline.merge(std::mem::take(&mut snap.timeline));
            changed = true;
        }
        if let Some(managed) = snap.managed.take() {
            if self.managed.as_ref() != Some(&managed) {
                self.managed = Some(managed);
                changed = true;
            }
        }
        for destination in snap.destinations.drain(..) {
            if self.destinations.back() != Some(&destination) {
                if self.destinations.len() >= 12 {
                    self.destinations.pop_front();
                }
                self.destinations.push_back(destination);
                changed = true;
            }
        }
        changed
    }
}

/// A plausible activity feed for headless verification (`--demo`).
fn demo_events() -> Vec<FeedEvent> {
    use crate::classify::{collapse_key, detail, title};
    let e = |kind: Kind, msg: &str, summary: &str, count: u64, perf: bool| FeedEvent {
        t: "16:29:58".into(),
        kind,
        title: title(msg),
        key: collapse_key(msg),
        detail: detail(summary),
        count,
        perf,
    };
    vec![
        e(Kind::NetFilter, "[0x783e86c3c0] Re-initialization successful; calling out to event handler with XPC_ERROR_CONNECTION_INTERRUPTED", "nehelper connection for delegate class 8 was interrupted", 5803, false),
        e(Kind::Eps, "[macevents_eps_heartbeat] - state: 1|0|0|0|0|0|0|0|0", "endpoint security heartbeat", 903, false),
        e(Kind::Directory, "Performance impact - Resolve user group list (>17 groups)", "wdavdaemon_enterprise resolved >17 directory groups", 46, true),
        e(Kind::Telemetry, "[telemetryd_v2] wrote 12 events to /Library/Logs/Microsoft/mdatp", "EDR telemetry batch", 770, false),
        e(Kind::Cloud, "nw_path_libinfo_path_check [Hostname:443 tcp, legacy-socket, attribution: developer]", "cloud check", 612, false),
        e(Kind::Auth, "[eps_log_auth_login_pkt] - es_type=NOTIFY_AUTHENTICATION|success=1", "logged authentication event", 61, false),
        e(Kind::Mdm, "Company Portal check-in completed", "policy sync", 44, false),
        e(Kind::Threat, "Threat Virus:DOS/EICAR_Test_File quarantined", "detection handled", 1, false),
    ]
}

/// A plausible dataset for headless verification (`--demo`), from real observations on a
/// managed Mac; the header says "demo data" so it is never mistaken for a live reading.
pub fn seed_demo(s: &mut StateFull) {
    s.demo = true;
    // A headless snapshot draws before the chart is measured; this is its width in the
    // default 1000 pt window, so the time axis lines up.
    s.explore_w = 720.0;
    s.health = Some(Health {
        app_version: "101.26092.0012".into(),
        definitions_version: "1.463.368.0".into(),
        definitions_age_min: 526,
        passive_mode: false,
        cloud_enabled: true,
        cloud_sample_submission: "safe".into(),
        full_disk_access: true,
        managed_by: "MDM".into(),
        healthy: true,
        engine_version: "1.1.26100.9000".into(),
        release_ring: "Production".into(),
        tamper_protection: "block".into(),
        behavior_monitoring: "enabled".into(),
        network_protection: "stopped".into(),
        dlp: "disabled".into(),
        troubleshooting_mode: false,
        device_tags: vec![],
        edr_endpoint: "https://winatp-gw-neu.microsoft.com/".into(),
        edr_geo: "europe".into(),
        org_id: "00000000-demo-0000-0000-000000000000".into(),
        machine_id: "demo0000machine0000id".into(),
        managed_settings: vec!["cloud protection".into(), "sample submission".into(), "real-time protection".into(), "passive mode".into()],
    });
    s.managed = Some(demo_managed());
    s.timeline = demo_timeline();
    s.threats = vec![
        // EICAR is the harmless file every antivirus treats as a test detection.
        Threat { name: "Virus:DOS/EICAR_Test_File".into(), t: "Nov 19 20:25".into(), status: "quarantined".into() },
    ];
    let row = |pid: u32, name: &str, group: Group, cpu: f32, mem: f32| ProcRow {
        pid, name: name.into(), group, cpu, mem_mb: mem, read_mb_s: 0.0, write_mb_s: 0.0,
    };
    s.procs = vec![
        row(592, "wdavdaemon (privileged)", Group::Defender, 1.2, 148.0),
        row(723, "wdavdaemon_enterprise (EDR)", Group::Defender, 2.8, 96.0),
        row(746, "telemetryd_v2", Group::Telemetry, 0.9, 54.0),
        row(81429, "wdavdaemon_unprivileged", Group::Defender, 0.4, 41.0),
        row(613, "epsext", Group::SysExt, 0.3, 28.0),
        row(656, "netext", Group::SysExt, 0.2, 22.0),
    ];
    for i in 0..SAMPLES {
        let t = i as f32 / 60.0;
        let spike = if i % 97 == 0 { 9.0 } else { 0.0 };
        let cpu = 3.5 + 2.5 * (t * 0.35).sin() + spike;
        s.samples.push_back(CpuSample { cpu, read_mb_s: 0.5 + 0.4 * (t * 0.5).cos().abs(), system_cpu: cpu * 4.0 });
    }
    s.peak_cpu = 14.0;
    s.live_cpu = 5.8;
    s.system_cpu = 23.0;
    s.cpu_seconds = 1847.0;
    let mut tallies = [0u64; KINDS];
    tallies[Kind::NetFilter.index()] = 5803;
    tallies[Kind::Eps.index()] = 903;
    tallies[Kind::Directory.index()] = 631;
    tallies[Kind::Telemetry.index()] = 770;
    tallies[Kind::Cloud.index()] = 612;
    tallies[Kind::Auth.index()] = 61;
    tallies[Kind::Mdm.index()] = 44;
    tallies[Kind::Scan.index()] = 2;
    tallies[Kind::Threat.index()] = 2;
    tallies[Kind::Definitions.index()] = 1;
    s.history = tallies;
    s.session = [0; KINDS];
    s.backfill = Backfill::Done { lines: 146_606 };
    s.events = demo_events().into();
    s.destinations = [
        "host#f623dd3b (hashed)".to_owned(),
        "host#9b21c40a (hashed)".to_owned(),
        "<private> (redacted)".to_owned(),
    ].into();
    s.peak_cpu = s.samples.iter().map(|x| x.cpu).fold(0.0f32, f32::max);
}

/// A managed Mac as Intune sets one up: the profiles and what they allow.
fn demo_managed() -> Managed {
    use crate::managed::{Enrollment, Profile};
    let p = |name: &str, payloads: &[&str]| Profile {
        name: name.into(),
        source: "MDM".into(),
        locked: true,
        installed: "2026-10-23".into(),
        payloads: payloads.iter().map(|s| (*s).to_owned()).collect(),
    };
    let mut mgmt = p("Management Profile", &["com.apple.mdm", "com.apple.security.root", "com.apple.security.root", "com.apple.security.acme"]);
    mgmt.source = "Manual".into();
    mgmt.locked = false;
    let profiles = vec![
        mgmt,
        p("Defender for Endpoint onboarding for macOS", &["com.microsoft.wdav.atp"]),
        p("com.microsoft.wdav", &["com.microsoft.wdav"]),
        p("fulldisk.mobileconfig", &["com.apple.TCC.configuration-profile-policy"]),
        p("netfilter.mobileconfig", &["com.apple.webcontent-filter"]),
        p("System Extension Profile", &["com.apple.system-extension-policy"]),
        p("FileVault Profile", &["com.apple.MCX.FileVault2"]),
        p("FileVault Escrow Profile", &["com.apple.security.FDERecoveryKeyEscrow", "com.apple.security.pkcs1"]),
        p("Extensible Single Sign On Profile", &["com.apple.extensiblesso"]),
        p("Credential Profile", &["com.apple.security.root"]),
        p("background_services.mobileconfig", &["com.apple.servicemanagement"]),
        p("Firewall Profile", &["com.apple.security.firewall"]),
        p("notif.mobileconfig", &["com.apple.notificationsettings"]),
        p("com.microsoft.autoupdate2", &["com.microsoft.autoupdate2"]),
    ];
    let prefs: std::collections::BTreeMap<String, serde_json::Value> = [
        ("com.apple.TCC.configuration-profile-policy", serde_json::json!({"Services": {"SystemPolicyAllFiles": [
            {"Allowed": 1, "Identifier": "com.microsoft.wdav"}, {"Allowed": 1, "Identifier": "com.microsoft.wdav.epsext"}]}})),
        ("com.apple.system-extension-policy", serde_json::json!({"AllowedSystemExtensions": {"UBF8T346G9": ["com.microsoft.wdav.epsext", "com.microsoft.wdav.netext"]}})),
        ("com.apple.extensiblesso", serde_json::json!({"URLs": ["https://login.microsoftonline.com", "https://login.microsoft.com"]})),
        ("com.microsoft.wdav", serde_json::json!({"cloudService": {"enabled": true, "automaticSampleSubmission": true}, "antivirusEngine": {"enableRealTimeProtection": true}})),
        ("com.microsoft.wdav.atp", serde_json::json!({"AllowUserOverrides": true})),
        ("com.apple.servicemanagement", serde_json::json!({"Rules": [{"RuleValue": "com.microsoft.fresno"}, {"RuleValue": "com.microsoft.dlp"}]})),
        ("com.microsoft.autoupdate2", serde_json::json!({"SendAllTelemetryEnabled": true})),
        ("com.apple.notificationsettings", serde_json::json!({"NotificationSettings": [{"BundleIdentifier": "com.microsoft.wdav.tray"}, {"BundleIdentifier": "com.microsoft.autoupdate2"}]})),
    ].into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
    let enrollment = Enrollment { enrolled: true, server: "i.manage.microsoft.com".into(), dep: false };
    Managed::from_parts(enrollment, profiles, &prefs)
}

/// 24 plausible hours: a quiet night, a working day with bursts, a directory-lookup storm,
/// a behavior detection, and CPU for the last hour the app was open.
fn demo_timeline() -> Timeline {
    // A fixed "now" (Fri 20.11.2026 17:00 CET) keeps snapshots identical between runs.
    let now = 29_918_880i64 + 16 * 60;
    let mut tl = Timeline { offset_min: Some(60), ..Timeline::default() };
    let mut seed = 0x2545_f491u32;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        (seed % 1000) as f32 / 1000.0
    };
    let msgs: [(Kind, &str, &str); 8] = [
        (Kind::NetFilter, "netext", "[0x783e86c3c0] Re-initialization successful; calling out to event handler"),
        (Kind::Eps, "epsext", "[macevents_eps_heartbeat] - state: 1|0|0|0|0|0|0|0|0"),
        (Kind::Telemetry, "telemetryd_v2", "[telemetryd_v2] wrote 12 events to /Library/Logs/Microsoft/mdatp"),
        (Kind::Cloud, "wdavdaemon_enterprise", "nw_path_libinfo_path_check [Hostname#f623dd3b:443 tcp]"),
        (Kind::Directory, "wdavdaemon_enterprise", "Performance impact - Resolve user group list (>17 groups)"),
        (Kind::Auth, "epsext", "[eps_log_auth_login_pkt] - es_type=NOTIFY_AUTHENTICATION|success=1"),
        (Kind::Mdm, "Company Portal", "Company Portal check-in completed"),
        (Kind::Scan, "wdavdaemon_unprivileged", "Scan task completed"),
    ];
    for m in (now - 1440)..now {
        let local_hour = ((m + 60).rem_euclid(1440)) / 60;
        let day = (8..18).contains(&local_hour);
        let activity = if day { 1.0 } else { 0.25 };
        for (kind, process, msg) in msgs {
            let rate = match kind {
                Kind::NetFilter => 9.0 * activity,
                Kind::Eps => 1.0,
                Kind::Telemetry => 2.2 * activity,
                Kind::Cloud => 1.8 * activity,
                Kind::Directory => if (now - 400..now - 370).contains(&m) { 14.0 } else { 0.15 * activity },
                Kind::Auth => if day { 0.12 } else { 0.01 },
                Kind::Mdm => if m % 480 == 0 { 3.0 } else { 0.0 },
                Kind::Scan => if m == now - 900 { 2.0 } else { 0.0 },
                _ => 0.0,
            };
            let n = (rate * (0.4 + 1.2 * rnd())).round() as u32;
            let clock = tl.clock(m);
            for _ in 0..n {
                let perf = crate::classify::flags_performance(msg);
                tl.add(m, kind, perf, &format!("{clock}:{:02}", (rnd() * 59.0) as u32), process, msg, &crate::classify::collapse_key(msg));
            }
        }
    }
    let threat = now - 19 * 60 - 35;
    let msg = "Threat Virus:DOS/EICAR_Test_File quarantined";
    tl.add(threat, Kind::Threat, false, &format!("{}:37", tl.clock(threat)), "wdavdaemon_unprivileged", msg, msg);
    tl.add(now - 200, Kind::Definitions, false, "13:40:12", "wdavdaemon", "Security intelligence updated to 1.463.386.0", "defs");
    for m in (now - 60)..now {
        for s in 0..60 {
            let t = (m * 60 + s) as f32 / 60.0;
            let spike = if (m - (now - 22)).abs() < 2 { 18.0 } else { 0.0 };
            let cpu = 3.5 + 2.5 * (t * 0.35).sin() + spike * rnd();
            tl.add_cpu(m, cpu, cpu * 4.0);
        }
    }
    tl
}
