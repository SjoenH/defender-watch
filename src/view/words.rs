//! Plain language: what the readings mean for someone who doesn't read logs. Pure functions,
//! so the wording is testable without drawing anything.

use rune::{Color, oklch};

use crate::classify::Kind;
use crate::state::State;

/// Apple Silicon draws roughly 3–4 W per active P-core; the estimate picks the middle and
/// says so. A 70 Wh pack is a typical 14-inch MacBook Pro.
pub const WATTS_PER_CORE: f32 = 3.5;
pub const BATTERY_WH: f32 = 70.0;
/// The backfill window, for "how often" phrasing.
pub const HISTORY_HOURS: f32 = 3.0;
/// Definitions older than this are worth a warning.
const STALE_DEFINITIONS_MIN: u64 = 3 * 24 * 60;

/// Traffic-light hues, used with an icon or a word, never alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Neutral,
}

impl Tone {
    pub fn color(self) -> Color {
        match self {
            Tone::Good => oklch(0.68, 0.15, 145.0),
            Tone::Warn => oklch(0.74, 0.14, 70.0),
            Tone::Bad => oklch(0.62, 0.19, 25.0),
            Tone::Neutral => oklch(0.64, 0.12, 250.0),
        }
    }
}

/// How much Defender is weighing on the Mac right now, from its CPU (percent of one core).
pub fn impact(cpu: f32) -> (&'static str, Tone) {
    if cpu < 5.0 {
        ("Not much", Tone::Good)
    } else if cpu < 15.0 {
        ("A little", Tone::Good)
    } else if cpu < 40.0 {
        ("Quite a bit", Tone::Warn)
    } else {
        ("A lot", Tone::Bad)
    }
}

/// Battery percent an hour at `cpu` percent of one core.
pub fn battery_per_hour(cpu: f32) -> f32 {
    cpu / 100.0 * WATTS_PER_CORE / BATTERY_WH * 100.0
}

/// What the page header and tiles say, computed once per frame.
pub struct Reading {
    pub impact: &'static str,
    pub impact_tone: Tone,
    /// "Using 5.8% of one core — about 0.3% of your battery an hour."
    pub impact_line: String,
    pub battery_per_hour: f32,
    /// Telemetry batches, past 3 h plus this session.
    pub reports: u64,
    /// Cloud calls, past 3 h plus this session.
    pub calls: u64,
    pub threats: usize,
    pub behavior_alerts: usize,
    /// `None` until `mdatp health` answers.
    pub protected: Option<bool>,
    pub problems: Vec<&'static str>,
}

impl Reading {
    pub fn of(s: &State) -> Reading {
        let (impact, impact_tone) = impact(s.live_cpu);
        let battery = battery_per_hour(s.live_cpu);
        Reading {
            impact,
            impact_tone,
            impact_line: format!(
                "Using {:.1}% of one processor core — about {:.1}% of your battery an hour.",
                s.live_cpu, battery,
            ),
            battery_per_hour: battery,
            reports: total(s, Kind::Telemetry),
            calls: total(s, Kind::Cloud),
            threats: s.threats.len(),
            behavior_alerts: s.threats.iter().filter(|t| t.is_behavior()).count(),
            protected: s.health.as_ref().map(|h| h.healthy && !h.passive_mode),
            problems: problems(s),
        }
    }
}

/// Past 3 hours plus this session.
pub fn total(s: &State, kind: Kind) -> u64 {
    s.history[kind.index()] + s.session[kind.index()]
}

fn problems(s: &State) -> Vec<&'static str> {
    let Some(h) = &s.health else { return vec![] };
    let mut p = vec![];
    if !h.healthy {
        p.push("Defender reports a health problem");
    }
    if h.passive_mode {
        p.push("Real-time protection is in passive mode");
    }
    if !h.full_disk_access {
        p.push("Defender is missing Full Disk Access");
    }
    if h.definitions_age_min > STALE_DEFINITIONS_MIN {
        p.push("Threat definitions are more than 3 days old");
    }
    p
}

pub fn definitions_fresh(age_min: u64) -> bool {
    age_min <= STALE_DEFINITIONS_MIN
}

/// What a kind of activity is, as a sentence.
pub fn doing(kind: Kind) -> &'static str {
    match kind {
        Kind::NetFilter => "Its network filter lost its connection and reconnected",
        Kind::Eps => "Recorded what happens on your Mac (files, apps)",
        Kind::Auth => "Recorded a login or unlock",
        Kind::Directory => "Looked up your user account and groups",
        Kind::Telemetry => "Sent a batch of telemetry to Microsoft",
        Kind::Cloud => "Checked in with Microsoft's cloud",
        Kind::Scan => "Scanned for malware",
        Kind::Threat => "Flagged something as suspicious",
        Kind::Definitions => "Updated its malware definitions",
        Kind::Mdm => "Checked in with IT (Intune policy sync)",
        Kind::Dlp => "Checked for sensitive data leaving the Mac",
        Kind::Other => "Other background work",
    }
}

/// A human name for a watched process.
pub fn process_name(name: &str) -> &'static str {
    let n = name.to_lowercase();
    if n.contains("wdavdaemon_enterprise") {
        "Corporate reporting (EDR)"
    } else if n.contains("wdavdaemon_unprivileged") {
        "File scanner"
    } else if n.contains("wdavdaemon") {
        "Antivirus engine"
    } else if n.contains("telemetryd") {
        "Telemetry writer"
    } else if n.contains("epsext") {
        "Activity recorder"
    } else if n.contains("netext") {
        "Network filter"
    } else if n.contains("dlp") {
        "Data-loss prevention"
    } else if n.contains("intune") || n.contains("company") || n.contains("single sign") {
        "Company Portal (IT sync)"
    } else if n.contains("mssense") {
        "Defender core"
    } else {
        "Defender helper"
    }
}

/// 5 803 events in 3 h → "about every 2 s".
pub fn rate(n: u64) -> String {
    if n == 0 {
        return String::new();
    }
    let secs = HISTORY_HOURS * 3600.0 / n as f32;
    if secs < 5.0 {
        "almost constantly".to_owned()
    } else if secs < 90.0 {
        format!("about every {} s", secs.round() as u64)
    } else if secs < 5400.0 {
        format!("about every {} min", (secs / 60.0).round() as u64)
    } else if n == 1 {
        "once".to_owned()
    } else if n == 2 {
        "twice".to_owned()
    } else {
        format!("{} times", count(n))
    }
}

/// The sample-submission policy, as what may leave the Mac.
pub fn upload_policy(setting: &str) -> &'static str {
    match setting {
        "safe" => "files it finds suspicious (programs, not documents)",
        "advanced" => "files it finds suspicious, including documents",
        "none" => "nothing automatically",
        _ => "files it finds suspicious",
    }
}

pub fn scan_kind(kind: &str) -> &'static str {
    let k = kind.to_lowercase();
    if k.contains("quick") {
        "a quick sweep of likely hiding spots"
    } else if k.contains("full") || k.contains("custom") {
        "a full sweep of every file"
    } else {
        "a sweep of files"
    }
}

pub fn age(minutes: u64) -> String {
    if minutes < 90 {
        format!("{minutes} min ago")
    } else if minutes < 48 * 60 {
        format!("{} h ago", minutes / 60)
    } else {
        format!("{} days ago", minutes / (24 * 60))
    }
}

/// 1382 → "1,382".
pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, d) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(d);
    }
    grouped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impact_bands() {
        assert_eq!(impact(0.0), ("Not much", Tone::Good));
        assert_eq!(impact(5.0).0, "A little");
        assert_eq!(impact(15.0), ("Quite a bit", Tone::Warn));
        assert_eq!(impact(80.0), ("A lot", Tone::Bad));
    }

    #[test]
    fn battery_is_watts_over_pack() {
        // A full core at 3.5 W from 70 Wh is 5% an hour.
        assert!((battery_per_hour(100.0) - 5.0).abs() < 1e-4);
    }

    #[test]
    fn rates_read_naturally() {
        assert_eq!(rate(0), "");
        assert_eq!(rate(5803), "almost constantly");
        assert_eq!(rate(903), "about every 12 s");
        assert_eq!(rate(44), "about every 4 min");
        assert_eq!(rate(1), "once");
        assert_eq!(rate(2), "twice");
    }

    #[test]
    fn counts_group_thousands() {
        assert_eq!(count(0), "0");
        assert_eq!(count(999), "999");
        assert_eq!(count(1382), "1,382");
        assert_eq!(count(146_606), "146,606");
    }

    #[test]
    fn process_names() {
        assert_eq!(process_name("wdavdaemon_enterprise (EDR)"), "Corporate reporting (EDR)");
        assert_eq!(process_name("wdavdaemon_unprivileged"), "File scanner");
        assert_eq!(process_name("wdavdaemon (privileged)"), "Antivirus engine");
        assert_eq!(process_name("epsext"), "Activity recorder");
    }

    #[test]
    fn ages() {
        assert_eq!(age(5), "5 min ago");
        assert_eq!(age(526), "8 h ago");
        assert_eq!(age(5000), "3 days ago");
    }
}
