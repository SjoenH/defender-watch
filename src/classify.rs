//! What a Defender/Intune unified-log line is *doing*: one kind per shenanigan family,
//! and a stable title so repeats of the same thing collapse into one feed entry.

use rune::Color;
use rune::oklch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The network filter extension drops and re-establishes its nehelper link.
    NetFilter,
    /// The endpoint security extension: heartbeats, mount events.
    Eps,
    /// Login/unlock/authentication packets the EPS extension logs.
    Auth,
    /// The EDR daemon querying OpenDirectory for users and groups.
    Directory,
    /// Telemetry writers (telemetryd_v2, CloudTelemetry).
    Telemetry,
    /// Cloud connectivity: TLS sessions, path checks, beacons.
    Cloud,
    /// Antivirus scans.
    Scan,
    /// Threat detections and handling.
    Threat,
    /// Security intelligence (definitions) updates.
    Definitions,
    /// Device management: Company Portal, SSO extension, MDM check-ins.
    Mdm,
    /// Data loss prevention agents.
    Dlp,
    /// Anything else from a watched process.
    Other,
}

pub const KINDS: usize = 12;

impl Kind {
    pub const ALL: [Kind; KINDS] = [
        Kind::NetFilter, Kind::Eps, Kind::Auth, Kind::Directory, Kind::Telemetry, Kind::Cloud,
        Kind::Scan, Kind::Threat, Kind::Definitions, Kind::Mdm, Kind::Dlp, Kind::Other,
    ];

    pub fn index(self) -> usize { Kind::ALL.iter().position(|k| *k == self).unwrap_or(KINDS - 1) }

    pub fn color(self) -> Color {
        match self {
            Kind::NetFilter => oklch(0.68, 0.16, 60.0),
            Kind::Eps => oklch(0.76, 0.12, 95.0),
            Kind::Auth => oklch(0.65, 0.08, 185.0),
            Kind::Directory => oklch(0.62, 0.14, 300.0),
            Kind::Telemetry => oklch(0.55, 0.15, 270.0),
            Kind::Cloud => oklch(0.62, 0.13, 250.0),
            Kind::Scan => oklch(0.66, 0.13, 145.0),
            Kind::Threat => oklch(0.58, 0.21, 25.0),
            Kind::Definitions => oklch(0.70, 0.10, 205.0),
            Kind::Mdm => oklch(0.62, 0.11, 160.0),
            Kind::Dlp => oklch(0.68, 0.14, 340.0),
            Kind::Other => oklch(0.55, 0.02, 0.0),
        }
    }
}

/// Whether a line of `kind` marks a moment worth a dot in the timeline's events lane,
/// rather than the background chatter its process writes all day.
pub fn is_milestone(kind: Kind, message: &str) -> bool {
    let ml = message.to_lowercase();
    match kind {
        Kind::Threat | Kind::Scan | Kind::Definitions => true,
        Kind::Mdm => ["check-in", "checkin", "check in", "policy", "enroll", "profile install", "profile remov", "compliance"]
            .iter()
            .any(|w| ml.contains(w)),
        _ => false,
    }
}

/// Classify one unified-log line from a watched process. `process` is the executable
/// basename, `subsystem` the log subsystem, `message` the first line of the message.
pub fn classify(process: &str, subsystem: &str, message: &str) -> Kind {
    let m = message;
    let ml = m.to_lowercase();
    let p = process.to_lowercase();

    if ml.contains("threat") || ml.contains("malware") || ml.contains("quarantin")
        || ml.contains("detection") || ml.contains("pua:") || ml.contains("trojan")
    {
        return Kind::Threat;
    }
    if ml.contains("scan") {
        return Kind::Scan;
    }
    // "SecKeyVerifySignature" is routine code-signature checking, not a definitions update.
    if ml.contains("definition") || (ml.contains("signature") && !ml.contains("seckey")) || ml.contains("engine version")
        || ml.contains("security intelligence")
    {
        return Kind::Definitions;
    }
    if ml.contains("dlp") || ml.contains("exfiltration") || ml.contains("sensitive data") {
        return Kind::Dlp;
    }
    if p.contains("epsext") || (subsystem == "mdatp" && p.contains("epsext")) {
        return if ml.contains("heartbeat") { Kind::Eps } else { Kind::Auth };
    }
    if p.contains("netext") || subsystem == "com.apple.networkextension" {
        return Kind::NetFilter;
    }
    if p.contains("telemetryd") || ml.contains("cloudtelemetry") || ml.contains("telemetry") {
        return Kind::Telemetry;
    }
    if p.contains("intune") || p.contains("company portal") || p.contains("single sign on") {
        return Kind::Mdm;
    }
    if p.contains("wdavdaemon_enterprise") || p.contains("mssense") {
        if ml.contains("records from directories") || ml.contains("user group list")
            || ml.contains("given node") || ml.contains("membership api")
            || ml.contains("fetch updated record") || ml.contains("credentials used for node")
            || ml.contains("retrieve group") || ml.contains("translate identifier")
            || ml.contains("directory")
        {
            return Kind::Directory;
        }
        if ml.contains("nehelper") {
            return Kind::NetFilter;
        }
        return Kind::Cloud;
    }
    if p.contains("wdav") {
        if ml.contains("startfilter") || ml.contains("session manager connection") {
            return Kind::NetFilter;
        }
        return Kind::Cloud;
    }
    Kind::Other
}

/// True when the message explicitly says it hurt performance ("Performance impact - ...").
pub fn flags_performance(message: &str) -> bool {
    message.to_lowercase().contains("performance impact")
}

/// A stable collapse key for a message: hex addresses, UUIDs and counters normalised away,
/// so repeats of the same shenanigan collapse onto one feed entry even when a `0x…` address
/// or a `seq=N` differs between lines.
pub fn collapse_key(message: &str) -> String {
    let first = message.lines().next().unwrap_or("").trim();
    let mut key = String::with_capacity(first.len());
    for (i, token) in first.split_whitespace().enumerate() {
        if i > 0 {
            key.push(' ');
        }
        key.push_str(if replace_token(token) { "#" } else { token });
        if key.len() > 90 {
            key.truncate(87);
            key.push('…');
            break;
        }
    }
    if key.is_empty() { "(empty message)".to_owned() } else { key }
}

fn replace_token(token: &str) -> bool {
    // Messages wrap hex addresses in brackets, quotes and commas; compare the core token.
    let token = token.trim_matches(|c: char| "[](){}\",;:'".contains(c));
    if token.starts_with("0x") && token.len() > 4 {
        return true;
    }
    // A UUID or a hex blob with separators: long, mixed hex and dashes.
    if token.len() >= 8 && token.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return true;
    }
    // A bare decimal or hex-looking number of 4+ digits ("seq=1254" already splits on '=',
    // but "|" and other separators do not).
    if token.len() >= 4 && token.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    false
}

/// The feed entry's display title: the message's first line, ellipsised.
pub fn title(message: &str) -> String {
    detail(message)
}

/// Shorten a message for the feed's detail line: first line, ellipsised.
pub fn detail(message: &str) -> String {
    let first = message.lines().next().unwrap_or("").trim();
    if first.chars().count() <= 110 {
        first.to_owned()
    } else {
        let cut = first.chars().take(107).collect::<String>();
        format!("{cut}…")
    }
}

/// True for the kinds that are Defender telling Microsoft something.
pub fn is_snitch(kind: Kind) -> bool {
    matches!(kind, Kind::Telemetry | Kind::Cloud)
}

/// A cloud destination, when the message names one. The unified log privacy-redacts most
/// hostnames to `<private>`, and network-framework logs hash them (`Hostname#f623dd3b:443`);
/// either is still evidence of a call home.
pub fn destination(message: &str) -> Option<String> {
    for token in message.split_whitespace() {
        if let Some((_, rest)) = token.split_once("Hostname#") {
            let host = rest.split([':', ' ', ',']).next().unwrap_or(rest);
            return Some(format!("host#{host} (hashed)"));
        }
        if token.contains("<private>") && (token.contains('.') || message.contains("connect")) {
            return Some("<private> (redacted)".into());
        }
        if token.ends_with("microsoft.com") || token.ends_with("msagmaps.net") || token.ends_with("msftconnecttest.com") {
            return Some(token.trim_end_matches([',', ':']).to_owned());
        }
    }
    None
}

#[cfg(test)]
mod classify_tests {    use super::*;

    #[test]
    fn netext_reinit_is_netfilter() {
        assert_eq!(classify("netext", "com.apple.networkextension",
            "[0x783e86c3c0] Re-initialization successful; calling out to event handler"), Kind::NetFilter);
    }

    #[test]
    fn directory_queries_and_perf_warnings_are_directory() {
        assert_eq!(classify("wdavdaemon_enterprise", "", "Querying records from directories"), Kind::Directory);
        assert_eq!(classify("wdavdaemon_enterprise", "", "Performance impact - Resolve user group list (>17 groups)"), Kind::Directory);
        assert!(flags_performance("Performance impact - Resolve user group list (>17 groups)"));
    }

    #[test]
    fn threats_win_over_scans() {
        assert_eq!(classify("wdavdaemon_unprivileged", "mdatp", "Threat name: Virus:DOS/EICAR_Test_File"), Kind::Threat);
        assert_eq!(classify("wdavdaemon_unprivileged", "mdatp", "Scan task completed"), Kind::Scan);
        assert_ne!(classify("wdavdaemon", "com.apple.securityd", "SecKeyVerifySignature"), Kind::Definitions);
        assert!(is_milestone(Kind::Mdm, "Company Portal check-in completed"));
        assert!(!is_milestone(Kind::Mdm, "Task <1.2> finished successfully"));
    }

    #[test]
    fn eps_heartbeat_and_auth_split() {
        assert_eq!(classify("epsext", "mdatp", "[macevents_eps_heartbeat] - state: 1|0|0|0|0|0|0|0|0"), Kind::Eps);
        assert_eq!(classify("epsext", "mdatp", "[eps_log_auth_login_pkt] - seq=1254|es_type=NOTIFY_AUTHENTICATION|success=1"), Kind::Auth);
    }

    #[test]
    fn collapse_key_merges_addresses_and_counters() {
        let a = collapse_key("[0x783e86c3c0] Re-initialization successful; calling out");
        let b = collapse_key("[0x101fd2dc0] Re-initialization successful; calling out");
        assert_eq!(a, b);
        assert_ne!(collapse_key("seq=1254|success=1"), collapse_key("seq=1255|success=1"));
        assert!(collapse_key("words like added stay").starts_with("words like added"));
    }

    #[test]
    fn destinations_from_hashed_hostnames() {
        assert_eq!(destination("nw_path_libinfo_path_check [BB6654B7 Hostname#f623dd3b:443 tcp]"), Some("host#f623dd3b (hashed)".into()));
        assert_eq!(destination("connect success to settings-win.data.microsoft.com"), Some("settings-win.data.microsoft.com".into()));
        assert_eq!(destination("nothing to see here"), None);
    }

    #[test]
    fn telemetry_and_cloud_snitch() {
        assert!(is_snitch(Kind::Telemetry));
        assert!(is_snitch(Kind::Cloud));
        assert!(!is_snitch(Kind::Scan));
    }
}
