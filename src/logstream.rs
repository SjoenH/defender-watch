//! The unified log: a live `log stream` for the feed, and a one-shot `log show --last 24h`
//! backfill for the timeline and the "past 3 hours" tallies.

use std::io::BufRead;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::classify;
use crate::state::{Backfill, FeedEvent, Snapshot, Store};
use crate::timeline::{Timeline, parse_log_time};

/// How far back the backfill reads.
const BACKFILL: &str = "24h";
/// The tallies on Overview and Privacy cover this many minutes.
const TALLY_MIN: i64 = 3 * 60;

/// Which processes we watch, as a `log` predicate.
const PREDICATE: &str = "process CONTAINS[c] \"wdav\" \
    OR process CONTAINS[c] \"epsext\" OR process CONTAINS[c] \"netext\" \
    OR process CONTAINS[c] \"telemetryd\" OR process CONTAINS[c] \"intune\" \
    OR process CONTAINS[c] \"company\" OR process CONTAINS[c] \"dlp\" \
    OR process CONTAINS[c] \"mssense\" OR process CONTAINS[c] \"Single Sign on\"";

/// The live stream's child process, killed at shutdown so it doesn't outlive the app.
static STREAM: Mutex<Option<Child>> = Mutex::new(None);

/// Kill the `log stream` child; call once `run` has returned.
pub fn shutdown() {
    if let Ok(mut slot) = STREAM.lock() {
        if let Some(child) = slot.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        *slot = None;
    }
}

/// Follow the log live, classify each line, keep the feed's tail and the live tallies.
pub fn run(store: Arc<Store>, wake: rune::Waker) {
    let Ok(mut child) = Command::new("/usr/bin/log")
        .args(["stream", "--style", "ndjson", "--predicate", PREDICATE])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    let stdout = child.stdout.take();
    if let Ok(mut slot) = STREAM.lock() {
        *slot = Some(child);
    }
    let Some(stdout) = stdout else { return };
    let mut tallies = [0u64; crate::classify::KINDS];
    let reader = std::io::BufReader::new(stdout);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let Some(entry) = Entry::parse(&line) else { continue };
        let kind = classify::classify(&entry.process, &entry.subsystem, &entry.message);
        tallies[kind.index()] += 1;
        let title = classify::title(&entry.message);
        let detail = classify::detail(&entry.message);
        let perf = classify::flags_performance(&entry.message);
        let t = entry.t.clone();
        let key = classify::collapse_key(&entry.message);
        let mut delta = Timeline::default();
        if let Some((minute, offset, clock)) = parse_log_time(&entry.ts) {
            delta.offset_min = Some(offset);
            delta.add(minute, kind, perf, &clock, &entry.process, &classify::detail(&entry.message), &key);
        }
        let kind2 = kind;
        let destination = if classify::is_snitch(kind2) { classify::destination(&entry.message) } else { None };
        store.publish(|snap| {
            snap.timeline.merge(delta);
            snap.live_tallies = Some(tallies);
            if let Some(destination) = destination {
                snap.destinations.push(destination);
                if snap.destinations.len() > 12 {
                    snap.destinations.remove(0);
                }
            }
            push_event(snap, FeedEvent { t, kind, title, key, detail, count: 1, perf });
        });
        wake();
    }
}

/// One event in the feed, collapsed onto its neighbour when it repeats.
fn push_event(snap: &mut Snapshot, mut event: FeedEvent) {
    if let Some(last) = snap.events.last_mut() {
        if last.kind == event.kind && last.key == event.key {
            last.count += event.count.max(1);
            last.t = event.t.clone();
            last.detail = event.detail.clone();
            last.perf |= event.perf;
            return;
        }
    }
    event.key.clear();
    snap.events.push(event);
    if snap.events.len() > crate::state::FEED {
        snap.events.remove(0);
    }
}

/// Read the log's past 24 hours into the timeline, and count the past 3 hours by kind;
/// the feed only starts at launch, so history only adds to the tallies.
pub fn run_backfill(store: Arc<Store>, wake: rune::Waker) {
    let Ok(mut child) = Command::new("/usr/bin/log")
        .args(["show", "--last", BACKFILL, "--style", "ndjson", "--predicate", PREDICATE])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    let Some(stdout) = child.stdout.take() else { return };
    store.publish(|snap| snap.backfill = Some(Backfill::Running { lines: 0 }));
    wake();

    let since = crate::timeline::now_minute() - TALLY_MIN;
    let reader = std::io::BufReader::new(stdout);
    let mut tallies = [0u64; crate::classify::KINDS];
    let mut batch = Timeline::default();
    let mut lines = 0u64;
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let Some(entry) = Entry::parse(&line) else { continue };
        let kind = classify::classify(&entry.process, &entry.subsystem, &entry.message);
        if let Some((minute, offset, clock)) = parse_log_time(&entry.ts) {
            batch.offset_min = Some(offset);
            let perf = classify::flags_performance(&entry.message);
            batch.add(minute, kind, perf, &clock, &entry.process, &classify::detail(&entry.message), &classify::collapse_key(&entry.message));
            if minute >= since {
                tallies[kind.index()] += 1;
            }
        }
        lines += 1;
        // Stream as it grows, so the pages start talking early.
        if lines % 8_000 == 0 {
            let t = tallies;
            let b = std::mem::take(&mut batch);
            store.publish(|snap| {
                snap.timeline.merge(b);
                snap.history_tallies = Some(t);
                snap.backfill = Some(Backfill::Running { lines });
            });
            wake();
        }
    }
    let t = tallies;
    store.publish(|snap| {
        snap.timeline.merge(batch);
        snap.history_tallies = Some(t);
        snap.backfill = Some(Backfill::Done { lines });
    });
    wake();
}

/// One parsed unified-log line, trimmed to what classification needs.
struct Entry {
    process: String,
    subsystem: String,
    message: String,
    /// The system's own timestamp, "16:30:20".
    t: String,
    /// The whole timestamp, "2026-11-20 16:30:20.123456+0100".
    ts: String,
}

impl Entry {
    fn parse(line: &str) -> Option<Entry> {
        let value: Value = serde_json::from_str(line).ok()?;
        let process = value["processImagePath"].as_str()?;
        let process = process.rsplit('/').next().unwrap_or(process).to_owned();
        let subsystem = value["subsystem"].as_str().unwrap_or("").to_owned();
        let message = value["eventMessage"].as_str().unwrap_or("").to_owned();
        let ts = value["timestamp"].as_str().unwrap_or("").to_owned();
        let t = ts.get(11..19).map(|s| s.to_owned()).unwrap_or_default();
        Some(Entry { process, subsystem, message, t, ts })
    }
}
