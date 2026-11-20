//! The timeline behind the Explore page: every watched log line counted into its minute by
//! kind, a few example messages per minute and kind for drilling in, and the family's CPU
//! per minute while the app is open.
//!
//! Minutes are UTC epoch minutes; `offset_min` (from the log's own timestamps) turns them
//! into the Mac's local clock for labels.

use std::collections::BTreeMap;

use crate::classify::{KINDS, Kind};

/// Distinct messages kept per minute and kind; repeats of one only bump its count.
pub const LINES_PER_CELL: usize = 6;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Bucket {
    pub kinds: [u32; KINDS],
    /// Lines whose own text said "Performance impact".
    pub perf: u32,
    /// Bit per kind: a line that marks a real event (see `classify::is_milestone`).
    pub marks: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Line {
    /// "16:30:20", local.
    pub t: String,
    pub process: String,
    pub message: String,
    /// The collapse key, so repeats merge.
    pub key: String,
    pub count: u32,
    pub perf: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CpuMinute {
    pub sum: f32,
    pub max: f32,
    pub system_sum: f32,
    pub n: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Timeline {
    pub buckets: BTreeMap<i64, Bucket>,
    pub lines: BTreeMap<(i64, usize), Vec<Line>>,
    pub cpu: BTreeMap<i64, CpuMinute>,
    /// Local time minus UTC, in minutes.
    pub offset_min: Option<i32>,
}

/// One drawn column: `minutes` minutes from `start`, summed.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Bin {
    pub start: i64,
    pub minutes: i64,
    pub kinds: [u32; KINDS],
    pub perf: u32,
    /// Bit per kind, as in `Bucket::marks`.
    pub marks: u32,
    pub cpu_avg: Option<f32>,
    pub cpu_max: Option<f32>,
}

impl Bin {
    pub fn total(&self, shown: &[bool; KINDS]) -> u32 {
        self.kinds.iter().zip(shown).filter(|(_, on)| **on).map(|(n, _)| *n).sum()
    }
}

impl Timeline {
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty() && self.cpu.is_empty()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add(&mut self, minute: i64, kind: Kind, perf: bool, t: &str, process: &str, message: &str, key: &str) {
        let b = self.buckets.entry(minute).or_default();
        b.kinds[kind.index()] += 1;
        if perf {
            b.perf += 1;
        }
        if crate::classify::is_milestone(kind, message) {
            b.marks |= 1 << kind.index();
        }
        let cell = self.lines.entry((minute, kind.index())).or_default();
        if let Some(line) = cell.iter_mut().find(|l| l.key == key) {
            line.count += 1;
            line.t = t.to_owned();
        } else if cell.len() < LINES_PER_CELL {
            cell.push(Line { t: t.to_owned(), process: process.to_owned(), message: message.to_owned(), key: key.to_owned(), count: 1, perf });
        }
    }

    pub fn add_cpu(&mut self, minute: i64, cpu: f32, system: f32) {
        let c = self.cpu.entry(minute).or_default();
        c.sum += cpu;
        c.system_sum += system;
        c.max = c.max.max(cpu);
        c.n += 1;
    }

    /// Fold `other` (a batch from a monitor thread) into this one.
    pub fn merge(&mut self, other: Timeline) {
        if self.offset_min.is_none() {
            self.offset_min = other.offset_min;
        }
        for (m, b) in other.buckets {
            let mine = self.buckets.entry(m).or_default();
            for (a, x) in mine.kinds.iter_mut().zip(b.kinds) {
                *a += x;
            }
            mine.perf += b.perf;
            mine.marks |= b.marks;
        }
        for (cell, lines) in other.lines {
            let mine = self.lines.entry(cell).or_default();
            for line in lines {
                if let Some(l) = mine.iter_mut().find(|l| l.key == line.key) {
                    l.count += line.count;
                } else if mine.len() < LINES_PER_CELL {
                    mine.push(line);
                }
            }
        }
        for (m, c) in other.cpu {
            let mine = self.cpu.entry(m).or_default();
            mine.sum += c.sum;
            mine.system_sum += c.system_sum;
            mine.max = mine.max.max(c.max);
            mine.n += c.n;
        }
    }

    /// The first and last minute anything was recorded.
    pub fn span(&self) -> Option<(i64, i64)> {
        let first = [self.buckets.keys().next(), self.cpu.keys().next()].into_iter().flatten().min()?;
        let last = [self.buckets.keys().next_back(), self.cpu.keys().next_back()].into_iter().flatten().max()?;
        Some((*first, *last))
    }

    /// `[from, to)` cut into at most `max_bins` equal columns of whole minutes.
    pub fn bins(&self, from: i64, to: i64, max_bins: usize) -> Vec<Bin> {
        let span = (to - from).max(1);
        let per = ((span as f64 / max_bins.max(1) as f64).ceil() as i64).max(1);
        let n = ((span + per - 1) / per) as usize;
        let mut bins: Vec<Bin> = (0..n).map(|i| Bin { start: from + i as i64 * per, minutes: per, ..Bin::default() }).collect();
        for (m, b) in self.buckets.range(from..to) {
            let bin = &mut bins[((m - from) / per) as usize];
            for (a, x) in bin.kinds.iter_mut().zip(b.kinds) {
                *a += x;
            }
            bin.perf += b.perf;
            bin.marks |= b.marks;
        }
        let mut cpu_n = vec![0u32; n];
        let mut cpu_sum = vec![0f32; n];
        for (m, c) in self.cpu.range(from..to) {
            let i = ((m - from) / per) as usize;
            cpu_sum[i] += c.sum;
            cpu_n[i] += c.n;
            let bin = &mut bins[i];
            bin.cpu_max = Some(bin.cpu_max.unwrap_or(0.0).max(c.max));
        }
        for (i, bin) in bins.iter_mut().enumerate() {
            if cpu_n[i] > 0 {
                bin.cpu_avg = Some(cpu_sum[i] / cpu_n[i] as f32);
            }
        }
        bins
    }

    /// The example lines for `[from, to)`, kinds in `shown`, most repeated first.
    pub fn lines_in(&self, from: i64, to: i64, shown: &[bool; KINDS], perf_only: bool) -> Vec<(i64, Kind, Line)> {
        let mut out: Vec<(i64, Kind, Line)> = vec![];
        for ((m, k), lines) in self.lines.range((from, 0)..(to, 0)) {
            if !shown[*k] {
                continue;
            }
            for line in lines {
                if perf_only && !line.perf {
                    continue;
                }
                if let Some(o) = out.iter_mut().find(|(_, kind, l)| kind.index() == *k && l.key == line.key) {
                    o.2.count += line.count;
                    if *m > o.0 {
                        o.0 = *m;
                        o.2.t = line.t.clone();
                    }
                } else {
                    out.push((*m, Kind::ALL[*k], line.clone()));
                }
            }
        }
        out.sort_by(|a, b| b.2.count.cmp(&a.2.count).then(b.0.cmp(&a.0)));
        out
    }

    /// Local "HH:MM" for an epoch minute.
    pub fn clock(&self, minute: i64) -> String {
        let local = minute + self.offset_min.unwrap_or(0) as i64;
        let m = local.rem_euclid(24 * 60);
        format!("{:02}:{:02}", m / 60, m % 60)
    }

    /// Local "Fri 20.11" for an epoch minute.
    pub fn day(&self, minute: i64) -> String {
        let local = minute + self.offset_min.unwrap_or(0) as i64;
        let days = local.div_euclid(24 * 60);
        let (_, mo, d) = civil_from_days(days);
        let wd = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
        format!("{wd} {d}.{mo}")
    }
}

/// The current UTC epoch minute.
pub fn now_minute() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64 / 60)
}

/// "2026-11-20 16:30:20.123456+0100" → (UTC epoch minute, offset in minutes, "16:30:20").
pub fn parse_log_time(ts: &str) -> Option<(i64, i32, String)> {
    let num = |a: usize, b: usize| ts.get(a..b)?.parse::<i64>().ok();
    let (y, mo, d, h, mi) = (num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?);
    let zone = ts.rfind(['+', '-']).filter(|i| *i > 19)?;
    let sign = if ts.as_bytes()[zone] == b'-' { -1 } else { 1 };
    let z = &ts[zone + 1..];
    let (zh, zm) = (z.get(0..2)?.parse::<i32>().ok()?, z.get(2..4).and_then(|s| s.parse::<i32>().ok()).unwrap_or(0));
    let offset = sign * (zh * 60 + zm);
    let local = days_from_civil(y, mo, d) * 24 * 60 + h * 60 + mi;
    Some((local - offset as i64, offset, ts.get(11..19)?.to_owned()))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod timeline_tests {
    use super::*;

    #[test]
    fn log_times_parse_to_utc_minutes() {
        let (m, off, t) = parse_log_time("2026-11-20 16:30:20.123456+0100").unwrap_or_default();
        assert_eq!(off, 60);
        assert_eq!(t, "16:30:20");
        let tl = Timeline { offset_min: Some(off), ..Timeline::default() };
        assert_eq!(tl.clock(m), "16:30");
        assert_eq!(tl.day(m), "Fri 20.11");
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(days_from_civil(2024, 2, 29)), (2024, 2, 29));
        assert!(parse_log_time("garbage").is_none());
    }

    #[test]
    fn bins_sum_minutes_and_repeats_collapse() {
        let mut tl = Timeline::default();
        for m in 0..10 {
            tl.add(m, Kind::NetFilter, false, "00:00:00", "netext", "reinit", "reinit");
        }
        tl.add(3, Kind::Directory, true, "00:03:00", "wdavdaemon_enterprise", "Performance impact", "perf");
        tl.add_cpu(3, 4.0, 20.0);
        tl.add_cpu(3, 8.0, 20.0);
        let bins = tl.bins(0, 10, 5);
        assert_eq!(bins.len(), 5);
        assert_eq!(bins[1].kinds[Kind::NetFilter.index()], 2);
        assert_eq!(bins[1].perf, 1);
        assert_eq!(bins[1].cpu_avg, Some(6.0));
        assert_eq!(bins[1].cpu_max, Some(8.0));
        assert_eq!(bins[0].cpu_avg, None);
        let shown = [true; KINDS];
        let lines = tl.lines_in(0, 10, &shown, false);
        assert_eq!(lines[0].2.count, 10);
        assert_eq!(tl.lines_in(0, 10, &shown, true).len(), 1);
    }

    #[test]
    fn merge_adds_up() {
        let mut a = Timeline::default();
        a.add(1, Kind::Cloud, false, "t", "p", "m", "k");
        let mut b = Timeline { offset_min: Some(60), ..Timeline::default() };
        b.add(1, Kind::Cloud, false, "t", "p", "m", "k");
        a.merge(b);
        assert_eq!(a.buckets[&1].kinds[Kind::Cloud.index()], 2);
        assert_eq!(a.lines[&(1, Kind::Cloud.index())][0].count, 2);
        assert_eq!(a.offset_min, Some(60));
    }
}
