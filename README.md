# defender-watch

What Microsoft Defender for Endpoint and Intune are doing to your Mac, and what it costs —
in CPU, in battery, and in what leaves the machine.

A small Rust dashboard built with [Rune](https://github.com/anomalyco/rune). It watches the
whole managed-device family on macOS: the `wdavdaemon` processes, the endpoint-security
(`epsext`) and network-filter (`netext`) system extensions, the DLP agents, the telemetry
writer, Company Portal and its SSO extension.

```
cargo run                            # live on this Mac
cargo run -- --snap watch.png --demo # headless render with plausible demo data
```

## What it shows

A window with a sidebar, in plain language. ⌘1–⌘7 switch pages.

- **Overview** — one verdict ("Your Mac is protected"), three tiles that open their pages
  (impact on your Mac, how often it talks to Microsoft, threats found), and what the
  products have been doing over the past 3 hours, in sentences with how often ("about every
  12 s"). `log show` backfills 24 hours; `log stream` keeps it live.
- **Timeline** — the past 24 hours, minute by minute: every line Defender and Intune wrote
  to the unified log, stacked by kind, with Defender's CPU underneath and a lane of real
  events above (detections, scans, definition updates, Intune check-ins). Drag to zoom,
  ⌘-scroll or pinch, scroll sideways to pan, filter by kind, click a column for the actual
  lines and which process wrote them.
- **Performance** — how much of the Mac Defender takes over the past 5 minutes: its slice
  of the whole processor next to everything else, its share of the work the processor was
  doing (and that share while the Mac was busy), disk reads, and memory and CPU per part.
  The battery cost is an estimate (~3.5 W per full core), and it says so. Time apps spend
  *waiting* on Defender's file checks uses no Defender CPU, so these charts can't show it.
- **Privacy** — telemetry batches and cloud check-ins, the destinations seen in the log
  (mostly privacy-hashed or `<private>`), and the sample submission setting: the policy that
  decides what Defender may *upload* to Microsoft.
- **Protection** — Defender's health checks, scans in progress, and quarantined threats,
  from `mdatp`, and Defender's settings (tamper protection, behavior monitoring, network
  protection, DLP, device tags, update channel).
- **Management** — what the employer's device management (Intune) has installed, read from
  the configuration profiles and managed preferences, and what each piece lets them do, in
  plain words: remote management, FileVault key escrow, Full Disk Access granted without
  asking, network filtering, extra root certificates, single sign-on. Also where Defender
  reports to, and which of its settings the tenant pins.
- **Activity log** — the live unified log, each line said in words over the raw message,
  repeats collapsed (`×N`), and lines the log itself calls a "Performance impact"
  highlighted.

## What it can and cannot see

Everything here is read **on the Mac**: `sysinfo` for process stats, the unified log
(`log show` / `log stream`), `mdatp health` / `threat list` / `scan list`, and the installed configuration profiles
(`system_profiler SPConfigurationProfileDataType`, `/Library/Managed Preferences`). No admin
rights needed, and nothing it shows leaves the machine.

It cannot see what Defender's EDR pipeline reports to your tenant — which is more. The
endpoint security extension records every process start with its **full command line**
(shell-expanded `argv`), file and login events, and the network extension records
connections; that goes to the admin console, not the local log. Two consequences worth
knowing:

- Secrets passed on a command line are recorded by the EDR. Use `curl -H @headerfile`,
  `curl --config -` or a file your script reads itself; never `expect` with passwords.
- The local log is quiet about it. A quiet dashboard is not proof of a quiet day.

## Layout

- `src/main.rs` — state, `poll`, thread startup; headless demo seeding
- `src/sampler.rs` — the one-second `sysinfo` sampler and periodic `mdatp` asks
- `src/logstream.rs` — live `log stream` and the 24-hour `log show` backfill
- `src/timeline.rs` — per-minute buckets, example lines and CPU behind the Timeline
- `src/managed.rs` — device-management enrollment, profiles, and what they allow
- `src/classify.rs` — one kind per shenanigan family, and collapse keys for the feed
- `src/mdatp.rs` — the `mdatp` CLI as data
- `src/view/` — the window: the sidebar (`mod.rs`), one file per page, the charts
  (`chart.rs`), and the plain-language wording (`words.rs`)

`--snap`/`--tree`/`--video` (Rune's headless tooling) work for verification; the `demo`,
`explore`, `explore-day`, `explore-zoomed`, `performance`, `privacy`, `protection`,
`management` and `activity` scenes fill the window with plausible
data so a snapshot has something to show (`--scene performance --snap perf.png --demo`).

`--install-notify` adds a launch agent that checks for new detections every 30 seconds and
notifies you (optionally on your phone through Pushover); `--uninstall-notify` removes it.

## Releases and the download page

`scripts/release.sh` builds a universal binary from a clean checkout of `origin/main`, signs it
with Developer ID, wraps it in a disk image that Apple notarizes and that gets the ticket
stapled, and publishes it as a GitHub Release tagged with the version in `Cargo.toml`. So the
download is always built from a commit you can read here. `scripts/screenshots.sh` renders the
page's pictures from demo data.

`site/` is the download page (Norwegian), published to GitHub Pages by
`.github/workflows/pages.yml`, and `argv-guard`, a Claude Code hook that stops commands that
would put a secret on the command line or look like a reverse shell.

macOS only (unified log, `mdatp`, the system extensions). MIT.
