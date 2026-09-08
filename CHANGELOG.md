## FlClash TUI v0.5.28

- Add CLI and TUI capture of an existing OpenSSH ControlMaster without a second login; only explicit user operations discover external masters. Recognize OpenSSH's `ControlMaster false` output correctly.
- Name imported subscriptions using the server-provided filename, with a unique generated fallback.

- Run SSH capture discovery asynchronously with bounded probes and ignore stale picker results. Validate capture targets before disconnecting, and restore the previous tunnel if replacement fails without starting a new login for an external ControlMaster.
- Prevent control-only SSH helpers from falling back to a fresh network connection; bound the SSH relay's upstream SOCKS handshake and preserve diagnostic state during tunnel shutdown.
- Import every concrete OpenSSH Host alias, accept tab-separated and quoted fields, resolve shared defaults through OpenSSH, retain aliases for ControlPath matching, and report missing requested hosts.
- Restrict connection close operations to the same user scope as the Connections list, except for system-wide TUN management.
- Avoid unchanged History writes and prevent rapid log exports from overwriting previous files. Make SSH attach help exit successfully and correct the Backend/SSH shutdown documentation.

## FlClash TUI v0.5.27

- Keep Dashboard/Proxies/Connections refreshes on Backend `status` so silent mode, SYSTEM TUN lock, and the `flc` READY/WAITING suffix are not replaced by the Core's silent runtime `mode: rule` overlay.

## FlClash TUI v0.5.26

- Cut idle cost without dropping daily flows: TUI ticks every 2s at 15 FPS, History/Logs bulk-fetch only on those pages, and Core `/traffic` and `/memory` streams run only on Dashboard (including leaving via flc Enter or `P`).
- Slow Backend History collection to 2s, skip rewriting the History file when nothing changed, and keep save/restore/clear plus `0600` permissions.
- Cap the managed Core Go heap at 512MiB unless `GOMEMLIMIT` is set, return unused memory after config load, and use the memconservative Geo loader at runtime without rewriting existing user YAML.
- Keep Dashboard as the daily Core/mode/flc/port/TUN/system-proxy surface; Settings keeps Allow LAN, IPv6, delay, log, and TUN scope. `q` still exits the TUI only; Ctrl+C remains a full exit.

## FlClash TUI v0.5.25

- Keep SSH independent of the proxy Backend: `flclash backend stop` ends Backend and Core only; use `flclash ssh disconnect` or `flclash exit` to tear down tunnels, and document that split in CLI help and the READMEs.
- Prompt once for an encrypted-key passphrase when `flc ssh COMMAND` auto-opens the default persistent tunnel, matching `flclash ssh connect`.
- Record a last-error when a rebuilt SSH tunnel comes up without a SOCKS5 listener, and inject every HTTP/HTTPS/ALL_PROXY environment variant into `flc ssh` child commands.
- Complete the user-facing silent/`flc` path from v0.5.24: Proxies selection drives the exit, Dashboard defaults to Core, and the TUI labels the row `flc` instead of `FLC outbound`.

## FlClash TUI v0.5.24

- Rename the Dashboard/Settings `FLC outbound` row to `flc`, default Dashboard focus to Core so silent mode does not land on a locked System proxy row, and drop the leftover typed FLC name prompt.
- Point silent-mode `flc` at the proxy group chosen in Proxies: selecting a node also becomes the FLC outbound, and Dashboard/Settings Enter opens that group instead of asking for a typed name.
- Keep CLI and TUI on the same silent path: switching to silent auto-selects a group, `flclash status`/`flc status` show `GROUP → node`, and leftover `flc select NAME` errors now tell you to pick a node in Proxies.
- Auto-select a usable FLC outbound when starting Core in silent mode from the TUI or `flclash core start`, instead of failing with `run flclash flc select NAME first` when none was saved.
- Make `flc ssh COMMAND` open the default or only SSH profile automatically, and rebuild a broken persistent tunnel instead of asking the user to reconnect first.
- Add `flclash ssh default`, TUI `u` to star a default profile, and `flclash ssh connect` without a name.
- Import OpenSSH `~/.ssh/config` Host entries with `flclash ssh import`, including User, Port, IdentityFile, ProxyJump, and Include files.
- Add a first-class Jump host field, fail SSH connects in 15 seconds by default, and map common OpenSSH failures into short actionable errors.
- Make `flclash ssh test` perform a SOCKS5 handshake after opening the tunnel, and show the last connect error on the SSH list and Dashboard.

## FlClash TUI v0.5.23

- Keep every OpenSSH helper detached from the terminal, use a saved password through the private askpass channel, and make stale control connections fail closed instead of displaying an interactive password prompt over the TUI.
- Prevent control, forwarding, health-check, remote-probe, and disconnect commands from starting a second authenticated SSH connection when their existing control socket is unavailable.
- Place OpenSSH and SSH traffic-meter sockets in a secure short runtime directory when the normal runtime path would exceed the Unix socket limit, with a real OpenSSH password-authentication regression test.

## FlClash TUI v0.5.22

- Make Dashboard public-IP detection event-driven instead of polling while the TUI is open.
- Refresh network detection at startup, on an explicit refresh, and after a route-changing operation such as a profile, proxy, mode, or TUN change.
- Keep local status and traffic refreshes independent from external network-detection requests.

## FlClash TUI v0.5.21

- Preserve standard SIP008 Shadowsocks `plugin_opts` during profile import,
  including v2ray-plugin and simple-obfs transport settings, instead of
  accepting a node whose effective transport configuration was lost.
- Reject concatenated or trailing JSON subscription data, and reserve every
  Mihomo built-in and generated proxy-group name while converting a feed so an
  imported profile remains valid when the Core starts.
- Add conversion coverage that exercises a full Mihomo configuration parse,
  not only raw YAML decoding.

## FlClash TUI v0.5.20

- Repair a saved silent-mode FLC outbound automatically when a Profile import,
  activation, update, restore, or Core restart removes or renames that outbound;
  invalid listeners no longer stay up and return empty HTTP 502 responses.
- Include authenticated loopback `flc-private` traffic in Connections and
  persistent History without weakening per-user filtering, and emit `[]`
  instead of `null` for an empty `connections --json` result.
- Show the complete Mihomo proxy chain (selected node through proxy group) and
  close Dashboard network-detection transports promptly so their idle sockets
  do not pollute Connections or History.
- Make `flclash port` report the configured port as documented while status
  continues to expose configured and active runtime ports independently.
- Resolve duplicate and reserved node names during subscription conversion
  instead of rejecting an otherwise valid feed.
- Add integration coverage for stale FLC repair before the first command, Core
  startup, and Profile hot reload, plus connection ownership and route tests.

## FlClash TUI v0.5.19

- Import Base64-wrapped node subscriptions such as the common plain-text
  `ss://`, `vmess://`, `vless://`, `trojan://`, Hysteria, TUIC, and AnyTLS
  feeds, converting them into a complete Mihomo profile before activation.
- Accept native Mihomo/Clash YAML, raw URI lists, Base64 YAML/URI lists,
  SIP008, supported sing-box/Xray JSON, and common Surge/Quantumult X/Loon
  proxy lines from both subscription URLs and local files of any extension.
- Validate every converted node with the bundled Mihomo parser and reject an
  incomplete conversion instead of silently dropping unsupported nodes.
- Show the detected format and node count after importing, and align the CLI,
  TUI, and documentation with the expanded input support.

## FlClash TUI v0.5.18

- Add a verified SSH direct path: `flc ssh -d COMMAND` refuses to run when B
  reports a transparent FlClash TUN, while ordinary `flc ssh COMMAND` clearly
  follows B's own Clash, routing, or network policy.
- Expand the SSH Dashboard with A/B inet addresses, B direct/managed exit
  cards, independent latency/download tests, and truthful blocked or unknown
  direct-path feedback.
- Move SSH directly below Dashboard in the sidebar, correct shortcut ordering
  and selected-row rendering, and harden History, Connections, Logs, Settings,
  and Profile refreshes against stale selections and hidden errors.
- Reclaim a TUI reliably when its terminal closes through HUP, TERM, stdin EOF,
  or a VS Code/WSL shell-parent exit, while keeping Backend and SSH relays
  intentionally independent from a normal `q` frontend exit.

## FlClash TUI v0.5.17

- fix(tui): harden SSH and connection state

## FlClash TUI v0.5.16

- Add a rootless Go SOCKS5 metering relay for persistent SSH tunnels, keeping
  the configured application port stable while hiding the OpenSSH upstream
  port and measuring live/cumulative upload, download, and active connections.
- Add a per-profile SSH Dashboard with tunnel control, SSH-exit public IP,
  five-sample route latency, Cloudflare download speed, a 30-sample traffic
  chart, cumulative traffic, active connections, and uptime.
- Keep temporary `flc ssh -u` tunnels direct and short-lived, preserve legacy
  persistent tunnel compatibility, and clean up the relay when OpenSSH exits,
  startup rolls back, a profile disconnects, or FlClash exits completely.
- Upgrade the private Backend protocol to v5 and merge the persistent rotated
  Backend log with current TUI events. Add log search, level filtering, live
  refresh, full-entry details, export, and confirmed persistent clearing.
- Expand History and Connections with traffic/activity summaries, text search,
  state filtering, full details, and confirmation before clearing records or
  closing selected/all connections.
- Update the Chinese and English usage documentation and add SOCKS5 relay,
  SSH Dashboard, persistent-log, filtering, detail, and confirmation tests.

## FlClash TUI v0.5.15

- Keep complete exit progressing through frontend, Backend, Core, socket, and
  lock cleanup even when SSH runtime cleanup fails, while returning every
  cleanup error to the caller.
- Keep failed Core listener starts and stops in a truthful, retryable state,
  validate that proxy ports actually close, and report rollback failures for
  traffic-mode, System proxy, FLC outbound, settings, and subscription updates.
- Make `logs --follow` survive log rotation and truncation, prevent blank Core
  connection IDs from polluting History, and refuse to overwrite corrupt or
  unsupported shared state during an update.
- Require an old Backend process to exit before upgrade, migration, or manual
  restart; reject oversized or trailing Backend requests and GitHub release
  metadata instead of accepting a partial first JSON value.
- Compare update prerelease versions with SemVer precedence (including numeric
  identifiers such as `beta.10`) and reject malformed SemVer tags.
- Rename the SSH profile fields to `SSH host` and `Identity(private key)`, and
  separate the private-key passphrase from the SSH server password. Both
  credentials can coexist in one profile and are selected by the matching
  OpenSSH AskPass prompt without exposing either value in arguments, status,
  JSON views, logs, or TUI output.
- Make first-time SSH connections work with saved credentials by defaulting to
  `StrictHostKeyChecking=accept-new`, while preserving an explicit per-profile
  host-key policy and still rejecting changed host keys.
- Fix SSH SOCKS5 startup by clearing inherited OpenSSH forwards before adding
  FlClash's dynamic forward through the live control master; previously
  `ClearAllForwardings=yes` also removed FlClash's own `-D` listener.
- Serialize command-scoped SSH tunnel startup and cleanup with complete-exit
  operations, and report cleanup failures instead of leaving them silent.
- Remove owned mode-`0600` AskPass secret files left by an interrupted process,
  force OpenSSH authentication prompts to the stable `C` locale, and reject
  unknown prompt types instead of returning the wrong credential.
- Distinguish a healthy `CONNECTED` SSH tunnel from a `BROKEN` control master
  whose local SOCKS5 listener is unavailable, while keeping the broken tunnel
  manageable so it can still be disconnected cleanly. Connecting the selected
  broken profile now rebuilds it, and `flc ssh` refuses to launch a command
  until the SOCKS5 listener is ready.

## FlClash TUI v0.5.14

- Add native TUI forms for SSH profile creation and editing, including masked
  passwords, OpenSSH options, fixed or automatic local SOCKS5 ports, and
  visible confirmation-based deletion.
- Add confirmation-based deletion for non-active subscription and local
  Profiles, with Backend revision checks, metadata cleanup, and rollback.
- Make connected SSH profiles read-only until disconnected, reject concurrent
  stale edits, and safely switch profiles that share one fixed local port with
  restoration of the previous tunnel on failure.
- Harden SSH tunnel cleanup, complete-exit behavior, compact TUI rendering, and
  Profile selection after deletion; expand lifecycle and failure-path tests.
- Simplify the Chinese and English README pages around installation and common
  usage, with detailed behavior retained in `CLI_LINUX.md`.

## FlClash TUI v0.5.13

- Fix silent-mode Core stop/start by explicitly dropping the private custom
  inbound before standard Mihomo listeners, so its TCP/UDP port is released.
- Replace the reverse `flc ssh` experiment with independent OpenSSH dynamic
  SOCKS5 profiles, persistent/manual tunnels, command-scoped `-u` tunnels,
  masked mode-`0600` password storage, and complete-exit cleanup.
- Add a standalone SSH TUI page and update command help, completion,
  documentation, and lifecycle/UI regression coverage.

## FlClash TUI v0.5.12

- Add idempotent `flclash exit` and make `Ctrl+C` fully stop every registered
  TUI frontend, Backend, and Core, with lock-validated TERM/KILL fallback and
  final process/socket/session-lock verification. Keep `q` scoped to the current
  TUI and usable as text while an input editor is active.
- Add `flc ssh` / `flclash flc ssh`: OpenSSH reverse forwarding exposes A's
  active FlClash proxy only to B's current proxy-aware shell or remote command,
  with automatic remote-port allocation, authenticated URL preservation,
  fail-closed setup, exit-code propagation, and deterministic tunnel cleanup.
- Extend runtime help, shell completion, Chinese/English documentation, Go
  regression tests, and pseudo-terminal lifecycle coverage.

## FlClash TUI v0.5.11

- Keep `q` scoped to the current TUI frontend, including synchronous frontend
  monitor and session-lock cleanup, without stopping the shared Backend.
- Route `Ctrl+C` through managed Backend and Core shutdown from normal,
  notification, selection, busy, input-editor, and process-signal paths.
- Wait for the Backend PID and Unix socket to disappear after the shutdown ACK;
  keep the frontend open with an error instead of reporting a false clean exit.
- Extend the real pseudo-terminal CI test to verify frontend registration,
  Backend/Core state, process liveness, and socket cleanup for both exit keys.

## FlClash TUI v0.5.10

- Add a white dotted baseline to the live traffic chart, while preserving blue
  upload, green download, and cyan overlap where curves meet the baseline.
- Serialize Backend History refresh and clear operations so an in-flight poll
  cannot restore entries after History was cleared, and drain the collector
  before the final shutdown save.
- Release temporary TUN leases after stopped-Core route tests and remove
  generated managed runtime YAML when a profile switch rolls back.
- Preserve completed operations as separate notification-history entries and
  keep the selected detail message's scroll position when background notices
  arrive.
- Extend terminal-size, notification, lifecycle, History, and release-path
  regression coverage.

## FlClash TUI v0.5.9

- Restore non-blocking, color-coded notification summaries in the lower-right
  footer and keep normal TUI navigation available while feedback is pending.
- Add `Ctrl+N` notification history and full-message details inside the existing
  TUI header, sidebar, and panel frame, with confirmation and scrolling.
- Keep the live upload/download speed legend matched to the chart's blue and
  green series colors without bleeding into surrounding borders.

## FlClash TUI v0.5.8

- Restore the original line-only 30-sample traffic chart without area fills or
  a separate baseline.
- Render upload in blue, download in green, and overlapping curve cells in cyan,
  with matching colored upload/download values in the chart legend.

## FlClash TUI v0.5.7

- Restyle the adaptive traffic chart with a gray baseline, blue upload, red
  download, purple overlap, and matching light area fills.
- Make Dashboard route latency and Cloudflare throughput selectable with the
  arrow keys and Enter while retaining the `d` and `v` shortcuts.
- Route Dashboard public-IP detection, latency, and speed tests through the
  authenticated private FLC listener in silent mode.
- Move operation progress, success, warnings, and errors into a FIFO notification
  page with Enter/Esc dismissal, scrolling, deduplication, and Logs integration.
- Keep panel borders unstyled so selected and colored row content cannot bleed
  into the Network detection frame.

## FlClash TUI v0.5.6

- Add an adaptive 30-sample Dashboard chart that overlays live upload and
  download traffic from the existing Mihomo traffic stream.
- Make `q` explicitly cancel and exit only the current TUI frontend while
  reserving Backend and Core shutdown for `Ctrl+C`.

## FlClash TUI v0.5.5

- Hide generated silent/managed runtime YAML files from Profile lists and add
  explicit local YAML import in both TUI and CLI.
- Reuse one runtime Proxy port across native and authenticated silent/FLC
  listeners, with readiness shown separately from the port value.
- Persist the shared 500-entry connection History across Backend restarts and
  add state, text, and count filters to `history show`.
- Add structured application events, sensitive-value redaction, bounded TUI
  logs, and Backend log rotation.
- Add a unified architecture-aware installer and simplify the Chinese and
  English GitHub landing pages.

## FlClash TUI v0.5.4

- Separate Backend-only `silent` and effective TUN state from the native mode
  and TUN values stored in YAML profiles.
- Prevent stopped-Core restarts and ordinary settings or Proxy port changes
  from attempting to serialize `silent` into the active profile.
- Preserve Backend-authoritative mode, TUN, listener, FLC, and System proxy
  status after managed operations refresh live Core configuration.
- Recover safely from stale staged settings created by earlier TUI versions.

## FlClash TUI v0.5.3

- Allow `rule`, `global`, and `direct` mode changes to persist while Core
  listeners are stopped, without contacting an unavailable live controller.
- Make TUN scope, lease, profile, and Core updates transactional; reject active
  scope replacement and restore the previous Core TUN state after failures.
- Keep System proxy updates and Dashboard network detection on the actual
  runtime listener when the configured Proxy port requires a fallback.
- Preserve Backend-authoritative mode and TUN state while Core is stopped, and
  prevent asynchronous TUI operations from restoring stale traffic counters.
- Reject ignored extra arguments in `flclash connections` commands.

## FlClash TUI v0.5.2

- Start a fresh silent-mode Core on the first `flc COMMAND`, automatically
  selecting and persisting a usable FLC outbound instead of leaving the CLI in
  a Core-stopped/FLC-not-selected deadlock.
- Bound desktop Core startup and shutdown waits, report early process exits,
  reap local Core processes, and release completed or timed-out IPC callbacks.
- Fail the Windows helper closed when its executable authorization token is
  absent or unreadable, and upgrade its HTTP stack to remove reachable Rust
  security advisories.
- Update vulnerable Go networking dependencies and the CI Go toolchain to
  versions with no reachable known vulnerabilities.
- Validate Flutter, plugin, Linux CLI, and Windows helper tests on every pull
  request, while keeping multi-platform packaging restricted to release tags.
- Package tagged releases as Linux TUI amd64/arm64 Debian and portable archives
  with checksums, replacing the unrelated Flutter GUI matrix and legacy
  third-party publishing steps.
- Repair changelog and release-note generation, and update official GitHub
  Actions to their Node 24-compatible major versions.
- Fix the CargoKit Apple build script's shell declaration and stop printing the
  complete build environment into logs.
- Make route-port tests deterministic and remove deprecated Flutter color APIs.
- Measure route and node latency from five samples, reporting the median and
  successive-sample jitter instead of a single inconsistent request.
- Measure aggregate Cloudflare download throughput over four concurrent streams
  with one shared five-second/100 MB budget.
- Run route tests through the Backend's actual runtime Proxy port and preserve
  their result after temporary Core lifecycle restoration.

## FlClash TUI v0.5.1

- Repair a missing silent-mode private listener on the first `flc COMMAND` invocation by automatically selecting the first usable configured proxy group, reloading Core transactionally, and persisting that FLC outbound.

## FlClash TUI v0.5.0

- Isolate managed Backends, runtime proxy entries, connections, and TUI clients per Linux UID.
- Automatically select a free runtime Proxy port while retaining the configured preferred port.
- Add user-scoped and exclusive system-scoped TUN modes with Backend IPC protocol v4.
- Install a Polkit-authorized root helper that owns TUN devices, policy routes, cgroup loop prevention, leases, and Backend-disconnect cleanup.
- Route connection mutations through Backend and expose UID/process ownership in History and Connections.

## FlClash TUI v0.4.3

- Open a four-item `rule` / `silent` / `global` / `direct` selector before the
  Dashboard or Settings changes outbound mode.
- Switch between Mihomo-native modes through its live configuration API instead
  of a full Core reload, while keeping profile persistence and rollback.
- Give mode and FLC-outbound operations the Core-reload timeout when a silent
  mode transition still requires a reload.

## FlClash TUI v0.4.2

- Fixed automatic Backend migration across service protocol versions.
- Added an unversioned compatibility handshake for discovering and gracefully
  stopping an older per-user Backend during upgrades.
- Wait for the old Backend PID to exit before starting its replacement, avoiding
  a race with the per-user process lock.
- Refuse automatic downgrade when the running Backend is newer than the client.
- Added protocol-negotiation, shutdown, process-exit, and downgrade regression tests.

## FlClash TUI v0.4.1

- Aligned Dashboard, CLI, and TUI actions behind the shared Backend transaction layer.
- Added silent proxy mode so only commands launched through `flc` use the proxy.
- Simplified management commands to `core`, `sys`, `tun`, `mode`, `port`, `net`,
  `history`, and `connections close all`, while retaining compatibility aliases.
- Replaced Requests with a shared 500-entry History view across terminal frontends.
- Made `q` detach only the current frontend, while `Ctrl+C` gracefully shuts down
  Backend and Core and reaps managed child processes.
- Updated bilingual documentation, shell completions, lifecycle tests, and packages.

## FlClash TUI v0.4.0

- Split `flclash` backend/TUI management from the `flc` command proxy.
- Added a single per-user backend with multi-frontend IPC, revision conflicts,
  request deduplication, watch notifications, profile locks, and transactional
  config rollback.
- Expanded lifecycle, service, profile, proxy, config, system-proxy, TUN,
  mode, connection, Geo, environment, doctor, completion, and help commands.
- Split Settings and Maintenance, made `q` and `Ctrl+C` detach only the current
  frontend, and kept the complete TUI usable at `40x10`.

## v0.8.94

- Fix macos performance issue

- Support custom global-ua

- Update core

- Optimize some details

- Fix linux silent launching not working

## v0.8.93

- Support custom overwrite

- Support run on demand

- Optimize windows ipc

- Optimize windows arm64

- Optimize build

- Optimize some details

- Update core

## v0.8.92

- Add sqlite store

- Optimize android quick action

- Optimize backup and restore

- Optimize more details

## v0.8.91

- Fix windows some issues

- Optimize overwrite handle

- Optimize access control page

- Optimize some details

## v0.8.90

- Fix android tile service

- Support append system DNS

- Fix some issues

- Update changelog

## v0.8.89

- Fix some issues

- Optimize Windows service mode

- Update core

- Update changelog

## v0.8.88

- Add android separates the core process

- Support core status check and force restart

- Optimize proxies page and access page

- Update flutter and pub dependencies

- Update go version

- Optimize more details

- Update changelog

## v0.8.87

- Optimize desktop view

- Optimize logs, requests, connection pages

- Optimize windows tray auto hide

- Optimize some details

- Update core

- Update changelog

## v0.8.86

- Fix windows tun issues

- Optimize android get system dns

- Optimize more details

- Update changelog

## v0.8.85

- Support override script

- Support proxies search

- Support svg display

- Optimize config persistence

- Add some scenes auto close connections

- Update core

- Optimize more details

## v0.8.84

- Fix windows service verify issues

- Update changelog

## v0.8.83

- Add windows server mode start process verify

- Add linux deb dependencies

- Add backup recovery strategy select

- Support custom text scaling

- Optimize the display of different text scale

- Optimize windows setup experience

- Optimize startTun performance

- Optimize android tv experience

- Optimize default option

- Optimize computed text size

- Optimize hyperOS freeform window

- Add developer mode

- Update core

- Optimize more details

- Add issues template

- Update changelog

## v0.8.82

- Optimize android vpn performance

- Add custom primary color and color scheme

- Add linux nad windows arm release

- Optimize requests and logs page

- Fix map input page delete issues

- Update changelog

## v0.8.81

- Add rule override

- Update core

- Optimize more details

- Update changelog

## v0.8.80

- Optimize dashboard performance

- Fix some issues

- Fix unselected proxy group delay issues

- Fix asn url issues

- Update changelog

## v0.8.79

- Fix tab delay view issues

- Fix tray action issues

- Fix get profile redirect client ua issues

- Fix proxy card delay view issues

- Add Russian, Japanese adaptation

- Fix some issues

- Update changelog

## v0.8.78

- Fix list form input view issues

- Fix traffic view issues

- Update changelog

## v0.8.77

- Optimize performance

- Update core

- Optimize core stability

- Fix linux tun authority check error

- Fix some issues

- Fix scroll physics error

- Update changelog

## v0.8.75

- Add windows storage corruption detection

- Fix core crash caused by windows resource manager restart

- Optimize logs, requests, access to pages

- Fix macos bypass domain issues

- Update changelog

## v0.8.74

- Fix some issues

- Update changelog

## v0.8.73

- Update popup menu

- Add file editor

- Fix android service issues

- Optimize desktop background performance

- Optimize android main process performance

- Optimize delay test

- Optimize vpn protect

- Update changelog

## v0.8.72

- Update core

- Fix some issues

- Update changelog

## v0.8.71

- Remake dashboard

- Optimize theme

- Optimize more details

- Update flutter version

- Update changelog

## v0.8.70

- Support better window position memory

- Add windows arm64 and linux arm64 build script

- Optimize some details

## v0.8.69

- Remake desktop

- Optimize change proxy

- Optimize network check

- Fix fallback issues

- Optimize lots of details

- Update change.yaml

- Fix android tile issues

- Fix windows tray issues

- Support setting bypassDomain

- Update flutter version

- Fix android service issues

- Fix macos dock exit button issues

- Add route address setting

- Optimize provider view

- Update changelog

- Update CHANGELOG.md

## v0.8.67

- Add android shortcuts

- Fix init params issues

- Fix dynamic color issues

- Optimize navigator animate

- Optimize window init

- Optimize fab

- Optimize save

## v0.8.66

- Fix the collapse issues

- Add fontFamily options

## v0.8.65

- Update core version

- Update flutter version

- Optimize ip check

- Optimize url-test

## v0.8.64

- Update release message

- Init auto gen changelog

- Fix windows tray issues

- Fix urltest issues

- Add auto changelog

- Fix windows admin auto launch issues

- Add android vpn options

- Support proxies icon configuration

- Optimize android immersion display

- Fix some issues

- Optimize ip detection

- Support android vpn ipv6 inbound switch

- Support log export

- Optimize more details

- Fix android system dns issues

- Optimize dns default option

- Fix some issues

- Update readme

## v0.8.60

- Fix build error2

- Fix build error

- Support desktop hotkey

- Support android ipv6 inbound

- Support android system dns

- fix some bugs

## v0.8.59

- Fix delete profile error

## v0.8.58

- Fix submit error 2

- Fix submit error

- Optimize DNS strategy

- Fix the problem that the tray is not displayed in some cases

- Optimize tray

- Update core

- Fix some error

## v0.8.57

- Fix tun update issues

- Add DNS override
- Fixed some bugs
- Optimize more detail

- Add Hosts override

## v0.8.56

- fix android tip error
- fix windows auto launch error

## v0.8.55

- Fix windows tray issues

- Optimize windows logic

- Optimize app logic

- Support windows administrator auto launch

- Support android close vpn

## v0.8.53

- Change flutter version

- Support profiles sort

- Support windows country flags display

- Optimize proxies page and profiles page columns

## v0.8.52

- Update flutter version

- Update version

- Update timeout time

- Update access control page

- Fix bug

## v0.8.51

- Optimize provider page

- Optimize delay test

- Support local backup and recovery

- Fix android tile service issues

## v0.8.49

- Fix linux core build error

- Add proxy-only traffic statistics

- Update core

- Optimize more details

- Merge pull request #140 from txyyh/main

- 添加自建 F-Droid 仓库相关 workflow
- Rename readme fingerprint

- Rename workflow deploy repo name

- Add download guide to README

- Add push release files to fdroid-repo

## v0.8.48

- Optimize proxies page

- Fix ua issues

- Optimize more details

## v0.8.47

- Fix windows build error

## v0.8.46

- Update app icon

- Fix desktop backup error

- Optimize request ua

- Change android icon

- Optimize dashboard

## v0.8.44

- Remove request validate certificate

- Sync core

## v0.8.43

- Fix windows error

## v0.8.42

- Fix setup.dart error

- Fix android system proxy not effective

- Add macos arm64

## v0.8.41

- Optimize proxies page

- Support mouse drag scroll

- Adjust desktop ui

- Revert "Fix android vpn issues"

- This reverts commit 891977408e6938e2acd74e9b9adb959c48c79988.

## v0.8.40

- Fix android vpn issues

- Fix android vpn issues

- Rollback partial modification

## v0.8.39

- Fix the problem that ui can't be synchronized when android vpn is occupied by an external

- Override default socksPort,port

## v0.8.38

- Fix fab issues

## v0.8.37

- Update version

- Fix the problem that vpn cannot be started in some cases

- Fix the problem that geodata url does not take effect

## v0.8.36

- Update ua

- Fix change outbound mode without check ip issues

- Separate android ui and vpn

- Fix url validate issues 2

- Add android hidden from the recent task

- Add geoip file

- Support modify geoData URL

## v0.8.35

- Fix url validate issues

- Fix check ip performance problem

- Optimize resources page

## v0.8.34

- Add ua selector

- Support modify test url

- Optimize android proxy

- Fix the error that async proxy provider could not selected the proxy

## v0.8.33

- Fix android proxy error

- Fix submit error

- Add windows tun

- Optimize android proxy

- Optimize change profile

- Update application ua

- Optimize delay test

## v0.8.32

- Fix android repeated request notification issues

## v0.8.31

- Fix memory overflow issues

## v0.8.30

- Optimize proxies expansion panel 2

- Fix android scan qrcode error

## v0.8.29

- Optimize proxies expansion panel

- Fix text error

## v0.8.28

- Optimize proxy

- Optimize delayed sorting performance

- Add expansion panel proxies page

- Support to adjust the proxy card size

- Support to adjust proxies columns number

- Fix autoRun show issues

- Fix Android 10 issues

- Optimize ip show

## v0.8.26

- Add intranet IP display

- Add connections page

- Add search in connections, requests

- Add keyword search in connections, requests, logs

- Add basic viewing editing capabilities

- Optimize update profile

## v0.8.25

- Update version

- Fix the problem of excessive memory usage in traffic usage.

- Add lightBlue theme color

- Fix start unable to update profile issues

- Fix flashback caused by process

## v0.8.23

- Add build version

- Optimize quick start

- Update system default option

## v0.8.22

- Update build.yml

- Fix android vpn close issues

- Add requests page

- Fix checkUpdate dark mode style error

- Fix quickStart error open app

- Add memory proxies tab index

- Support hidden group

- Optimize logs

- Fix externalController hot load error

## v0.8.21

- Add tcp concurrent switch

- Add system proxy switch

- Add geodata loader switch

- Add external controller switch

- Add auto gc on trim memory

- Fix android notification error

## v0.8.20

- Fix ipv6 error

- Fix android udp direct error

- Add ipv6 switch

- Add access all selected button

- Remove android low version splash

## v0.8.19

- Update version

- Add allowBypass

- Fix Android only pick .text file issues

## v0.8.18

- Fix search issues

## v0.8.17

- Fix LoadBalance, Relay load error

- Fix build.yml4

- Fix build.yml3

- Fix build.yml2

- Fix build.yml

- Add search function at access control

- Fix the issues with the profile add button to cover the edit button

- Adapt LoadBalance and Relay

- Add arm

- Fix android notification icon error

## v0.8.16

- Add one-click update all profiles
- Add expire show

## v0.8.15

- Temp remove tun mode

- Remove macos in workflow

- Change go version

## v0.8.14

- Update Version

- Fix tun unable to open

## v0.8.13

- Optimize delay test2

- Optimize delay test

- Add check ip

- add check ip request

## v0.8.12

- Fix the problem that the download of remote resources failed after GeodataMode was turned on, which caused the
  application to flash back.

- Fix edit profile error

- Fix quickStart change proxy error

- Fix core version

## v0.8.10

- Fix core version

## v0.8.9

- Update file_picker

- Add resources page

- Optimize more detail

- Add access selected sorted

- Fix notification duplicate creation issue

- Fix AccessControl click issue

## v0.8.7

- Fix Workflow

- Fix Linux unable to open

- Update README.md 3

- Create LICENSE
- Update README.md 2

- Update README.md

- Optimize workFlow

## v0.8.6

- optimize checkUpdate

## v0.8.5

- Fix submit error

## v0.8.4

- add WebDAV

- add Auto check updates

- Optimize more details

- optimize delayTest

## v0.8.2

- upgrade flutter version

## v0.8.1

- Update kernel
- Add import profile via QR code image

## v0.8.0

- Add compatibility mode and adapt clash scheme.

## v0.7.14

- update Version

- Reconstruction application proxy logic

## v0.7.13

- Fix Tab destroy error

## v0.7.12

- Optimize repeat healthcheck

## v0.7.11

- Optimize Direct mode ui

## v0.7.10

- Optimize Healthcheck

- Remove proxies position animation, improve performance
- Add Telegram Link

- Update healthcheck policy

- New Check URLTest

- Fix the problem of invalid auto-selection

## v0.7.8

- New Async UpdateConfig

- add changeProfileDebounce

- Update Workflow

- Fix ChangeProfile block

- Fix Release Message Error

## v0.7.7

- Update Selector 2

## v0.7.6

- Update Version

- Fix Proxies Select Error

## v0.7.5

- Fix the problem that the proxy group is empty in global mode.

- Fix the problem that the proxy group is empty in global mode.

## v0.7.4

- Add ProxyProvider2

## v0.7.3

- Add ProxyProvider

- Update Version

- Update ProxyGroup Sort

- Fix Android quickStart VpnService some problems

## v0.7.1

- Update version

- Set Android notification low importance

- Fix the issue that VpnService can't be closed correctly in special cases

- Fix the problem that TileService is not destroyed correctly in some cases

- Adjust tab animation defaults

- Add Telegram in README_zh_CN.md

- Add Telegram

## v0.7.0

- update mobile_scanner

- Initial commit
