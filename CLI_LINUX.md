# FlClash Linux CLI/TUI quick reference

This is the complete Linux CLI/TUI reference. The concise Chinese landing page is [README.md](README.md), with an English version in [README_EN.md](README_EN.md). Runtime help is available through `flclash --help`, `flclash COMMAND --help`, and `flc --help`.

## Build and install

```bash
git submodule update --init --recursive
make cli-linux
./dist/flclash
```

`dist/flclash` is the manager and `dist/flc` is the command-wrapper entry point. Keep `dist/data/` beside a portable build. Debian packages install `/usr/bin/flclash`, `/usr/bin/flc`, documentation, and bundled Geo data.

## Process model

- **Backend** is the detached per-user coordinator and the only managed writer of shared YAML/state and System proxy settings.
- **Core** is Mihomo and its traffic listeners. It may be stopped while Backend stays running.
- **System proxy** changes supported Linux desktop HTTP/HTTPS settings; it is not the same as starting Core.
- **TUN** is a separately leased user- or system-scoped entry managed by the packaged root helper.
- **Proxy port** is Mihomo's `mixed-port`: one port accepts HTTP and SOCKS5 proxy clients.

CLI and TUI frontends submit revisioned transactions to Backend over a private Unix socket. Backend validates, writes atomically, reloads Core, and rolls back on failure. Multiple TUI frontends may attach to the same Backend, but only one Backend is allowed per user.

Managed proxy listeners accept only loopback sockets owned by the Backend UID. Each user therefore sees and closes only connections accepted by that user's Core. Port conflicts do not prevent a second user from starting: Backend keeps the configured port as the preference and selects a free runtime port.

Lifecycle keys and commands:

```text
q in TUI                 exit and clean up only this frontend process
close TUI terminal       exit and clean up only this frontend process
Ctrl+C in managed TUI    stop Backend + Core + SSH tunnels, disconnect all frontends, wait for cleanup
flclash core stop        stop Core, keep Backend
flclash backend stop     stop Backend + Core; SSH tunnels stay up
flclash shutdown         alias for backend stop (SSH stays)
flclash ssh disconnect   stop SSH tunnels only
flclash exit             stop TUI frontends, Backend, Core, and SSH tunnels; remove runtime state
```

## Core command map

```bash
flclash                          # open TUI
flclash core status
flclash core start
flclash core stop
flclash core restart
flclash core reload [--config PATH]

flclash backend status
flclash backend start
flclash backend restart
flclash backend stop
flclash backend logs
flclash backend clients
flclash exit

flclash status [--json] [--watch]
flclash logs [--lines N] [--follow]
```

Dashboard-equivalent commands:

```bash
flclash sys status|on|off
flclash tun status|on|off
flclash mode                         # get
flclash mode rule|global|direct|silent
flclash port                         # get
flclash port PORT|off
flclash flc status
flclash flc select NAME            # optional override; Proxies selection also sets this
flclash flc test
flclash flc env
flclash net show|refresh|delay|speed
```

`net delay` warms the active route, takes five RTT samples, and reports
the median and mean successive-sample jitter. `net speed` measures aggregate
Cloudflare download throughput across four concurrent streams, stopping after
99,999,999 bytes or five seconds. Both commands use the Backend's active runtime
Proxy port, including an automatically selected fallback port. In `silent`
mode they use the authenticated private FLC listener, so the reported public IP,
latency, and throughput describe the selected flc group rather than the
machine's direct connection.

Profiles and configuration:

```bash
flclash profile list [--json]
flclash profile current
flclash profile import URL
flclash profile import-file /path/to/nodes.txt
flclash profile use NAME
flclash profile update [NAME]
flclash profile rename NAME NEW_NAME
flclash profile edit [NAME]
flclash profile delete NAME
flclash profile link --config PATH URL

flclash config path|show|validate|edit|backup|restore
flclash check --config PATH
```

Proxy state, History, and connections:

```bash
flclash proxy groups [--json]
flclash proxy nodes GROUP [--json]
flclash proxy select GROUP NODE
flclash proxy delay NODE [--test-url URL]
flclash proxy speed NODE

flclash history show [--follow] [--json] [--state all|active|done] [--search TEXT] [--limit N]
flclash history clear
flclash connections show [--json]
flclash connections close ID
flclash connections close all
```

History is Backend's shared, persistent, up-to-500-entry record derived from active Mihomo connections. It contains active and recently completed flows, not HTTP bodies. Backend reloads it after restart; restored entries begin as completed until Mihomo reports them active again. `history clear` clears both memory and disk without closing connections, while `connections close all` does not erase History.

Authenticated loopback traffic from the private silent-mode FLC listener is included even when Mihomo cannot resolve its process UID; unknown UID traffic from any other inbound remains hidden outside system-scoped TUN. Connections and History show the complete route from the selected node through its proxy group. `flclash port` prints the configured port; `flclash status --json` exposes both `configured_proxy_port` and the possibly reallocated `active_proxy_port`.

`profile import` and `profile import-file` accept Mihomo/Clash YAML, raw URI lists, standard or URL-safe Base64-wrapped YAML/URI lists, SIP008 JSON, supported sing-box/Xray JSON outbounds, and common Surge/Quantumult X/Loon proxy lines. Local files may use any extension and are converted into a copied `.yaml` profile without modifying the source; duplicate file names gain `-2`, `-3`, and so on, while duplicate node names are renamed deterministically. Every converted node is validated by Mihomo, and an unsupported or malformed node rejects the whole import instead of being silently dropped. Internal `.flclash-silent-runtime-*` and `.flclash-managed-runtime-*` YAML files are never shown as Profiles.

TUN scope is explicit:

```bash
flclash tun on              # current UID; same as: tun user on
flclash tun user off
flclash tun system on       # Polkit authorization; exclusive for the machine
flclash tun status
```

Multiple user-scoped leases may coexist. A system-scoped lease conflicts with every other TUN lease and is released automatically when its owning Backend exits. User scope restores after Backend restart; system scope stays off until authorized again. The `.deb` installs `flclash-tun-helper.service`; portable tar installations retain non-TUN features but report that the helper is unavailable.

Other commands:

```bash
flclash geo status|update
flclash env [--json]
flclash doctor [--json]
flclash completion bash|zsh|fish
flclash update --check
flclash update [--yes] [--download-only]
flclash run [--config PATH]            # advanced foreground mode
flclash version
```

Compatibility aliases include `service`, `system-proxy`, `outbound-mode`, `mixed-port`, `requests`, `connections close-all`, and `flclash exec -- COMMAND`. Prefer `backend`, `sys`, `mode`, `port`, `history`, `connections close all`, and `flc COMMAND` in new scripts.

## Silent mode and `flc`

`silent` is the default. It does not proactively take over user network connections: ordinary applications remain direct and only `flc`-prefixed commands use FlClash. Backend disables System proxy, TUN, LAN/DNS/controller/user listeners in a temporary runtime overlay. `flc` uses the same proxy group you select in Proxies: pick a node there, and silent traffic follows that group's current node. Starting Core, or the first `flc COMMAND`, auto-selects the first usable group when none has been chosen yet. After that it exposes one authenticated loopback listener on the same runtime Proxy port used by native modes; before listeners start it exposes no traffic entry, and Backend remains available with Core stopped. The shared YAML is not modified.

```bash
flclash core start
# In TUI Proxies, select a node; flc follows that group
flc curl https://example.com
```

Outside silent mode, `flc` uses the normal Proxy port. It sets `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` only for the child process. It verifies the entry and fails closed instead of silently running direct. Applications must support proxy environment variables. Use an explicit shell for pipelines:

```bash
flc sh -c 'curl -s https://example.com | jq .'
```

### Independent SSH command proxy

SSH profiles and tunnels are independent of Mihomo, subscriptions, Core state,
and the normal `flc` proxy. The machine running FlClash is always the traffic
source and the configured SSH host is the network exit. For a persistent
tunnel, FlClash exposes one loopback-only Go SOCKS5 relay and connects it to a
hidden OpenSSH dynamic SOCKS5 forward. The relay injects
`socks5h://127.0.0.1:PORT` into the local child command's upper- and lower-case
proxy environment. For example, if FlClash runs only on B and the profile points
to A, B's selected traffic exits through A; A only needs an SSH server:

```bash
flclash ssh import
flclash ssh add home A --user user --port 2222 --local-port 1080 --password
flclash ssh default home
flc ssh curl https://example.com

# Strict direct: refuse when the SSH host reports a transparent FlClash TUN
flc ssh -d curl https://example.com

flc ssh -u home git ls-remote https://github.com/owner/repository.git

# Encrypted key plus SSH password (including publickey,password MFA servers)
flclash ssh add school A --user user --identity ~/.ssh/id_ed25519 --passphrase --password
flclash ssh list
flclash ssh test home
ALL_PROXY=socks5h://127.0.0.1:1080 curl https://example.com
flclash ssh disconnect home
```

`--local-port PORT` gives persistent connections a stable loopback SOCKS5
address for other local applications. Use `--local-port auto` to return to
automatic allocation. Temporary `flc ssh -u` tunnels always use an automatic
port, so they cannot steal the persistent application endpoint. Fixed-port
conflicts fail closed instead of silently choosing another port.
The relay counts bytes and active connections as they pass through, so the SSH
Dashboard can show 30-sample live traffic and cumulative totals without root,
eBPF, packet capture, or changes to the remote SSH server.

`flc ssh COMMAND` only hands traffic to the SSH host. The host decides whether
its Clash/TUN/routing policy handles the post-decryption connection. `flc ssh
-d COMMAND` is the explicit direct path: before executing, it invokes the
read-only `flclash ssh probe --json` capability on the headless SSH host and
refuses if FlClash is unavailable, incompatible, or reports a transparent TUN.
This fail-closed check prevents a TUN-captured flow from being labelled direct.
Both persistent and temporary (`flc ssh -u NAME`) commands support `-d`.

`flc ssh COMMAND` opens the default SSH profile, or the only configured
profile, as a persistent tunnel when none is connected. If the persistent
tunnel is present but its SOCKS5 listener is down, FlClash rebuilds it before
running the command. `flclash ssh connect` without a name uses the same
resolution. If that host already has a live OpenSSH ControlMaster (for example
`ControlMaster auto` in `~/.ssh/config`), connect reuses it: FlClash only adds a
dynamic SOCKS forward and the local traffic relay. `flclash ssh attach [NAME]`
does the same capture and never starts a second login; `--list` probes matching
masters. The TUI Capture row and `a` also probe only when you ask; idle refresh
and `ssh list` do not. Detach (`ssh disconnect` or `flclash exit`) cancels
the SOCKS forward and leaves the user's SSH session running. A plain interactive
`ssh user@host` without ControlMaster cannot be captured. `-u NAME` creates a
separate temporary tunnel for that command and
closes it afterwards; an existing persistent tunnel remains open. Commands must
support proxy environment variables and SOCKS5. Tunnel setup is fail-closed, so
a failed SSH connection never runs the command directly. `flclash ssh import`
copies concrete OpenSSH `Host` entries from `~/.ssh/config`. `--jump HOST`
sets ProxyJump without burying it in raw OpenSSH options. Connects time out in
15 seconds unless a profile option overrides `ConnectTimeout`.

`--user` is required for new profiles; the compatibility form `user@host` is
still accepted and split into Username and Host. Legacy bare-host profiles are
marked incomplete until a Username is added instead of silently inheriting the
current Linux user. `--passphrase` reads the private-key passphrase and
`--password` reads the SSH server login password; both are confirmed without
terminal echo and may coexist. Unencrypted keys need no passphrase. An encrypted
key without a saved passphrase prompts once in the TUI or CLI terminal and does
not save the answer. A specified key is tried before a saved login password,
which remains available for fallback or `publickey,password` MFA. Without a
saved login password, password authentication is disabled rather than allowing
OpenSSH to take over the terminal. Profiles are stored separately in mode-`0600` `.flclash-ssh.json`;
list/status/TUI/log output exposes only set flags or `********`. Key files,
ssh-agent, and safe `--option KEY=VALUE` OpenSSH settings are also supported.
New hosts default to `StrictHostKeyChecking=accept-new`: the first key is added
to `known_hosts`, while a later key change is rejected. Set an explicit
`StrictHostKeyChecking=...` profile option to override this policy.
OpenSSH stdout/stderr never writes directly over the TUI. Non-fatal diagnostics,
including post-quantum key-exchange warnings from newer OpenSSH releases, are
kept in Logs; connection failures show a short error with full sanitized output
available there.
WSL-mounted private keys commonly appear as mode `0777`, which OpenSSH refuses.
Copy such a key from `/mnt/c/...` into `~/.ssh/` and set mode `0600`; FlClash
detects open permissions before attempting authentication and reports this fix.

The SSH TUI page performs every management action without suspending or leaving
the full-screen interface. Its main view keeps a bordered profile list above
the selected profile's Dashboard. Tab cycles focus through sidebar, profile
list, and Dashboard; Shift+Tab reverses it. In the profile list, Enter connects
a disconnected or broken profile, while Enter on a healthy profile focuses its
Dashboard without disconnecting it. Press `n` to add, `e` to edit, `u` to set
or clear the default profile, or `x` to delete the selected profile. A `*`
marks the default profile used by `flc ssh` and `flclash ssh connect`. In the Dashboard, Up/Down selects Tunnel, Public
IP, SSH route, or Cloudflare download; Enter runs the selected action. `n`, `d`,
and `v` directly refresh the exit IP, run the five-sample route delay test, or
run the download speed test. The Dashboard also shows relay-only
live/cumulative traffic, active connections, and uptime. Esc moves Dashboard
focus back to the profile list, then back to the sidebar. In the form, use
`Up/Down` or `Tab` to select a row and
`Enter` to edit or confirm it. Key-passphrase and SSH-password replacements are
entered twice and stay masked; `c` stages removal of the selected secret.
OpenSSH options are separate rows: use the
add row to create one and `x` to remove the selected option. Select Save to
commit or press `Esc` to discard the form. Deletion also stays in the TUI and
requires `Enter` confirmation; `Esc` cancels it.

A connected SSH profile opens as `CONNECTED · READ ONLY`; disconnect it before
editing. `flclash ssh edit` enforces the same rule. Selecting another profile
is an explicit tunnel switch: FlClash stops the previous tunnel before starting
the new one, which also permits profiles to share one fixed local SOCKS5 port.
If the new tunnel fails, FlClash attempts to restore the previous tunnel and
reports both errors if restoration also fails. Concurrent editors are rejected
instead of silently overwriting a newer profile.

Live `flclash port PORT` changes are Backend transactions: target TCP/UDP availability, the new listener, old-listener closure, and managed System proxy are checked, with rollback on failure. Listener recreation is not a zero-gap handoff.

## TUI pages and keys

```text
1 Dashboard     Core/System proxy/TUN/Mode/Proxy port/network/memory/30-sample traffic chart
2 SSH            profile list and selected tunnel Dashboard shown together
3 Proxies       groups/nodes/Providers, selection, delay and speed tests
4 Profiles      import URL/local profile, activate, update, rename, edit, delete non-active
5 History        shared persistent flows, summaries, search/filter, details
6 Connections    active flows, summaries, search, details, confirmed close actions
7 Logs           persistent Backend + TUI events, search/filter/details/export/clear
8 Settings       complete traffic/Core/System proxy settings
9 Maintenance    YAML edit, backup/restore, Geo, traffic reset, update check
```

```text
←/→, Tab       switch navigation/content      ↑↓ or w/s    move
Enter           open/apply selected row        Esc           back
r / R           refresh / reload config         ?             help
[/]             Groups/Providers                PgUp/PgDn     Dashboard scroll
d / v           page-scoped delay / speed       n             network/import
/ / f           search / page-scoped filter
Ctrl+N          notification history/details
S / c / t / m   System proxy/Core/TUN/mode list p, +, -       Proxy port
U, F2/u, e      update/rename/edit Profile; SSH u sets default
x               delete Profile/SSH; clear page data
q               exit only this TUI               Ctrl+C        exit TUIs + Backend + Core + SSH
```

The Dashboard overlays upload (blue), download (green), and overlap (cyan) as
line-only curves above a white dotted baseline on one shared-scale, 30-sample
chart. The colored `↑` and `↓` speed values above the chart act as its legend.
`Rule route`/`Silent route` and `Cloudflare DL` are selectable with ↑/↓ or
`w`/`s`; Enter runs the selected test, while `d` and `v` remain direct shortcuts.
Compact terminals expose the chart and selected rows through automatic
Dashboard scrolling, and the layout remains operable down to `40x10`.
Long-running tests run outside the input loop; group speed tests are serial and
each node uses four download streams for at most 100 MB or five seconds. Delay
tests use five samples and show median/jitter when space permits.

Operation progress, results, warnings, and errors appear as non-blocking,
color-coded summaries at the lower right. `Ctrl+N` opens the latest 50 entries
inside the existing TUI frame: ↑/↓ selects an entry, PgUp/PgDn scrolls its full
message, Enter confirms it, and Esc returns to the unchanged underlying page.
Notifications are also written to Logs; repeated progress for one operation
updates and moves its existing history entry instead of creating duplicates.

Application events use timestamped INFO/WARN/ERROR records. The TUI reads the
persistent Backend log and its rotated backup through the private versioned IPC,
then merges current frontend events. The Backend log rotates at 5 MiB and keeps
one backup. `/` searches text, `f` filters levels, Enter opens the full record,
and clear removes both persistent files after confirmation. Subscription URLs,
YAML contents, and FLC credentials are not logged.

Selecting Mode, or pressing `m` on Dashboard/Settings, opens the `rule`, `silent`, `global`, and `direct` list before making any change. Use ↑/↓ or `w`/`s` and press Enter to confirm.

## Data and advanced external mode

Default data lives in `~/.config/flclash/`. The Backend socket and single-user ownership lock normally live in `/run/user/<UID>/flclash/`. `--directory` and `--config` select managed data; they do not create a second Backend.

To inspect a separately managed Mihomo instance:

```bash
flclash tui --no-start --controller 127.0.0.1:9090
flclash proxy groups --controller 127.0.0.1:9090
flclash proxy select --controller 127.0.0.1:9090 GROUP NODE
```

This external mode does not own FlClash's shared YAML, Backend, or System proxy. Keep external controllers bound securely and provide `--secret` where required.
