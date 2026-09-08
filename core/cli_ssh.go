//go:build linux && !cgo && cli

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	cliSSHConfigFilename       = ".flclash-ssh.json"
	cliSSHConfigLockFilename   = ".flclash-ssh.lock"
	cliSSHRuntimeDirectoryName = "ssh"
	cliSSHPersistentStateFile  = "persistent.json"
	cliSSHLastErrorFile        = "last-error.json"
	cliSSHConfigVersion        = 2
	cliSSHAskpassFileEnv       = "FLCLASH_SSH_ASKPASS_FILE"
	cliSSHRemoteProbeVersion   = 1
)

type cliExitCodeError struct{ code int }

func (e *cliExitCodeError) Error() string { return "" }
func (e *cliExitCodeError) ExitCode() int { return e.code }

type cliSSHProfile struct {
	Name               string   `json:"name"`
	Username           string   `json:"username,omitempty"`
	Host               string   `json:"host,omitempty"`
	Destination        string   `json:"-"`
	Port               int      `json:"port"`
	LocalPort          int      `json:"local_port,omitempty"`
	Jump               string   `json:"jump,omitempty"`
	Identity           string   `json:"identity,omitempty"`
	IdentityPassphrase string   `json:"identity_passphrase,omitempty"`
	Password           string   `json:"password,omitempty"`
	Options            []string `json:"options,omitempty"`
}

type cliSSHConfig struct {
	Version  int             `json:"version"`
	Default  string          `json:"default,omitempty"`
	Profiles []cliSSHProfile `json:"profiles"`
}

type cliSSHLastError struct {
	Name  string    `json:"name"`
	Error string    `json:"error"`
	At    time.Time `json:"at"`
}

type cliSSHTunnelState struct {
	Name         string    `json:"name"`
	Destination  string    `json:"destination"`
	Port         int       `json:"port"`
	UpstreamPort int       `json:"upstream_port,omitempty"`
	ControlPath  string    `json:"control_path"`
	RelayControl string    `json:"relay_control,omitempty"`
	RelayPID     int       `json:"relay_pid,omitempty"`
	Kind         string    `json:"kind"`
	StartedAt    time.Time `json:"started_at"`
	StatePath    string    `json:"-"`
}

type cliSSHProfileView struct {
	Name          string    `json:"name"`
	Username      string    `json:"username,omitempty"`
	Host          string    `json:"host,omitempty"`
	Destination   string    `json:"destination"`
	Port          int       `json:"port"`
	LocalPort     int       `json:"local_port,omitempty"`
	Jump          string    `json:"jump,omitempty"`
	Identity      string    `json:"identity,omitempty"`
	Options       []string  `json:"options,omitempty"`
	PassphraseSet bool      `json:"identity_passphrase_set"`
	PasswordSet   bool      `json:"password_set"`
	NeedsUsername bool      `json:"needs_username"`
	Default       bool      `json:"default,omitempty"`
	Connected     bool      `json:"connected"`
	Attached      bool      `json:"attached,omitempty"`
	Attachable    bool      `json:"attachable,omitempty"`
	Ready         bool      `json:"ready"`
	SocksPort     int       `json:"socks_port,omitempty"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
}

type cliSSHProfileEdit struct {
	Name, Username, Host, Destination            string
	Jump, Identity, IdentityPassphrase, Password string
	Port, LocalPort                              int
	Options                                      []string
	PortSet, LocalPortSet, IdentitySet           bool
	JumpSet, ClearJump                           bool
	PassphraseSet, ClearPassphrase               bool
	PasswordSet, ClearPassword, OptionsSet       bool
}

type cliSSHProfileJSON struct {
	Name               string   `json:"name"`
	Username           string   `json:"username,omitempty"`
	Host               string   `json:"host,omitempty"`
	Destination        string   `json:"destination,omitempty"`
	Port               int      `json:"port"`
	LocalPort          int      `json:"local_port,omitempty"`
	Jump               string   `json:"jump,omitempty"`
	Identity           string   `json:"identity,omitempty"`
	IdentityPassphrase string   `json:"identity_passphrase,omitempty"`
	Password           string   `json:"password,omitempty"`
	Options            []string `json:"options,omitempty"`
}

func (profile cliSSHProfile) MarshalJSON() ([]byte, error) {
	profile = normalizeCLISSHProfile(profile)
	return json.Marshal(cliSSHProfileJSON{
		Name:               profile.Name,
		Username:           profile.Username,
		Host:               profile.Host,
		Port:               profile.Port,
		LocalPort:          profile.LocalPort,
		Jump:               profile.Jump,
		Identity:           profile.Identity,
		IdentityPassphrase: profile.IdentityPassphrase,
		Password:           profile.Password,
		Options:            profile.Options,
	})
}

func (profile *cliSSHProfile) UnmarshalJSON(data []byte) error {
	var value cliSSHProfileJSON
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*profile = normalizeCLISSHProfile(cliSSHProfile{
		Name:               value.Name,
		Username:           value.Username,
		Host:               value.Host,
		Destination:        value.Destination,
		Port:               value.Port,
		LocalPort:          value.LocalPort,
		Jump:               value.Jump,
		Identity:           value.Identity,
		IdentityPassphrase: value.IdentityPassphrase,
		Password:           value.Password,
		Options:            value.Options,
	})
	return nil
}

func splitCLISSHDestination(destination string) (string, string) {
	destination = strings.TrimSpace(destination)
	separator := strings.LastIndex(destination, "@")
	if separator <= 0 || separator >= len(destination)-1 {
		return "", destination
	}
	return destination[:separator], destination[separator+1:]
}

func formatCLISSHDestination(username, host string) string {
	if username == "" {
		return host
	}
	return username + "@" + host
}

func normalizeCLISSHProfile(profile cliSSHProfile) cliSSHProfile {
	profile.Username = strings.TrimSpace(profile.Username)
	profile.Host = strings.TrimSpace(profile.Host)
	profile.Jump = strings.TrimSpace(profile.Jump)
	if profile.Host == "" && profile.Destination != "" {
		profile.Username, profile.Host = splitCLISSHDestination(profile.Destination)
	}
	profile.Destination = formatCLISSHDestination(profile.Username, profile.Host)
	return profile
}

type cliSSHAskpassSecrets struct {
	IdentityPassphrase string `json:"identity_passphrase,omitempty"`
	Password           string `json:"password,omitempty"`
}

type cliSSHCredentials struct {
	IdentityPassphrase string
}

// cliSSHRemoteProbe is intentionally small and read-only. It is executed on
// the SSH host before a direct command is allowed: once a remote transparent
// TUN is active, a normal SSH dynamic forward can no longer honestly promise
// to bypass that host's FlClash traffic policy.
type cliSSHRemoteProbe struct {
	ProtocolVersion int    `json:"protocol_version"`
	Available       bool   `json:"available"`
	Version         string `json:"version,omitempty"`
	BackendRunning  bool   `json:"backend_running"`
	CoreRunning     bool   `json:"core_running"`
	TunEnabled      bool   `json:"tun_enabled"`
	DirectAllowed   bool   `json:"direct_allowed"`
	IntranetIP      string `json:"intranet_ip,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

type cliSSHIdentityKind byte

const (
	cliSSHIdentityNone cliSSHIdentityKind = iota
	cliSSHIdentityUnencrypted
	cliSSHIdentityEncrypted
)

type cliSSHCredentialRequiredError struct {
	Profile  string
	Identity string
}

const cliSSHCommandOutputLimit = 64 * 1024

var cliSSHAskpassExecutable = os.Executable

type cliSSHCappedBuffer struct {
	buffer bytes.Buffer
}

func (buffer *cliSSHCappedBuffer) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := cliSSHCommandOutputLimit - buffer.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = buffer.buffer.Write(data)
	}
	return originalLength, nil
}

func (buffer *cliSSHCappedBuffer) String() string {
	return buffer.buffer.String()
}

func (err *cliSSHCredentialRequiredError) Error() string {
	return fmt.Sprintf(
		"private key %q is encrypted; enter its passphrase to connect",
		err.Identity,
	)
}

func sshManagementCommand(args []string) error {
	if len(args) == 0 || cliSubcommandHelp(args) {
		printSSHManagementUsage(os.Stdout)
		return nil
	}
	switch args[0] {
	case "add":
		return cliSSHAddCommand(args[1:])
	case "edit":
		return cliSSHEditCommand(args[1:])
	case "delete", "remove", "rm":
		return cliSSHDeleteCommand(args[1:])
	case "list", "ls":
		return cliSSHListCommand(args[1:])
	case "show":
		return cliSSHShowCommand(args[1:])
	case "connect", "open":
		return cliSSHConnectCommand(args[1:])
	case "disconnect", "close":
		return cliSSHDisconnectCommand(args[1:])
	case "status":
		return cliSSHStatusCommand(args[1:])
	case "test":
		return cliSSHTestCommand(args[1:])
	case "default":
		return cliSSHDefaultCommand(args[1:])
	case "import":
		return cliSSHImportCommand(args[1:])
	case "attach":
		return cliSSHAttachCommand(args[1:])
	case "probe":
		return cliSSHProbeCommand(args[1:])
	default:
		return fmt.Errorf("unknown ssh command %q; use `flclash ssh -help`", args[0])
	}
}

func printSSHManagementUsage(w io.Writer) {
	fmt.Fprintln(w, "Proxy local traffic through an SSH host's network exit.")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  flclash ssh add NAME HOST --user USER [--port PORT] [--local-port PORT|auto] [--jump HOST] [--identity PATH] [--passphrase] [--password] [--option KEY=VALUE]")
	fmt.Fprintln(w, "  flclash ssh add NAME user@host [OPTIONS]  # compatibility syntax")
	fmt.Fprintln(w, "  flclash ssh edit NAME [HOST] [--user USER] [OPTIONS]")
	fmt.Fprintln(w, "  flclash ssh import [HOST...] [--file PATH]")
	fmt.Fprintln(w, "  flclash ssh default [NAME|--clear]")
	fmt.Fprintln(w, "  flclash ssh delete|show NAME")
	fmt.Fprintln(w, "  flclash ssh list|status [--json]")
	fmt.Fprintln(w, "  flclash ssh connect [NAME]")
	fmt.Fprintln(w, "  flclash ssh attach [NAME] | --list")
	fmt.Fprintln(w, "  flclash ssh disconnect [NAME|all]")
	fmt.Fprintln(w, "  flclash ssh test [NAME]")
	fmt.Fprintln(w, "  flclash ssh probe --json  # read-only endpoint check for flc ssh -d")
	fmt.Fprintln(w, "`ssh add` with no arguments and `ssh edit NAME` open an interactive prompt.")
	fmt.Fprintln(w, "`ssh connect` and `flc ssh COMMAND` use the default profile, or the only profile, when NAME is omitted.")
	fmt.Fprintln(w, "`ssh connect` reuses a live OpenSSH ControlMaster for that host when one exists; `ssh attach` only captures, never starts a new login.")
	fmt.Fprintln(w, "A broken persistent tunnel is rebuilt automatically before `flc ssh COMMAND` runs.")
}

var (
	activeCLIPersistentSSHTunnelForCommand        = activeCLIPersistentSSHTunnel
	connectCLISSHProfileForCommand                = connectCLISSHProfile
	connectCLISSHProfileWithCredentialsForCommand = connectCLISSHProfileWithCredentials
	ensureCLIPersistentSSHTunnelForCommand        = ensureCLIPersistentSSHTunnel
	promptCLISSHSecretOnceForCommand              = promptCLISSHSecretOnce
	startCLITransientSSHTunnelForCommand          = startCLITransientSSHTunnel
	stopCLITransientSSHTunnelForCommand           = stopCLITransientSSHTunnel
	runCLICommandWithSSHProxyForCommand           = runCLICommandWithSSHProxy
	probeCLISSHRemoteForCommand                   = probeCLISSHRemote
)

func flcSSHCommand(args []string) error {
	if len(args) == 0 || cliSubcommandHelp(args) {
		printFLCSSHUsage(os.Stdout)
		return nil
	}
	profileName := ""
	direct := false
	for len(args) > 0 {
		switch {
		case args[0] == "-d" || args[0] == "--direct":
			direct = true
			args = args[1:]
		case args[0] == "-u" || args[0] == "--use":
			if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
				return errors.New("usage: flc ssh [-d] -u NAME COMMAND [ARG...]")
			}
			if profileName != "" {
				return errors.New("SSH profile may only be selected once")
			}
			profileName, args = args[1], args[2:]
		case strings.HasPrefix(args[0], "--use="):
			if profileName != "" || strings.TrimSpace(strings.TrimPrefix(args[0], "--use=")) == "" {
				return errors.New("SSH profile may only be selected once")
			}
			profileName, args = strings.TrimPrefix(args[0], "--use="), args[1:]
		default:
			goto command
		}
	}

command:
	if len(args) == 0 {
		return errors.New("flc ssh requires a local command")
	}
	if profileName != "" {
		profile, err := loadCLISSHProfile(profileName)
		if err != nil {
			return err
		}
		state, err := startCLITransientSSHTunnelForCommand(profile)
		if err != nil {
			state, err = startCLITransientSSHTunnelAfterPassphrase(profile, err)
		}
		if err != nil {
			return err
		}
		commandErr := runCLICommandThroughSSHForCommand(args, state, direct)
		stopErr := stopCLITransientSSHTunnelForCommand(state)
		return errors.Join(commandErr, stopErr)
	}
	state, err := ensureCLIPersistentSSHTunnelForCommand("")
	if err != nil {
		state, err = retryCLISSHConnectWithPassphrase("", err)
	}
	if err != nil {
		return err
	}
	if !cliSSHTunnelReady(state) {
		return fmt.Errorf(
			"SSH tunnel %q is connected but its SOCKS5 listener is unavailable",
			state.Name,
		)
	}
	return runCLICommandThroughSSHForCommand(args, state, direct)
}

func startCLITransientSSHTunnelAfterPassphrase(
	profile cliSSHProfile,
	err error,
) (cliSSHTunnelState, error) {
	passphrase, name, promptErr := promptCLISSHPassphraseFromError(err)
	if promptErr != nil {
		return cliSSHTunnelState{}, promptErr
	}
	if name != "" && !strings.EqualFold(name, profile.Name) {
		return cliSSHTunnelState{}, err
	}
	profile, prepErr := prepareCLISSHProfileCredentials(
		profile,
		cliSSHCredentials{IdentityPassphrase: passphrase},
	)
	if prepErr != nil {
		return cliSSHTunnelState{}, prepErr
	}
	return startCLITransientSSHTunnelForCommand(profile)
}

func retryCLISSHConnectWithPassphrase(
	name string,
	err error,
) (cliSSHTunnelState, error) {
	passphrase, profileName, promptErr := promptCLISSHPassphraseFromError(err)
	if promptErr != nil {
		return cliSSHTunnelState{}, promptErr
	}
	if name == "" {
		name = profileName
	}
	state, _, connErr := connectCLISSHProfileWithCredentialsForCommand(
		name,
		cliSSHCredentials{IdentityPassphrase: passphrase},
	)
	return state, connErr
}

func promptCLISSHPassphraseFromError(err error) (string, string, error) {
	var required *cliSSHCredentialRequiredError
	if !errors.As(err, &required) {
		return "", "", err
	}
	passphrase, promptErr := promptCLISSHSecretOnceForCommand("Private key passphrase")
	if promptErr != nil {
		return "", required.Profile, promptErr
	}
	return passphrase, required.Profile, nil
}

func ensureCLIPersistentSSHTunnel(name string) (cliSSHTunnelState, error) {
	state, active, err := activeCLIPersistentSSHTunnelForCommand()
	if err != nil {
		return cliSSHTunnelState{}, err
	}
	if active && cliSSHTunnelReady(state) &&
		(name == "" || strings.EqualFold(state.Name, name)) {
		return state, nil
	}
	if name == "" && active {
		name = state.Name
	}
	if name == "" {
		name, err = resolveCLISSHConnectName("")
		if err != nil {
			return cliSSHTunnelState{}, err
		}
	} else if !active || !strings.EqualFold(state.Name, name) {
		if _, err := resolveCLISSHConnectName(name); err != nil {
			return cliSSHTunnelState{}, err
		}
	}
	state, _, err = connectCLISSHProfileForCommand(name)
	if err != nil {
		return cliSSHTunnelState{}, fmt.Errorf("open SSH tunnel %q: %w", name, err)
	}
	if !cliSSHTunnelReady(state) {
		message := fmt.Sprintf(
			"SSH tunnel %q is connected but its SOCKS5 listener is unavailable",
			state.Name,
		)
		_ = saveCLISSHLastError(state.Name, message)
		return state, errors.New(message)
	}
	return state, nil
}

func resolveCLISSHConnectName(name string) (string, error) {
	name = strings.TrimSpace(name)
	config, err := loadCLISSHConfig()
	if err != nil {
		return "", err
	}
	if name != "" {
		if _, found := findCLISSHProfile(config.Profiles, name); !found {
			return "", fmt.Errorf("SSH profile %q does not exist; add it with `flclash ssh add` or `flclash ssh import`", name)
		}
		return name, nil
	}
	if defaultName := strings.TrimSpace(config.Default); defaultName != "" {
		if _, found := findCLISSHProfile(config.Profiles, defaultName); found {
			return defaultName, nil
		}
	}
	switch len(config.Profiles) {
	case 0:
		return "", errors.New("no SSH profiles configured; add one with `flclash ssh add` or `flclash ssh import`")
	case 1:
		return config.Profiles[0].Name, nil
	default:
		return "", errors.New("no SSH tunnel is open; run `flclash ssh connect NAME`, set a default with `flclash ssh default NAME`, or use `flc ssh -u NAME COMMAND`")
	}
}

func runCLICommandThroughSSHForCommand(
	args []string,
	state cliSSHTunnelState,
	direct bool,
) error {
	if direct {
		if err := requireCLISSHDirectExit(state); err != nil {
			return err
		}
	}
	return runCLICommandWithSSHProxyForCommand(args, state.Port)
}

func requireCLISSHDirectExit(state cliSSHTunnelState) error {
	probe, err := probeCLISSHRemoteForCommand(state)
	if err != nil {
		return fmt.Errorf("verify direct SSH exit on %q: %w", state.Name, err)
	}
	if probe.ProtocolVersion != cliSSHRemoteProbeVersion {
		return fmt.Errorf(
			"SSH host direct check is incompatible (protocol %d); update FlClash on the SSH host",
			probe.ProtocolVersion,
		)
	}
	if !probe.Available {
		reason := cliDisplayValue(probe.Reason)
		return fmt.Errorf(
			"SSH host cannot verify a direct exit: %s; start/update FlClash on the SSH host",
			reason,
		)
	}
	if !probe.DirectAllowed {
		reason := probe.Reason
		if reason == "" {
			reason = "transparent TUN is enabled"
		}
		return fmt.Errorf(
			"SSH direct exit refused: %s; use `flc ssh COMMAND` to follow the SSH host network policy",
			reason,
		)
	}
	return nil
}

func printFLCSSHUsage(w io.Writer) {
	fmt.Fprintln(w, "Run one local command through an SSH host's network policy.")
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  flc ssh COMMAND [ARG...]")
	fmt.Fprintln(w, "  flc ssh [-d|--direct] [-u NAME|--use NAME] COMMAND [ARG...]")
	fmt.Fprintln(w, "Without -u, a persistent tunnel is opened for the default or only SSH profile.")
	fmt.Fprintln(w, "A broken persistent tunnel is rebuilt before the command runs.")
	fmt.Fprintln(w, "-u creates a temporary tunnel which is always closed after the command.")
	fmt.Fprintln(w, "Without -d, the SSH host decides whether Clash/TUN/routing handles the flow.")
	fmt.Fprintln(w, "-d fails closed when the SSH host reports a transparent FlClash TUN.")
}

func cliSSHProbeCommand(args []string) error {
	if len(args) != 1 || args[0] != "--json" {
		return errors.New("usage: flclash ssh probe --json")
	}
	probe := cliSSHRemoteProbe{
		ProtocolVersion: cliSSHRemoteProbeVersion,
		Version:         cliVersion,
	}
	_, status, err := currentManagedServiceRaw()
	if err != nil {
		probe.Reason = "FlClash Backend is unavailable"
		return writeCLIJSON(os.Stdout, probe)
	}
	probe.Available = true
	probe.BackendRunning = true
	probe.CoreRunning = status.Running
	probe.TunEnabled = status.TunState == "on"
	probe.DirectAllowed = !probe.TunEnabled
	probe.IntranetIP = detectTUIIntranetIP()
	if probe.TunEnabled {
		probe.Reason = "FlClash transparent TUN is enabled"
	} else {
		probe.Reason = "FlClash TUN is off"
	}
	return writeCLIJSON(os.Stdout, probe)
}

func cliSSHAddCommand(args []string) error {
	edit, interactive, err := parseCLISSHProfileEdit(args, false)
	if err != nil {
		return err
	}
	if interactive {
		edit, err = promptCLISSHProfile(cliSSHProfile{}, false)
		if err != nil {
			return err
		}
	}
	profile, err := cliSSHProfileFromEdit(cliSSHProfile{}, edit, false)
	if err != nil {
		return err
	}
	err = addCLISSHProfile(profile)
	if err == nil {
		fmt.Printf("SSH profile %s added (%s)\n", profile.Name, profile.Destination)
	}
	return err
}

func cliSSHEditCommand(args []string) error {
	if len(args) == 0 || cliSubcommandHelp(args) {
		return errors.New("usage: flclash ssh edit NAME [HOST] [--user USER] [OPTIONS]")
	}
	existing, err := loadCLISSHProfile(args[0])
	if err != nil {
		return err
	}
	if connected, err := cliSSHProfileConnected(existing.Name); err != nil {
		return err
	} else if connected {
		return fmt.Errorf(
			"SSH profile %q is connected; disconnect it before editing",
			existing.Name,
		)
	}
	originalFingerprint, err := cliSSHProfileFingerprint(existing)
	if err != nil {
		return err
	}
	edit, interactive, err := parseCLISSHProfileEdit(args, true)
	if err != nil {
		return err
	}
	if interactive {
		edit, err = promptCLISSHProfile(existing, true)
		if err != nil {
			return err
		}
	}
	updated, err := cliSSHProfileFromEdit(existing, edit, true)
	if err != nil {
		return err
	}
	err = replaceCLISSHProfile(args[0], originalFingerprint, updated)
	if err == nil {
		fmt.Printf("SSH profile %s updated\n", updated.Name)
	}
	return err
}

func cliSSHDeleteCommand(args []string) error {
	if len(args) != 1 || cliSubcommandHelp(args) {
		return errors.New("usage: flclash ssh delete NAME")
	}
	err := deleteCLISSHProfile(args[0])
	if err == nil {
		fmt.Printf("SSH profile %s deleted\n", args[0])
	}
	return err
}

func cliSSHListCommand(args []string) error {
	jsonOutput := len(args) == 1 && args[0] == "--json"
	if len(args) > 0 && !jsonOutput {
		return errors.New("usage: flclash ssh list [--json]")
	}
	views, err := loadCLISSHProfileViews()
	if err != nil {
		return err
	}
	if jsonOutput {
		return writeCLIJSON(os.Stdout, views)
	}
	if len(views) == 0 {
		fmt.Println("No SSH profiles configured")
		return nil
	}
	for _, view := range views {
		status, endpoint := "DISCONNECTED", ""
		marker := "  "
		if view.Default {
			marker = "* "
		}
		if view.NeedsUsername {
			status, endpoint = "NEEDS USER", " · edit before connecting"
		} else if view.Connected && view.Ready {
			configured := "auto"
			if view.LocalPort > 0 {
				configured = strconv.Itoa(view.LocalPort)
			}
			status = "CONNECTED"
			if view.Attached {
				status = "ATTACHED"
			}
			endpoint = fmt.Sprintf(
				" · SOCKS5 127.0.0.1:%d · configured %s",
				view.SocksPort,
				configured,
			)
		} else if view.Connected {
			status, endpoint = "BROKEN", fmt.Sprintf(
				" · SOCKS5 127.0.0.1:%d unavailable",
				view.SocksPort,
			)
		} else if view.LocalPort > 0 {
			endpoint = fmt.Sprintf(" · local 127.0.0.1:%d", view.LocalPort)
		} else {
			endpoint = " · local auto"
		}
		if view.Jump != "" {
			endpoint += " · via " + view.Jump
		}
		if view.LastError != "" && !(view.Connected && view.Ready) {
			endpoint += " · last error: " + view.LastError
		}
		auth := cliSSHAuthenticationLabel(
			view.Identity,
			view.PassphraseSet,
			view.PasswordSet,
		)
		fmt.Printf("%s%-16s %-12s %-28s · %s%s\n", marker, view.Name, status, view.Destination, auth, endpoint)
	}
	return nil
}

func cliSSHShowCommand(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: flclash ssh show NAME [--json]")
	}
	views, err := loadCLISSHProfileViews()
	if err != nil {
		return err
	}
	for _, view := range views {
		if !strings.EqualFold(view.Name, args[0]) {
			continue
		}
		if len(args) == 2 {
			if args[1] != "--json" {
				return fmt.Errorf("unknown option %q", args[1])
			}
			return writeCLIJSON(os.Stdout, view)
		}
		localPort := "auto"
		if view.LocalPort > 0 {
			localPort = strconv.Itoa(view.LocalPort)
		}
		fmt.Printf(
			"Name:                  %s\nDefault:               %s\nSSH username:          %s\nSSH host:              %s\nJump host:             %s\nSSH port:              %d\nLocal SOCKS:           %s\nIdentity(private key): %s\nKey passphrase:        %s\nSSH password:          %s\nConnected:             %s\nSOCKS5 ready:          %s\n",
			view.Name,
			cliOnOff(view.Default),
			cliDisplayValue(view.Username),
			view.Host,
			cliDisplayValue(view.Jump),
			view.Port,
			localPort,
			cliDisplayValue(view.Identity),
			cliSSHMaskedSecret(view.PassphraseSet),
			cliSSHMaskedSecret(view.PasswordSet),
			cliOnOff(view.Connected),
			cliOnOff(view.Ready),
		)
		if view.SocksPort > 0 {
			fmt.Printf("SOCKS5:      127.0.0.1:%d\n", view.SocksPort)
		}
		if view.LastError != "" {
			fmt.Printf("Last error:            %s\n", view.LastError)
		}
		return nil
	}
	return fmt.Errorf("SSH profile %q does not exist", args[0])
}

func cliSSHConnectCommand(args []string) error {
	if cliSubcommandHelp(args) || len(args) > 1 {
		return errors.New("usage: flclash ssh connect [NAME]")
	}
	name := firstCLIArgument(args)
	resolved, err := resolveCLISSHConnectName(name)
	if err != nil {
		return err
	}
	state, alreadyConnected, err := connectCLISSHProfile(resolved)
	if err != nil {
		state, err = retryCLISSHConnectWithPassphrase(resolved, err)
		alreadyConnected = false
	}
	if err != nil {
		return err
	}
	if alreadyConnected {
		fmt.Printf("SSH %s already connected · SOCKS5 127.0.0.1:%d\n", state.Name, state.Port)
		return nil
	}
	if state.Kind == cliSSHAttachedKind {
		fmt.Printf("SSH %s attached · SOCKS5 127.0.0.1:%d\n", state.Name, state.Port)
		return nil
	}
	fmt.Printf("SSH %s connected · SOCKS5 127.0.0.1:%d\n", state.Name, state.Port)
	return nil
}

func cliSSHDisconnectCommand(args []string) error {
	if len(args) > 1 {
		return errors.New("usage: flclash ssh disconnect [NAME|all]")
	}
	if len(args) == 1 && args[0] == "all" {
		if err := stopAllCLISSHTunnels(); err != nil {
			return err
		}
		fmt.Println("All SSH tunnels disconnected")
		return nil
	}
	state, disconnected, err := disconnectCLISSHProfile(firstCLIArgument(args))
	if err != nil {
		return err
	}
	if !disconnected {
		fmt.Println("No persistent SSH tunnel is open")
		return nil
	}
	fmt.Printf("SSH %s disconnected\n", state.Name)
	return nil
}

func cliSSHStatusCommand(args []string) error {
	if len(args) == 0 {
		return cliSSHListCommand(nil)
	}
	if len(args) == 1 && args[0] == "--json" {
		return cliSSHListCommand(args)
	}
	return cliSSHShowCommand(args)
}

func cliSSHTestCommand(args []string) error {
	if len(args) > 1 {
		return errors.New("usage: flclash ssh test [NAME]")
	}
	state, latency, err := testCLISSHProfile(firstCLIArgument(args))
	if err != nil {
		return err
	}
	fmt.Printf("SSH %s ready · SOCKS5 127.0.0.1:%d · handshake %s\n", state.Name, state.Port, latency)
	return nil
}

func cliSSHDefaultCommand(args []string) error {
	if cliSubcommandHelp(args) || len(args) > 1 {
		return errors.New("usage: flclash ssh default [NAME|--clear]")
	}
	if len(args) == 0 {
		config, err := loadCLISSHConfig()
		if err != nil {
			return err
		}
		if strings.TrimSpace(config.Default) == "" {
			fmt.Println("No default SSH profile")
			return nil
		}
		fmt.Printf("Default SSH profile %s\n", config.Default)
		return nil
	}
	if args[0] == "--clear" || args[0] == "clear" {
		if err := setCLISSHDefault(""); err != nil {
			return err
		}
		fmt.Println("Default SSH profile cleared")
		return nil
	}
	if err := setCLISSHDefault(args[0]); err != nil {
		return err
	}
	fmt.Printf("Default SSH profile %s\n", args[0])
	return nil
}

func firstCLIArgument(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func cliSSHAuthenticationLabel(identity string, passphraseSet, passwordSet bool) string {
	if identity != "" {
		key := "key"
		if passphraseSet {
			key += " + passphrase ****"
		}
		if passwordSet {
			return key + " → password **** fallback/MFA"
		}
		return key + " only"
	}
	if passwordSet {
		return "password **** only"
	}
	return "agent/default key only"
}

func parseCLISSHProfileEdit(args []string, editing bool) (cliSSHProfileEdit, bool, error) {
	edit := cliSSHProfileEdit{Port: 22}
	if len(args) == 0 {
		return edit, true, nil
	}
	arguments := make(map[string]bool, len(args))
	for _, argument := range args {
		arguments[argument] = true
	}
	if arguments["--passphrase"] && arguments["--clear-passphrase"] {
		return edit, false, errors.New("--passphrase and --clear-passphrase cannot be used together")
	}
	if arguments["--password"] && arguments["--clear-password"] {
		return edit, false, errors.New("--password and --clear-password cannot be used together")
	}
	jumpAssigned := arguments["--jump"]
	for argument := range arguments {
		if strings.HasPrefix(argument, "--jump=") {
			jumpAssigned = true
		}
	}
	if jumpAssigned && arguments["--clear-jump"] {
		return edit, false, errors.New("--jump and --clear-jump cannot be used together")
	}
	positionals := []string{}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		next := func() (string, error) {
			if index+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", argument)
			}
			index++
			return args[index], nil
		}
		switch {
		case argument == "--port":
			value, err := next()
			if err != nil {
				return edit, false, err
			}
			edit.Port, err = strconv.Atoi(value)
			if err != nil || edit.Port < 1 || edit.Port > 65535 {
				return edit, false, fmt.Errorf("invalid SSH port %q", value)
			}
			edit.PortSet = true
		case strings.HasPrefix(argument, "--port="):
			value := strings.TrimPrefix(argument, "--port=")
			var err error
			edit.Port, err = strconv.Atoi(value)
			if err != nil || edit.Port < 1 || edit.Port > 65535 {
				return edit, false, fmt.Errorf("invalid SSH port %q", value)
			}
			edit.PortSet = true
		case argument == "--local-port":
			value, err := next()
			if err != nil {
				return edit, false, err
			}
			edit.LocalPort, err = parseCLISSHLocalPort(value)
			if err != nil {
				return edit, false, err
			}
			edit.LocalPortSet = true
		case strings.HasPrefix(argument, "--local-port="):
			value := strings.TrimPrefix(argument, "--local-port=")
			var err error
			edit.LocalPort, err = parseCLISSHLocalPort(value)
			if err != nil {
				return edit, false, err
			}
			edit.LocalPortSet = true
		case argument == "--jump":
			value, err := next()
			if err != nil {
				return edit, false, err
			}
			edit.Jump = value
			edit.JumpSet = true
		case strings.HasPrefix(argument, "--jump="):
			edit.Jump = strings.TrimPrefix(argument, "--jump=")
			edit.JumpSet = true
		case argument == "--clear-jump":
			edit.ClearJump = true
		case argument == "--identity":
			value, err := next()
			if err != nil {
				return edit, false, err
			}
			edit.Identity = value
			edit.IdentitySet = true
		case strings.HasPrefix(argument, "--identity="):
			edit.Identity = strings.TrimPrefix(argument, "--identity=")
			edit.IdentitySet = true
		case argument == "--user":
			value, err := next()
			if err != nil {
				return edit, false, err
			}
			edit.Username = strings.TrimSpace(value)
		case strings.HasPrefix(argument, "--user="):
			edit.Username = strings.TrimSpace(strings.TrimPrefix(argument, "--user="))
		case argument == "--passphrase":
			value, err := promptCLISSHSecret("Private key passphrase")
			if err != nil {
				return edit, false, err
			}
			edit.IdentityPassphrase, edit.PassphraseSet = value, true
		case argument == "--clear-passphrase":
			edit.ClearPassphrase = true
		case argument == "--option":
			value, err := next()
			if err != nil {
				return edit, false, err
			}
			if err := validateCLISSHOption(value); err != nil {
				return edit, false, err
			}
			edit.Options = append(edit.Options, value)
			edit.OptionsSet = true
		case strings.HasPrefix(argument, "--option="):
			value := strings.TrimPrefix(argument, "--option=")
			if err := validateCLISSHOption(value); err != nil {
				return edit, false, err
			}
			edit.Options = append(edit.Options, value)
			edit.OptionsSet = true
		case argument == "--password":
			value, err := promptCLISSHSecret("SSH password")
			if err != nil {
				return edit, false, err
			}
			edit.Password, edit.PasswordSet = value, true
		case argument == "--clear-password":
			edit.ClearPassword = true
		case strings.HasPrefix(argument, "-"):
			return edit, false, fmt.Errorf("unknown SSH profile option %q", argument)
		default:
			positionals = append(positionals, argument)
		}
	}
	if !editing && edit.ClearPassphrase {
		return edit, false, errors.New("--clear-passphrase is only valid with `ssh edit`")
	}
	if !editing && edit.ClearPassword {
		return edit, false, errors.New("--clear-password is only valid with `ssh edit`")
	}
	if !editing && edit.ClearJump {
		return edit, false, errors.New("--clear-jump is only valid with `ssh edit`")
	}
	if editing {
		if len(positionals) < 1 || len(positionals) > 2 {
			return edit, false, errors.New("usage: flclash ssh edit NAME [HOST] [--user USER] [OPTIONS]")
		}
		edit.Name = positionals[0]
		if len(positionals) == 2 {
			parsedUser, parsedHost := splitCLISSHDestination(positionals[1])
			if edit.Username != "" && parsedUser != "" && edit.Username != parsedUser {
				return edit, false, errors.New("SSH username conflicts with user@host destination")
			}
			if edit.Username == "" {
				edit.Username = parsedUser
			}
			edit.Host = parsedHost
			edit.Destination = formatCLISSHDestination(edit.Username, edit.Host)
		}
		return edit, len(args) == 1, nil
	}
	if len(positionals) != 2 {
		return edit, false, errors.New("usage: flclash ssh add NAME HOST --user USER [OPTIONS]")
	}
	edit.Name = positionals[0]
	parsedUser, parsedHost := splitCLISSHDestination(positionals[1])
	if edit.Username != "" && parsedUser != "" && edit.Username != parsedUser {
		return edit, false, errors.New("SSH username conflicts with user@host destination")
	}
	if edit.Username == "" {
		edit.Username = parsedUser
	}
	edit.Host = parsedHost
	edit.Destination = formatCLISSHDestination(edit.Username, edit.Host)
	return edit, false, nil
}

func cliSSHProfileFromEdit(existing cliSSHProfile, edit cliSSHProfileEdit, editing bool) (cliSSHProfile, error) {
	profile := existing
	if edit.Name != "" {
		profile.Name = edit.Name
	}
	if edit.Host != "" || edit.Destination != "" {
		profile.Host = edit.Host
		if profile.Host == "" {
			_, profile.Host = splitCLISSHDestination(edit.Destination)
		}
	}
	if edit.Username != "" || !editing {
		profile.Username = edit.Username
	}
	if !editing || edit.PortSet || existing.Port == 0 {
		profile.Port = edit.Port
	}
	if !editing || edit.LocalPortSet {
		profile.LocalPort = edit.LocalPort
	}
	if edit.JumpSet || !editing {
		profile.Jump = edit.Jump
	} else if edit.ClearJump {
		profile.Jump = ""
	}
	if edit.IdentitySet || !editing {
		profile.Identity = edit.Identity
	}
	if edit.PassphraseSet {
		profile.IdentityPassphrase = edit.IdentityPassphrase
	} else if edit.ClearPassphrase {
		profile.IdentityPassphrase = ""
	}
	if edit.OptionsSet || !editing {
		profile.Options = append([]string(nil), edit.Options...)
	}
	if edit.PasswordSet {
		profile.Password = edit.Password
	} else if edit.ClearPassword {
		profile.Password = ""
	}
	if profile.Port == 0 {
		profile.Port = 22
	}
	profile = normalizeCLISSHProfile(profile)
	return profile, validateCLISSHProfile(profile)
}

func parseCLISSHLocalPort(value string) (int, error) {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "auto") || value == "0" {
		return 0, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid local SOCKS5 port %q; use 1-65535 or auto", value)
	}
	return port, nil
}

func addCLISSHProfile(profile cliSSHProfile) error {
	profile = normalizeCLISSHProfile(profile)
	if err := validateCLISSHProfile(profile); err != nil {
		return err
	}
	return updateCLISSHConfig(func(config *cliSSHConfig) error {
		if _, found := findCLISSHProfile(config.Profiles, profile.Name); found {
			return fmt.Errorf("SSH profile %q already exists", profile.Name)
		}
		profile.Options = append([]string(nil), profile.Options...)
		config.Profiles = append(config.Profiles, profile)
		sort.Slice(config.Profiles, func(i, j int) bool {
			return strings.ToLower(config.Profiles[i].Name) <
				strings.ToLower(config.Profiles[j].Name)
		})
		if strings.TrimSpace(config.Default) == "" {
			config.Default = profile.Name
		}
		return nil
	})
}

func cliSSHProfileFingerprint(profile cliSSHProfile) (string, error) {
	data, err := json.Marshal(profile)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:]), nil
}

func replaceCLISSHProfile(
	originalName,
	expectedFingerprint string,
	profile cliSSHProfile,
) error {
	profile = normalizeCLISSHProfile(profile)
	if err := validateCLISSHProfile(profile); err != nil {
		return err
	}
	lock, err := lockCLISSHTunnelOperation()
	if err != nil {
		return err
	}
	defer lock.release()
	if state, active, stateErr := activeCLIPersistentSSHTunnelForOperation(); stateErr != nil {
		return stateErr
	} else if active && strings.EqualFold(state.Name, originalName) {
		return fmt.Errorf(
			"SSH profile %q is connected; disconnect it before editing",
			originalName,
		)
	}
	return updateCLISSHConfigForOperation(func(config *cliSSHConfig) error {
		index, found := findCLISSHProfile(config.Profiles, originalName)
		if !found {
			return fmt.Errorf("SSH profile %q does not exist", originalName)
		}
		fingerprint, err := cliSSHProfileFingerprint(config.Profiles[index])
		if err != nil {
			return err
		}
		if expectedFingerprint != "" && fingerprint != expectedFingerprint {
			return fmt.Errorf(
				"SSH profile %q changed in another frontend; reopen it before saving",
				originalName,
			)
		}
		if other, duplicate := findCLISSHProfile(config.Profiles, profile.Name); duplicate && other != index {
			return fmt.Errorf("SSH profile %q already exists", profile.Name)
		}
		profile.Options = append([]string(nil), profile.Options...)
		config.Profiles[index] = profile
		if strings.EqualFold(config.Default, originalName) {
			config.Default = profile.Name
		}
		sort.Slice(config.Profiles, func(i, j int) bool {
			return strings.ToLower(config.Profiles[i].Name) <
				strings.ToLower(config.Profiles[j].Name)
		})
		return nil
	})
}

func deleteCLISSHProfile(name string) error {
	lock, err := lockCLISSHTunnelOperation()
	if err != nil {
		return err
	}
	defer lock.release()
	profile, err := loadCLISSHProfile(name)
	if err != nil {
		return err
	}
	state, active, err := activeCLIPersistentSSHTunnelForOperation()
	if err != nil {
		return err
	}
	wasConnected := active && strings.EqualFold(state.Name, name)
	if wasConnected {
		if err := stopCLIStateTunnelForOperation(state); err != nil {
			return err
		}
	}
	err = updateCLISSHConfigForOperation(func(config *cliSSHConfig) error {
		index, found := findCLISSHProfile(config.Profiles, name)
		if !found {
			return fmt.Errorf("SSH profile %q does not exist", name)
		}
		config.Profiles = append(config.Profiles[:index], config.Profiles[index+1:]...)
		if strings.EqualFold(config.Default, name) {
			config.Default = ""
		}
		return nil
	})
	if err == nil || !wasConnected {
		return err
	}
	_, restoreErr := startCLIPersistentSSHTunnelForOperation(profile)
	if restoreErr != nil {
		return fmt.Errorf(
			"delete SSH profile %q: %v; restore previous tunnel: %w",
			name,
			err,
			restoreErr,
		)
	}
	return fmt.Errorf(
		"delete SSH profile %q: %w; previous tunnel restored",
		name,
		err,
	)
}

var (
	activeCLIPersistentSSHTunnelForOperation = activeCLIPersistentSSHTunnel
	startCLIPersistentSSHTunnelForOperation  = startCLIPersistentSSHTunnel
	stopCLIStateTunnelForOperation           = stopCLIStateTunnel
	updateCLISSHConfigForOperation           = updateCLISSHConfig
	addCLISSHDynamicForwardForOperation      = addCLISSHDynamicForward
	startCLISSHRelayForOperation             = startCLISSHRelay
)

func cliSSHProfileConnected(name string) (bool, error) {
	state, active, err := activeCLIPersistentSSHTunnelForOperation()
	if err != nil {
		return false, err
	}
	return active && strings.EqualFold(state.Name, name), nil
}

func connectCLISSHProfile(name string) (cliSSHTunnelState, bool, error) {
	return connectCLISSHProfileWithCredentials(name, cliSSHCredentials{})
}

func connectCLISSHProfileWithCredentials(
	name string,
	credentials cliSSHCredentials,
) (cliSSHTunnelState, bool, error) {
	lock, err := lockCLISSHTunnelOperation()
	if err != nil {
		return cliSSHTunnelState{}, false, err
	}
	defer lock.release()
	profile, err := loadCLISSHProfile(name)
	if err != nil {
		_ = saveCLISSHLastError(name, err.Error())
		return cliSSHTunnelState{}, false, err
	}
	profile, err = prepareCLISSHProfileCredentials(profile, credentials)
	if err != nil {
		_ = saveCLISSHLastError(profile.Name, err.Error())
		return cliSSHTunnelState{}, false, err
	}
	old, oldActive, err := activeCLIPersistentSSHTunnelForOperation()
	if err != nil {
		return cliSSHTunnelState{}, false, err
	}
	if oldActive && strings.EqualFold(old.Name, profile.Name) {
		if cliSSHTunnelReady(old) {
			_ = clearCLISSHLastError(profile.Name)
			return old, true, nil
		}
		if err := stopCLIStateTunnelForOperation(old); err != nil {
			_ = saveCLISSHLastError(old.Name, err.Error())
			return cliSSHTunnelState{}, false,
				fmt.Errorf("stop broken SSH tunnel %q: %w", old.Name, err)
		}
		state, err := startCLIPersistentSSHTunnelForOperation(profile)
		if err != nil {
			_ = saveCLISSHLastError(profile.Name, err.Error())
			return cliSSHTunnelState{}, false,
				fmt.Errorf("restart broken SSH tunnel %q: %w", profile.Name, err)
		}
		_ = clearCLISSHLastError(profile.Name)
		return state, false, nil
	}
	var oldProfile cliSSHProfile
	if oldActive {
		oldProfile, err = loadCLISSHProfile(old.Name)
		if err != nil {
			return cliSSHTunnelState{}, false, fmt.Errorf(
				"active SSH profile %q cannot be restored; disconnect it before switching: %w",
				old.Name,
				err,
			)
		}
		if err := stopCLIStateTunnelForOperation(old); err != nil {
			return cliSSHTunnelState{}, false,
				fmt.Errorf("stop previous SSH tunnel %q: %w", old.Name, err)
		}
	}
	state, err := startCLIPersistentSSHTunnelForOperation(profile)
	if err == nil {
		_ = clearCLISSHLastError(profile.Name)
		return state, false, nil
	}
	_ = saveCLISSHLastError(profile.Name, err.Error())
	if !oldActive {
		return cliSSHTunnelState{}, false, err
	}
	_, restoreErr := startCLIPersistentSSHTunnelForOperation(oldProfile)
	if restoreErr != nil {
		return cliSSHTunnelState{}, false, fmt.Errorf(
			"connect SSH profile %q: %v; restore previous tunnel %q: %w",
			profile.Name,
			err,
			old.Name,
			restoreErr,
		)
	}
	return cliSSHTunnelState{}, false, fmt.Errorf(
		"connect SSH profile %q: %w; previous tunnel %q restored",
		profile.Name,
		err,
		old.Name,
	)
}

func disconnectCLISSHProfile(name string) (cliSSHTunnelState, bool, error) {
	lock, err := lockCLISSHTunnelOperation()
	if err != nil {
		return cliSSHTunnelState{}, false, err
	}
	defer lock.release()
	state, active, err := activeCLIPersistentSSHTunnelForOperation()
	if err != nil {
		return cliSSHTunnelState{}, false, err
	}
	if !active {
		return cliSSHTunnelState{}, false, nil
	}
	if name != "" && !strings.EqualFold(name, state.Name) {
		return cliSSHTunnelState{}, false,
			fmt.Errorf("SSH profile %q is not connected", name)
	}
	if err := stopCLIStateTunnelForOperation(state); err != nil {
		return cliSSHTunnelState{}, false, err
	}
	return state, true, nil
}

func testCLISSHProfile(name string) (cliSSHTunnelState, time.Duration, error) {
	resolved, err := resolveCLISSHConnectName(name)
	if err != nil {
		return cliSSHTunnelState{}, 0, err
	}
	started := time.Now()
	state, err := ensureCLIPersistentSSHTunnel(resolved)
	if err != nil {
		state, err = retryCLISSHConnectWithPassphrase(resolved, err)
	}
	if err != nil {
		return cliSSHTunnelState{}, 0, err
	}
	if err := probeCLISSHSOCKS(state.Port, 2*time.Second); err != nil {
		return state, 0, fmt.Errorf("SSH SOCKS5 handshake failed: %w", err)
	}
	return state, time.Since(started).Round(time.Millisecond), nil
}

func setCLISSHDefault(name string) error {
	name = strings.TrimSpace(name)
	return updateCLISSHConfig(func(config *cliSSHConfig) error {
		if name == "" {
			config.Default = ""
			return nil
		}
		if _, found := findCLISSHProfile(config.Profiles, name); !found {
			return fmt.Errorf("SSH profile %q does not exist", name)
		}
		config.Default = name
		return nil
	})
}

func promptCLISSHProfile(existing cliSSHProfile, editing bool) (cliSSHProfileEdit, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return cliSSHProfileEdit{}, errors.New("interactive SSH profile input requires a terminal")
	}
	reader := bufio.NewReader(os.Stdin)
	edit := cliSSHProfileEdit{Port: 22}
	var err error
	edit.Name, err = promptCLISSHLine(reader, "Name", existing.Name, false)
	if err != nil {
		return edit, err
	}
	edit.Username, err = promptCLISSHLine(reader, "SSH username", existing.Username, false)
	if err != nil {
		return edit, err
	}
	edit.Host, err = promptCLISSHLine(reader, "SSH host or alias", existing.Host, false)
	if err != nil {
		return edit, err
	}
	edit.Destination = formatCLISSHDestination(edit.Username, edit.Host)
	edit.Jump, err = promptCLISSHLine(reader, "Jump host (optional)", existing.Jump, true)
	if err != nil {
		return edit, err
	}
	edit.JumpSet = true
	port := existing.Port
	if port == 0 {
		port = 22
	}
	portText, err := promptCLISSHLine(reader, "SSH port", strconv.Itoa(port), false)
	if err != nil {
		return edit, err
	}
	edit.Port, err = strconv.Atoi(portText)
	if err != nil || edit.Port < 1 || edit.Port > 65535 {
		return edit, fmt.Errorf("invalid SSH port %q", portText)
	}
	edit.PortSet = true
	localPortText := "auto"
	if existing.LocalPort > 0 {
		localPortText = strconv.Itoa(existing.LocalPort)
	}
	localPortText, err = promptCLISSHLine(
		reader,
		"Local SOCKS5 port (auto or 1-65535)",
		localPortText,
		false,
	)
	if err != nil {
		return edit, err
	}
	edit.LocalPort, err = parseCLISSHLocalPort(localPortText)
	if err != nil {
		return edit, err
	}
	edit.LocalPortSet = true
	edit.Identity, err = promptCLISSHLine(reader, "Identity (private key, optional)", existing.Identity, true)
	if err != nil {
		return edit, err
	}
	edit.IdentitySet = true
	answer, err := promptCLISSHLine(reader, "Save/replace private key passphrase? [y/N]", "n", true)
	if err != nil {
		return edit, err
	}
	if strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes") {
		edit.IdentityPassphrase, err = promptCLISSHSecret("Private key passphrase")
		edit.PassphraseSet = err == nil
		if err != nil {
			return edit, err
		}
	}
	if editing && existing.IdentityPassphrase != "" && !edit.PassphraseSet {
		answer, err = promptCLISSHLine(
			reader,
			"Clear saved private key passphrase? [y/N]",
			"n",
			true,
		)
		if err != nil {
			return edit, err
		}
		edit.ClearPassphrase = strings.EqualFold(answer, "y") ||
			strings.EqualFold(answer, "yes")
	}
	answer, err = promptCLISSHLine(reader, "Save/replace SSH password? [y/N]", "n", true)
	if err != nil {
		return edit, err
	}
	if strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes") {
		edit.Password, err = promptCLISSHSecret("SSH password")
		edit.PasswordSet = err == nil
		if err != nil {
			return edit, err
		}
	}
	if editing && existing.Password != "" && !edit.PasswordSet {
		answer, err = promptCLISSHLine(
			reader,
			"Clear saved password? [y/N]",
			"n",
			true,
		)
		if err != nil {
			return edit, err
		}
		edit.ClearPassword = strings.EqualFold(answer, "y") ||
			strings.EqualFold(answer, "yes")
	}
	if editing {
		edit.Options, edit.OptionsSet = append([]string(nil), existing.Options...), true
	}
	return edit, nil
}

func promptCLISSHLine(reader *bufio.Reader, label, defaultValue string, optional bool) (string, error) {
	if defaultValue == "" {
		fmt.Fprintf(os.Stderr, "%s: ", label)
	} else {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, defaultValue)
	}
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		value = defaultValue
	}
	if value == "" && !optional {
		return "", fmt.Errorf("%s must not be empty", label)
	}
	return value, nil
}

func promptCLISSHSecret(label string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("%s requires an interactive terminal", label)
	}
	fmt.Fprintf(os.Stderr, "%s: ", label)
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "Confirm %s: ", strings.ToLower(label))
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(first) == 0 {
		return "", fmt.Errorf("%s must not be empty", strings.ToLower(label))
	}
	if string(first) != string(second) {
		return "", fmt.Errorf("%s values do not match", strings.ToLower(label))
	}
	return string(first), nil
}

func promptCLISSHSecretOnce(label string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("%s requires an interactive terminal", label)
	}
	fmt.Fprintf(os.Stderr, "%s: ", label)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(value) == 0 {
		return "", fmt.Errorf("%s must not be empty", strings.ToLower(label))
	}
	return string(value), nil
}

func validateCLISSHProfile(profile cliSSHProfile) error {
	profile = normalizeCLISSHProfile(profile)
	if err := validateCLISSHProfileStructure(profile); err != nil {
		return err
	}
	if profile.Username == "" {
		return errors.New("SSH username is required")
	}
	if profile.Identity == "" && profile.IdentityPassphrase != "" {
		return errors.New("private key passphrase requires an Identity(private key)")
	}
	if profile.Jump != "" &&
		(cliSSHOptionConfigured(profile.Options, "ProxyJump") ||
			cliSSHOptionConfigured(profile.Options, "JumpHost")) {
		return errors.New("Jump host cannot be combined with a ProxyJump/JumpHost option")
	}
	for _, option := range profile.Options {
		if err := validateCLISSHOption(option); err != nil {
			return err
		}
	}
	return nil
}

func validateCLISSHProfileStructure(profile cliSSHProfile) error {
	profile = normalizeCLISSHProfile(profile)
	if profile.Name == "" || len(profile.Name) > 64 {
		return errors.New("SSH profile name must contain 1 to 64 characters")
	}
	for _, value := range profile.Name {
		if !((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || strings.ContainsRune("._-", value)) {
			return errors.New("SSH profile name may contain only letters, numbers, dot, underscore, and hyphen")
		}
	}
	if profile.Username != "" && (strings.HasPrefix(profile.Username, "-") ||
		strings.ContainsAny(profile.Username, "@ \t\r\n\x00")) {
		return errors.New("SSH username is invalid")
	}
	if profile.Host == "" || strings.HasPrefix(profile.Host, "-") ||
		strings.ContainsAny(profile.Host, "@ \t\r\n\x00") {
		return errors.New("SSH host is invalid")
	}
	if profile.Port < 1 || profile.Port > 65535 {
		return errors.New("SSH port must be between 1 and 65535")
	}
	if profile.LocalPort < 0 || profile.LocalPort > 65535 {
		return errors.New("local SOCKS5 port must be auto or between 1 and 65535")
	}
	if err := validateCLISSHJump(profile.Jump); err != nil {
		return err
	}
	for _, option := range profile.Options {
		if err := validateCLISSHOptionSyntax(option); err != nil {
			return err
		}
	}
	return nil
}

func expandCLISSHIdentityPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func inspectCLISSHIdentity(
	path,
	passphrase string,
) (cliSSHIdentityKind, error) {
	if strings.TrimSpace(path) == "" {
		return cliSSHIdentityNone, nil
	}
	path = expandCLISSHIdentityPath(path)
	info, err := os.Stat(path)
	if err != nil {
		return cliSSHIdentityNone, fmt.Errorf("inspect SSH private key %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return cliSSHIdentityNone, fmt.Errorf("SSH private key %q must be a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return cliSSHIdentityNone, fmt.Errorf(
			"SSH private key %q permissions are too open (%04o); copy it into ~/.ssh and run chmod 600",
			path,
			info.Mode().Perm(),
		)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cliSSHIdentityNone, fmt.Errorf("read SSH private key %q: %w", path, err)
	}
	if _, err := cryptossh.ParseRawPrivateKey(data); err == nil {
		return cliSSHIdentityUnencrypted, nil
	} else {
		var missing *cryptossh.PassphraseMissingError
		if !errors.As(err, &missing) {
			return cliSSHIdentityNone, fmt.Errorf("parse SSH private key %q: %w", path, err)
		}
	}
	if passphrase == "" {
		return cliSSHIdentityEncrypted, nil
	}
	if _, err := cryptossh.ParseRawPrivateKeyWithPassphrase(
		data,
		[]byte(passphrase),
	); err != nil {
		return cliSSHIdentityEncrypted,
			fmt.Errorf("private key passphrase for %q is incorrect: %w", path, err)
	}
	return cliSSHIdentityEncrypted, nil
}

func prepareCLISSHProfileCredentials(
	profile cliSSHProfile,
	credentials cliSSHCredentials,
) (cliSSHProfile, error) {
	profile = normalizeCLISSHProfile(profile)
	if err := validateCLISSHProfile(profile); err != nil {
		return profile, err
	}
	if profile.Identity == "" {
		if profile.IdentityPassphrase != "" {
			return profile, errors.New("private key passphrase requires an Identity(private key)")
		}
		return profile, nil
	}
	passphrase := profile.IdentityPassphrase
	if credentials.IdentityPassphrase != "" {
		passphrase = credentials.IdentityPassphrase
	}
	kind, err := inspectCLISSHIdentity(profile.Identity, passphrase)
	if err != nil {
		return profile, err
	}
	switch kind {
	case cliSSHIdentityUnencrypted:
		profile.IdentityPassphrase = ""
	case cliSSHIdentityEncrypted:
		if passphrase == "" {
			return profile, &cliSSHCredentialRequiredError{
				Profile:  profile.Name,
				Identity: expandCLISSHIdentityPath(profile.Identity),
			}
		}
		profile.IdentityPassphrase = passphrase
	}
	return profile, nil
}

func validateCLISSHOption(option string) error {
	if err := validateCLISSHOptionSyntax(option); err != nil {
		return err
	}
	key, value, found := strings.Cut(option, "=")
	_ = value
	_ = found
	disallowed := map[string]bool{
		"batchmode": true, "clearallforwardings": true, "controlmaster": true,
		"controlpath": true, "controlpersist": true, "dynamicforward": true,
		"exitonforwardfailure": true, "forkafterauthentication": true,
		"identitiesonly": true, "identityfile": true,
		"kbdinteractiveauthentication": true, "localcommand": true,
		"numberofpasswordprompts": true, "passwordauthentication": true,
		"permitlocalcommand": true, "preferredauthentications": true,
		"pubkeyauthentication": true, "remotecommand": true,
		"sessiontype": true, "user": true,
	}
	if disallowed[strings.ToLower(strings.TrimSpace(key))] {
		return fmt.Errorf("SSH option %q conflicts with FlClash tunnel management", key)
	}
	return nil
}

func validateCLISSHJump(jump string) error {
	jump = strings.TrimSpace(jump)
	if jump == "" {
		return nil
	}
	if strings.HasPrefix(jump, "-") || strings.ContainsAny(jump, " \t\r\n\x00") {
		return errors.New("SSH jump host is invalid")
	}
	return nil
}

func validateCLISSHOptionSyntax(option string) error {
	key, value, found := strings.Cut(option, "=")
	if !found || strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" ||
		strings.ContainsAny(option, "\r\n\x00") {
		return fmt.Errorf("SSH option %q must use KEY=VALUE", option)
	}
	return nil
}

func loadCLISSHConfig() (cliSSHConfig, error) {
	paths, err := resolvePaths("", "")
	if err != nil {
		return cliSSHConfig{}, err
	}
	path := filepath.Join(paths.homeDir, cliSSHConfigFilename)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return cliSSHConfig{Version: cliSSHConfigVersion}, nil
	}
	if err != nil {
		return cliSSHConfig{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !cliPathOwnedByCurrentUser(info) || info.Mode().Perm()&0o077 != 0 {
		return cliSSHConfig{}, fmt.Errorf("unsafe SSH configuration %q; it must be an owned regular file with mode 0600", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cliSSHConfig{}, err
	}
	var config cliSSHConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("parse SSH configuration: %w", err)
	}
	if config.Version != 1 && config.Version != cliSSHConfigVersion {
		return config, fmt.Errorf("unsupported SSH configuration version %d", config.Version)
	}
	for index, profile := range config.Profiles {
		profile = normalizeCLISSHProfile(profile)
		config.Profiles[index] = profile
		if err := validateCLISSHProfileStructure(profile); err != nil {
			return config, fmt.Errorf("invalid SSH profile %q: %w", profile.Name, err)
		}
	}
	return config, nil
}

func updateCLISSHConfig(update func(*cliSSHConfig) error) error {
	paths, err := resolvePaths("", "")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(paths.homeDir, 0o700); err != nil {
		return err
	}
	lock, err := acquireCLIFileLock(filepath.Join(paths.homeDir, cliSSHConfigLockFilename), cliProcessOwner{Kind: "ssh-config", PID: os.Getpid(), HomeDir: paths.homeDir, StartedAt: time.Now()})
	if err != nil {
		return fmt.Errorf("lock SSH configuration: %w", err)
	}
	defer lock.release()
	config, err := loadCLISSHConfig()
	if err != nil {
		return err
	}
	if err := update(&config); err != nil {
		return err
	}
	config.Version = cliSSHConfigVersion
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return writeCLISSHFileAtomically(filepath.Join(paths.homeDir, cliSSHConfigFilename), append(data, '\n'))
}

func writeCLISSHFileAtomically(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".flclash-ssh-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func loadCLISSHProfile(name string) (cliSSHProfile, error) {
	config, err := loadCLISSHConfig()
	if err != nil {
		return cliSSHProfile{}, err
	}
	index, found := findCLISSHProfile(config.Profiles, name)
	if !found {
		return cliSSHProfile{}, fmt.Errorf("SSH profile %q does not exist; add it with `flclash ssh add`", name)
	}
	return config.Profiles[index], nil
}
func findCLISSHProfile(profiles []cliSSHProfile, name string) (int, bool) {
	for index, profile := range profiles {
		if strings.EqualFold(profile.Name, name) {
			return index, true
		}
	}
	return -1, false
}

func loadCLISSHProfileViews() ([]cliSSHProfileView, error) {
	config, err := loadCLISSHConfig()
	if err != nil {
		return nil, err
	}
	active, connected, err := activeCLIPersistentSSHTunnel()
	if err != nil {
		return nil, err
	}
	lastError, _ := loadCLISSHLastError()
	views := make([]cliSSHProfileView, 0, len(config.Profiles))
	for _, profile := range config.Profiles {
		profile = normalizeCLISSHProfile(profile)
		view := cliSSHProfileView{
			Name:          profile.Name,
			Username:      profile.Username,
			Host:          profile.Host,
			Destination:   profile.Destination,
			Port:          profile.Port,
			LocalPort:     profile.LocalPort,
			Jump:          profile.Jump,
			Identity:      profile.Identity,
			Options:       append([]string(nil), profile.Options...),
			PassphraseSet: profile.IdentityPassphrase != "",
			PasswordSet:   profile.Password != "",
			NeedsUsername: profile.Username == "",
			Default:       strings.EqualFold(config.Default, profile.Name),
		}
		if connected && strings.EqualFold(active.Name, profile.Name) {
			view.Connected = true
			view.Attached = active.Kind == cliSSHAttachedKind
			view.Ready = cliSSHTunnelReady(active)
			view.SocksPort = active.Port
			view.StartedAt = active.StartedAt
		}
		if strings.EqualFold(lastError.Name, profile.Name) {
			view.LastError = lastError.Error
		}
		views = append(views, view)
	}
	return views, nil
}

func runCLISSHCommand(
	command *exec.Cmd,
	event string,
	logSuccessOutput bool,
) error {
	var stdout, stderr cliSSHCappedBuffer
	prepareCLISSHNonInteractiveCommand(command)
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	output := strings.TrimSpace(strings.Join(
		[]string{stdout.String(), stderr.String()},
		"\n",
	))
	if output != "" && (err != nil || logSuccessOutput) {
		level := "WARN"
		if err != nil {
			level = "ERROR"
		}
		if paths, pathErr := resolvePaths("", ""); pathErr == nil {
			appendCLIApplicationLog(paths.homeDir, level, event, output)
		} else {
			appendTUILogEvent(level, event+" · "+output)
		}
	}
	if err == nil {
		return nil
	}
	summary := cliSSHOutputSummary(stderr.String())
	if summary == "" {
		summary = cliSSHOutputSummary(stdout.String())
	}
	if summary == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, formatCLISSHErrorSummary(summary))
}

func formatCLISSHErrorSummary(summary string) string {
	friendly := cliSSHFriendlyError(summary)
	if friendly == summary {
		return summary
	}
	return friendly + " · " + summary
}

func runCLISSHProbe(command *exec.Cmd) error {
	var stdout, stderr cliSSHCappedBuffer
	prepareCLISSHNonInteractiveCommand(command)
	command.Stdout = &stdout
	command.Stderr = &stderr
	return command.Run()
}

// prepareCLISSHNonInteractiveCommand makes every OpenSSH helper incapable of
// taking over the terminal. Authentication is either supplied through our
// private askpass file during initial connect or rejected by the control-only
// arguments below; a TUI must never be obscured by an OpenSSH prompt.
func prepareCLISSHNonInteractiveCommand(command *exec.Cmd) {
	command.Stdin = nil
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	}
}

func probeCLISSHRemote(state cliSSHTunnelState) (cliSSHRemoteProbe, error) {
	if strings.TrimSpace(state.ControlPath) == "" || strings.TrimSpace(state.Destination) == "" {
		return cliSSHRemoteProbe{}, errors.New("SSH control connection is unavailable")
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return cliSSHRemoteProbe{}, errors.New("OpenSSH client `ssh` is required")
	}
	arguments := cliSSHControlClientArguments(state)
	arguments = append(
		arguments,
		state.Destination,
		"flclash", "ssh", "probe", "--json",
	)
	command := exec.Command(sshPath, arguments...)
	var stdout, stderr cliSSHCappedBuffer
	prepareCLISSHNonInteractiveCommand(command)
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		summary := cliSSHOutputSummary(stderr.String())
		if summary == "" {
			summary = cliSSHOutputSummary(stdout.String())
		}
		if summary != "" {
			return cliSSHRemoteProbe{}, fmt.Errorf("run remote FlClash probe: %w: %s", err, formatCLISSHErrorSummary(summary))
		}
		return cliSSHRemoteProbe{}, fmt.Errorf("run remote FlClash probe: %w", err)
	}
	var probe cliSSHRemoteProbe
	if err := json.Unmarshal([]byte(stdout.String()), &probe); err != nil {
		return cliSSHRemoteProbe{}, fmt.Errorf("parse remote FlClash probe: %w", err)
	}
	return probe, nil
}

func cliSSHOutputSummary(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for index := len(lines) - 1; index >= 0; index-- {
		line := strings.Join(strings.Fields(lines[index]), " ")
		if line == "" || strings.Contains(line, "post-quantum key exchange") ||
			strings.Contains(line, "store now, decrypt later") ||
			strings.Contains(line, "openssh.com/pq.html") {
			continue
		}
		return truncateTUI(line, 320)
	}
	return ""
}

func cliSSHFriendlyError(summary string) string {
	lower := strings.ToLower(summary)
	switch {
	case strings.Contains(lower, "permission denied"):
		return "authentication failed; check username, private key, passphrase, or password"
	case strings.Contains(lower, "connection timed out") || strings.Contains(lower, "operation timed out"):
		return "connection timed out; check the SSH host, port, and network path"
	case strings.Contains(lower, "connection refused"):
		return "connection refused; the SSH server is not accepting connections on that port"
	case strings.Contains(lower, "no route to host"):
		return "no route to the SSH host; check the destination and local network"
	case strings.Contains(lower, "network is unreachable"):
		return "network is unreachable; check the destination and local network"
	case strings.Contains(lower, "could not resolve hostname") || strings.Contains(lower, "name or service not known"):
		return "SSH host name could not be resolved"
	case strings.Contains(lower, "host key verification failed"):
		return "SSH host key changed or is not trusted; inspect known_hosts before retrying"
	case strings.Contains(lower, "too many authentication"):
		return "too many authentication failures; specify Identity(private key) or a saved password"
	case strings.Contains(lower, "identity file") && strings.Contains(lower, "not accessible"):
		return "private key is not accessible; copy it out of /mnt/c and chmod 600"
	case strings.Contains(lower, "bad permissions"):
		return "private key permissions are too open; copy it to ~/.ssh and chmod 600"
	case strings.Contains(lower, "connection reset"):
		return "SSH connection reset by the remote host"
	default:
		return summary
	}
}

func cliSSHMaskedSecret(set bool) string {
	if set {
		return "********"
	}
	return "not saved"
}

func startCLISSHTunnel(profile cliSSHProfile, kind string) (cliSSHTunnelState, error) {
	var err error
	profile, err = prepareCLISSHProfileCredentials(profile, cliSSHCredentials{})
	if err != nil {
		return cliSSHTunnelState{}, err
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return cliSSHTunnelState{}, errors.New("OpenSSH client `ssh` is required")
	}
	runtimeDirectory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		return cliSSHTunnelState{}, err
	}
	socketDirectory, err := ensureCLISSHSocketDirectory(runtimeDirectory)
	if err != nil {
		return cliSSHTunnelState{}, err
	}
	configuredPort := configuredCLISSHLocalPort(profile, kind)
	fixedPort := configuredPort > 0
	attemptLimit := 3
	if fixedPort {
		attemptLimit = 1
	}
	for attempt := 0; attempt < attemptLimit; attempt++ {
		port := configuredPort
		if !fixedPort {
			port, err = allocateCLISSHPort()
			if err != nil {
				return cliSSHTunnelState{}, err
			}
		} else if err := waitCLISSHPortAvailable(port, time.Second); err != nil {
			return cliSSHTunnelState{}, err
		}
		digest := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%d:%s", profile.Name, os.Getpid(), time.Now().UnixNano(), kind)))
		controlPath := filepath.Join(socketDirectory, fmt.Sprintf("ctl-%x.sock", digest[:8]))
		upstreamPort := port
		if kind == "persistent" {
			upstreamPort, err = allocateCLISSHPort()
			if err != nil {
				return cliSSHTunnelState{}, err
			}
			for upstreamPort == port {
				upstreamPort, err = allocateCLISSHPort()
				if err != nil {
					return cliSSHTunnelState{}, err
				}
			}
		}
		state := cliSSHTunnelState{
			Name:         profile.Name,
			Destination:  formatCLISSHDestination(profile.Username, profile.Host),
			Port:         port,
			UpstreamPort: upstreamPort,
			ControlPath:  controlPath,
			Kind:         kind,
			StartedAt:    time.Now(),
		}
		if kind != "persistent" {
			state.UpstreamPort = 0
		}
		args := cliSSHTunnelArguments(profile, controlPath)
		args = append(args, profile.Host)
		command := exec.Command(sshPath, args...)
		cleanup, err := configureCLISSHAskpass(
			command,
			profile.IdentityPassphrase,
			profile.Password,
		)
		if err != nil {
			return state, err
		}
		runErr := runCLISSHCommand(command, "ssh_connect", true)
		cleanup()
		if runErr == nil {
			if forwardErr := addCLISSHDynamicForwardForOperation(sshPath, state); forwardErr != nil {
				runErr = errors.Join(
					fmt.Errorf("configure SSH SOCKS5 forward: %w", forwardErr),
					stopCLIStateTunnel(state),
				)
			}
		}
		if runErr != nil {
			_ = os.Remove(controlPath)
			if attempt < attemptLimit-1 {
				continue
			}
			return state, fmt.Errorf("start SSH SOCKS5 tunnel %q: %w", profile.Name, runErr)
		}
		state.StatePath = filepath.Join(runtimeDirectory, fmt.Sprintf("%s-%d-%d.json", kind, os.Getpid(), time.Now().UnixNano()))
		if err := saveCLISSHTunnelState(state); err != nil {
			_ = stopCLIStateTunnel(state)
			return state, err
		}
		if kind == "persistent" {
			deadline := time.Now().Add(5 * time.Second)
			for !cliSSHSOCKSReady(state.UpstreamPort) && time.Now().Before(deadline) {
				time.Sleep(25 * time.Millisecond)
			}
			if !cliSSHSOCKSReady(state.UpstreamPort) {
				_ = stopCLIStateTunnel(state)
				return state, fmt.Errorf("SSH tunnel %q upstream did not become ready", profile.Name)
			}
			if relayErr := startCLISSHRelayForOperation(&state); relayErr != nil {
				_ = stopCLIStateTunnel(state)
				return state, fmt.Errorf("start SSH traffic meter: %w", relayErr)
			}
			if err := saveCLISSHTunnelState(state); err != nil {
				_ = stopCLIStateTunnel(state)
				return state, err
			}
		}
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if cliSSHTunnelAlive(sshPath, state) {
				return state, nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		_ = stopCLIStateTunnel(state)
		return state, fmt.Errorf("SSH tunnel %q did not become ready", profile.Name)
	}
	return cliSSHTunnelState{}, errors.New("could not allocate a local SSH SOCKS5 port")
}

func startCLITransientSSHTunnel(profile cliSSHProfile) (cliSSHTunnelState, error) {
	lock, err := lockCLISSHTunnelOperation()
	if err != nil {
		return cliSSHTunnelState{}, err
	}
	defer lock.release()
	return startCLISSHTunnel(profile, "transient")
}

func stopCLITransientSSHTunnel(state cliSSHTunnelState) error {
	lock, err := waitCLISSHTunnelOperationLock(15 * time.Second)
	if err != nil {
		return err
	}
	defer lock.release()
	return stopCLIStateTunnel(state)
}

func waitCLISSHTunnelOperationLock(timeout time.Duration) (*cliFileLock, error) {
	deadline := time.Now().Add(timeout)
	for {
		lock, err := lockCLISSHTunnelOperation()
		if err == nil {
			return lock, nil
		}
		var busy *cliLockBusyError
		if !errors.As(err, &busy) || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func cliSSHTunnelArguments(
	profile cliSSHProfile,
	controlPath string,
) []string {
	args := []string{
		"-f",
		"-N",
		"-M",
		"-S", controlPath,
		"-p", strconv.Itoa(profile.Port),
		"-l", profile.Username,
		"-o", "ControlMaster=yes",
		"-o", "ControlPersist=no",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ClearAllForwardings=yes",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
	}
	if !cliSSHOptionConfigured(profile.Options, "ConnectTimeout") {
		args = append(args, "-o", "ConnectTimeout=15")
	}
	if !cliSSHOptionConfigured(profile.Options, "ConnectionAttempts") {
		args = append(args, "-o", "ConnectionAttempts=1")
	}
	if profile.IdentityPassphrase == "" && profile.Password == "" {
		args = append(args, "-o", "BatchMode=yes")
	}
	switch {
	case profile.Identity != "" && profile.Password != "":
		args = append(args,
			"-o", "IdentitiesOnly=yes",
			"-o", "PreferredAuthentications=publickey,keyboard-interactive,password",
			"-o", "NumberOfPasswordPrompts=1",
		)
	case profile.Identity != "":
		args = append(args,
			"-o", "IdentitiesOnly=yes",
			"-o", "PreferredAuthentications=publickey",
			"-o", "PasswordAuthentication=no",
			"-o", "KbdInteractiveAuthentication=no",
		)
	case profile.Password != "":
		args = append(args,
			"-o", "PubkeyAuthentication=no",
			"-o", "PreferredAuthentications=keyboard-interactive,password",
			"-o", "NumberOfPasswordPrompts=1",
		)
	default:
		args = append(args,
			"-o", "PreferredAuthentications=publickey",
			"-o", "PasswordAuthentication=no",
			"-o", "KbdInteractiveAuthentication=no",
		)
	}
	if !cliSSHOptionConfigured(profile.Options, "StrictHostKeyChecking") {
		args = append(args, "-o", "StrictHostKeyChecking=accept-new")
	}
	if profile.Identity != "" {
		args = append(args, "-i", profile.Identity)
	}
	if profile.Jump != "" &&
		!cliSSHOptionConfigured(profile.Options, "ProxyJump") &&
		!cliSSHOptionConfigured(profile.Options, "JumpHost") {
		args = append(args, "-o", "ProxyJump="+profile.Jump)
	}
	for _, option := range profile.Options {
		args = append(args, "-o", option)
	}
	return args
}

func addCLISSHDynamicForward(sshPath string, state cliSSHTunnelState) error {
	command := exec.Command(sshPath, cliSSHDynamicForwardArguments(state)...)
	return runCLISSHCommand(command, "ssh_forward", true)
}

func cliSSHDynamicForwardArguments(state cliSSHTunnelState) []string {
	arguments := cliSSHControlClientArguments(state)
	arguments = append(arguments,
		"-O", "forward",
		"-D", net.JoinHostPort("127.0.0.1", strconv.Itoa(cliSSHUpstreamPort(state))),
	)
	return append(arguments, state.Destination)
}

// cliSSHControlClientArguments is used only after an authenticated master has
// been created. If its socket has disappeared, OpenSSH must fail locally
// rather than fall back to a new network connection and prompt on /dev/tty.
func cliSSHControlClientArguments(state cliSSHTunnelState) []string {
	return []string{
		"-S", state.ControlPath,
		// A missing master must never fall back to a fresh network connection.
		"-o", "ProxyCommand=false",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "PubkeyAuthentication=no",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "PreferredAuthentications=none",
	}
}

func cliSSHControlOperationArguments(
	state cliSSHTunnelState,
	operation string,
) []string {
	arguments := cliSSHControlClientArguments(state)
	arguments = append(arguments, "-O", operation)
	return append(arguments, state.Destination)
}

func cliSSHUpstreamPort(state cliSSHTunnelState) int {
	if state.UpstreamPort > 0 {
		return state.UpstreamPort
	}
	return state.Port
}

func cliSSHOptionConfigured(options []string, wantedKey string) bool {
	for _, option := range options {
		key, _, found := strings.Cut(option, "=")
		if found && strings.EqualFold(strings.TrimSpace(key), wantedKey) {
			return true
		}
	}
	return false
}

func startCLIPersistentSSHTunnel(profile cliSSHProfile) (cliSSHTunnelState, error) {
	if controlPath, ok := findCLILiveSSHMaster(profile); ok {
		state, err := attachCLISSHTunnel(profile, controlPath)
		if err != nil {
			return cliSSHTunnelState{}, fmt.Errorf(
				"reuse existing SSH connection %q: %w",
				profile.Name,
				err,
			)
		}
		return state, nil
	}
	state, err := startCLISSHTunnel(profile, "persistent")
	if err != nil {
		return cliSSHTunnelState{}, err
	}
	return persistCLISSHTunnelState(state)
}

func configuredCLISSHLocalPort(profile cliSSHProfile, kind string) int {
	if kind != "persistent" && kind != cliSSHAttachedKind {
		return 0
	}
	return profile.LocalPort
}

func configureCLISSHAskpass(
	command *exec.Cmd,
	identityPassphrase,
	password string,
) (func(), error) {
	if identityPassphrase == "" && password == "" {
		return func() {}, nil
	}
	directory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		return nil, err
	}
	if err := cleanupCLISSHAskpassSecrets(directory); err != nil {
		return nil, err
	}
	secret, err := os.CreateTemp(directory, "askpass-*.secret")
	if err != nil {
		return nil, err
	}
	path := secret.Name()
	cleanup := func() { _ = secret.Close(); _ = os.Remove(path) }
	if err := secret.Chmod(0o600); err != nil {
		cleanup()
		return nil, err
	}
	data, err := json.Marshal(cliSSHAskpassSecrets{
		IdentityPassphrase: identityPassphrase,
		Password:           password,
	})
	if err != nil {
		cleanup()
		return nil, err
	}
	if _, err := secret.Write(data); err != nil {
		cleanup()
		return nil, err
	}
	if err := secret.Close(); err != nil {
		cleanup()
		return nil, err
	}
	executable, err := cliSSHAskpassExecutable()
	if err != nil {
		cleanup()
		return nil, err
	}
	command.Env = cliSSHAskpassEnvironment(os.Environ(), executable, path)
	return cleanup, nil
}

func cliSSHAskpassEnvironment(environment []string, executable, secretPath string) []string {
	replaced := map[string]bool{
		"SSH_ASKPASS":         true,
		"SSH_ASKPASS_REQUIRE": true,
		"DISPLAY":             true,
		"LC_ALL":              true,
		cliSSHAskpassFileEnv:  true,
	}
	result := make([]string, 0, len(environment)+len(replaced))
	for _, item := range environment {
		key, _, found := strings.Cut(item, "=")
		if found && replaced[key] {
			continue
		}
		result = append(result, item)
	}
	return append(
		result,
		"SSH_ASKPASS="+executable,
		"SSH_ASKPASS_REQUIRE=force",
		"DISPLAY=flclash-askpass",
		"LC_ALL=C",
		cliSSHAskpassFileEnv+"="+secretPath,
	)
}

func cleanupCLISSHAskpassSecrets(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	var cleanupErrors []error
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "askpass-") ||
			!strings.HasSuffix(name, ".secret") {
			continue
		}
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				cleanupErrors = append(cleanupErrors, err)
			}
			continue
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			!cliPathOwnedByCurrentUser(info) || info.Mode().Perm()&0o077 != 0 {
			cleanupErrors = append(
				cleanupErrors,
				fmt.Errorf("unsafe stale SSH askpass secret %q", path),
			)
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			cleanupErrors = append(
				cleanupErrors,
				fmt.Errorf("remove stale SSH askpass secret %q: %w", path, err),
			)
		}
	}
	return errors.Join(cleanupErrors...)
}

func cliSSHAskpassCommand(args []string) error {
	path := os.Getenv(cliSSHAskpassFileEnv)
	answer, err := cliSSHAskpassAnswer(strings.Join(args, " "), path)
	if err != nil {
		return err
	}
	_, err = io.WriteString(os.Stdout, answer)
	return err
}

func cliSSHAskpassAnswer(prompt, path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !cliPathOwnedByCurrentUser(info) || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("unsafe SSH askpass secret")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var secrets cliSSHAskpassSecrets
	if err := json.Unmarshal(data, &secrets); err != nil {
		return "", errors.New("invalid SSH askpass secret")
	}
	lowerPrompt := strings.ToLower(prompt)
	switch {
	case strings.Contains(lowerPrompt, "passphrase"):
		if secrets.IdentityPassphrase == "" {
			return "", errors.New("no private key passphrase is saved")
		}
		return secrets.IdentityPassphrase, nil
	case strings.Contains(lowerPrompt, "password"):
		if secrets.Password == "" {
			return "", errors.New("no SSH password is saved")
		}
		return secrets.Password, nil
	default:
		return "", errors.New("unsupported SSH authentication prompt")
	}
}

func allocateCLISSHPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func checkCLISSHPortAvailable(port int) error {
	listener, err := net.Listen(
		"tcp4",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
	)
	if err != nil {
		return fmt.Errorf("local SSH SOCKS5 port %d is already in use: %w", port, err)
	}
	return listener.Close()
}

func waitCLISSHPortAvailable(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		lastErr = checkCLISSHPortAvailable(port)
		if lastErr == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return lastErr
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func ensureCLISSHRuntimeDirectory() (string, error) {
	base, err := ensureCLIRuntimeDirectory()
	if err != nil {
		return "", err
	}
	directory := filepath.Join(base, cliSSHRuntimeDirectoryName)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !cliPathOwnedByCurrentUser(info) {
		return "", fmt.Errorf("unsafe SSH runtime directory %q", directory)
	}
	if info.Mode().Perm()&0o077 != 0 {
		_ = os.Chmod(directory, 0o700)
	}
	return directory, nil
}

func ensureCLISSHSocketDirectory(runtimeDirectory string) (string, error) {
	maximumPath := len((syscall.RawSockaddrUnix{}).Path) - 1
	probePath := filepath.Join(runtimeDirectory, "ctl-0000000000000000.sock")
	// OpenSSH creates a temporary control socket with an additional random
	// suffix before atomically moving it into place.
	if len(probePath)+24 <= maximumPath {
		return runtimeDirectory, nil
	}
	digest := sha256.Sum256([]byte(runtimeDirectory))
	directory := filepath.Join(
		"/tmp",
		fmt.Sprintf("flclash-ssh-%d-%x", os.Getuid(), digest[:4]),
	)
	if err := os.Mkdir(directory, 0o700); err != nil && !os.IsExist(err) {
		return "", err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		!cliPathOwnedByCurrentUser(info) {
		return "", fmt.Errorf("unsafe SSH socket directory %q", directory)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(directory, 0o700); err != nil {
			return "", err
		}
	}
	return directory, nil
}

func lockCLISSHTunnelOperation() (*cliFileLock, error) {
	directory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		return nil, err
	}
	lock, err := acquireCLIFileLock(
		filepath.Join(directory, "operation.lock"),
		cliProcessOwner{
			Kind:      "ssh-tunnel",
			PID:       os.Getpid(),
			StartedAt: time.Now(),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("another SSH tunnel operation is running: %w", err)
	}
	return lock, nil
}

func cliSSHTunnelAlive(sshPath string, state cliSSHTunnelState) bool {
	if state.Port < 1 || state.ControlPath == "" {
		return false
	}
	if !cliSSHMasterAlive(sshPath, state) {
		return false
	}
	return cliSSHTunnelReady(state)
}

func cliSSHTunnelReady(state cliSSHTunnelState) bool {
	if state.RelayControl != "" || state.RelayPID > 0 ||
		(state.UpstreamPort > 0 && (state.Kind == "persistent" || state.Kind == cliSSHAttachedKind)) {
		return cliSSHSOCKSReady(cliSSHUpstreamPort(state)) && cliSSHRelayReady(state)
	}
	return cliSSHSOCKSReady(state.Port)
}

func cliSSHSOCKSReady(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	connection, err := net.DialTimeout(
		"tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		250*time.Millisecond,
	)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func probeCLISSHSOCKS(port int, timeout time.Duration) error {
	if port < 1 || port > 65535 {
		return errors.New("SSH SOCKS5 port is invalid")
	}
	connection, err := net.DialTimeout(
		"tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		timeout,
	)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if _, err := connection.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(connection, reply); err != nil {
		return err
	}
	if reply[0] != 5 {
		return errors.New("listener is not SOCKS5")
	}
	if reply[1] != 0 {
		return errors.New("SOCKS5 authentication is required")
	}
	return nil
}

func saveCLISSHLastError(name, message string) error {
	name = strings.TrimSpace(name)
	message = strings.TrimSpace(message)
	if name == "" || message == "" {
		return nil
	}
	directory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		return err
	}
	data, err := json.Marshal(cliSSHLastError{
		Name:  name,
		Error: truncateTUI(message, 320),
		At:    time.Now(),
	})
	if err != nil {
		return err
	}
	return writeCLISSHFileAtomically(
		filepath.Join(directory, cliSSHLastErrorFile),
		append(data, '\n'),
	)
}

func clearCLISSHLastError(name string) error {
	lastError, err := loadCLISSHLastError()
	if err != nil || lastError.Name == "" {
		return err
	}
	if name != "" && !strings.EqualFold(lastError.Name, name) {
		return nil
	}
	directory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(directory, cliSSHLastErrorFile)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func loadCLISSHLastError() (cliSSHLastError, error) {
	directory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		return cliSSHLastError{}, err
	}
	data, err := os.ReadFile(filepath.Join(directory, cliSSHLastErrorFile))
	if os.IsNotExist(err) {
		return cliSSHLastError{}, nil
	}
	if err != nil {
		return cliSSHLastError{}, err
	}
	var lastError cliSSHLastError
	if err := json.Unmarshal(data, &lastError); err != nil {
		return cliSSHLastError{}, err
	}
	return lastError, nil
}

func cliSSHMasterAlive(sshPath string, state cliSSHTunnelState) bool {
	if state.ControlPath == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	check := exec.CommandContext(
		ctx,
		sshPath,
		cliSSHControlOperationArguments(state, "check")...,
	)
	check.WaitDelay = time.Second
	return runCLISSHProbe(check) == nil
}
func saveCLISSHTunnelState(state cliSSHTunnelState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeCLISSHFileAtomically(state.StatePath, append(data, '\n'))
}
func loadCLISSHTunnelState(path string) (cliSSHTunnelState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return cliSSHTunnelState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !cliPathOwnedByCurrentUser(info) || info.Mode().Perm()&0o077 != 0 {
		return cliSSHTunnelState{}, fmt.Errorf("unsafe SSH runtime state %q", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cliSSHTunnelState{}, err
	}
	var state cliSSHTunnelState
	if err := json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	state.StatePath = path
	return state, nil
}

func activeCLIPersistentSSHTunnel() (cliSSHTunnelState, bool, error) {
	directory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		return cliSSHTunnelState{}, false, err
	}
	path := filepath.Join(directory, cliSSHPersistentStateFile)
	state, err := loadCLISSHTunnelState(path)
	if os.IsNotExist(err) {
		return cliSSHTunnelState{}, false, nil
	}
	if err != nil {
		return state, false, err
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return state, false,
			errors.New("OpenSSH client `ssh` is required to inspect the SSH tunnel")
	}
	if cliSSHMasterAlive(sshPath, state) {
		return state, true, nil
	}
	_ = stopCLISSHRelay(state)
	if cliSSHTunnelOwnsMaster(state) {
		_ = os.Remove(state.ControlPath)
	}
	_ = os.Remove(path)
	return cliSSHTunnelState{}, false, nil
}

func stopCLIStateTunnel(state cliSSHTunnelState) error {
	if !cliSSHTunnelOwnsMaster(state) {
		return stopCLIAttachedTunnel(state)
	}
	var cleanupErrors []error
	if err := stopCLISSHRelay(state); err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("stop SSH traffic meter: %w", err))
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		cleanupErrors = append(cleanupErrors, errors.New("OpenSSH client `ssh` is required to stop the SSH tunnel"))
		return errors.Join(cleanupErrors...)
	}
	if cliSSHMasterAlive(sshPath, state) {
		command := exec.Command(
			sshPath,
			cliSSHControlOperationArguments(state, "exit")...,
		)
		if err := runCLISSHCommand(command, "ssh_disconnect", false); err != nil &&
			cliSSHMasterAlive(sshPath, state) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("stop SSH tunnel %q: %w", state.Name, err))
		}
		deadline := time.Now().Add(time.Second)
		for cliSSHMasterAlive(sshPath, state) && time.Now().Before(deadline) {
			time.Sleep(25 * time.Millisecond)
		}
		if cliSSHMasterAlive(sshPath, state) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("SSH tunnel %q did not stop", state.Name))
			return errors.Join(cleanupErrors...)
		}
	}
	if state.ControlPath != "" {
		if err := os.Remove(state.ControlPath); err != nil && !os.IsNotExist(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove SSH control socket: %w", err))
		}
	}
	if state.StatePath != "" {
		if err := os.Remove(state.StatePath); err != nil && !os.IsNotExist(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove SSH runtime state: %w", err))
		}
	}
	return errors.Join(cleanupErrors...)
}

func stopAllCLISSHTunnels() error {
	lock, err := waitCLISSHTunnelOperationLock(15 * time.Second)
	if err != nil {
		return err
	}
	defer lock.release()
	directory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	var stopErrors []error
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == cliSSHLastErrorFile || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		state, stateErr := loadCLISSHTunnelState(path)
		if stateErr == nil {
			if err := stopCLIStateTunnelForOperation(state); err != nil {
				stopErrors = append(stopErrors, err)
			}
		} else {
			stopErrors = append(
				stopErrors,
				fmt.Errorf("inspect SSH runtime state %q: %w", path, stateErr),
			)
		}
	}
	if err := cleanupCLISSHAskpassSecrets(directory); err != nil {
		stopErrors = append(stopErrors, err)
	}
	return errors.Join(stopErrors...)
}

func runCLICommandWithSSHProxy(args []string, port int) error {
	executable, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("command not found or cannot be executed: %q (%v)", args[0], err)
	}
	args = cliWrappedCommandArguments(executable, args)
	proxyURL := "socks5h://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	command := exec.Command(executable, args[1:]...)
	command.Args, command.Env = args, cliProxyEnvironment(os.Environ(), proxyURL)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := command.Start(); err != nil {
		return fmt.Errorf("cannot start command %q: %w", args[0], err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	interrupt := make(chan os.Signal, 2)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	var result error
	select {
	case result = <-done:
	case received := <-interrupt:
		_ = command.Process.Signal(received)
		select {
		case <-done:
		case <-time.After(cliExitTerminatePeriod):
			_ = command.Process.Kill()
			<-done
		}
		if received == syscall.SIGINT {
			return &cliExitCodeError{code: 130}
		}
		return &cliExitCodeError{code: 143}
	}
	if result != nil {
		var exitError *exec.ExitError
		if errors.As(result, &exitError) {
			return &cliExitCodeError{code: exitError.ExitCode()}
		}
		return fmt.Errorf("command %q failed: %w", args[0], result)
	}
	return nil
}
