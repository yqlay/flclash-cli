//go:build linux && !cgo && cli

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const cliSSHAttachedKind = "attached"

var attachCLISSHTunnelForOperation = attachCLISSHTunnel

func cliSSHTunnelOwnsMaster(state cliSSHTunnelState) bool {
	return state.Kind != cliSSHAttachedKind
}

func findCLILiveSSHMaster(profile cliSSHProfile) (string, bool) {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return "", false
	}
	profile = normalizeCLISSHProfile(profile)
	if profile.Username == "" || profile.Host == "" {
		return "", false
	}
	path := cliSSHConfigControlPath(sshPath, profile)
	if path == "" {
		return "", false
	}
	path = filepath.Clean(path)
	if !cliSSHControlPathOwned(path) {
		return "", false
	}
	if !cliSSHMasterCheck(sshPath, path, profile) {
		return "", false
	}
	return path, true
}

func cliSSHConfigControlPath(sshPath string, profile cliSSHProfile) string {
	args := []string{
		"-G",
		"-p", strconv.Itoa(profile.Port),
		"-l", profile.Username,
	}
	if profile.Jump != "" {
		args = append(args, "-o", "ProxyJump="+profile.Jump)
	}
	for _, option := range profile.Options {
		args = append(args, "-o", option)
	}
	args = append(args, profile.Host)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, sshPath, args...)
	command.WaitDelay = time.Second
	prepareCLISSHNonInteractiveCommand(command)
	output, err := command.Output()
	if err != nil {
		return ""
	}
	controlPath := ""
	controlMaster := ""
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "controlpath":
			controlPath = strings.TrimSpace(value)
		case "controlmaster":
			controlMaster = strings.ToLower(strings.TrimSpace(value))
		}
	}
	if controlPath == "" || strings.EqualFold(controlPath, "none") {
		return ""
	}
	if !cliSSHControlMasterEnabled(controlMaster) {
		return ""
	}
	return expandCLISSHIdentityPath(controlPath)
}

func cliSSHControlMasterEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "true", "auto", "ask", "autoask":
		return true
	default:
		return false
	}
}

func cliSSHControlPathOwned(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if !cliPathOwnedByCurrentUser(info) {
		return false
	}
	if info.Mode().Perm()&0o077 != 0 {
		return false
	}
	return info.Mode()&os.ModeSocket != 0 || info.Mode().IsRegular()
}

func cliSSHMasterCheck(sshPath, controlPath string, profile cliSSHProfile) bool {
	state := cliSSHTunnelState{
		ControlPath: controlPath,
		Destination: formatCLISSHDestination(profile.Username, profile.Host),
	}
	return cliSSHMasterAlive(sshPath, state)
}

func attachCLISSHTunnel(profile cliSSHProfile, controlPath string) (cliSSHTunnelState, error) {
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
	if !cliSSHControlPathOwned(controlPath) {
		return cliSSHTunnelState{}, fmt.Errorf("unsafe SSH control socket %q", controlPath)
	}
	configuredPort := configuredCLISSHLocalPort(profile, cliSSHAttachedKind)
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
		upstreamPort, err := allocateCLISSHPort()
		if err != nil {
			return cliSSHTunnelState{}, err
		}
		for upstreamPort == port {
			upstreamPort, err = allocateCLISSHPort()
			if err != nil {
				return cliSSHTunnelState{}, err
			}
		}
		state := cliSSHTunnelState{
			Name:         profile.Name,
			Destination:  formatCLISSHDestination(profile.Username, profile.Host),
			Port:         port,
			UpstreamPort: upstreamPort,
			ControlPath:  controlPath,
			Kind:         cliSSHAttachedKind,
			StartedAt:    time.Now(),
		}
		if !cliSSHMasterAlive(sshPath, state) {
			return state, fmt.Errorf(
				"no OpenSSH ControlMaster for %s; ordinary ssh sessions cannot be captured",
				state.Destination,
			)
		}
		if forwardErr := addCLISSHDynamicForwardForOperation(sshPath, state); forwardErr != nil {
			_ = cancelCLISSHDynamicForward(sshPath, state)
			if attempt < attemptLimit-1 {
				continue
			}
			return state, fmt.Errorf("configure SSH SOCKS5 forward on existing connection: %w", forwardErr)
		}
		state.StatePath = filepath.Join(
			runtimeDirectory,
			fmt.Sprintf("%s-%d-%d.json", cliSSHAttachedKind, os.Getpid(), time.Now().UnixNano()),
		)
		if err := saveCLISSHTunnelState(state); err != nil {
			_ = cancelCLISSHDynamicForward(sshPath, state)
			return state, err
		}
		deadline := time.Now().Add(5 * time.Second)
		for !cliSSHSOCKSReady(state.UpstreamPort) && time.Now().Before(deadline) {
			time.Sleep(25 * time.Millisecond)
		}
		if !cliSSHSOCKSReady(state.UpstreamPort) {
			_ = stopCLIAttachedTunnel(state)
			return state, fmt.Errorf("SSH tunnel %q upstream did not become ready", profile.Name)
		}
		if relayErr := startCLISSHRelayForOperation(&state); relayErr != nil {
			_ = stopCLIAttachedTunnel(state)
			return state, fmt.Errorf("start SSH traffic meter: %w", relayErr)
		}
		if err := saveCLISSHTunnelState(state); err != nil {
			_ = stopCLIAttachedTunnel(state)
			return state, err
		}
		aliveDeadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(aliveDeadline) {
			if cliSSHTunnelAlive(sshPath, state) {
				return persistCLISSHTunnelState(state)
			}
			time.Sleep(50 * time.Millisecond)
		}
		_ = stopCLIAttachedTunnel(state)
		return state, fmt.Errorf("SSH tunnel %q did not become ready", profile.Name)
	}
	return cliSSHTunnelState{}, errors.New("could not allocate a local SSH SOCKS5 port")
}

func cancelCLISSHDynamicForward(sshPath string, state cliSSHTunnelState) error {
	command := exec.Command(sshPath, cliSSHCancelDynamicForwardArguments(state)...)
	return runCLISSHCommand(command, "ssh_forward_cancel", false)
}

func cliSSHCancelDynamicForwardArguments(state cliSSHTunnelState) []string {
	arguments := cliSSHControlClientArguments(state)
	arguments = append(arguments,
		"-O", "cancel",
		"-D", net.JoinHostPort("127.0.0.1", strconv.Itoa(cliSSHUpstreamPort(state))),
	)
	return append(arguments, state.Destination)
}

func stopCLIAttachedTunnel(state cliSSHTunnelState) error {
	var cleanupErrors []error
	if err := stopCLISSHRelay(state); err != nil {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("stop SSH traffic meter: %w", err))
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		cleanupErrors = append(cleanupErrors, errors.New("OpenSSH client `ssh` is required to detach the SSH tunnel"))
		return errors.Join(cleanupErrors...)
	}
	if cliSSHMasterAlive(sshPath, state) {
		if err := cancelCLISSHDynamicForward(sshPath, state); err != nil && cliSSHMasterAlive(sshPath, state) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("cancel SSH SOCKS5 forward %q: %w", state.Name, err))
		}
	}
	if state.StatePath != "" {
		if err := os.Remove(state.StatePath); err != nil && !os.IsNotExist(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove SSH runtime state: %w", err))
		}
	}
	return errors.Join(cleanupErrors...)
}

func persistCLISSHTunnelState(state cliSSHTunnelState) (cliSSHTunnelState, error) {
	runtimeDirectory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		return cliSSHTunnelState{}, errors.Join(err, stopCLIStateTunnel(state))
	}
	persistentPath := filepath.Join(runtimeDirectory, cliSSHPersistentStateFile)
	if state.StatePath == persistentPath {
		return state, nil
	}
	if err := os.Rename(state.StatePath, persistentPath); err != nil {
		return cliSSHTunnelState{}, errors.Join(err, stopCLIStateTunnel(state))
	}
	state.StatePath = persistentPath
	if err := saveCLISSHTunnelState(state); err != nil {
		return cliSSHTunnelState{}, errors.Join(err, stopCLIStateTunnel(state))
	}
	return state, nil
}

func attachCLISSHProfile(name string) (cliSSHTunnelState, bool, error) {
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
	old, oldActive, err := activeCLIPersistentSSHTunnelForOperation()
	if err != nil {
		return cliSSHTunnelState{}, false, err
	}
	if oldActive && strings.EqualFold(old.Name, profile.Name) {
		if cliSSHTunnelReady(old) {
			_ = clearCLISSHLastError(profile.Name)
			return old, true, nil
		}
	}
	controlPath, ok := findCLILiveSSHMaster(profile)
	if !ok {
		err := fmt.Errorf(
			"no OpenSSH ControlMaster for %s; ordinary ssh sessions cannot be captured",
			formatCLISSHDestination(profile.Username, profile.Host),
		)
		_ = saveCLISSHLastError(profile.Name, err.Error())
		return cliSSHTunnelState{}, false, err
	}
	// Do not disrupt the current route merely because the requested master
	// cannot be captured. Validate the target before releasing our old tunnel.
	profile, err = prepareCLISSHProfileCredentials(profile, cliSSHCredentials{})
	if err != nil {
		return cliSSHTunnelState{}, false, err
	}
	var oldProfile cliSSHProfile
	if oldActive {
		oldProfile, err = loadCLISSHProfile(old.Name)
		if err != nil {
			return cliSSHTunnelState{}, false, fmt.Errorf("cannot restore current SSH profile: %w", err)
		}
		if err := stopCLIStateTunnelForOperation(old); err != nil {
			_ = saveCLISSHLastError(old.Name, err.Error())
			return cliSSHTunnelState{}, false,
				fmt.Errorf("stop previous SSH tunnel %q: %w", old.Name, err)
		}
	}
	state, err := attachCLISSHTunnelForOperation(profile, controlPath)
	if err != nil {
		_ = saveCLISSHLastError(profile.Name, err.Error())
		if oldActive {
			var restoreErr error
			if cliSSHTunnelOwnsMaster(old) {
				_, restoreErr = startCLIPersistentSSHTunnelForOperation(oldProfile)
			} else {
				// An external master must never be replaced by a new login.
				_, restoreErr = attachCLISSHTunnelForOperation(oldProfile, old.ControlPath)
			}
			if restoreErr != nil {
				return cliSSHTunnelState{}, false, fmt.Errorf("capture SSH: %v; restore previous tunnel %q: %w", err, old.Name, restoreErr)
			}
			return cliSSHTunnelState{}, false, fmt.Errorf("capture SSH: %w; previous tunnel %q restored", err, old.Name)
		}
		return cliSSHTunnelState{}, false, err
	}
	_ = clearCLISSHLastError(profile.Name)
	return state, false, nil
}

func listCLISSHAttachCandidates() ([]string, error) {
	config, err := loadCLISSHConfig()
	if err != nil {
		return nil, err
	}
	lines := make([]string, 0, len(config.Profiles))
	for _, profile := range config.Profiles {
		profile = normalizeCLISSHProfile(profile)
		if profile.Username == "" {
			continue
		}
		path, ok := findCLILiveSSHMaster(profile)
		if !ok {
			continue
		}
		lines = append(lines, fmt.Sprintf(
			"%-16s %-28s %s",
			profile.Name,
			formatCLISSHDestination(profile.Username, profile.Host),
			path,
		))
	}
	return lines, nil
}

func cliSSHAttachCommand(args []string) error {
	if cliSubcommandHelp(args) {
		fmt.Println("Usage: flclash ssh attach [NAME] | --list")
		return nil
	}
	if len(args) == 1 && args[0] == "--list" {
		lines, err := listCLISSHAttachCandidates()
		if err != nil {
			return err
		}
		if len(lines) == 0 {
			fmt.Println("No OpenSSH ControlMaster matches a FlClash SSH profile")
			return nil
		}
		for _, line := range lines {
			fmt.Println(line)
		}
		return nil
	}
	if len(args) > 1 {
		return errors.New("usage: flclash ssh attach [NAME] | --list")
	}
	name := firstCLIArgument(args)
	resolved, err := resolveCLISSHConnectName(name)
	if err != nil {
		return err
	}
	state, already, err := attachCLISSHProfile(resolved)
	if err != nil {
		return err
	}
	if already {
		fmt.Printf("SSH %s already connected · SOCKS5 127.0.0.1:%d\n", state.Name, state.Port)
		return nil
	}
	fmt.Printf("SSH %s attached · SOCKS5 127.0.0.1:%d\n", state.Name, state.Port)
	return nil
}
