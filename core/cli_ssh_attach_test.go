//go:build linux && !cgo && cli

package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCLISSHCancelForwardDoesNotExitMaster(t *testing.T) {
	state := cliSSHTunnelState{
		Destination:  "student@example.edu",
		Port:         1080,
		UpstreamPort: 18080,
		ControlPath:  "/tmp/control.sock",
		Kind:         cliSSHAttachedKind,
	}
	joined := " " + strings.Join(cliSSHCancelDynamicForwardArguments(state), " ") + " "
	for _, expected := range []string{
		" -O cancel ",
		" -D 127.0.0.1:18080 ",
		" -S /tmp/control.sock ",
		" student@example.edu ",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("cancel arguments omit %q: %s", expected, joined)
		}
	}
	if strings.Contains(joined, " -O exit ") {
		t.Fatalf("cancel arguments must not exit the master: %s", joined)
	}
}

func TestStopAttachedSSHTunnelLeavesUserMaster(t *testing.T) {
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	logPath := filepath.Join(t.TempDir(), "ssh.log")
	script := "#!/bin/sh\n" +
		"control=''\noperation=''\nprevious=''\n" +
		"for argument in \"$@\"; do\n" +
		"  if [ \"$previous\" = '-S' ]; then control=\"$argument\"; fi\n" +
		"  if [ \"$previous\" = '-O' ]; then operation=\"$argument\"; fi\n" +
		"  previous=\"$argument\"\n" +
		"done\n" +
		"echo \"$operation\" >> \"" + logPath + "\"\n" +
		"if [ \"$operation\" = check ]; then test -e \"$control\"; exit $?; fi\n" +
		"if [ \"$operation\" = cancel ]; then exit 0; fi\n" +
		"if [ \"$operation\" = exit ]; then rm -f \"$control\"; exit 0; fi\n" +
		"exit 1\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	controlPath := filepath.Join(t.TempDir(), "user-cm.sock")
	statePath := filepath.Join(t.TempDir(), "attached.json")
	if err := os.WriteFile(controlPath, []byte("master"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := cliSSHTunnelState{
		Name:        "home",
		Destination: "deploy@gateway.example.com",
		Port:        1080,
		ControlPath: controlPath,
		Kind:        cliSSHAttachedKind,
		StatePath:   statePath,
	}
	if err := saveCLISSHTunnelState(state); err != nil {
		t.Fatal(err)
	}
	if err := stopCLIStateTunnel(state); err != nil {
		t.Fatalf("detach user SSH: %v", err)
	}
	if _, err := os.Stat(controlPath); err != nil {
		t.Fatalf("detach removed the user's ControlMaster: %v", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("detach left FlClash SSH state: %v", err)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), "cancel") {
		t.Fatalf("detach did not cancel the SOCKS forward: %s", logged)
	}
	if strings.Contains(string(logged), "exit") {
		t.Fatalf("detach exited the user's SSH master: %s", logged)
	}
}

func TestFindLiveSSHMasterUsesOpenSSHConfigControlPath(t *testing.T) {
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	controlPath := filepath.Join(t.TempDir(), "cm.sock")
	if err := os.WriteFile(controlPath, []byte("master"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"control=''\noperation=''\nprevious=''\n" +
		"for argument in \"$@\"; do\n" +
		"  if [ \"$previous\" = '-S' ]; then control=\"$argument\"; fi\n" +
		"  if [ \"$previous\" = '-O' ]; then operation=\"$argument\"; fi\n" +
		"  previous=\"$argument\"\n" +
		"done\n" +
		"case \" $* \" in\n" +
		"  *' -G '*) printf 'controlmaster auto\\ncontrolpath %s\\n' '" + controlPath + "' ;;\n" +
		"  *)\n" +
		"    if [ \"$operation\" = check ]; then test -e \"$control\"; exit $?; fi\n" +
		"    exit 1 ;;\n" +
		"esac\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	path, ok := findCLILiveSSHMaster(cliSSHProfile{
		Name:     "home",
		Username: "deploy",
		Host:     "gateway.example.com",
		Port:     22,
	})
	if !ok || path != controlPath {
		t.Fatalf("live master = %q %t", path, ok)
	}
}

func TestAttachSSHProfileFailsClosedWithoutControlMaster(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	script := "#!/bin/sh\n" +
		"case \" $* \" in\n" +
		"  *' -G '*) printf 'controlmaster no\\ncontrolpath none\\n' ;;\n" +
		"  *) exit 1 ;;\n" +
		"esac\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := addCLISSHProfile(cliSSHProfile{
		Name:     "home",
		Username: "deploy",
		Host:     "gateway.example.com",
		Port:     22,
	}); err != nil {
		t.Fatal(err)
	}
	_, _, err := attachCLISSHProfile("home")
	if err == nil || !strings.Contains(err.Error(), "ordinary ssh sessions cannot be captured") {
		t.Fatalf("attach without ControlMaster = %v", err)
	}
}

func TestStartPersistentSSHTunnelAttachesExistingMaster(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	controlPath := filepath.Join(t.TempDir(), "cm.sock")
	if err := os.WriteFile(controlPath, []byte("master"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"control=''\noperation=''\nprevious=''\n" +
		"for argument in \"$@\"; do\n" +
		"  if [ \"$previous\" = '-S' ]; then control=\"$argument\"; fi\n" +
		"  if [ \"$previous\" = '-O' ]; then operation=\"$argument\"; fi\n" +
		"  previous=\"$argument\"\n" +
		"done\n" +
		"case \" $* \" in\n" +
		"  *' -G '*) printf 'controlmaster auto\\ncontrolpath %s\\n' '" + controlPath + "' ;;\n" +
		"  *)\n" +
		"    if [ \"$operation\" = check ]; then test -e \"$control\"; exit $?; fi\n" +
		"    if [ \"$operation\" = forward ]; then exit 0; fi\n" +
		"    if [ \"$operation\" = cancel ]; then exit 0; fi\n" +
		"    if [ \"$operation\" = exit ]; then rm -f \"$control\"; exit 0; fi\n" +
		"    exit 99 ;;\n" +
		"esac\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	runtimeRoot := t.TempDir()
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	previousForward := addCLISSHDynamicForwardForOperation
	previousRelay := startCLISSHRelayForOperation
	var upstream net.Listener
	addCLISSHDynamicForwardForOperation = func(path string, state cliSSHTunnelState) error {
		if err := addCLISSHDynamicForward(path, state); err != nil {
			return err
		}
		var err error
		upstream, err = net.Listen(
			"tcp4",
			net.JoinHostPort("127.0.0.1", strconv.Itoa(cliSSHUpstreamPort(state))),
		)
		return err
	}
	startCLISSHRelayForOperation = func(state *cliSSHTunnelState) error {
		return startTestSSHRelay(t, state)
	}
	t.Cleanup(func() {
		if upstream != nil {
			_ = upstream.Close()
		}
		cliRuntimeDirectoryOverride = previousRuntime
		addCLISSHDynamicForwardForOperation = previousForward
		startCLISSHRelayForOperation = previousRelay
	})
	state, err := startCLIPersistentSSHTunnel(cliSSHProfile{
		Name:     "home",
		Username: "deploy",
		Host:     "gateway.example.com",
		Port:     22,
	})
	if err != nil {
		t.Fatalf("attach existing master: %v", err)
	}
	if state.Kind != cliSSHAttachedKind {
		t.Fatalf("tunnel kind = %q", state.Kind)
	}
	if state.ControlPath != controlPath {
		t.Fatalf("attached control path = %s", state.ControlPath)
	}
	if err := stopCLIStateTunnel(state); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if _, err := os.Stat(controlPath); err != nil {
		t.Fatalf("stop attached tunnel removed user master: %v", err)
	}
}

func TestConnectCLISSHProfileReusesLiveMasterWithoutNewLogin(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	controlPath := filepath.Join(t.TempDir(), "cm.sock")
	if err := os.WriteFile(controlPath, []byte("master"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "ssh.log")
	script := "#!/bin/sh\n" +
		"echo \"$*\" >> \"" + logPath + "\"\n" +
		"control=''\noperation=''\nprevious=''\n" +
		"for argument in \"$@\"; do\n" +
		"  if [ \"$previous\" = '-S' ]; then control=\"$argument\"; fi\n" +
		"  if [ \"$previous\" = '-O' ]; then operation=\"$argument\"; fi\n" +
		"  previous=\"$argument\"\n" +
		"done\n" +
		"case \" $* \" in\n" +
		"  *' -f '*|*' -N '*|*' -M '*) exit 99 ;;\n" +
		"  *' -G '*) printf 'controlmaster true\\ncontrolpath %s\\n' '" + controlPath + "' ;;\n" +
		"  *)\n" +
		"    if [ \"$operation\" = check ]; then test -e \"$control\"; exit $?; fi\n" +
		"    if [ \"$operation\" = forward ]; then exit 0; fi\n" +
		"    if [ \"$operation\" = cancel ]; then exit 0; fi\n" +
		"    if [ \"$operation\" = exit ]; then rm -f \"$control\"; exit 0; fi\n" +
		"    exit 99 ;;\n" +
		"esac\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	runtimeRoot := t.TempDir()
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	previousForward := addCLISSHDynamicForwardForOperation
	previousRelay := startCLISSHRelayForOperation
	var upstream net.Listener
	addCLISSHDynamicForwardForOperation = func(path string, state cliSSHTunnelState) error {
		if err := addCLISSHDynamicForward(path, state); err != nil {
			return err
		}
		var err error
		upstream, err = net.Listen(
			"tcp4",
			net.JoinHostPort("127.0.0.1", strconv.Itoa(cliSSHUpstreamPort(state))),
		)
		return err
	}
	startCLISSHRelayForOperation = func(state *cliSSHTunnelState) error {
		return startTestSSHRelay(t, state)
	}
	t.Cleanup(func() {
		if upstream != nil {
			_ = upstream.Close()
		}
		cliRuntimeDirectoryOverride = previousRuntime
		addCLISSHDynamicForwardForOperation = previousForward
		startCLISSHRelayForOperation = previousRelay
	})
	if err := addCLISSHProfile(cliSSHProfile{
		Name:     "home",
		Username: "deploy",
		Host:     "gateway.example.com",
		Port:     22,
	}); err != nil {
		t.Fatal(err)
	}
	state, already, err := connectCLISSHProfile("home")
	if err != nil {
		t.Fatalf("connect existing master: %v", err)
	}
	if already {
		t.Fatal("expected a new attach, not an already-connected tunnel")
	}
	if state.Kind != cliSSHAttachedKind {
		t.Fatalf("tunnel kind = %q", state.Kind)
	}
	if state.ControlPath != controlPath {
		t.Fatalf("connected control path = %s", state.ControlPath)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{" -f ", " -N ", " -M ", " -O exit "} {
		if strings.Contains(" "+string(logged)+" ", forbidden) {
			t.Fatalf("connect started a new SSH login or exited the master:%s\nlog:\n%s", forbidden, logged)
		}
	}
	if !strings.Contains(string(logged), " -O forward ") {
		t.Fatalf("connect did not hang SOCKS on the live master:\n%s", logged)
	}
	if err := stopCLIStateTunnel(state); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if _, err := os.Stat(controlPath); err != nil {
		t.Fatalf("stop attached tunnel removed user master: %v", err)
	}
	logged, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), " -O cancel ") {
		t.Fatalf("detach did not cancel the SOCKS forward:\n%s", logged)
	}
	if strings.Contains(string(logged), " -O exit ") {
		t.Fatalf("detach exited the user's SSH master:\n%s", logged)
	}
}

func startTestSSHRelay(t *testing.T, state *cliSSHTunnelState) error {
	t.Helper()
	public, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(state.Port)))
	if err != nil {
		return err
	}
	controlPath := filepath.Join(t.TempDir(), "relay.sock")
	_ = os.Remove(controlPath)
	control, err := net.Listen("unix", controlPath)
	if err != nil {
		_ = public.Close()
		return err
	}
	if err := os.Chmod(controlPath, 0o600); err != nil {
		_ = public.Close()
		_ = control.Close()
		return err
	}
	state.RelayControl = controlPath
	state.RelayPID = os.Getpid()
	go func() {
		defer public.Close()
		defer control.Close()
		for {
			connection, acceptErr := control.Accept()
			if acceptErr != nil {
				return
			}
			var request cliSSHRelayRequest
			if err := json.NewDecoder(connection).Decode(&request); err != nil {
				_ = connection.Close()
				continue
			}
			stats := cliSSHRelayStats{
				PID:          state.RelayPID,
				StartedAt:    time.Now(),
				ListenPort:   state.Port,
				UpstreamPort: state.UpstreamPort,
				OK:           true,
			}
			_ = json.NewEncoder(connection).Encode(stats)
			_ = connection.Close()
			if request.Action == "shutdown" {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = public.Close()
		_ = control.Close()
	})
	return nil
}

func TestTUISSHAttachKeyOpensCapturePicker(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	controlPath := filepath.Join(t.TempDir(), "cm.sock")
	if err := os.WriteFile(controlPath, []byte("master"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"control=''\noperation=''\nprevious=''\n" +
		"for argument in \"$@\"; do\n" +
		"  if [ \"$previous\" = '-S' ]; then control=\"$argument\"; fi\n" +
		"  if [ \"$previous\" = '-O' ]; then operation=\"$argument\"; fi\n" +
		"  previous=\"$argument\"\n" +
		"done\n" +
		"case \" $* \" in\n" +
		"  *' -G '*) printf 'controlmaster auto\\ncontrolpath %s\\n' '" + controlPath + "' ;;\n" +
		"  *)\n" +
		"    if [ \"$operation\" = check ]; then test -e \"$control\"; exit $?; fi\n" +
		"    exit 1 ;;\n" +
		"esac\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageSSH
	model.snapshot.FocusSidebar = false
	model.snapshot.SSHDashboardFocus = false
	model.snapshot.SelectedSSH = 0
	model.snapshot.SSHProfiles = []tuiSSHProfile{{
		Name:        "home",
		Username:    "deploy",
		Host:        "gateway.example.com",
		Destination: "deploy@gateway.example.com",
		Port:        22,
	}}
	if command := model.handleKey(tuiKeyAllowLAN); command != nil {
		t.Fatal("capture picker should wait for confirmation")
	}
	if !model.sshCaptureOpen || len(model.sshCaptureNames) != 1 ||
		model.sshCaptureNames[0] != "home" {
		t.Fatalf("capture picker = open %t names %v", model.sshCaptureOpen, model.sshCaptureNames)
	}
	view := model.View()
	if !strings.Contains(stripTUIANSI(view), "Capture existing SSH") ||
		!strings.Contains(stripTUIANSI(view), "deploy@gateway.example.com") {
		t.Fatalf("capture overlay missing:\n%s", view)
	}
}

func TestCLISSHControlMasterEnabledMatchesOpenSSHDashG(t *testing.T) {
	for _, value := range []string{"yes", "true", "auto", "ask", "autoask", "YES", " True "} {
		if !cliSSHControlMasterEnabled(value) {
			t.Fatalf("ControlMaster %q should be reusable", value)
		}
	}
	for _, value := range []string{"", "no", "false", "none", "off"} {
		if cliSSHControlMasterEnabled(value) {
			t.Fatalf("ControlMaster %q must fail closed", value)
		}
	}
}

func TestFindLiveSSHMasterRejectsControlMasterFalseWithLeftoverSocket(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	controlPath := filepath.Join(t.TempDir(), "cm.sock")
	if err := os.WriteFile(controlPath, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "ssh.log")
	script := "#!/bin/sh\n" +
		"echo \"$*\" >> \"" + logPath + "\"\n" +
		"control=''\noperation=''\nprevious=''\n" +
		"for argument in \"$@\"; do\n" +
		"  if [ \"$previous\" = '-S' ]; then control=\"$argument\"; fi\n" +
		"  if [ \"$previous\" = '-O' ]; then operation=\"$argument\"; fi\n" +
		"  previous=\"$argument\"\n" +
		"done\n" +
		"case \" $* \" in\n" +
		"  *' -G '*) printf 'controlmaster false\\ncontrolpath %s\\n' '" + controlPath + "' ;;\n" +
		"  *)\n" +
		"    if [ \"$operation\" = check ]; then test -e \"$control\"; exit $?; fi\n" +
		"    exit 1 ;;\n" +
		"esac\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := addCLISSHProfile(cliSSHProfile{
		Name:     "home",
		Username: "deploy",
		Host:     "gateway.example.com",
		Port:     22,
	}); err != nil {
		t.Fatal(err)
	}
	path, ok := findCLILiveSSHMaster(cliSSHProfile{
		Name:     "home",
		Username: "deploy",
		Host:     "gateway.example.com",
		Port:     22,
	})
	if ok || path != "" {
		t.Fatalf("leftover socket with controlmaster false = %q %t", path, ok)
	}
	_, _, err := attachCLISSHProfile("home")
	if err == nil || !strings.Contains(err.Error(), "ordinary ssh sessions cannot be captured") {
		t.Fatalf("attach with ControlMaster false = %v", err)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logged), " -O check ") {
		t.Fatalf("disabled ControlMaster still probed the leftover socket:\n%s", logged)
	}
}

func TestFindLiveSSHMasterAcceptsControlMasterTrue(t *testing.T) {
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	controlPath := filepath.Join(t.TempDir(), "cm.sock")
	if err := os.WriteFile(controlPath, []byte("master"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n" +
		"control=''\noperation=''\nprevious=''\n" +
		"for argument in \"$@\"; do\n" +
		"  if [ \"$previous\" = '-S' ]; then control=\"$argument\"; fi\n" +
		"  if [ \"$previous\" = '-O' ]; then operation=\"$argument\"; fi\n" +
		"  previous=\"$argument\"\n" +
		"done\n" +
		"case \" $* \" in\n" +
		"  *' -G '*) printf 'controlmaster true\\ncontrolpath %s\\n' '" + controlPath + "' ;;\n" +
		"  *)\n" +
		"    if [ \"$operation\" = check ]; then test -e \"$control\"; exit $?; fi\n" +
		"    exit 1 ;;\n" +
		"esac\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	path, ok := findCLILiveSSHMaster(cliSSHProfile{
		Name:     "home",
		Username: "deploy",
		Host:     "gateway.example.com",
		Port:     22,
	})
	if !ok || path != controlPath {
		t.Fatalf("live master with controlmaster true = %q %t", path, ok)
	}
}

func TestLoadCLISSHProfileViewsDoesNotProbeControlMaster(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	probed := filepath.Join(binDirectory, "probed")
	script := "#!/bin/sh\necho probed >> \"" + probed + "\"\nexit 99\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := addCLISSHProfile(cliSSHProfile{
		Name:     "home",
		Username: "deploy",
		Host:     "gateway.example.com",
		Port:     22,
	}); err != nil {
		t.Fatal(err)
	}
	views, err := loadCLISSHProfileViews()
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].Attachable {
		t.Fatalf("list probed ControlMaster: %+v", views)
	}
	listOutput := captureCLIOutput(t, func() error { return cliSSHListCommand(nil) })
	if !strings.Contains(listOutput, "home") {
		t.Fatalf("ssh list output = %q", listOutput)
	}
	snapshot := tuiSnapshot{Page: tuiPageSSH, SelectedSSH: tuiSSHCaptureRow}
	refreshTUISSH(&snapshot)
	if len(snapshot.SSHProfiles) != 1 || snapshot.SSHProfiles[0].Attachable {
		t.Fatalf("TUI refresh probed ControlMaster: %+v", snapshot.SSHProfiles)
	}
	if _, err := os.Stat(probed); !os.IsNotExist(err) {
		t.Fatal("ssh list/refresh probed ControlMaster without a user request")
	}
}

func TestTUISSHRendersCaptureRow(t *testing.T) {
	var output strings.Builder
	snapshot := tuiSnapshot{
		Page:        tuiPageSSH,
		SelectedSSH: tuiSSHCaptureRow,
		SSHProfiles: []tuiSSHProfile{{
			Name:     "home",
			Username: "deploy",
			Host:     "gateway.example.com",
			Port:     22,
		}},
	}
	drawTUISSH(&output, snapshot, 120, 36)
	plain := stripTUIANSI(output.String())
	for _, expected := range []string{
		"Capture existing SSH",
		"Enter probes live ControlMaster",
		"Probe runs only when you ask",
	} {
		if !strings.Contains(plain, expected) {
			t.Fatalf("SSH page missing %q:\n%s", expected, plain)
		}
	}
}
