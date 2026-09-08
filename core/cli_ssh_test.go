//go:build linux && !cgo && cli

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	cryptossh "golang.org/x/crypto/ssh"
)

func TestParseCLISSHProfileEdit(t *testing.T) {
	edit, interactive, err := parseCLISSHProfileEdit([]string{
		"school",
		"student@example.edu",
		"--port",
		"2222",
		"--local-port",
		"1080",
		"--identity",
		"/tmp/id_ed25519",
		"--option",
		"StrictHostKeyChecking=yes",
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if interactive || edit.Name != "school" ||
		edit.Username != "student" || edit.Host != "example.edu" ||
		edit.Destination != "student@example.edu" || edit.Port != 2222 ||
		edit.Identity != "/tmp/id_ed25519" || edit.LocalPort != 1080 ||
		!edit.LocalPortSet || len(edit.Options) != 1 {
		t.Fatalf("unexpected parsed profile: %+v", edit)
	}
}

func TestParseCLISSHProfileEditSupportsSeparateRequiredUsername(t *testing.T) {
	edit, interactive, err := parseCLISSHProfileEdit([]string{
		"school",
		"example.edu",
		"--user",
		"student",
	}, false)
	if err != nil || interactive || edit.Username != "student" ||
		edit.Host != "example.edu" {
		t.Fatalf("separate SSH username parse = %+v, interactive:%t err:%v", edit, interactive, err)
	}
	if _, _, err := parseCLISSHProfileEdit([]string{"school", "example.edu"}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := cliSSHProfileFromEdit(cliSSHProfile{}, cliSSHProfileEdit{
		Name: "school",
		Host: "example.edu",
		Port: 22,
	}, false); err == nil || !strings.Contains(err.Error(), "username") {
		t.Fatalf("missing SSH username error = %v", err)
	}
}

func TestCLISSHConfigV1MigrationSplitsDestinationAndMarksBareHost(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	directory := filepath.Join(configRoot, "flclash")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, cliSSHConfigFilename)
	legacy := `{"version":1,"profiles":[` +
		`{"name":"split","destination":"student@example.edu","port":22},` +
		`{"name":"incomplete","destination":"ssh-alias","port":22}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := loadCLISSHConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Profiles[0].Username != "student" || config.Profiles[0].Host != "example.edu" ||
		config.Profiles[1].Username != "" || config.Profiles[1].Host != "ssh-alias" {
		t.Fatalf("migrated SSH profiles = %+v", config.Profiles)
	}
	views, err := loadCLISSHProfileViews()
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 2 || !views[1].NeedsUsername {
		t.Fatalf("legacy bare host was not marked incomplete: %+v", views)
	}
	if err := updateCLISSHConfig(func(*cliSSHConfig) error { return nil }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"version": 2`) ||
		strings.Contains(string(data), `"destination"`) {
		t.Fatalf("SSH config was not serialized as v2: %s", data)
	}
}

func TestParseCLISSHProfileEditRejectsCredentialConflicts(t *testing.T) {
	for _, arguments := range [][]string{
		{"school", "student@example.edu", "--passphrase", "--clear-passphrase"},
		{"school", "student@example.edu", "--password", "--clear-password"},
		{"school", "student@example.edu", "--jump", "bastion", "--clear-jump"},
		{"school", "student@example.edu", "--clear-passphrase"},
		{"school", "student@example.edu", "--clear-password"},
		{"school", "student@example.edu", "--clear-jump"},
	} {
		if _, _, err := parseCLISSHProfileEdit(arguments, false); err == nil {
			t.Fatalf("conflicting SSH credential arguments were accepted: %v", arguments)
		}
	}
}

func TestValidateCLISSHProfileRejectsWhitespaceInHost(t *testing.T) {
	for _, destination := range []string{
		"ssh student@example.edu",
		"student@example.edu extra",
		"student@example.edu\tproxy",
	} {
		err := validateCLISSHProfile(cliSSHProfile{
			Name:        "school",
			Destination: destination,
			Port:        22,
		})
		if err == nil {
			t.Fatalf("invalid SSH host %q was accepted", destination)
		}
	}
}

func TestCLISSHConfigIsPrivateAndViewsMaskSecrets(t *testing.T) {
	configRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	t.Cleanup(func() { cliRuntimeDirectoryOverride = previousRuntime })

	err := updateCLISSHConfig(func(config *cliSSHConfig) error {
		config.Profiles = []cliSSHProfile{{
			Name:               "school",
			Destination:        "student@example.edu",
			Port:               22,
			LocalPort:          1080,
			Identity:           "/tmp/id_ed25519",
			IdentityPassphrase: "do-not-display-passphrase",
			Password:           "do-not-display-password",
		}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configRoot, "flclash", cliSSHConfigFilename)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("SSH config mode = %o, want 0600", info.Mode().Perm())
	}
	views, err := loadCLISSHProfileViews()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(views)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || !views[0].PassphraseSet || !views[0].PasswordSet ||
		views[0].LocalPort != 1080 ||
		strings.Contains(string(encoded), "do-not-display-passphrase") ||
		strings.Contains(string(encoded), "do-not-display-password") {
		t.Fatalf("SSH secret leaked through view: %s", encoded)
	}
}

func TestCLISSHAskpassSelectsKeyPassphraseAndPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "askpass.secret")
	data, err := json.Marshal(cliSSHAskpassSecrets{
		IdentityPassphrase: "key-secret",
		Password:           "login-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		prompt string
		want   string
	}{
		{"Enter passphrase for key '/tmp/id_ed25519':", "key-secret"},
		{"student@example.edu's password:", "login-secret"},
	} {
		answer, err := cliSSHAskpassAnswer(test.prompt, path)
		if err != nil || answer != test.want {
			t.Fatalf("askpass answer for %q = %q, %v; want %q", test.prompt, answer, err, test.want)
		}
	}
	if _, err := cliSSHAskpassAnswer("Confirm host key?", path); err == nil {
		t.Fatal("askpass answered an unrelated authentication prompt")
	}
}

func writeTestCLISSHPrivateKey(
	t *testing.T,
	passphrase string,
) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = cryptossh.MarshalPrivateKey(key, "flclash-test")
	} else {
		block, err = cryptossh.MarshalPrivateKeyWithPassphrase(
			key,
			"flclash-test",
			[]byte(passphrase),
		)
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInspectCLISSHIdentityDistinguishesEncryption(t *testing.T) {
	plain := writeTestCLISSHPrivateKey(t, "")
	kind, err := inspectCLISSHIdentity(plain, "")
	if err != nil || kind != cliSSHIdentityUnencrypted {
		t.Fatalf("plain SSH key inspection = %v, %v", kind, err)
	}
	encrypted := writeTestCLISSHPrivateKey(t, "key-secret")
	kind, err = inspectCLISSHIdentity(encrypted, "")
	if err != nil || kind != cliSSHIdentityEncrypted {
		t.Fatalf("encrypted SSH key inspection = %v, %v", kind, err)
	}
	if _, err := inspectCLISSHIdentity(encrypted, "wrong"); err == nil ||
		!strings.Contains(err.Error(), "incorrect") {
		t.Fatalf("wrong key passphrase error = %v", err)
	}
	if kind, err = inspectCLISSHIdentity(encrypted, "key-secret"); err != nil || kind != cliSSHIdentityEncrypted {
		t.Fatalf("unlocked SSH key inspection = %v, %v", kind, err)
	}
}

func TestInspectCLISSHIdentityRejectsOpenPermissions(t *testing.T) {
	path := writeTestCLISSHPrivateKey(t, "")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectCLISSHIdentity(path, ""); err == nil ||
		!strings.Contains(err.Error(), "permissions are too open") ||
		!strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("open SSH key permissions error = %v", err)
	}
}

func TestPrepareCLISSHProfileCredentialsRequestsOnlyEncryptedKeyPassphrase(t *testing.T) {
	plain := cliSSHProfile{
		Name:     "plain",
		Username: "student",
		Host:     "example.edu",
		Port:     22,
		Identity: writeTestCLISSHPrivateKey(t, ""),
	}
	if _, err := prepareCLISSHProfileCredentials(plain, cliSSHCredentials{}); err != nil {
		t.Fatalf("unencrypted SSH key required a passphrase: %v", err)
	}
	encrypted := plain
	encrypted.Name = "encrypted"
	encrypted.Identity = writeTestCLISSHPrivateKey(t, "key-secret")
	if _, err := prepareCLISSHProfileCredentials(encrypted, cliSSHCredentials{}); err == nil {
		t.Fatal("encrypted SSH key without passphrase was accepted")
	} else {
		var required *cliSSHCredentialRequiredError
		if !errors.As(err, &required) {
			t.Fatalf("encrypted SSH key error = %T %v", err, err)
		}
	}
	prepared, err := prepareCLISSHProfileCredentials(
		encrypted,
		cliSSHCredentials{IdentityPassphrase: "key-secret"},
	)
	if err != nil || prepared.IdentityPassphrase != "key-secret" {
		t.Fatalf("one-time key passphrase preparation = %+v, %v", prepared, err)
	}
}

func TestCLISSHAskpassRejectsMissingOrUnsafeSecrets(t *testing.T) {
	directory := t.TempDir()
	missingPassword := filepath.Join(directory, "missing-password.secret")
	data, err := json.Marshal(cliSSHAskpassSecrets{IdentityPassphrase: "key-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(missingPassword, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cliSSHAskpassAnswer("Password:", missingPassword); err == nil ||
		!strings.Contains(err.Error(), "no SSH password") {
		t.Fatalf("missing SSH password error = %v", err)
	}
	unsafe := filepath.Join(directory, "unsafe.secret")
	if err := os.WriteFile(unsafe, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cliSSHAskpassAnswer("Passphrase:", unsafe); err == nil ||
		!strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("unsafe askpass secret error = %v", err)
	}
}

func TestConfigureCLISSHAskpassKeepsBothSecretsOutOfEnvironment(t *testing.T) {
	runtimeRoot := t.TempDir()
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	t.Cleanup(func() { cliRuntimeDirectoryOverride = previousRuntime })
	directory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		t.Fatal(err)
	}
	stalePath := filepath.Join(directory, "askpass-stale.secret")
	if err := os.WriteFile(stalePath, []byte("stale-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_ASKPASS", "/tmp/stale-askpass")
	t.Setenv("SSH_ASKPASS_REQUIRE", "prefer")
	t.Setenv("DISPLAY", ":99")
	t.Setenv("LC_ALL", "zh_CN.UTF-8")
	t.Setenv(cliSSHAskpassFileEnv, "/tmp/stale-secret")
	command := exec.Command("true")
	cleanup, err := configureCLISSHAskpass(command, "key-secret", "login-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		cleanup()
		t.Fatalf("stale SSH askpass secret was not removed: %v", err)
	}
	secretPath := ""
	environment := map[string]string{}
	for _, value := range command.Env {
		if strings.Contains(value, "key-secret") || strings.Contains(value, "login-secret") {
			cleanup()
			t.Fatal("SSH secret leaked into the child environment")
		}
		if strings.HasPrefix(value, cliSSHAskpassFileEnv+"=") {
			secretPath = strings.TrimPrefix(value, cliSSHAskpassFileEnv+"=")
		}
		key, item, found := strings.Cut(value, "=")
		if found {
			environment[key] = item
		}
	}
	if secretPath == "" {
		cleanup()
		t.Fatal("SSH askpass secret path was not configured")
	}
	if environment["LC_ALL"] != "C" ||
		environment["SSH_ASKPASS_REQUIRE"] != "force" ||
		environment["DISPLAY"] != "flclash-askpass" ||
		environment["SSH_ASKPASS"] == "/tmp/stale-askpass" ||
		environment[cliSSHAskpassFileEnv] != secretPath {
		cleanup()
		t.Fatalf("SSH askpass environment was not replaced safely: %+v", environment)
	}
	for prompt, want := range map[string]string{
		"Enter passphrase for key:": "key-secret",
		"Password:":                 "login-secret",
	} {
		answer, err := cliSSHAskpassAnswer(prompt, secretPath)
		if err != nil || answer != want {
			cleanup()
			t.Fatalf("configured askpass answer for %q = %q, %v", prompt, answer, err)
		}
	}
	cleanup()
	if _, err := os.Stat(secretPath); !os.IsNotExist(err) {
		t.Fatalf("askpass temporary secret remains after cleanup: %v", err)
	}
}

func TestStopAllCLISSHTunnelsRemovesStaleAskpassSecrets(t *testing.T) {
	runtimeRoot := t.TempDir()
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	t.Cleanup(func() { cliRuntimeDirectoryOverride = previousRuntime })
	directory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "askpass-crashed.secret")
	if err := os.WriteFile(path, []byte("stale-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stopAllCLISSHTunnels(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("complete SSH cleanup left stale askpass secret: %v", err)
	}
}

func TestTUISSHPageRendersMaskedAuthentication(t *testing.T) {
	snapshot := tuiSnapshot{
		Page:         tuiPageSSH,
		SelectedMenu: int(tuiPageSSH),
		SSHProfiles: []tuiSSHProfile{{
			Name:          "school",
			Destination:   "student@example.edu",
			Port:          22,
			LocalPort:     1080,
			Identity:      "/tmp/id_ed25519",
			PassphraseSet: true,
			PasswordSet:   true,
			Connected:     true,
			Ready:         true,
			SocksPort:     45678,
		}},
	}
	output := stripTUIANSI(renderTUIAtSize(
		snapshot,
		cliPaths{},
		"private Unix socket",
		true,
		false,
		220,
		30,
	))
	for _, expected := range []string{
		"SSH profiles · 1 configured",
		"SSH Dashboard · school",
		"school",
		"CONNECTED",
		"key + passphrase **** → password **** fallback/MFA",
		"SOCKS5 127.0.0.1:45678",
		"configured 1080",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("SSH page does not contain %q:\n%s", expected, output)
		}
	}
}

func TestTUISSHPageDistinguishesBrokenSOCKSListener(t *testing.T) {
	output := stripTUIANSI(renderTUIAtSize(
		tuiSnapshot{
			Page: tuiPageSSH,
			SSHProfiles: []tuiSSHProfile{{
				Name:        "school",
				Destination: "student@example.edu",
				Port:        22,
				Connected:   true,
				Ready:       false,
				SocksPort:   45678,
			}},
		},
		cliPaths{},
		"private Unix socket",
		true,
		false,
		180,
		30,
	))
	for _, expected := range []string{"BROKEN", "SOCKS5 127.0.0.1:45678 unavailable"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("broken SSH page does not contain %q:\n%s", expected, output)
		}
	}
}

func TestTUISSHDashboardShowsExitTestsAndRelayTraffic(t *testing.T) {
	output := stripTUIANSI(renderTUIAtSize(
		tuiSnapshot{
			Page:              tuiPageSSH,
			SSHDashboardFocus: true,
			SSHConnections:    2,
			SSHTraffic:        trafficSnapshot{Up: 1024, Down: 2048},
			SSHTotalTraffic:   trafficSnapshot{Up: 4096, Down: 8192},
			SSHTrafficHistory: []trafficSnapshot{{Up: 1024, Down: 2048}},
			SSHNetwork:        tuiNetworkInfo{PublicIP: "203.0.113.8", Country: "SG"},
			SSHProfiles: []tuiSSHProfile{{
				Name:        "school",
				Destination: "student@example.edu",
				Port:        22,
				Connected:   true,
				Ready:       true,
				SocksPort:   1080,
				StartedAt:   time.Now().Add(-time.Minute),
			}},
		},
		cliPaths{},
		"private Unix socket",
		true,
		false,
		180,
		40,
	))
	for _, expected := range []string{
		"SSH profiles · 1 configured",
		"SSH Dashboard · school",
		"SOCKS5 127.0.0.1:1080",
		"203.0.113.8  [SG]",
		"Managed CF DL",
		"Live traffic",
		"2 active",
		"only traffic through this SSH SOCKS5 port",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("SSH Dashboard does not contain %q:\n%s", expected, output)
		}
	}
}

func TestTUIEnterReconnectsBrokenSSHProfileFromProfileBox(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.width = 120
	model.height = 30
	model.snapshot.Page = tuiPageSSH
	model.snapshot.FocusSidebar = false
	model.snapshot.SSHProfiles = []tuiSSHProfile{{
		Name:      "school",
		Connected: true,
		Ready:     false,
	}}
	command := model.selectCurrent()
	if command == nil || model.snapshot.Status != "SSH connect school..." {
		t.Fatalf("broken SSH profile action = command:%t status:%q", command != nil, model.snapshot.Status)
	}
	if model.snapshot.SSHDashboardFocus {
		t.Fatal("broken SSH profile moved focus before reconnecting")
	}
}

func TestTUIEnterFocusesDashboardForHealthySSHProfile(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageSSH
	model.snapshot.FocusSidebar = false
	model.snapshot.SSHProfiles = []tuiSSHProfile{{
		Name:      "school",
		Connected: true,
		Ready:     true,
		SocksPort: 1080,
	}}
	command := model.selectCurrent()
	if !model.snapshot.SSHDashboardFocus {
		t.Fatal("healthy SSH profile Enter did not focus its Dashboard")
	}
	if command == nil {
		t.Fatal("healthy SSH profile Enter did not refresh Dashboard data")
	}
	if strings.Contains(model.snapshot.Status, "disconnect") {
		t.Fatalf("profile-box Enter unexpectedly disconnected tunnel: %q", model.snapshot.Status)
	}
}

func TestTUISSHProfileSelectionResetsMetricsAndRefreshesReadyProfile(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageSSH
	model.snapshot.SSHProfiles = []tuiSSHProfile{
		{Name: "first"},
		{Name: "second", Connected: true, Ready: true, SocksPort: 1080},
	}
	model.snapshot.SSHNetwork = tuiNetworkInfo{PublicIP: "203.0.113.1"}
	model.snapshot.SSHDelay = tuiDelayResult{MedianMillis: 25}
	model.snapshot.SSHTrafficHistory = []trafficSnapshot{{Up: 10, Down: 20}}

	command := model.moveSelection(1)
	if model.snapshot.SelectedSSH != 1 {
		t.Fatalf("selected SSH profile = %d, want 1", model.snapshot.SelectedSSH)
	}
	if model.snapshot.SSHNetwork.PublicIP != "" ||
		model.snapshot.SSHDelay.MedianMillis != 0 ||
		len(model.snapshot.SSHTrafficHistory) != 0 {
		t.Fatalf("SSH metrics survived profile switch: %+v", model.snapshot)
	}
	if command == nil {
		t.Fatal("ready SSH profile switch did not schedule Dashboard refresh")
	}
}

func TestTUISSHNewKeyUsesCurrentFocus(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageSSH
	model.snapshot.FocusSidebar = false
	_ = model.handleKey(tuiKeyNewProfile)
	if !model.sshFormOpen {
		t.Fatal("n in SSH profile box did not open add form")
	}

	model.resetSSHForm()
	model.snapshot.SSHDashboardFocus = true
	_ = model.handleKey(tuiKeyNewProfile)
	if model.sshFormOpen {
		t.Fatal("n in SSH Dashboard unexpectedly opened add form")
	}
}

func TestTUISSHCompactPageKeepsProfilesAndDashboardVisible(t *testing.T) {
	output := stripTUIANSI(tuiRenderPage(
		tuiSnapshot{
			Page: tuiPageSSH,
			SSHProfiles: []tuiSSHProfile{{
				Name:        "school",
				Destination: "student@example.edu",
				Port:        22,
			}},
		},
		cliPaths{},
		96,
		12,
	))
	for _, expected := range []string{
		"SSH profiles · 1 configured",
		"SSH Dashboard · school",
		"Traffic",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("compact SSH page does not contain %q:\n%s", expected, output)
		}
	}
}

func TestTUISSHEncryptedKeyPromptStaysInsideFrameAndMasksInput(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageSSH
	model.snapshot.SSHProfiles = []tuiSSHProfile{{Name: "school"}}
	_, _ = model.Update(tuiSSHCommandResultMsg{
		action:       "connect",
		selectedName: "school",
		err: &cliSSHCredentialRequiredError{
			Profile:  "school",
			Identity: "/home/student/.ssh/id_ed25519",
		},
	})
	if !model.sshCredentialPromptOpen {
		t.Fatal("encrypted SSH key did not open the TUI credential prompt")
	}
	secret := "one-time-secret"
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(secret)})
	view := model.View()
	if strings.Contains(view, secret) || !strings.Contains(stripTUIANSI(view), "One-time credential") {
		t.Fatalf("SSH credential prompt leaked or omitted state:\n%s", view)
	}
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if command == nil || model.sshCredentialPromptOpen || len(model.sshCredentialInput) != 0 {
		t.Fatalf(
			"SSH credential submission = command:%t open:%t input:%d",
			command != nil,
			model.sshCredentialPromptOpen,
			len(model.sshCredentialInput),
		)
	}
}

func TestTUISSHFormUsesDistinctHostKeyAndSecretLabels(t *testing.T) {
	snapshot := tuiSnapshot{
		Page: tuiPageSSH,
		SSHForm: tuiSSHFormView{
			Open:          true,
			Name:          "school",
			Username:      "student",
			Host:          "example.edu",
			Port:          22,
			Identity:      "/tmp/id_ed25519",
			PassphraseSet: true,
			PasswordSet:   true,
		},
	}
	output := stripTUIANSI(renderTUIAtSize(
		snapshot,
		cliPaths{},
		"private Unix socket",
		true,
		false,
		180,
		30,
	))
	for _, expected := range []string{
		"SSH username",
		"student",
		"SSH host",
		"example.edu",
		"Identity(private key)",
		"Jump host",
		"Key passphrase",
		"SSH password",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("SSH form does not contain %q:\n%s", expected, output)
		}
	}
	if strings.Contains(output, "SSH exit") {
		t.Fatalf("SSH form still contains the old SSH exit label:\n%s", output)
	}
}

func TestCLISSHProfileEditPreservesOrClearsCredentialsIndependently(t *testing.T) {
	existing := cliSSHProfile{
		Name:               "school",
		Destination:        "student@example.edu",
		Port:               22,
		Identity:           "/tmp/id_ed25519",
		IdentityPassphrase: "key-secret",
		Password:           "login-secret",
	}
	preserved, err := cliSSHProfileFromEdit(existing, cliSSHProfileEdit{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if preserved.IdentityPassphrase != "key-secret" ||
		preserved.Password != "login-secret" {
		t.Fatalf("empty edit did not preserve both credentials: %+v", preserved)
	}
	clearedPassphrase, err := cliSSHProfileFromEdit(existing, cliSSHProfileEdit{
		ClearPassphrase: true,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if clearedPassphrase.IdentityPassphrase != "" ||
		clearedPassphrase.Password != "login-secret" {
		t.Fatalf("passphrase clear affected the wrong credential: %+v", clearedPassphrase)
	}
	clearedPassword, err := cliSSHProfileFromEdit(existing, cliSSHProfileEdit{
		ClearPassword: true,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if clearedPassword.IdentityPassphrase != "key-secret" ||
		clearedPassword.Password != "" {
		t.Fatalf("password clear affected the wrong credential: %+v", clearedPassword)
	}
}

func TestCLISSHRejectsManagedForwardingOptions(t *testing.T) {
	for _, option := range []string{
		"ControlPath=/tmp/socket",
		"DynamicForward=127.0.0.1:9999",
		"LocalCommand=id",
	} {
		if err := validateCLISSHOption(option); err == nil {
			t.Fatalf("managed option %q was accepted", option)
		}
	}
}

func TestCLISSHTunnelArgumentsUseSafeFirstConnectPolicy(t *testing.T) {
	profile := cliSSHProfile{
		Username: "student",
		Host:     "example.edu",
		Port:     2222,
		Identity: "/tmp/id_ed25519",
	}
	arguments := cliSSHTunnelArguments(profile, "/tmp/control.sock")
	joined := strings.Join(arguments, " ")
	for _, expected := range []string{
		"-p 2222",
		"-i /tmp/id_ed25519",
		"-l student",
		"PreferredAuthentications=publickey",
		"PasswordAuthentication=no",
		"BatchMode=yes",
		"ClearAllForwardings=yes",
		"ConnectTimeout=15",
		"ConnectionAttempts=1",
		"StrictHostKeyChecking=accept-new",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("SSH arguments do not contain %q: %v", expected, arguments)
		}
	}
	profile.Options = []string{"StrictHostKeyChecking=yes"}
	arguments = cliSSHTunnelArguments(profile, "/tmp/control.sock")
	joined = strings.Join(arguments, " ")
	if strings.Contains(joined, "StrictHostKeyChecking=accept-new") ||
		!strings.Contains(joined, "StrictHostKeyChecking=yes") {
		t.Fatalf("explicit host-key policy did not override the default: %v", arguments)
	}
	forwardArguments := cliSSHDynamicForwardArguments(cliSSHTunnelState{
		Destination: "student@example.edu",
		Port:        1080,
		ControlPath: "/tmp/control.sock",
	})
	if joined := strings.Join(forwardArguments, " "); !strings.Contains(joined, "-O forward -D 127.0.0.1:1080") {
		t.Fatalf("dynamic forward control arguments are incomplete: %v", forwardArguments)
	}
	profile.Jump = "bastion.example.edu"
	joined = strings.Join(cliSSHTunnelArguments(profile, "/tmp/control.sock"), " ")
	if !strings.Contains(joined, "ProxyJump=bastion.example.edu") {
		t.Fatalf("jump host was not passed to OpenSSH: %v", joined)
	}
}

func TestCLISSHControlArgumentsCannotPromptOrReauthenticate(t *testing.T) {
	state := cliSSHTunnelState{
		Destination: "student@example.edu",
		Port:        1080,
		ControlPath: "/tmp/control.sock",
	}
	for name, arguments := range map[string][]string{
		"forward": cliSSHDynamicForwardArguments(state),
		"cancel":  cliSSHCancelDynamicForwardArguments(state),
		"check":   cliSSHControlOperationArguments(state, "check"),
		"exit":    cliSSHControlOperationArguments(state, "exit"),
		"probe":   cliSSHControlClientArguments(state),
	} {
		joined := " " + strings.Join(arguments, " ") + " "
		for _, expected := range []string{
			" -S /tmp/control.sock ",
			" BatchMode=yes ",
			" ProxyCommand=false ",
			" StrictHostKeyChecking=yes ",
			" PubkeyAuthentication=no ",
			" PasswordAuthentication=no ",
			" KbdInteractiveAuthentication=no ",
			" PreferredAuthentications=none ",
		} {
			if !strings.Contains(joined, expected) {
				t.Fatalf("%s control arguments omit %q: %v", name, expected, arguments)
			}
		}
	}
}

func TestStartCLISSHTunnelUsesSavedPasswordThroughAskpass(t *testing.T) {
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	sshScript := "#!/bin/sh\n" +
		"control=''\n" +
		"previous=''\n" +
		"for argument in \"$@\"; do\n" +
		"  if [ \"$previous\" = '-S' ]; then control=\"$argument\"; fi\n" +
		"  previous=\"$argument\"\n" +
		"done\n" +
		"case \" $* \" in\n" +
		"  *' -O check '*) test -e \"$control\" ;;\n" +
		"  *' -O forward '*)\n" +
		"    case \" $* \" in *' BatchMode=yes '*' PasswordAuthentication=no '*' KbdInteractiveAuthentication=no '*) test -e \"$control\" ;; *) exit 41 ;; esac ;;\n" +
		"  *' -O exit '*) rm -f \"$control\" ;;\n" +
		"  *)\n" +
		"    test \"$SSH_ASKPASS_REQUIRE\" = force || exit 42\n" +
		"    test \"$DISPLAY\" = flclash-askpass || exit 43\n" +
		"    answer=\"$(\"$SSH_ASKPASS\" \"student@127.0.0.1's password:\")\"\n" +
		"    test \"$answer\" = stored-password || exit 44\n" +
		"    touch \"$control\" ;;\n" +
		"esac\n"
	if err := os.WriteFile(sshPath, []byte(sshScript), 0o700); err != nil {
		t.Fatal(err)
	}
	askpassPath := filepath.Join(binDirectory, "askpass")
	askpassScript := `#!/bin/sh
case "$1" in
  *assword*) sed -n 's/.*"password":"\([^"]*\)".*/\1/p' "$FLCLASH_SSH_ASKPASS_FILE" ;;
  *) exit 45 ;;
esac
`
	if err := os.WriteFile(askpassPath, []byte(askpassScript), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	runtimeRoot := t.TempDir()
	previousRuntime := cliRuntimeDirectoryOverride
	previousAskpassExecutable := cliSSHAskpassExecutable
	previousForward := addCLISSHDynamicForwardForOperation
	cliRuntimeDirectoryOverride = runtimeRoot
	cliSSHAskpassExecutable = func() (string, error) { return askpassPath, nil }
	var listener net.Listener
	addCLISSHDynamicForwardForOperation = func(
		path string,
		state cliSSHTunnelState,
	) error {
		if err := addCLISSHDynamicForward(path, state); err != nil {
			return err
		}
		var err error
		listener, err = net.Listen(
			"tcp4",
			net.JoinHostPort("127.0.0.1", strconv.Itoa(state.Port)),
		)
		return err
	}
	t.Cleanup(func() {
		if listener != nil {
			_ = listener.Close()
		}
		cliRuntimeDirectoryOverride = previousRuntime
		cliSSHAskpassExecutable = previousAskpassExecutable
		addCLISSHDynamicForwardForOperation = previousForward
	})

	state, err := startCLISSHTunnel(cliSSHProfile{
		Name:     "password",
		Username: "student",
		Host:     "127.0.0.1",
		Port:     22,
		Password: "stored-password",
	}, "transient")
	if err != nil {
		t.Fatalf("saved-password SSH tunnel = %v", err)
	}
	if err := stopCLIStateTunnel(state); err != nil {
		t.Fatalf("stop saved-password SSH tunnel: %v", err)
	}
}

func TestOpenSSHUsesSavedPasswordWithoutTerminalPrompt(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH client is unavailable")
	}
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := cryptossh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	authenticated := make(chan struct{}, 1)
	serverConfig := &cryptossh.ServerConfig{
		PasswordCallback: func(
			metadata cryptossh.ConnMetadata,
			password []byte,
		) (*cryptossh.Permissions, error) {
			if metadata.User() != "student" || string(password) != "stored-password" {
				return nil, errors.New("invalid test credentials")
			}
			select {
			case authenticated <- struct{}{}:
			default:
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)
	server, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverErrors := make(chan error, 8)
	go func() {
		for {
			connection, acceptErr := server.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				sshConnection, channels, requests, handshakeErr := cryptossh.NewServerConn(
					connection,
					serverConfig,
				)
				if handshakeErr != nil {
					serverErrors <- handshakeErr
					return
				}
				go cryptossh.DiscardRequests(requests)
				go func() {
					for channel := range channels {
						_ = channel.Reject(cryptossh.UnknownChannelType, "unsupported test channel")
					}
				}()
				serverErrors <- sshConnection.Wait()
			}()
		}
	}()
	t.Cleanup(func() { _ = server.Close() })

	askpassPath := filepath.Join(t.TempDir(), "askpass")
	askpassScript := `#!/bin/sh
case "$1" in
  *assword*) sed -n 's/.*"password":"\([^"]*\)".*/\1/p' "$FLCLASH_SSH_ASKPASS_FILE" ;;
  *) exit 51 ;;
esac
`
	if err := os.WriteFile(askpassPath, []byte(askpassScript), 0o700); err != nil {
		t.Fatal(err)
	}
	previousRuntime := cliRuntimeDirectoryOverride
	previousAskpassExecutable := cliSSHAskpassExecutable
	cliRuntimeDirectoryOverride = t.TempDir()
	cliSSHAskpassExecutable = func() (string, error) { return askpassPath, nil }
	t.Cleanup(func() {
		cliRuntimeDirectoryOverride = previousRuntime
		cliSSHAskpassExecutable = previousAskpassExecutable
	})

	type tunnelResult struct {
		state cliSSHTunnelState
		err   error
	}
	result := make(chan tunnelResult, 1)
	serverPort := server.Addr().(*net.TCPAddr).Port
	go func() {
		state, startErr := startCLISSHTunnel(cliSSHProfile{
			Name:     "password",
			Username: "student",
			Host:     "127.0.0.1",
			Port:     serverPort,
			Password: "stored-password",
			Options: []string{
				"StrictHostKeyChecking=no",
				"UserKnownHostsFile=/dev/null",
				"LogLevel=ERROR",
			},
		}, "transient")
		result <- tunnelResult{state: state, err: startErr}
	}()
	var state cliSSHTunnelState
	select {
	case started := <-result:
		state, err = started.state, started.err
		if err != nil {
			select {
			case serverErr := <-serverErrors:
				t.Fatalf("real OpenSSH password tunnel = %v; server: %v", err, serverErr)
			default:
				t.Fatalf("real OpenSSH password tunnel = %v", err)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("real OpenSSH password tunnel did not finish authentication")
	}
	select {
	case <-authenticated:
	case <-time.After(2 * time.Second):
		t.Fatal("OpenSSH did not authenticate with the saved password")
	}
	if err := stopCLIStateTunnel(state); err != nil {
		t.Fatalf("stop real OpenSSH password tunnel: %v", err)
	}
	select {
	case serverErr := <-serverErrors:
		if serverErr != nil && !errors.Is(serverErr, net.ErrClosed) &&
			!strings.Contains(serverErr.Error(), "disconnected by user") {
			t.Fatalf("test SSH server: %v", serverErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OpenSSH master did not close")
	}
}

func TestCLISSHTunnelArgumentsUseDeterministicAuthenticationMatrix(t *testing.T) {
	tests := []struct {
		name       string
		profile    cliSSHProfile
		expected   []string
		unexpected []string
	}{
		{
			name: "key_and_password",
			profile: cliSSHProfile{
				Identity: "/tmp/key",
				Password: "secret",
			},
			expected: []string{
				"IdentitiesOnly=yes",
				"PreferredAuthentications=publickey,keyboard-interactive,password",
			},
		},
		{
			name: "password_only",
			profile: cliSSHProfile{
				Password: "secret",
			},
			expected: []string{
				"PubkeyAuthentication=no",
				"PreferredAuthentications=keyboard-interactive,password",
			},
		},
		{
			name:    "agent_default_key",
			profile: cliSSHProfile{},
			expected: []string{
				"PreferredAuthentications=publickey",
				"PasswordAuthentication=no",
			},
			unexpected: []string{"NumberOfPasswordPrompts"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.profile.Username = "student"
			test.profile.Host = "example.edu"
			test.profile.Port = 22
			joined := strings.Join(cliSSHTunnelArguments(test.profile, "/tmp/control"), " ")
			for _, expected := range test.expected {
				if !strings.Contains(joined, expected) {
					t.Fatalf("SSH auth arguments missing %q: %s", expected, joined)
				}
			}
			for _, unexpected := range test.unexpected {
				if strings.Contains(joined, unexpected) {
					t.Fatalf("SSH auth arguments contain %q: %s", unexpected, joined)
				}
			}
		})
	}
}

func TestRunCLISSHCommandCapturesWarningsWithoutTerminalOutput(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	clearTUILogs()
	command := exec.Command(
		"sh",
		"-c",
		"printf '%s\\n' '** WARNING: connection is not using a post-quantum key exchange algorithm.' >&2",
	)
	if err := runCLISSHCommand(command, "ssh_connect", true); err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(cliLogSnapshot(), "\n"); !strings.Contains(joined, "post-quantum key exchange") {
		t.Fatalf("captured OpenSSH warning was not written to Logs: %s", joined)
	}
	failure := exec.Command(
		"sh",
		"-c",
		"printf '%s\\n' '** WARNING: connection is not using a post-quantum key exchange algorithm.' 'Permission denied (publickey).' >&2; exit 1",
	)
	err := runCLISSHCommand(failure, "ssh_connect", true)
	if err == nil || !strings.Contains(err.Error(), "Permission denied") ||
		strings.Contains(err.Error(), "post-quantum") {
		t.Fatalf("captured SSH failure summary = %v", err)
	}
}

func TestPrepareCLISSHNonInteractiveCommandDetachesTerminal(t *testing.T) {
	command := exec.Command("true")
	prepareCLISSHNonInteractiveCommand(command)
	if command.Stdin != nil || command.SysProcAttr == nil || !command.SysProcAttr.Setsid {
		t.Fatalf("SSH command still has terminal access: %+v", command.SysProcAttr)
	}
}

func TestStartCLISSHTunnelAddsForwardAfterClearingConfiguredForwards(t *testing.T) {
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	script := "#!/bin/sh\n" +
		"control=''\nprevious=''\n" +
		"for argument in \"$@\"; do\n" +
		"  if [ \"$previous\" = '-S' ]; then control=\"$argument\"; fi\n" +
		"  previous=\"$argument\"\n" +
		"done\n" +
		"case \" $* \" in\n" +
		"  *' -O check '*) test -e \"$control\" ;;\n" +
		"  *' -O exit '*) unlink \"$control\" ;;\n" +
		"  *) touch \"$control\" ;;\n" +
		"esac\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	runtimeRoot := t.TempDir()
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	previousForward := addCLISSHDynamicForwardForOperation
	var listener net.Listener
	addCLISSHDynamicForwardForOperation = func(
		_ string,
		state cliSSHTunnelState,
	) error {
		var err error
		listener, err = net.Listen(
			"tcp4",
			net.JoinHostPort("127.0.0.1", strconv.Itoa(state.Port)),
		)
		return err
	}
	t.Cleanup(func() {
		if listener != nil {
			_ = listener.Close()
		}
		cliRuntimeDirectoryOverride = previousRuntime
		addCLISSHDynamicForwardForOperation = previousForward
	})
	state, err := startCLISSHTunnel(cliSSHProfile{
		Name:        "school",
		Destination: "student@example.edu",
		Port:        22,
	}, "transient")
	if err != nil {
		t.Fatal(err)
	}
	if listener == nil || !cliSSHTunnelAlive(sshPath, state) {
		t.Fatalf("two-stage SSH SOCKS5 tunnel is not ready: %+v", state)
	}
	if err := stopCLIStateTunnel(state); err != nil {
		t.Fatal(err)
	}
}

func TestStartCLISSHTunnelCleansMasterWhenForwardFails(t *testing.T) {
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	script := "#!/bin/sh\n" +
		"control=''\nprevious=''\n" +
		"for argument in \"$@\"; do\n" +
		"  if [ \"$previous\" = '-S' ]; then control=\"$argument\"; fi\n" +
		"  previous=\"$argument\"\n" +
		"done\n" +
		"case \" $* \" in\n" +
		"  *' -O check '*) test -e \"$control\" ;;\n" +
		"  *' -O exit '*) unlink \"$control\" ;;\n" +
		"  *) touch \"$control\" ;;\n" +
		"esac\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	runtimeRoot := t.TempDir()
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	previousForward := addCLISSHDynamicForwardForOperation
	forwardCalls := 0
	addCLISSHDynamicForwardForOperation = func(string, cliSSHTunnelState) error {
		forwardCalls++
		return errors.New("simulated dynamic forward failure")
	}
	t.Cleanup(func() {
		cliRuntimeDirectoryOverride = previousRuntime
		addCLISSHDynamicForwardForOperation = previousForward
	})
	_, err := startCLISSHTunnel(cliSSHProfile{
		Name:        "school",
		Destination: "student@example.edu",
		Port:        22,
	}, "transient")
	if err == nil || !strings.Contains(err.Error(), "configure SSH SOCKS5 forward") {
		t.Fatalf("dynamic-forward failure = %v", err)
	}
	if forwardCalls != 3 {
		t.Fatalf("automatic-port forward attempts = %d, want 3", forwardCalls)
	}
	directory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "ctl-") ||
			strings.HasSuffix(entry.Name(), ".json") {
			t.Fatalf("failed dynamic forward left runtime state %q", entry.Name())
		}
	}
}

func TestWaitCLISSHTunnelOperationLockWaitsForCleanupTurn(t *testing.T) {
	runtimeRoot := t.TempDir()
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	t.Cleanup(func() { cliRuntimeDirectoryOverride = previousRuntime })
	first, err := lockCLISSHTunnelOperation()
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan struct {
		lock *cliFileLock
		err  error
	}, 1)
	go func() {
		lock, err := waitCLISSHTunnelOperationLock(2 * time.Second)
		result <- struct {
			lock *cliFileLock
			err  error
		}{lock: lock, err: err}
	}()
	select {
	case early := <-result:
		first.release()
		if early.lock != nil {
			early.lock.release()
		}
		t.Fatalf("operation lock wait returned before release: %v", early.err)
	case <-time.After(75 * time.Millisecond):
	}
	first.release()
	select {
	case acquired := <-result:
		if acquired.err != nil || acquired.lock == nil {
			t.Fatalf("operation lock was not acquired after release: %v", acquired.err)
		}
		acquired.lock.release()
	case <-time.After(2 * time.Second):
		t.Fatal("operation lock wait did not finish after release")
	}
}

func TestRunCLICommandWithSSHProxySetsEnvironmentAndExitCode(t *testing.T) {
	err := runCLICommandWithSSHProxy([]string{
		"sh",
		"-c",
		"test \"$ALL_PROXY\" = socks5h://127.0.0.1:45678 && " +
			"test \"$all_proxy\" = socks5h://127.0.0.1:45678 && " +
			"test \"$HTTP_PROXY\" = socks5h://127.0.0.1:45678 && " +
			"test \"$HTTPS_PROXY\" = socks5h://127.0.0.1:45678 && " +
			"test \"$http_proxy\" = socks5h://127.0.0.1:45678 && " +
			"test \"$https_proxy\" = socks5h://127.0.0.1:45678 && " +
			"exit 7",
	}, 45678)
	var exitError *cliExitCodeError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 7 {
		t.Fatalf("SSH wrapper exit = %v, want exit code 7 with socks5h env", err)
	}
}

func TestFLCSSHTransientCommandReportsCommandAndCleanupFailures(t *testing.T) {
	configRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	if err := addCLISSHProfile(cliSSHProfile{
		Name:        "school",
		Destination: "student@example.edu",
		Port:        22,
	}); err != nil {
		t.Fatal(err)
	}
	previousStart := startCLITransientSSHTunnelForCommand
	previousStop := stopCLITransientSSHTunnelForCommand
	previousRun := runCLICommandWithSSHProxyForCommand
	started, ran, stopped := false, false, false
	startCLITransientSSHTunnelForCommand = func(profile cliSSHProfile) (cliSSHTunnelState, error) {
		started = profile.Name == "school"
		return cliSSHTunnelState{Name: profile.Name, Port: 1080}, nil
	}
	runCLICommandWithSSHProxyForCommand = func(args []string, port int) error {
		ran = port == 1080 && len(args) == 2 && args[0] == "curl"
		return errors.New("simulated command failure")
	}
	stopCLITransientSSHTunnelForCommand = func(state cliSSHTunnelState) error {
		stopped = state.Name == "school"
		return errors.New("simulated cleanup failure")
	}
	t.Cleanup(func() {
		cliRuntimeDirectoryOverride = previousRuntime
		startCLITransientSSHTunnelForCommand = previousStart
		stopCLITransientSSHTunnelForCommand = previousStop
		runCLICommandWithSSHProxyForCommand = previousRun
	})
	err := flcSSHCommand([]string{"-u", "school", "curl", "https://example.com"})
	if err == nil || !strings.Contains(err.Error(), "simulated command failure") ||
		!strings.Contains(err.Error(), "simulated cleanup failure") {
		t.Fatalf("combined transient SSH command error = %v", err)
	}
	if !started || !ran || !stopped {
		t.Fatalf("transient SSH lifecycle = start:%t run:%t stop:%t", started, ran, stopped)
	}
}

func TestFLCSSHTransientStartFailureDoesNotRunCommandOrCleanup(t *testing.T) {
	configRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	if err := addCLISSHProfile(cliSSHProfile{
		Name:        "school",
		Destination: "student@example.edu",
		Port:        22,
	}); err != nil {
		t.Fatal(err)
	}
	previousStart := startCLITransientSSHTunnelForCommand
	previousStop := stopCLITransientSSHTunnelForCommand
	previousRun := runCLICommandWithSSHProxyForCommand
	ran, stopped := false, false
	startCLITransientSSHTunnelForCommand = func(cliSSHProfile) (cliSSHTunnelState, error) {
		return cliSSHTunnelState{}, errors.New("simulated start failure")
	}
	runCLICommandWithSSHProxyForCommand = func([]string, int) error {
		ran = true
		return nil
	}
	stopCLITransientSSHTunnelForCommand = func(cliSSHTunnelState) error {
		stopped = true
		return nil
	}
	t.Cleanup(func() {
		cliRuntimeDirectoryOverride = previousRuntime
		startCLITransientSSHTunnelForCommand = previousStart
		stopCLITransientSSHTunnelForCommand = previousStop
		runCLICommandWithSSHProxyForCommand = previousRun
	})
	err := flcSSHCommand([]string{"-u", "school", "curl"})
	if err == nil || !strings.Contains(err.Error(), "simulated start failure") {
		t.Fatalf("transient SSH start error = %v", err)
	}
	if ran || stopped {
		t.Fatalf("failed transient SSH start ran command=%t cleanup=%t", ran, stopped)
	}
}

func TestFLCSSHPersistentCommandRejectsBrokenSOCKSListener(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	previousActive := activeCLIPersistentSSHTunnelForCommand
	previousConnect := connectCLISSHProfileForCommand
	previousRun := runCLICommandWithSSHProxyForCommand
	runCalled := false
	connectCalled := false
	activeCLIPersistentSSHTunnelForCommand = func() (cliSSHTunnelState, bool, error) {
		return cliSSHTunnelState{Name: "school", Port: port}, true, nil
	}
	connectCLISSHProfileForCommand = func(string) (cliSSHTunnelState, bool, error) {
		connectCalled = true
		return cliSSHTunnelState{}, false, errors.New("reconnect failed")
	}
	runCLICommandWithSSHProxyForCommand = func([]string, int) error {
		runCalled = true
		return nil
	}
	t.Cleanup(func() {
		activeCLIPersistentSSHTunnelForCommand = previousActive
		connectCLISSHProfileForCommand = previousConnect
		runCLICommandWithSSHProxyForCommand = previousRun
	})
	err = flcSSHCommand([]string{"curl", "https://example.com"})
	if err == nil || !strings.Contains(err.Error(), "reconnect failed") {
		t.Fatalf("broken persistent SSH command error = %v", err)
	}
	if !connectCalled {
		t.Fatal("broken SSH tunnel was not rebuilt before failing closed")
	}
	if runCalled {
		t.Fatal("command ran while the persistent SSH SOCKS5 listener was unavailable")
	}
}

func TestFLCSSHDirectFailsClosedWhenRemoteTunIsEnabled(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	previousActive := activeCLIPersistentSSHTunnelForCommand
	previousProbe := probeCLISSHRemoteForCommand
	previousRun := runCLICommandWithSSHProxyForCommand
	runCalled := false
	activeCLIPersistentSSHTunnelForCommand = func() (cliSSHTunnelState, bool, error) {
		return cliSSHTunnelState{Name: "school", Port: port}, true, nil
	}
	probeCLISSHRemoteForCommand = func(cliSSHTunnelState) (cliSSHRemoteProbe, error) {
		return cliSSHRemoteProbe{
			ProtocolVersion: cliSSHRemoteProbeVersion,
			Available:       true,
			TunEnabled:      true,
			Reason:          "FlClash transparent TUN is enabled",
		}, nil
	}
	runCLICommandWithSSHProxyForCommand = func([]string, int) error {
		runCalled = true
		return nil
	}
	t.Cleanup(func() {
		activeCLIPersistentSSHTunnelForCommand = previousActive
		probeCLISSHRemoteForCommand = previousProbe
		runCLICommandWithSSHProxyForCommand = previousRun
	})
	err = flcSSHCommand([]string{"-d", "curl", "https://example.com"})
	if err == nil || !strings.Contains(err.Error(), "direct exit refused") {
		t.Fatalf("direct command with remote TUN error = %v", err)
	}
	if runCalled {
		t.Fatal("direct command ran while the remote TUN made it unsafe")
	}
}

func TestFLCSSHDirectRunsOnlyAfterRemoteProbeAllowsIt(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	previousActive := activeCLIPersistentSSHTunnelForCommand
	previousProbe := probeCLISSHRemoteForCommand
	previousRun := runCLICommandWithSSHProxyForCommand
	ran := false
	activeCLIPersistentSSHTunnelForCommand = func() (cliSSHTunnelState, bool, error) {
		return cliSSHTunnelState{Name: "school", Port: port}, true, nil
	}
	probeCLISSHRemoteForCommand = func(cliSSHTunnelState) (cliSSHRemoteProbe, error) {
		return cliSSHRemoteProbe{
			ProtocolVersion: cliSSHRemoteProbeVersion,
			Available:       true,
			DirectAllowed:   true,
			Reason:          "FlClash TUN is off",
		}, nil
	}
	runCLICommandWithSSHProxyForCommand = func(args []string, receivedPort int) error {
		ran = receivedPort == port && len(args) == 2 && args[0] == "curl"
		return nil
	}
	t.Cleanup(func() {
		activeCLIPersistentSSHTunnelForCommand = previousActive
		probeCLISSHRemoteForCommand = previousProbe
		runCLICommandWithSSHProxyForCommand = previousRun
	})
	if err := flcSSHCommand([]string{"--direct", "curl", "https://example.com"}); err != nil {
		t.Fatal(err)
	}
	if !ran {
		t.Fatal("direct command did not run through the verified SSH SOCKS5 port")
	}
}

func TestFLCSSHDirectTemporaryTunnelCleansUpAfterRejectedProbe(t *testing.T) {
	configRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	if err := addCLISSHProfile(cliSSHProfile{
		Name: "school", Destination: "student@example.edu", Port: 22,
	}); err != nil {
		t.Fatal(err)
	}
	previousStart := startCLITransientSSHTunnelForCommand
	previousStop := stopCLITransientSSHTunnelForCommand
	previousProbe := probeCLISSHRemoteForCommand
	previousRun := runCLICommandWithSSHProxyForCommand
	stopped, ran := false, false
	startCLITransientSSHTunnelForCommand = func(profile cliSSHProfile) (cliSSHTunnelState, error) {
		return cliSSHTunnelState{Name: profile.Name, Port: 1080}, nil
	}
	stopCLITransientSSHTunnelForCommand = func(state cliSSHTunnelState) error {
		stopped = state.Name == "school"
		return nil
	}
	probeCLISSHRemoteForCommand = func(cliSSHTunnelState) (cliSSHRemoteProbe, error) {
		return cliSSHRemoteProbe{ProtocolVersion: cliSSHRemoteProbeVersion, Available: true, TunEnabled: true}, nil
	}
	runCLICommandWithSSHProxyForCommand = func([]string, int) error {
		ran = true
		return nil
	}
	t.Cleanup(func() {
		cliRuntimeDirectoryOverride = previousRuntime
		startCLITransientSSHTunnelForCommand = previousStart
		stopCLITransientSSHTunnelForCommand = previousStop
		probeCLISSHRemoteForCommand = previousProbe
		runCLICommandWithSSHProxyForCommand = previousRun
	})
	err := flcSSHCommand([]string{"-u", "school", "-d", "curl", "https://example.com"})
	if err == nil || !strings.Contains(err.Error(), "direct exit refused") {
		t.Fatalf("temporary direct command error = %v", err)
	}
	if !stopped || ran {
		t.Fatalf("temporary direct lifecycle = stopped:%t ran:%t", stopped, ran)
	}
}

func TestTUISSHDirectDashboardLabelsBlockedRemoteTun(t *testing.T) {
	output := stripTUIANSI(renderTUIAtSize(
		tuiSnapshot{
			Page:              tuiPageSSH,
			SSHDashboardFocus: true,
			SSHDirectProbe: cliSSHRemoteProbe{
				ProtocolVersion: cliSSHRemoteProbeVersion,
				Available:       true,
				TunEnabled:      true,
				Reason:          "FlClash transparent TUN is enabled",
			},
			SSHProfiles: []tuiSSHProfile{{
				Name: "school", Destination: "student@example.edu", Port: 22,
				Connected: true, Ready: true, SocksPort: 1080,
			}},
		},
		cliPaths{}, "private Unix socket", true, false, 180, 40,
	))
	for _, expected := range []string{
		"B managed IP", "B direct exit", "BLOCKED · FlClash transparent TUN is enabled", "Direct CF DL",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("SSH direct Dashboard does not contain %q:\n%s", expected, output)
		}
	}
}

func TestTUISSHDashboardOrdersInetDirectAndManagedExitRows(t *testing.T) {
	output := stripTUIANSI(renderTUIAtSize(
		tuiSnapshot{
			Page:              tuiPageSSH,
			SSHDashboardFocus: true,
			SSHNetwork: tuiNetworkInfo{
				IntranetIP: "172.18.130.216 (eth7)",
				PublicIP:   "198.51.100.10",
				Country:    "HK",
			},
			SSHDirectProbe: cliSSHRemoteProbe{
				ProtocolVersion: cliSSHRemoteProbeVersion,
				Available:       true,
				DirectAllowed:   true,
				IntranetIP:      "192.168.1.20 (eth0)",
				Reason:          "FlClash TUN is off",
			},
			SSHDirectNetwork: tuiNetworkInfo{
				PublicIP: "203.0.113.20",
				Country:  "SG",
			},
			SSHProfiles: []tuiSSHProfile{{
				Name: "school", Destination: "student@example.edu", Port: 22,
				Connected: true, Ready: true, SocksPort: 1080,
			}},
		},
		cliPaths{}, "private Unix socket", true, false, 180, 40,
	))
	wantOrder := []string{
		"A inet IP",
		"B inet IP",
		"B direct exit",
		"B direct IP",
		"Direct RTT",
		"Direct CF DL",
		"B managed IP",
		"Managed RTT",
		"Managed CF DL",
	}
	previous := -1
	for _, label := range wantOrder {
		position := strings.Index(output, label)
		if position < 0 || position <= previous {
			t.Fatalf("SSH Dashboard row %q is missing or out of order:\n%s", label, output)
		}
		previous = position
	}
	for _, expected := range []string{
		"172.18.130.216 (eth7)",
		"192.168.1.20 (eth0)",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("SSH Dashboard does not render %q:\n%s", expected, output)
		}
	}
}

func TestTUISSHDashboardDirectRowsRouteTestsToDirectExit(t *testing.T) {
	for row := 0; row < tuiSSHDashboardRowCount; row++ {
		wantDirect := row >= tuiSSHDashboardDirectExitRow &&
			row <= tuiSSHDashboardDirectSpeedRow
		if got := tuiSSHDashboardRowIsDirect(row); got != wantDirect {
			t.Fatalf("SSH Dashboard row %d direct = %t, want %t", row, got, wantDirect)
		}
	}
}

func TestTUISSHAddAndEditStayInsideTUI(t *testing.T) {
	configRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	t.Cleanup(func() { cliRuntimeDirectoryOverride = previousRuntime })

	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageSSH
	model.snapshot.SelectedMenu = int(tuiPageSSH)
	model.snapshot.FocusSidebar = false
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if command != nil {
		t.Fatal("SSH add left the TUI through an external command")
	}
	if !model.sshFormOpen || model.sshFormExisting {
		t.Fatalf("SSH add form state = open %t existing %t", model.sshFormOpen, model.sshFormExisting)
	}
	keyPassphrase := "never-render-this-passphrase"
	identity := writeTestCLISSHPrivateKey(t, keyPassphrase)
	model.sshForm = cliSSHProfile{
		Name:               "school",
		Destination:        "student@example.edu",
		Port:               2222,
		LocalPort:          1080,
		Identity:           identity,
		IdentityPassphrase: keyPassphrase,
		Password:           "never-render-this-password",
		Options:            []string{"StrictHostKeyChecking=yes"},
	}
	model.sshFormPassphraseChanged = true
	model.sshFormPasswordChanged = true
	model.sshFormSelected = model.sshFormSaveRow()
	command = model.activateSSHFormRow()
	if command == nil {
		t.Fatal("SSH form save did not schedule a config write")
	}
	message, ok := command().(tuiSSHCommandResultMsg)
	if !ok || message.err != nil {
		t.Fatalf("SSH form save result = %#v", message)
	}
	_, _ = model.Update(message)
	profile, err := loadCLISSHProfile("school")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Destination != "student@example.edu" || profile.Port != 2222 ||
		profile.LocalPort != 1080 ||
		profile.IdentityPassphrase != "never-render-this-passphrase" ||
		profile.Password != "never-render-this-password" || len(profile.Options) != 1 {
		t.Fatalf("saved SSH profile = %+v", profile)
	}
	if strings.Contains(model.View(), profile.IdentityPassphrase) ||
		strings.Contains(model.View(), profile.Password) {
		t.Fatal("SSH secret leaked through the TUI view")
	}

	model.beginSSHForm(true)
	if !model.sshFormOpen || !model.sshFormExisting ||
		model.sshForm.IdentityPassphrase != "never-render-this-passphrase" ||
		model.sshForm.Password != "never-render-this-password" {
		t.Fatalf("SSH edit form did not load the selected profile: %+v", model.sshForm)
	}
	model.sshForm.Username = "new"
	model.sshForm.Host = "example.edu"
	model.sshFormSelected = model.sshFormSaveRow()
	command = model.activateSSHFormRow()
	message = command().(tuiSSHCommandResultMsg)
	if message.err != nil {
		t.Fatal(message.err)
	}
	profile, err = loadCLISSHProfile("school")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Destination != "new@example.edu" ||
		profile.IdentityPassphrase != "never-render-this-passphrase" ||
		profile.Password != "never-render-this-password" {
		t.Fatalf("SSH edit did not preserve secrets: %+v", profile)
	}
}

func TestCLISSHLocalPortPolicy(t *testing.T) {
	profile := cliSSHProfile{LocalPort: 1080}
	if port := configuredCLISSHLocalPort(profile, "persistent"); port != 1080 {
		t.Fatalf("persistent local port = %d, want 1080", port)
	}
	if port := configuredCLISSHLocalPort(profile, "transient"); port != 0 {
		t.Fatalf("transient local port = %d, want automatic", port)
	}
	for _, value := range []string{"auto", "0"} {
		if port, err := parseCLISSHLocalPort(value); err != nil || port != 0 {
			t.Fatalf("parse local port %q = %d, %v", value, port, err)
		}
	}
	for _, value := range []string{"-1", "65536", "invalid"} {
		if _, err := parseCLISSHLocalPort(value); err == nil {
			t.Fatalf("invalid local port %q was accepted", value)
		}
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := checkCLISSHPortAvailable(port); err == nil ||
		!strings.Contains(err.Error(), "already in use") {
		t.Fatalf("occupied local port check = %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := checkCLISSHPortAvailable(port); err != nil {
		t.Fatalf("released local port was unavailable: %v", err)
	}
}

func TestTUISSHFormSecretsAndOptionEditing(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.sshFormOpen = true
	identity := writeTestCLISSHPrivateKey(t, "old-passphrase")
	model.sshForm = cliSSHProfile{
		Name:               "school",
		Destination:        "student@example.edu",
		Port:               22,
		Identity:           identity,
		IdentityPassphrase: "old-passphrase",
		Password:           "old-password",
	}
	model.refreshSSHFormIdentityState()
	model.sshFormSelected = tuiSSHFormLocalPortRow
	model.beginSSHFormFieldEdit()
	model.sshFormInput = []rune("1080")
	model.sshFormCursor = len(model.sshFormInput)
	if !model.commitSSHFormField() || model.sshForm.LocalPort != 1080 {
		t.Fatalf("fixed local SOCKS5 port was not staged: %d", model.sshForm.LocalPort)
	}
	model.sshFormSelected = tuiSSHFormLocalPortRow
	model.beginSSHFormFieldEdit()
	model.sshFormInput = []rune("auto")
	model.sshFormCursor = len(model.sshFormInput)
	if !model.commitSSHFormField() || model.sshForm.LocalPort != 0 {
		t.Fatalf("automatic local SOCKS5 port was not staged: %d", model.sshForm.LocalPort)
	}
	model.sshFormSelected = tuiSSHFormPassphraseRow
	model.beginSSHFormFieldEdit()
	model.sshFormInput = []rune("new-passphrase")
	model.sshFormCursor = len(model.sshFormInput)
	if model.commitSSHFormField() {
		t.Fatal("private key passphrase was committed without confirmation")
	}
	if !model.sshFormPassphraseConfirm {
		t.Fatal("private key passphrase confirmation phase was not entered")
	}
	if strings.Contains(model.View(), "new-passphrase") ||
		strings.Contains(model.View(), "old-passphrase") {
		t.Fatal("private key passphrase leaked while editing")
	}
	model.sshFormInput = []rune("new-passphrase")
	model.sshFormCursor = len(model.sshFormInput)
	if !model.commitSSHFormField() ||
		model.sshForm.IdentityPassphrase != "new-passphrase" {
		t.Fatal("confirmed private key passphrase was not staged")
	}
	model.sshFormSelected = tuiSSHFormPassphraseRow
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	if model.sshForm.IdentityPassphrase != "" ||
		!model.sshFormPassphraseCleared {
		t.Fatal("private key passphrase clear state was not staged")
	}

	model.sshFormSelected = tuiSSHFormPasswordRow
	model.beginSSHFormFieldEdit()
	model.sshFormInput = []rune("new-secret")
	model.sshFormCursor = len(model.sshFormInput)
	if model.commitSSHFormField() {
		t.Fatal("password was committed without confirmation")
	}
	if !model.sshFormPasswordConfirm {
		t.Fatal("password confirmation phase was not entered")
	}
	if strings.Contains(model.View(), "new-secret") || strings.Contains(model.View(), "old-password") {
		t.Fatal("SSH password leaked while editing")
	}
	model.sshFormInput = []rune("new-secret")
	model.sshFormCursor = len(model.sshFormInput)
	if !model.commitSSHFormField() || model.sshForm.Password != "new-secret" {
		t.Fatal("confirmed password was not staged")
	}
	model.sshFormSelected = tuiSSHFormPasswordRow
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	if model.sshForm.Password != "" || !model.sshFormPasswordCleared {
		t.Fatal("password clear state was not staged")
	}

	model.sshFormSelected = model.sshFormAddOptionRow()
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !model.sshFormFieldEditing || len(model.sshForm.Options) != 1 {
		t.Fatal("add-option row did not open an in-TUI field")
	}
	model.sshFormInput = []rune("ControlPath=/tmp/unsafe")
	model.sshFormCursor = len(model.sshFormInput)
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !model.sshFormFieldEditing || !strings.Contains(model.snapshot.Status, "conflicts") {
		t.Fatalf("unsafe option was accepted: %q", model.snapshot.Status)
	}
	model.sshFormInput = []rune("ServerAliveInterval=30")
	model.sshFormCursor = len(model.sshFormInput)
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if model.sshFormFieldEditing || model.sshForm.Options[0] != "ServerAliveInterval=30" {
		t.Fatalf("valid option was not staged: %+v", model.sshForm.Options)
	}
}

func TestTUISSHDeleteRequiresConfirmation(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageSSH
	model.snapshot.FocusSidebar = false
	model.snapshot.SSHProfiles = []tuiSSHProfile{{Name: "school"}}
	model.snapshot.SelectedSSH = 0
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if command != nil || !model.sshDeleteConfirmOpen {
		t.Fatalf("SSH delete did not open confirmation: command=%v open=%t", command, model.sshDeleteConfirmOpen)
	}
	if !strings.Contains(stripTUIANSI(model.View()), "Delete school?") {
		t.Fatal("SSH delete confirmation did not render its target")
	}
	_, command = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if command != nil || model.sshDeleteConfirmOpen {
		t.Fatal("SSH delete confirmation did not cancel in place")
	}
}

func TestTUISSHEditFormDeleteAction(t *testing.T) {
	configRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	t.Cleanup(func() { cliRuntimeDirectoryOverride = previousRuntime })
	if err := addCLISSHProfile(cliSSHProfile{
		Name:        "school",
		Destination: "student@example.edu",
		Port:        22,
	}); err != nil {
		t.Fatal(err)
	}

	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageSSH
	model.snapshot.FocusSidebar = false
	refreshTUISSH(&model.snapshot)
	model.beginSSHForm(true)
	if row := model.sshFormDeleteRow(); row < 0 || row >= model.sshFormRowCount() {
		t.Fatalf("SSH edit delete row = %d of %d", row, model.sshFormRowCount())
	}
	plain := stripTUIANSI(model.View())
	if !strings.Contains(plain, "Delete profile") {
		t.Fatalf("SSH edit form has no visible delete action:\n%s", plain)
	}
	model.sshFormSelected = model.sshFormDeleteRow()
	if command := model.activateSSHFormRow(); command != nil {
		t.Fatal("SSH edit delete action skipped confirmation")
	}
	if !model.sshDeleteConfirmOpen || !model.sshFormOpen {
		t.Fatal("SSH edit delete confirmation did not preserve the form")
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if model.sshDeleteConfirmOpen || !model.sshFormOpen {
		t.Fatal("cancelling SSH deletion did not return to the edit form")
	}

	model.sshFormSelected = model.sshFormDeleteRow()
	_ = model.activateSSHFormRow()
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if command == nil || model.sshFormOpen {
		t.Fatal("confirmed SSH deletion did not close the edit form")
	}
	message, ok := command().(tuiSSHCommandResultMsg)
	if !ok || message.err != nil {
		t.Fatalf("SSH deletion result = %#v", message)
	}
	if _, err := loadCLISSHProfile("school"); err == nil {
		t.Fatal("SSH profile still exists after confirmed form deletion")
	}

	addModel := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	addModel.sshFormOpen = true
	addModel.sshFormExisting = false
	if addModel.sshFormDeleteRow() != -1 ||
		strings.Contains(stripTUIANSI(addModel.View()), "Delete profile") {
		t.Fatal("SSH add form exposed a delete action")
	}
}

func TestTUISSHSaveFailureKeepsFormOpen(t *testing.T) {
	configRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	t.Cleanup(func() { cliRuntimeDirectoryOverride = previousRuntime })
	if err := addCLISSHProfile(cliSSHProfile{
		Name:        "school",
		Destination: "first@example.edu",
		Port:        22,
	}); err != nil {
		t.Fatal(err)
	}

	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.sshFormOpen = true
	model.sshForm = cliSSHProfile{
		Name:        "school",
		Destination: "duplicate@example.edu",
		Port:        22,
	}
	model.sshFormSelected = model.sshFormSaveRow()
	command := model.saveSSHForm()
	message := command().(tuiSSHCommandResultMsg)
	if message.err == nil {
		t.Fatal("duplicate SSH profile was accepted")
	}
	_, _ = model.Update(message)
	if !model.sshFormOpen || model.sshForm.Destination != "duplicate@example.edu" {
		t.Fatalf("failed save discarded the SSH form: %+v", model.sshForm)
	}
	if !strings.Contains(model.snapshot.Status, "already exists") {
		t.Fatalf("failed save status = %q", model.snapshot.Status)
	}
}

func TestTUISSHFormPreservesQuitSemantics(t *testing.T) {
	originalExit := completeCLIExitForTUI
	completeCLIExitForTUI = func(int) error { return nil }
	t.Cleanup(func() { completeCLIExitForTUI = originalExit })
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.sshFormOpen = true
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if command == nil || !model.frontendExitRequested || model.sshFormOpen {
		t.Fatalf(
			"q did not exit from SSH form: command=%v exit=%t form=%t",
			command,
			model.frontendExitRequested,
			model.sshFormOpen,
		)
	}
	busyModel := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	busyModel.sshFormOpen = true
	busyModel.busy = true
	_, command = busyModel.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if command == nil || !busyModel.frontendExitRequested || busyModel.sshFormOpen {
		t.Fatalf(
			"q did not exit during SSH save: command=%v exit=%t form=%t",
			command,
			busyModel.frontendExitRequested,
			busyModel.sshFormOpen,
		)
	}
	interruptModel := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	interruptModel.sshFormOpen = true
	interruptModel.sshFormReadOnly = true
	_, command = interruptModel.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if command == nil || !interruptModel.shutdownRequested ||
		interruptModel.frontendExitRequested || interruptModel.sshFormOpen {
		t.Fatalf(
			"Ctrl+C did not fully shut down from SSH details: command=%v shutdown=%t frontend=%t form=%t",
			command,
			interruptModel.shutdownRequested,
			interruptModel.frontendExitRequested,
			interruptModel.sshFormOpen,
		)
	}
}

func TestConnectedSSHProfileIsReadOnlyInTUIAndCLI(t *testing.T) {
	configRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	previousActive := activeCLIPersistentSSHTunnelForOperation
	connected := true
	activeCLIPersistentSSHTunnelForOperation = func() (cliSSHTunnelState, bool, error) {
		if !connected {
			return cliSSHTunnelState{}, false, nil
		}
		return cliSSHTunnelState{Name: "school", Port: 1080}, true, nil
	}
	t.Cleanup(func() {
		cliRuntimeDirectoryOverride = previousRuntime
		activeCLIPersistentSSHTunnelForOperation = previousActive
	})
	if err := addCLISSHProfile(cliSSHProfile{
		Name:        "school",
		Destination: "student@example.edu",
		Port:        22,
		LocalPort:   1080,
		Password:    "never-render-this",
		Options:     []string{"Compression=yes"},
	}); err != nil {
		t.Fatal(err)
	}

	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageSSH
	model.snapshot.FocusSidebar = false
	model.snapshot.SSHProfiles = []tuiSSHProfile{{
		Name:      "school",
		Connected: true,
	}}
	model.beginSSHForm(true)
	if !model.sshFormOpen || !model.sshFormReadOnly {
		t.Fatalf("connected SSH form state = open:%t read-only:%t", model.sshFormOpen, model.sshFormReadOnly)
	}
	plain := stripTUIANSI(model.View())
	for _, expected := range []string{
		"CONNECTED · READ ONLY",
		"Save unavailable",
		"disconnect before editing",
		"Compression=yes",
	} {
		if !strings.Contains(plain, expected) {
			t.Fatalf("read-only SSH details do not contain %q:\n%s", expected, plain)
		}
	}
	if strings.Contains(plain, "never-render-this") {
		t.Fatal("connected SSH details leaked the password")
	}
	model.sshFormSelected = tuiSSHFormDestinationRow
	if command := model.activateSSHFormRow(); command != nil || model.sshFormFieldEditing {
		t.Fatal("connected SSH details allowed field editing")
	}
	model.sshForm.Destination = "staged@example.edu"
	if command := model.saveSSHForm(); command != nil {
		t.Fatal("connected SSH details scheduled a save")
	}
	saved, err := loadCLISSHProfile("school")
	if err != nil {
		t.Fatal(err)
	}
	if saved.Destination != "student@example.edu" {
		t.Fatalf("read-only SSH details changed disk config: %+v", saved)
	}
	if err := cliSSHEditCommand([]string{"school", "new@example.edu"}); err == nil ||
		!strings.Contains(err.Error(), "disconnect it before editing") {
		t.Fatalf("connected CLI edit error = %v", err)
	}

	connected = false
	model = newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.SSHProfiles = []tuiSSHProfile{{Name: "school"}}
	model.beginSSHForm(true)
	if !model.sshFormOpen || model.sshFormReadOnly {
		t.Fatal("disconnected SSH profile did not become editable after reopening")
	}
}

func TestReplaceCLISSHProfileRejectsStaleFrontend(t *testing.T) {
	configRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	previousActive := activeCLIPersistentSSHTunnelForOperation
	activeCLIPersistentSSHTunnelForOperation = func() (cliSSHTunnelState, bool, error) {
		return cliSSHTunnelState{}, false, nil
	}
	t.Cleanup(func() {
		cliRuntimeDirectoryOverride = previousRuntime
		activeCLIPersistentSSHTunnelForOperation = previousActive
	})
	original := cliSSHProfile{
		Name:        "school",
		Destination: "first@example.edu",
		Port:        22,
	}
	if err := addCLISSHProfile(original); err != nil {
		t.Fatal(err)
	}
	fingerprint, err := cliSSHProfileFingerprint(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := updateCLISSHConfig(func(config *cliSSHConfig) error {
		config.Profiles[0].Username = "external"
		config.Profiles[0].Host = "example.edu"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	stale := original
	stale.Username = "stale"
	stale.Host = "example.edu"
	err = replaceCLISSHProfile("school", fingerprint, stale)
	if err == nil || !strings.Contains(err.Error(), "changed in another frontend") {
		t.Fatalf("stale SSH edit error = %v", err)
	}
	saved, err := loadCLISSHProfile("school")
	if err != nil {
		t.Fatal(err)
	}
	if saved.Destination != "external@example.edu" {
		t.Fatalf("stale SSH edit overwrote external change: %+v", saved)
	}
}

func TestConnectCLISSHProfileRestoresPreviousTunnel(t *testing.T) {
	for _, restoreFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "restored", true: "restore_failed"}[restoreFails], func(t *testing.T) {
			configRoot := t.TempDir()
			runtimeRoot := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", configRoot)
			previousRuntime := cliRuntimeDirectoryOverride
			cliRuntimeDirectoryOverride = runtimeRoot
			previousActive := activeCLIPersistentSSHTunnelForOperation
			previousStart := startCLIPersistentSSHTunnelForOperation
			previousStop := stopCLIStateTunnelForOperation
			t.Cleanup(func() {
				cliRuntimeDirectoryOverride = previousRuntime
				activeCLIPersistentSSHTunnelForOperation = previousActive
				startCLIPersistentSSHTunnelForOperation = previousStart
				stopCLIStateTunnelForOperation = previousStop
			})
			for _, profile := range []cliSSHProfile{
				{Name: "old", Destination: "old@example.edu", Port: 22, LocalPort: 1080},
				{Name: "new", Destination: "new@example.edu", Port: 22, LocalPort: 1080},
			} {
				if err := addCLISSHProfile(profile); err != nil {
					t.Fatal(err)
				}
			}
			activeCLIPersistentSSHTunnelForOperation = func() (cliSSHTunnelState, bool, error) {
				return cliSSHTunnelState{Name: "old", Port: 1080}, true, nil
			}
			var operations []string
			stopCLIStateTunnelForOperation = func(state cliSSHTunnelState) error {
				operations = append(operations, "stop:"+state.Name)
				return nil
			}
			startCLIPersistentSSHTunnelForOperation = func(profile cliSSHProfile) (cliSSHTunnelState, error) {
				operations = append(operations, "start:"+profile.Name)
				if profile.Name == "new" || restoreFails {
					return cliSSHTunnelState{}, errors.New("simulated start failure")
				}
				return cliSSHTunnelState{Name: profile.Name, Port: profile.LocalPort}, nil
			}
			_, _, err := connectCLISSHProfile("new")
			if err == nil {
				t.Fatal("failed SSH switch unexpectedly succeeded")
			}
			expected := []string{"stop:old", "start:new", "start:old"}
			if strings.Join(operations, ",") != strings.Join(expected, ",") {
				t.Fatalf("SSH switch operations = %v, want %v", operations, expected)
			}
			if restoreFails {
				if !strings.Contains(err.Error(), "restore previous tunnel") {
					t.Fatalf("double SSH failure error = %v", err)
				}
			} else if !strings.Contains(err.Error(), "previous tunnel \"old\" restored") {
				t.Fatalf("restored SSH switch error = %v", err)
			}
		})
	}
}

func TestConnectCLISSHProfileSwitchesSharedFixedPort(t *testing.T) {
	configRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	previousActive := activeCLIPersistentSSHTunnelForOperation
	previousStart := startCLIPersistentSSHTunnelForOperation
	previousStop := stopCLIStateTunnelForOperation
	t.Cleanup(func() {
		cliRuntimeDirectoryOverride = previousRuntime
		activeCLIPersistentSSHTunnelForOperation = previousActive
		startCLIPersistentSSHTunnelForOperation = previousStart
		stopCLIStateTunnelForOperation = previousStop
	})
	for _, profile := range []cliSSHProfile{
		{Name: "old", Destination: "old@example.edu", Port: 22, LocalPort: 1080},
		{Name: "new", Destination: "new@example.edu", Port: 22, LocalPort: 1080},
	} {
		if err := addCLISSHProfile(profile); err != nil {
			t.Fatal(err)
		}
	}
	activeCLIPersistentSSHTunnelForOperation = func() (cliSSHTunnelState, bool, error) {
		return cliSSHTunnelState{Name: "old", Port: 1080}, true, nil
	}
	var operations []string
	stopCLIStateTunnelForOperation = func(state cliSSHTunnelState) error {
		operations = append(operations, "stop:"+state.Name)
		return nil
	}
	startCLIPersistentSSHTunnelForOperation = func(profile cliSSHProfile) (cliSSHTunnelState, error) {
		operations = append(operations, "start:"+profile.Name)
		return cliSSHTunnelState{Name: profile.Name, Port: profile.LocalPort}, nil
	}
	state, alreadyConnected, err := connectCLISSHProfile("new")
	if err != nil || alreadyConnected || state.Name != "new" || state.Port != 1080 {
		t.Fatalf("shared-port SSH switch = state:%+v already:%t err:%v", state, alreadyConnected, err)
	}
	expected := []string{"stop:old", "start:new"}
	if strings.Join(operations, ",") != strings.Join(expected, ",") {
		t.Fatalf("shared-port SSH switch operations = %v, want %v", operations, expected)
	}
}

func TestConnectCLISSHProfileRestartsBrokenSelectedTunnel(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	runtimeRoot := t.TempDir()
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	t.Cleanup(func() { cliRuntimeDirectoryOverride = previousRuntime })
	profile := cliSSHProfile{
		Name:        "school",
		Destination: "student@example.edu",
		Port:        22,
	}
	if err := addCLISSHProfile(profile); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	brokenPort := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	broken := cliSSHTunnelState{Name: profile.Name, Port: brokenPort}
	repaired := cliSSHTunnelState{Name: profile.Name, Port: 2080}
	previousActive := activeCLIPersistentSSHTunnelForOperation
	previousStart := startCLIPersistentSSHTunnelForOperation
	previousStop := stopCLIStateTunnelForOperation
	stopCalled, startCalled := false, false
	activeCLIPersistentSSHTunnelForOperation = func() (cliSSHTunnelState, bool, error) {
		return broken, true, nil
	}
	stopCLIStateTunnelForOperation = func(state cliSSHTunnelState) error {
		stopCalled = state == broken
		return nil
	}
	startCLIPersistentSSHTunnelForOperation = func(received cliSSHProfile) (cliSSHTunnelState, error) {
		startCalled = received.Name == profile.Name
		return repaired, nil
	}
	t.Cleanup(func() {
		activeCLIPersistentSSHTunnelForOperation = previousActive
		startCLIPersistentSSHTunnelForOperation = previousStart
		stopCLIStateTunnelForOperation = previousStop
	})
	state, alreadyConnected, err := connectCLISSHProfile(profile.Name)
	if err != nil || alreadyConnected || state != repaired || !stopCalled || !startCalled {
		t.Fatalf(
			"restart broken selected SSH tunnel = state:%+v already:%t stop:%t start:%t err:%v",
			state,
			alreadyConnected,
			stopCalled,
			startCalled,
			err,
		)
	}
}

func TestDeleteConnectedCLISSHProfileRestoresTunnelOnConfigFailure(t *testing.T) {
	configRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	previousActive := activeCLIPersistentSSHTunnelForOperation
	previousStart := startCLIPersistentSSHTunnelForOperation
	previousStop := stopCLIStateTunnelForOperation
	previousUpdate := updateCLISSHConfigForOperation
	t.Cleanup(func() {
		cliRuntimeDirectoryOverride = previousRuntime
		activeCLIPersistentSSHTunnelForOperation = previousActive
		startCLIPersistentSSHTunnelForOperation = previousStart
		stopCLIStateTunnelForOperation = previousStop
		updateCLISSHConfigForOperation = previousUpdate
	})
	profile := cliSSHProfile{Name: "school", Destination: "student@example.edu", Port: 22}
	if err := addCLISSHProfile(profile); err != nil {
		t.Fatal(err)
	}
	activeCLIPersistentSSHTunnelForOperation = func() (cliSSHTunnelState, bool, error) {
		return cliSSHTunnelState{Name: "school", Port: 1080}, true, nil
	}
	stopped, restored := false, false
	stopCLIStateTunnelForOperation = func(cliSSHTunnelState) error {
		stopped = true
		return nil
	}
	startCLIPersistentSSHTunnelForOperation = func(restoredProfile cliSSHProfile) (cliSSHTunnelState, error) {
		restored = restoredProfile.Name == profile.Name
		return cliSSHTunnelState{Name: restoredProfile.Name}, nil
	}
	updateCLISSHConfigForOperation = func(func(*cliSSHConfig) error) error {
		return errors.New("simulated config write failure")
	}
	err := deleteCLISSHProfile("school")
	if err == nil || !strings.Contains(err.Error(), "previous tunnel restored") ||
		!stopped || !restored {
		t.Fatalf("connected SSH delete rollback = stopped:%t restored:%t err:%v", stopped, restored, err)
	}
	if _, err := loadCLISSHProfile("school"); err != nil {
		t.Fatalf("failed delete removed SSH profile: %v", err)
	}
}

func TestStopCLIStateTunnelKeepsStateWhenOpenSSHExitFails(t *testing.T) {
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	sshScript := "#!/bin/sh\n" +
		"control=''\noperation=''\nprevious=''\n" +
		"for argument in \"$@\"; do\n" +
		"  if [ \"$previous\" = '-S' ]; then control=\"$argument\"; fi\n" +
		"  if [ \"$previous\" = '-O' ]; then operation=\"$argument\"; fi\n" +
		"  previous=\"$argument\"\n" +
		"done\n" +
		"if [ \"$operation\" = check ]; then test -f \"$control\"; exit $?; fi\n" +
		"if [ \"$operation\" = exit ]; then exit 1; fi\n" +
		"exit 1\n"
	if err := os.WriteFile(sshPath, []byte(sshScript), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlPath := filepath.Join(t.TempDir(), "control.sock")
	statePath := filepath.Join(t.TempDir(), "persistent.json")
	for _, path := range []string{controlPath, statePath} {
		if err := os.WriteFile(path, []byte("state"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state := cliSSHTunnelState{
		Name:        "school",
		Destination: "student@example.edu",
		Port:        listener.Addr().(*net.TCPAddr).Port,
		ControlPath: controlPath,
		StatePath:   statePath,
	}
	if err := stopCLIStateTunnel(state); err == nil {
		t.Fatal("failed OpenSSH exit was reported as success")
	}
	for _, path := range []string{controlPath, statePath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("failed OpenSSH exit removed %s: %v", path, err)
		}
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(controlPath); err != nil {
		t.Fatal(err)
	}
	if err := stopCLIStateTunnel(state); err != nil {
		t.Fatalf("stale SSH state cleanup failed: %v", err)
	}
	for _, path := range []string{controlPath, statePath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("stale SSH state remains at %s: %v", path, err)
		}
	}
}

func TestActiveCLISSHTunnelKeepsBrokenForwardManageable(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	binDirectory := t.TempDir()
	sshPath := filepath.Join(binDirectory, "ssh")
	script := "#!/bin/sh\n" +
		"control=''\noperation=''\nprevious=''\n" +
		"for argument in \"$@\"; do\n" +
		"  if [ \"$previous\" = '-S' ]; then control=\"$argument\"; fi\n" +
		"  if [ \"$previous\" = '-O' ]; then operation=\"$argument\"; fi\n" +
		"  previous=\"$argument\"\n" +
		"done\n" +
		"if [ \"$operation\" = check ]; then test -f \"$control.master\"; exit $?; fi\n" +
		"if [ \"$operation\" = exit ]; then rm -f \"$control.master\"; exit 0; fi\n" +
		"exit 1\n"
	if err := os.WriteFile(sshPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	runtimeRoot := t.TempDir()
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	t.Cleanup(func() { cliRuntimeDirectoryOverride = previousRuntime })
	directory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	controlPath := filepath.Join(directory, "control.sock")
	masterMarker := controlPath + ".master"
	if err := os.WriteFile(masterMarker, []byte("alive"), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(directory, cliSSHPersistentStateFile)
	state := cliSSHTunnelState{
		Name:        "school",
		Destination: "student@example.edu",
		Port:        port,
		ControlPath: controlPath,
		Kind:        "persistent",
		StartedAt:   time.Now(),
		StatePath:   statePath,
	}
	if err := addCLISSHProfile(cliSSHProfile{
		Name:        state.Name,
		Destination: state.Destination,
		Port:        22,
	}); err != nil {
		t.Fatal(err)
	}
	if err := saveCLISSHTunnelState(state); err != nil {
		t.Fatal(err)
	}
	loaded, active, err := activeCLIPersistentSSHTunnel()
	if err != nil || !active || loaded.Name != "school" {
		t.Fatalf("broken SOCKS listener state = state:%+v active:%t err:%v", loaded, active, err)
	}
	for _, path := range []string{masterMarker, statePath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("broken SSH tunnel lost manageable state at %s: %v", path, err)
		}
	}
	views, err := loadCLISSHProfileViews()
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || !views[0].Connected || views[0].Ready || views[0].SocksPort != port {
		t.Fatalf("broken SSH tunnel view = %+v", views)
	}
	listOutput := captureCLIOutput(t, func() error { return cliSSHListCommand(nil) })
	if !strings.Contains(listOutput, "BROKEN") ||
		!strings.Contains(listOutput, "SOCKS5 127.0.0.1:"+strconv.Itoa(port)+" unavailable") {
		t.Fatalf("broken SSH list output = %q", listOutput)
	}
	showOutput := captureCLIOutput(t, func() error {
		return cliSSHShowCommand([]string{"school"})
	})
	if !strings.Contains(showOutput, "Connected:             running") ||
		!strings.Contains(showOutput, "SOCKS5 ready:          stopped") {
		t.Fatalf("broken SSH show output = %q", showOutput)
	}
	if err := stopCLIStateTunnel(loaded); err != nil {
		t.Fatalf("broken SSH forward could not be disconnected: %v", err)
	}
	for _, path := range []string{masterMarker, statePath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("disconnected broken SSH tunnel artifact remains at %s: %v", path, err)
		}
	}
}

func TestStopAllCLISSHTunnelsPreservesInvalidRuntimeState(t *testing.T) {
	runtimeRoot := t.TempDir()
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	t.Cleanup(func() { cliRuntimeDirectoryOverride = previousRuntime })
	directory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(directory, "broken.json")
	if err := os.WriteFile(statePath, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = stopAllCLISSHTunnels()
	if err == nil || !strings.Contains(err.Error(), "inspect SSH runtime state") {
		t.Fatalf("invalid SSH runtime state error = %v", err)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("invalid SSH runtime state was hidden by deletion: %v", err)
	}
}

func TestTUISSHFormRenderingFitsTerminal(t *testing.T) {
	for width := 40; width <= 140; width++ {
		for height := 10; height <= 40; height++ {
			for _, readOnly := range []bool{false, true} {
				snapshot := tuiSnapshot{
					Page: tuiPageSSH,
					SSHForm: tuiSSHFormView{
						Open:        true,
						Existing:    true,
						ReadOnly:    readOnly,
						Name:        "school",
						Destination: "student@example.edu",
						Port:        22,
						LocalPort:   1080,
						PasswordSet: true,
						Options:     []string{"ServerAliveInterval=30", "Compression=yes"},
						Selected:    tuiSSHFormOptionStartRow + 1,
					},
				}
				output := renderTUIAtSize(
					snapshot,
					cliPaths{},
					"private Unix socket",
					true,
					false,
					width,
					height,
				)
				lines := strings.Split(output, "\n")
				if len(lines) != height {
					t.Fatalf("SSH form read-only=%t at %dx%d has %d lines", readOnly, width, height, len(lines))
				}
				for lineNumber, line := range lines {
					if got := tuiDisplayWidth(stripTUIANSI(line)); got != width {
						t.Fatalf("SSH form read-only=%t at %dx%d line %d width = %d", readOnly, width, height, lineNumber, got)
					}
				}
			}
		}
	}
}

func TestParseCLISSHProfileEditJump(t *testing.T) {
	edit, interactive, err := parseCLISSHProfileEdit([]string{
		"school",
		"student@example.edu",
		"--jump",
		"bastion.example.edu",
	}, false)
	if err != nil || interactive || edit.Jump != "bastion.example.edu" || !edit.JumpSet {
		t.Fatalf("jump parse = %+v interactive:%t err:%v", edit, interactive, err)
	}
	profile, err := cliSSHProfileFromEdit(cliSSHProfile{}, edit, false)
	if err != nil || profile.Jump != "bastion.example.edu" {
		t.Fatalf("jump profile = %+v err:%v", profile, err)
	}
}

func TestResolveCLISSHConnectNameUsesDefaultThenOnlyProfile(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	if err := addCLISSHProfile(cliSSHProfile{
		Name:     "home",
		Username: "user",
		Host:     "example.edu",
		Port:     22,
	}); err != nil {
		t.Fatal(err)
	}
	if err := addCLISSHProfile(cliSSHProfile{
		Name:     "school",
		Username: "student",
		Host:     "school.example.edu",
		Port:     22,
	}); err != nil {
		t.Fatal(err)
	}
	name, err := resolveCLISSHConnectName("")
	if err != nil || name != "home" {
		t.Fatalf("first profile should become default, got %q err:%v", name, err)
	}
	if err := setCLISSHDefault("school"); err != nil {
		t.Fatal(err)
	}
	name, err = resolveCLISSHConnectName("")
	if err != nil || name != "school" {
		t.Fatalf("explicit default = %q err:%v", name, err)
	}
	if err := setCLISSHDefault(""); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveCLISSHConnectName(""); err == nil || !strings.Contains(err.Error(), "default") {
		t.Fatalf("ambiguous profiles without default error = %v", err)
	}
}

func TestFLCSSHCommandAutoConnectsDefaultProfile(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	if err := addCLISSHProfile(cliSSHProfile{
		Name:     "home",
		Username: "user",
		Host:     "example.edu",
		Port:     22,
	}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	previousActive := activeCLIPersistentSSHTunnelForCommand
	previousConnect := connectCLISSHProfileForCommand
	previousRun := runCLICommandWithSSHProxyForCommand
	connectName := ""
	runPort := 0
	activeCLIPersistentSSHTunnelForCommand = func() (cliSSHTunnelState, bool, error) {
		return cliSSHTunnelState{}, false, nil
	}
	connectCLISSHProfileForCommand = func(name string) (cliSSHTunnelState, bool, error) {
		connectName = name
		return cliSSHTunnelState{Name: name, Port: port}, false, nil
	}
	runCLICommandWithSSHProxyForCommand = func(args []string, gotPort int) error {
		runPort = gotPort
		return nil
	}
	t.Cleanup(func() {
		activeCLIPersistentSSHTunnelForCommand = previousActive
		connectCLISSHProfileForCommand = previousConnect
		runCLICommandWithSSHProxyForCommand = previousRun
	})
	if err := flcSSHCommand([]string{"curl", "https://example.com"}); err != nil {
		t.Fatal(err)
	}
	if connectName != "home" || runPort != port {
		t.Fatalf("auto-connect name=%q port=%d, want home/%d", connectName, runPort, port)
	}
}

func TestFLCSSHPersistentCommandReconnectsBrokenSOCKSListener(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	previousActive := activeCLIPersistentSSHTunnelForCommand
	previousConnect := connectCLISSHProfileForCommand
	previousRun := runCLICommandWithSSHProxyForCommand
	runPort := 0
	activeCLIPersistentSSHTunnelForCommand = func() (cliSSHTunnelState, bool, error) {
		return cliSSHTunnelState{Name: "school", Port: 1}, true, nil
	}
	connectCLISSHProfileForCommand = func(name string) (cliSSHTunnelState, bool, error) {
		if name != "school" {
			t.Fatalf("reconnect name = %q", name)
		}
		return cliSSHTunnelState{Name: name, Port: port}, false, nil
	}
	runCLICommandWithSSHProxyForCommand = func(args []string, gotPort int) error {
		runPort = gotPort
		return nil
	}
	t.Cleanup(func() {
		activeCLIPersistentSSHTunnelForCommand = previousActive
		connectCLISSHProfileForCommand = previousConnect
		runCLICommandWithSSHProxyForCommand = previousRun
	})
	if err := flcSSHCommand([]string{"curl", "https://example.com"}); err != nil {
		t.Fatal(err)
	}
	if runPort != port {
		t.Fatalf("rebuilt SSH command used port %d, want %d", runPort, port)
	}
}

func TestFLCSSHPersistentCommandPromptsForEncryptedKey(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	previousEnsure := ensureCLIPersistentSSHTunnelForCommand
	previousPrompt := promptCLISSHSecretOnceForCommand
	previousConnect := connectCLISSHProfileWithCredentialsForCommand
	previousRun := runCLICommandWithSSHProxyForCommand
	prompted := false
	runPort := 0
	ensureCLIPersistentSSHTunnelForCommand = func(string) (cliSSHTunnelState, error) {
		return cliSSHTunnelState{}, &cliSSHCredentialRequiredError{
			Profile:  "school",
			Identity: "/tmp/id_ed25519",
		}
	}
	promptCLISSHSecretOnceForCommand = func(string) (string, error) {
		prompted = true
		return "one-time-secret", nil
	}
	connectCLISSHProfileWithCredentialsForCommand = func(
		name string,
		credentials cliSSHCredentials,
	) (cliSSHTunnelState, bool, error) {
		if name != "school" || credentials.IdentityPassphrase != "one-time-secret" {
			t.Fatalf("passphrase retry = name %q credentials %+v", name, credentials)
		}
		return cliSSHTunnelState{Name: name, Port: port}, false, nil
	}
	runCLICommandWithSSHProxyForCommand = func(args []string, gotPort int) error {
		runPort = gotPort
		return nil
	}
	t.Cleanup(func() {
		ensureCLIPersistentSSHTunnelForCommand = previousEnsure
		promptCLISSHSecretOnceForCommand = previousPrompt
		connectCLISSHProfileWithCredentialsForCommand = previousConnect
		runCLICommandWithSSHProxyForCommand = previousRun
	})
	if err := flcSSHCommand([]string{"curl", "https://example.com"}); err != nil {
		t.Fatal(err)
	}
	if !prompted {
		t.Fatal("encrypted default SSH profile did not prompt for a passphrase")
	}
	if runPort != port {
		t.Fatalf("passphrase retry used port %d, want %d", runPort, port)
	}
}

func TestEnsureCLIPersistentSSHTunnelRecordsLastErrorWhenSOCKSNotReady(t *testing.T) {
	configRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	if err := addCLISSHProfile(cliSSHProfile{
		Name:     "school",
		Username: "student",
		Host:     "example.edu",
		Port:     22,
	}); err != nil {
		t.Fatal(err)
	}
	previousActive := activeCLIPersistentSSHTunnelForCommand
	previousConnect := connectCLISSHProfileForCommand
	activeCLIPersistentSSHTunnelForCommand = func() (cliSSHTunnelState, bool, error) {
		return cliSSHTunnelState{}, false, nil
	}
	connectCLISSHProfileForCommand = func(name string) (cliSSHTunnelState, bool, error) {
		return cliSSHTunnelState{Name: name, Port: 1}, false, nil
	}
	t.Cleanup(func() {
		cliRuntimeDirectoryOverride = previousRuntime
		activeCLIPersistentSSHTunnelForCommand = previousActive
		connectCLISSHProfileForCommand = previousConnect
	})
	_, err := ensureCLIPersistentSSHTunnel("school")
	if err == nil || !strings.Contains(err.Error(), "SOCKS5 listener is unavailable") {
		t.Fatalf("unready SSH tunnel error = %v", err)
	}
	lastError, loadErr := loadCLISSHLastError()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if lastError.Name != "school" || !strings.Contains(lastError.Error, "SOCKS5 listener is unavailable") {
		t.Fatalf("last SSH error = %+v", lastError)
	}
}

func TestProbeCLISSHSOCKSAcceptsNoAuthGreeting(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		header := make([]byte, 3)
		if _, readErr := io.ReadFull(connection, header); readErr != nil {
			return
		}
		_, _ = connection.Write([]byte{5, 0})
	}()
	if err := probeCLISSHSOCKS(port, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestCLISSHFriendlyErrorMapsOpenSSHFailures(t *testing.T) {
	got := formatCLISSHErrorSummary("user@host: Permission denied (publickey).")
	if !strings.Contains(got, "authentication failed") || !strings.Contains(got, "Permission denied") {
		t.Fatalf("friendly auth error = %q", got)
	}
	if got := cliSSHFriendlyError("custom remote failure"); got != "custom remote failure" {
		t.Fatalf("unknown SSH error was rewritten: %q", got)
	}
}

func TestTUISSHPageRendersDefaultAndLastError(t *testing.T) {
	output := stripTUIANSI(renderTUIAtSize(
		tuiSnapshot{
			Page: tuiPageSSH,
			SSHProfiles: []tuiSSHProfile{{
				Name:        "school",
				Default:     true,
				LastError:   "authentication failed; check username",
				Destination: "student@example.edu",
				Port:        22,
			}},
		},
		cliPaths{},
		"private Unix socket",
		true,
		false,
		180,
		30,
	))
	for _, expected := range []string{
		"*school",
		"DEFAULT",
		"authentication failed; check username",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("SSH page does not contain %q:\n%s", expected, output)
		}
	}
}

func TestTUISSHToggleDefault(t *testing.T) {
	configRoot := t.TempDir()
	runtimeRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	previousRuntime := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = runtimeRoot
	t.Cleanup(func() { cliRuntimeDirectoryOverride = previousRuntime })
	if err := addCLISSHProfile(cliSSHProfile{
		Name:     "home",
		Username: "user",
		Host:     "home.example.edu",
		Port:     22,
	}); err != nil {
		t.Fatal(err)
	}
	if err := addCLISSHProfile(cliSSHProfile{
		Name:     "school",
		Username: "student",
		Host:     "example.edu",
		Port:     22,
	}); err != nil {
		t.Fatal(err)
	}
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	refreshTUISSH(&model.snapshot)
	model.snapshot.Page = tuiPageSSH
	model.snapshot.FocusSidebar = false
	model.snapshot.SelectedSSH = 0
	if model.snapshot.SSHProfiles[0].Name != "home" || !model.snapshot.SSHProfiles[0].Default {
		t.Fatalf("unexpected initial SSH views: %+v", model.snapshot.SSHProfiles)
	}
	command := model.toggleSelectedSSHDefault()
	if command == nil {
		t.Fatal("default toggle did not schedule an update")
	}
	message := command().(tuiSSHCommandResultMsg)
	if message.err != nil {
		t.Fatal(message.err)
	}
	_, _ = model.Update(message)
	if model.snapshot.SSHProfiles[0].Default {
		t.Fatal("default SSH profile was not cleared")
	}
	model.snapshot.SelectedSSH = 1
	command = model.toggleSelectedSSHDefault()
	if command == nil {
		t.Fatal("second default toggle did not schedule an update")
	}
	message = command().(tuiSSHCommandResultMsg)
	if message.err != nil {
		t.Fatal(message.err)
	}
	_, _ = model.Update(message)
	if !model.snapshot.SSHProfiles[1].Default || model.snapshot.SSHProfiles[1].Name != "school" {
		t.Fatalf("school was not marked default: %+v", model.snapshot.SSHProfiles)
	}
}
