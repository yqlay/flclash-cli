//go:build linux && !cgo && cli

package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCloseConnectionsRespectsVisibleUserScope(t *testing.T) {
	var deleted []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(`{"connections":[{"id":"own","metadata":{"uid":1001}},{"id":"other","metadata":{"uid":1002}}]}`))
			return
		}
		deleted = append(deleted, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	controller := controllerClient{options: controllerOptions{address: server.URL}}
	if err := closeTUIVisibleConnections(controller, 1001, false, ""); err != nil {
		t.Fatal(err)
	}
	if strings.Join(deleted, ",") != "/connections/own" {
		t.Fatalf("deleted %v", deleted)
	}
	deleted = nil
	if err := closeTUIVisibleConnections(controller, 1001, false, "other"); err == nil {
		t.Fatal("other user's connection was accepted")
	}
	if len(deleted) != 0 {
		t.Fatalf("deleted invisible connection: %v", deleted)
	}
	if err := closeTUIVisibleConnections(controller, 1001, true, ""); err != nil {
		t.Fatal(err)
	}
	if strings.Join(deleted, ",") != "/connections" {
		t.Fatalf("system scope deleted %v", deleted)
	}
}

func newTestTUIServiceRuntime(t *testing.T) *tuiServiceRuntime {
	t.Helper()
	directory := t.TempDir()
	return newTUIServiceRuntime(
		cliPaths{
			homeDir:    directory,
			configPath: filepath.Join(directory, "config.yaml"),
		},
		defaultCLITestURL,
		filepath.Join(directory, "core.sock"),
		nil,
		nil,
	)
}

type countingTUIListener struct {
	net.Listener
	accepted atomic.Int32
}

func (l *countingTUIListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return connection, err
}

func TestTUIServiceRuntimeRejectsStaleRevision(t *testing.T) {
	runtime := newTestTUIServiceRuntime(t)
	stale := uint64(0)
	status := runtime.handle(tuiServiceRequest{
		ProtocolVersion:  tuiServiceProtocolVersion,
		RequestID:        "stale-request",
		ExpectedRevision: &stale,
		Action:           "reload",
	})
	if status.OK || status.ErrorCode != tuiServiceErrorConflict || status.Revision != 1 {
		t.Fatalf("stale mutation response = %+v", status)
	}
	var serviceErr *tuiServiceError
	err := &tuiServiceError{
		Code:     status.ErrorCode,
		Revision: status.Revision,
		Message:  status.Error,
	}
	if !errors.As(err, &serviceErr) || serviceErr.Code != tuiServiceErrorConflict {
		t.Fatalf("structured conflict error = %#v", err)
	}
}

func TestTUIServiceRuntimeKeepsFailedStartCleanupManageable(t *testing.T) {
	runtime := newTestTUIServiceRuntime(t)
	previousStop := stopTUIServiceCoreListeners
	previousWait := waitTUIServiceProxyPortState
	stopTUIServiceCoreListeners = func() bool { return false }
	waitTUIServiceProxyPortState = func(int, bool, time.Duration) bool {
		return false
	}
	t.Cleanup(func() {
		stopTUIServiceCoreListeners = previousStop
		waitTUIServiceProxyPortState = previousWait
	})

	err := runtime.rollbackStartedCore(17890, errors.New("simulated startup failure"))
	status := runtime.snapshot("")
	if err == nil || !strings.Contains(err.Error(), "cleanup failed") ||
		!status.Running || status.ActiveProxyPort != 17890 {
		t.Fatalf("failed Core start cleanup = status:%+v err:%v", status, err)
	}
}

func TestTUIServiceRuntimeDoesNotReportStoppedWhileListenerRemains(t *testing.T) {
	runtime := newTestTUIServiceRuntime(t)
	runtime.mu.Lock()
	runtime.running = true
	runtime.activePort = 17890
	runtime.mu.Unlock()
	previousStop := stopTUIServiceCoreListeners
	previousWait := waitTUIServiceProxyPortState
	stopTUIServiceCoreListeners = func() bool { return true }
	waitTUIServiceProxyPortState = func(port int, open bool, _ time.Duration) bool {
		return port == 17890 && open
	}
	t.Cleanup(func() {
		stopTUIServiceCoreListeners = previousStop
		waitTUIServiceProxyPortState = previousWait
	})

	changed, err := runtime.stopCoreAndProxy(runtime.snapshot(""))
	status := runtime.snapshot("")
	if err == nil || changed || !strings.Contains(err.Error(), "did not stop") ||
		!status.Running || status.ActiveProxyPort != 17890 {
		t.Fatalf("lingering Core listener stop = changed:%t status:%+v err:%v", changed, status, err)
	}
}

func TestTUIServiceRuntimeFailedShutdownRemainsRetryable(t *testing.T) {
	runtime := newTestTUIServiceRuntime(t)
	runtime.mu.Lock()
	runtime.running = true
	runtime.activePort = 17890
	runtime.mu.Unlock()
	previousStop := stopTUIServiceCoreListeners
	stopTUIServiceCoreListeners = func() bool { return false }
	t.Cleanup(func() { stopTUIServiceCoreListeners = previousStop })

	status := runtime.handle(tuiServiceRequest{
		ProtocolVersion: tuiServiceProtocolVersion,
		RequestID:       "failed-shutdown",
		Action:          "shutdown",
	})
	if status.OK || !status.Running || status.ShuttingDown ||
		!strings.Contains(status.Error, "stop proxy listeners failed") {
		t.Fatalf("failed shutdown state = %+v", status)
	}
}

func TestTUIServiceRuntimeDeletesProfileAndLinkedMetadata(t *testing.T) {
	directory := t.TempDir()
	activePath := filepath.Join(directory, "config.yaml")
	targetPath := filepath.Join(directory, "school.yaml")
	for _, path := range []string{activePath, targetPath} {
		if err := os.WriteFile(path, []byte(defaultTUIConfig), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := rememberTUISubscriptionSource(
		directory,
		targetPath,
		"https://secret.example/subscription-token",
	); err != nil {
		t.Fatal(err)
	}
	runtime := newTUIServiceRuntime(
		cliPaths{homeDir: directory, configPath: activePath},
		defaultCLITestURL,
		filepath.Join(directory, "core.sock"),
		nil,
		nil,
	)
	revision := uint64(1)
	status := runtime.handle(tuiServiceRequest{
		ProtocolVersion:  tuiServiceProtocolVersion,
		RequestID:        "delete-profile",
		ExpectedRevision: &revision,
		Action:           "delete_profile",
		ConfigPath:       targetPath,
	})
	if !status.OK || status.Revision != 2 {
		t.Fatalf("delete Profile response = %+v", status)
	}
	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		t.Fatalf("deleted Profile still exists: %v", err)
	}
	if _, err := loadTUISubscriptionSource(directory, targetPath); err == nil ||
		!strings.Contains(err.Error(), "not linked") {
		t.Fatalf("deleted Profile metadata remains: %v", err)
	}

	revision = status.Revision
	status = runtime.handle(tuiServiceRequest{
		ProtocolVersion:  tuiServiceProtocolVersion,
		RequestID:        "delete-active-profile",
		ExpectedRevision: &revision,
		Action:           "delete_profile",
		ConfigPath:       activePath,
	})
	if status.OK || !strings.Contains(status.Error, "active profile") {
		t.Fatalf("active Profile deletion response = %+v", status)
	}
	if _, err := os.Stat(activePath); err != nil {
		t.Fatalf("active Profile was removed: %v", err)
	}
}

func TestTUIServiceRuntimeDeduplicatesRequestID(t *testing.T) {
	runtime := newTestTUIServiceRuntime(t)
	request := tuiServiceRequest{
		ProtocolVersion: tuiServiceProtocolVersion,
		RequestID:       "retry-id",
		Action:          "status",
	}
	first := runtime.handle(request)
	runtime.bumpRevision()
	second := runtime.handle(request)
	if first.Revision != 1 || second.Revision != first.Revision {
		t.Fatalf("deduplicated revisions = %d then %d", first.Revision, second.Revision)
	}
	fresh := runtime.handle(tuiServiceRequest{
		ProtocolVersion: tuiServiceProtocolVersion,
		RequestID:       "fresh-id",
		Action:          "status",
	})
	if fresh.Revision != 2 {
		t.Fatalf("fresh status revision = %d, want 2", fresh.Revision)
	}
}

func TestTUIServiceRuntimeDeduplicatesConcurrentMutation(t *testing.T) {
	directory := t.TempDir()
	var shutdownCount atomic.Int32
	runtime := newTUIServiceRuntime(
		cliPaths{
			homeDir:    directory,
			configPath: filepath.Join(directory, "config.yaml"),
		},
		defaultCLITestURL,
		filepath.Join(directory, "core.sock"),
		nil,
		func() { shutdownCount.Add(1) },
	)
	revision := uint64(1)
	request := tuiServiceRequest{
		ProtocolVersion:  tuiServiceProtocolVersion,
		RequestID:        "same-shutdown",
		ExpectedRevision: &revision,
		Action:           "shutdown",
	}
	const callers = 32
	var wait sync.WaitGroup
	wait.Add(callers)
	results := make(chan tuiServiceStatus, callers)
	for remaining := callers; remaining > 0; remaining-- {
		go func() {
			defer wait.Done()
			results <- runtime.handle(request)
		}()
	}
	wait.Wait()
	close(results)
	for status := range results {
		if !status.OK || status.Revision != 2 || !status.ShuttingDown {
			t.Fatalf("deduplicated mutation response = %+v", status)
		}
	}
	if shutdownCount.Load() != 0 {
		t.Fatalf("shutdown callback ran before ACK: %d", shutdownCount.Load())
	}
	runtime.signalShutdown()
	if shutdownCount.Load() != 1 {
		t.Fatalf("shutdown callback count = %d", shutdownCount.Load())
	}
}

func TestTUIServiceRuntimeWatchReportsMonotonicRevision(t *testing.T) {
	runtime := newTestTUIServiceRuntime(t)
	result := make(chan tuiServiceStatus, 1)
	go func() {
		result <- runtime.handle(tuiServiceRequest{
			ProtocolVersion: tuiServiceProtocolVersion,
			RequestID:       "watch-id",
			Action:          "watch",
			AfterRevision:   1,
			WatchTimeoutMS:  1000,
		})
	}()
	time.Sleep(20 * time.Millisecond)
	runtime.bumpRevision()
	select {
	case status := <-result:
		if !status.OK || status.Revision != 2 {
			t.Fatalf("watch response = %+v", status)
		}
	case <-time.After(time.Second):
		t.Fatal("watch did not wake after revision changed")
	}
}

func TestTUIServiceRuntimeStatusDoesNotWaitForMutationQueue(t *testing.T) {
	runtime := newTestTUIServiceRuntime(t)
	runtime.mutationMu.Lock()
	defer runtime.mutationMu.Unlock()

	result := make(chan tuiServiceStatus, 1)
	go func() {
		result <- runtime.handle(tuiServiceRequest{
			ProtocolVersion: tuiServiceProtocolVersion,
			RequestID:       "status-during-mutation",
			Action:          "status",
		})
	}()
	select {
	case status := <-result:
		if !status.OK || status.Revision != 1 {
			t.Fatalf("status response = %+v", status)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("status waited for the serialized mutation queue")
	}
}

func TestTUIServiceRuntimeRejectsUnsupportedProtocol(t *testing.T) {
	runtime := newTestTUIServiceRuntime(t)
	status := runtime.handle(tuiServiceRequest{
		ProtocolVersion: tuiServiceProtocolVersion + 1,
		RequestID:       "future-client",
		Action:          "status",
	})
	if status.OK || status.ErrorCode != tuiServiceErrorUnsupported {
		t.Fatalf("unsupported protocol response = %+v", status)
	}
}

func TestTUIServiceRuntimeReusesCoreControllerConnection(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "core.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	countingListener := &countingTUIListener{Listener: listener}
	var requestCount atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(
		w http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/connections" {
			http.NotFound(w, request)
			return
		}
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"connections":[]}`))
	})}
	go func() { _ = server.Serve(countingListener) }()
	t.Cleanup(func() { _ = server.Close() })

	runtime := newTUIServiceRuntime(
		cliPaths{
			homeDir:    directory,
			configPath: filepath.Join(directory, "config.yaml"),
		},
		defaultCLITestURL,
		socketPath,
		nil,
		nil,
	)
	t.Cleanup(runtime.closeCoreController)
	runtime.setRunning(true)
	for index := 0; index < 25; index++ {
		status := runtime.historyStatus("")
		if !status.OK {
			t.Fatalf("history status failed: %+v", status)
		}
	}

	if got := requestCount.Load(); got != 25 {
		t.Fatalf("Core request count = %d, want 25", got)
	}
	if got := countingListener.accepted.Load(); got != 1 {
		t.Fatalf("Core Unix connections = %d, want one reused connection", got)
	}
}

func TestTUIServiceRuntimeSelectProxyValidatesAndRollsBack(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "core.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	var selectionMu sync.Mutex
	selection := "DIRECT"
	selections := make([]string, 0, 3)
	server := &http.Server{Handler: http.HandlerFunc(func(
		w http.ResponseWriter,
		request *http.Request,
	) {
		selectionMu.Lock()
		defer selectionMu.Unlock()
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/proxies":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"proxies": map[string]any{
					"PROXY": map[string]any{
						"type": "Selector",
						"now":  selection,
						"all":  []string{"DIRECT", "Node A"},
					},
				},
			})
		case request.Method == http.MethodPut && request.URL.Path == "/proxies/PROXY":
			var body struct {
				Name string `json:"name"`
			}
			if decodeErr := json.NewDecoder(request.Body).Decode(&body); decodeErr != nil {
				http.Error(w, decodeErr.Error(), http.StatusBadRequest)
				return
			}
			selection = body.Name
			selections = append(selections, body.Name)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, request)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	runtime := newTUIServiceRuntime(
		cliPaths{
			homeDir:    directory,
			configPath: filepath.Join(directory, "config.yaml"),
		},
		defaultCLITestURL,
		socketPath,
		nil,
		nil,
	)
	runtime.trafficMode = "rule"
	if _, err := runtime.selectProxy("PROXY", "missing"); err == nil {
		t.Fatal("proxy outside the selected group was accepted")
	}
	selectionMu.Lock()
	if len(selections) != 0 {
		selectionMu.Unlock()
		t.Fatalf("invalid selection changed Core: %v", selections)
	}
	selectionMu.Unlock()
	changed, err := runtime.selectProxy("PROXY", "Node A")
	if err != nil || !changed {
		t.Fatalf("valid selection = %v, %v", changed, err)
	}
	if saved := loadTUISelectedProxies(directory)["PROXY"]; saved != "Node A" {
		t.Fatalf("saved selection = %q, want Node A", saved)
	}
	if saved := loadTUIFLCOutbound(directory); saved != "PROXY" {
		t.Fatalf("FLC outbound after Proxies selection = %q, want PROXY", saved)
	}

	statePath := filepath.Join(directory, tuiStateFilename)
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.selectProxy("PROXY", "DIRECT"); err == nil {
		t.Fatal("selection succeeded when its state could not be saved")
	}
	selectionMu.Lock()
	defer selectionMu.Unlock()
	if selection != "Node A" {
		t.Fatalf("Core rollback selection = %q, want Node A", selection)
	}
	if len(selections) != 3 || selections[0] != "Node A" ||
		selections[1] != "DIRECT" || selections[2] != "Node A" {
		t.Fatalf("Core selection transaction = %v", selections)
	}
}

func TestTUIServiceRuntimePatchesNativeModeWithoutReload(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(configPath, []byte(defaultTUIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	coreSocket := filepath.Join(directory, "core.sock")
	listener, err := net.Listen("unix", coreSocket)
	if err != nil {
		t.Fatal(err)
	}
	var patchCount atomic.Int32
	var patchedMode string
	var patchedModeMu sync.Mutex
	server := &http.Server{Handler: http.HandlerFunc(func(
		w http.ResponseWriter,
		request *http.Request,
	) {
		if request.Method != http.MethodPatch || request.URL.Path != "/configs" {
			http.NotFound(w, request)
			return
		}
		var body struct {
			Mode string `json:"mode"`
		}
		if decodeErr := json.NewDecoder(request.Body).Decode(&body); decodeErr != nil {
			http.Error(w, decodeErr.Error(), http.StatusBadRequest)
			return
		}
		patchedModeMu.Lock()
		patchedMode = body.Mode
		patchedModeMu.Unlock()
		patchCount.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	runtime := newTUIServiceRuntime(
		cliPaths{homeDir: directory, configPath: configPath},
		defaultCLITestURL,
		coreSocket,
		nil,
		nil,
	)
	runtime.configureRuntimePolicy(
		"rule",
		7890,
		configPath,
		tuiFLCListenerState{},
	)
	runtime.setRunning(true)
	changed, err := runtime.applyTrafficMode("global")
	if err != nil || !changed {
		t.Fatalf("native mode change = %t, %v", changed, err)
	}
	patchedModeMu.Lock()
	mode := patchedMode
	patchedModeMu.Unlock()
	if patchCount.Load() != 1 || mode != "global" {
		t.Fatalf("Core mode patches = %d, last mode %q", patchCount.Load(), mode)
	}
	settings := loadTUIConfiguredSettings(configPath, true)
	if settings == nil || settings.Mode != "global" {
		t.Fatalf("persisted settings = %+v", settings)
	}
	status := runtime.snapshot("")
	if status.Mode != "global" {
		t.Fatalf("runtime mode = %q, want global", status.Mode)
	}
	if saved := loadTUITrafficMode(directory, configPath); saved != "global" {
		t.Fatalf("saved mode = %q, want global", saved)
	}
}

func TestTUIServiceRuntimeRestoresProfileWhenNativeModePatchFails(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(configPath, []byte(defaultTUIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	coreSocket := filepath.Join(directory, "core.sock")
	listener, err := net.Listen("unix", coreSocket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(
		w http.ResponseWriter,
		_ *http.Request,
	) {
		http.Error(w, "patch rejected", http.StatusInternalServerError)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	runtime := newTUIServiceRuntime(
		cliPaths{homeDir: directory, configPath: configPath},
		defaultCLITestURL,
		coreSocket,
		nil,
		nil,
	)
	runtime.configureRuntimePolicy(
		"rule",
		7890,
		configPath,
		tuiFLCListenerState{},
	)
	runtime.setRunning(true)
	if changed, err := runtime.applyTrafficMode("global"); err == nil || changed {
		t.Fatalf("failed native mode patch = %t, %v", changed, err)
	}
	settings := loadTUIConfiguredSettings(configPath, true)
	if settings == nil || settings.Mode != "rule" {
		t.Fatalf("failed patch did not restore profile: %+v", settings)
	}
	if status := runtime.snapshot(""); status.Mode != "rule" {
		t.Fatalf("failed patch changed runtime mode to %q", status.Mode)
	}
}

func TestTUIServiceRuntimeChangesNativeModeWhileCoreStopped(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(configPath, []byte(defaultTUIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := newTUIServiceRuntime(
		cliPaths{homeDir: directory, configPath: configPath},
		defaultCLITestURL,
		filepath.Join(directory, "missing-core.sock"),
		nil,
		nil,
	)
	runtime.configureRuntimePolicy(
		"rule",
		7890,
		configPath,
		tuiFLCListenerState{},
	)

	changed, err := runtime.applyTrafficMode("global")
	if err != nil || !changed {
		t.Fatalf("stopped native mode change = %t, %v", changed, err)
	}
	settings := loadTUIConfiguredSettings(configPath, true)
	if settings == nil || settings.Mode != "global" {
		t.Fatalf("persisted stopped settings = %+v", settings)
	}
	status := runtime.snapshot("")
	if status.Running || status.Mode != "global" {
		t.Fatalf("stopped runtime status = %+v", status)
	}
	if saved := loadTUITrafficMode(directory, configPath); saved != "global" {
		t.Fatalf("saved stopped mode = %q", saved)
	}
}

func TestTUIServiceRuntimeRejectsActiveTunScopeChange(t *testing.T) {
	runtime := newTestTUIServiceRuntime(t)
	runtime.configureManagedRuntimePolicy(
		"rule",
		7890,
		7890,
		runtime.paths.configPath,
		tuiFLCListenerState{},
		tuiTunScopeUser,
		true,
	)

	changed, err := runtime.applyTun(true, tuiTunScopeSystem)
	if err == nil || changed ||
		!strings.Contains(err.Error(), "Turn TUN off") &&
			!strings.Contains(err.Error(), "turn TUN off") {
		t.Fatalf("active TUN scope change = %t, %v", changed, err)
	}
	status := runtime.snapshot("")
	if status.TunScope != tuiTunScopeUser || status.TunState != "on" {
		t.Fatalf("TUN changed after rejected scope switch: %+v", status)
	}
}

func TestTUIServiceRuntimeDoesNotApplyTunWhenScopeSaveFails(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(configPath, []byte(defaultTUIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(
		filepath.Join(directory, tuiTunScopeFilename),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	runtime := newTUIServiceRuntime(
		cliPaths{homeDir: directory, configPath: configPath},
		defaultCLITestURL,
		filepath.Join(directory, "core.sock"),
		nil,
		nil,
	)
	runtime.configureManagedRuntimePolicy(
		"rule",
		7890,
		7890,
		configPath,
		tuiFLCListenerState{},
		tuiTunScopeUser,
		false,
	)

	changed, err := runtime.applyTun(true, tuiTunScopeUser)
	if err == nil || changed {
		t.Fatalf("TUN with unwritable scope state = %t, %v", changed, err)
	}
	settings := loadTUIConfiguredSettings(configPath, true)
	if settings == nil || settings.TunEnabled {
		t.Fatalf("failed TUN scope save changed profile: %+v", settings)
	}
	status := runtime.snapshot("")
	if status.TunState != "off" || status.TunScope != tuiTunScopeUser {
		t.Fatalf("failed TUN scope save changed runtime: %+v", status)
	}
}

func TestTUIServiceRuntimeRestoresTunRuntimeAfterSettingsFailure(t *testing.T) {
	directory := t.TempDir()
	profileDirectory := filepath.Join(directory, "profiles")
	if err := os.Mkdir(profileDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(profileDirectory, "config.yaml")
	if err := os.WriteFile(configPath, []byte(defaultTUIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(profileDirectory, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(profileDirectory, 0o700) })

	runtime := newTUIServiceRuntime(
		cliPaths{homeDir: directory, configPath: configPath},
		defaultCLITestURL,
		filepath.Join(directory, "core.sock"),
		nil,
		nil,
	)
	runtime.configureManagedRuntimePolicy(
		"rule",
		7890,
		7890,
		configPath,
		tuiFLCListenerState{},
		tuiTunScopeUser,
		false,
	)

	changed, err := runtime.applyTun(true, tuiTunScopeUser)
	if err == nil || changed {
		t.Fatalf("TUN with unwritable profile = %t, %v", changed, err)
	}
	status := runtime.snapshot("")
	if status.TunState != "off" || status.TunScope != tuiTunScopeUser {
		t.Fatalf("failed TUN settings changed runtime: %+v", status)
	}
	settings := loadTUIConfiguredSettings(configPath, true)
	if settings == nil || settings.TunEnabled {
		t.Fatalf("failed TUN settings changed profile: %+v", settings)
	}
	if saved := loadTUITunScope(directory); saved != tuiTunScopeUser {
		t.Fatalf("failed TUN settings left scope %q", saved)
	}
	data, err := runtime.coreController.request(http.MethodGet, "/configs", nil)
	if err != nil {
		t.Fatalf("restored Core state is unavailable: %v", err)
	}
	var coreSettings tuiConfigResponse
	if err := json.Unmarshal(data, &coreSettings); err != nil {
		t.Fatal(err)
	}
	if coreSettings.Tun.Enable {
		t.Fatal("Core retained TUN after the settings transaction rolled back")
	}
}

func TestTUIServiceRuntimeRemovesGeneratedConfigWhenProfileSwitchFails(
	t *testing.T,
) {
	t.Cleanup(func() {
		_ = handleShutdown()
	})
	directory := t.TempDir()
	currentPath := filepath.Join(directory, "current.yaml")
	targetPath := filepath.Join(directory, "target.yaml")
	for _, path := range []string{currentPath, targetPath} {
		if err := os.WriteFile(path, []byte(defaultTUIConfig), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runtime := newTUIServiceRuntime(
		cliPaths{homeDir: directory, configPath: currentPath},
		defaultCLITestURL,
		filepath.Join(directory, "core.sock"),
		nil,
		nil,
	)
	runtime.configureManagedRuntimePolicy(
		"rule",
		7890,
		7890,
		currentPath,
		tuiFLCListenerState{},
		tuiTunScopeUser,
		false,
	)
	if err := os.Mkdir(
		filepath.Join(directory, tuiStateFilename),
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	changed, err := runtime.reload(targetPath)
	if err == nil || changed || !strings.Contains(err.Error(), "remember active profile") {
		t.Fatalf("profile switch with failed state save = %t, %v", changed, err)
	}
	matches, globErr := filepath.Glob(
		filepath.Join(directory, tuiManagedRuntimeConfigPrefix+"*.yaml"),
	)
	if globErr != nil {
		t.Fatal(globErr)
	}
	if len(matches) != 0 {
		t.Fatalf("failed profile switch leaked generated configs: %v", matches)
	}
	status := runtime.snapshot("")
	if filepath.Clean(status.ConfigPath) != filepath.Clean(currentPath) {
		t.Fatalf("failed profile switch changed active profile: %+v", status)
	}
}

func TestTUIServiceRuntimeBacksUpNestedProfileThroughBackend(t *testing.T) {
	runtime := newTestTUIServiceRuntime(t)
	nested := filepath.Join(runtime.paths.homeDir, "profiles")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(nested, "work.yaml")
	content := []byte("mixed-port: 7891\nmode: rule\n")
	if err := os.WriteFile(profilePath, content, 0o640); err != nil {
		t.Fatal(err)
	}
	changed, backupPath, err := runtime.backupProfile(profilePath)
	if err != nil || !changed {
		t.Fatalf("backup result = %t, %q, %v", changed, backupPath, err)
	}
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) != string(content) {
		t.Fatalf("backup content = %q, want %q", backup, content)
	}
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %o, want 600", info.Mode().Perm())
	}

	symlinkPath := filepath.Join(nested, "linked.yaml")
	if err := os.Symlink(profilePath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runtime.backupProfile(symlinkPath); err == nil {
		t.Fatal("Backend accepted a symlink profile backup target")
	}
}
