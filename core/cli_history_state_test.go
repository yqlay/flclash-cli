//go:build linux && !cgo && cli

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestTUIHistoryCollectorIntervalIsAtLeastTwoSeconds(t *testing.T) {
	if tuiHistoryCollectorInterval < 2*time.Second {
		t.Fatalf(
			"history collector interval = %s, want at least 2s",
			tuiHistoryCollectorInterval,
		)
	}
	if historyPersistenceInterval() <= 0 {
		t.Fatal("history persist interval is not a readable duration")
	}
}

func TestHistoryCollectorDoesNotDirtyUnchangedSnapshots(t *testing.T) {
	runtime := &tuiServiceRuntime{}
	runtime.recordHistoryUpdate([]tuiRequest{})
	if runtime.historyVersion != 0 {
		t.Fatal("empty poll dirtied empty history")
	}
	entries := []tuiRequest{{tuiConnection: tuiConnection{ID: "closed"}, Active: false}}
	runtime.recordHistoryUpdate(entries)
	version := runtime.historyVersion
	for range 3 {
		runtime.recordHistoryUpdate(updateTUIRequestHistory(entries, nil, time.Now()))
	}
	if runtime.historyVersion != version {
		t.Fatal("unchanged closed connections dirtied history on each poll")
	}
	changed := append([]tuiRequest(nil), entries...)
	changed[0].Download++
	runtime.recordHistoryUpdate(changed)
	if runtime.historyVersion != version+1 {
		t.Fatal("traffic change did not dirty history")
	}
}

func TestTUIHistoryPersistSkipsUnchangedFile(t *testing.T) {
	directory := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	entries := []tuiRequest{{
		tuiConnection: tuiConnection{
			ID:      "connection-1",
			Host:    "example.test",
			Network: "tcp",
			Chain:   "PROXY",
		},
		FirstSeen: now.Add(-time.Minute),
		LastSeen:  now,
		Active:    true,
	}}
	if err := saveTUIHistory(directory, entries); err != nil {
		t.Fatal(err)
	}
	runtime := newTUIServiceRuntime(
		cliPaths{homeDir: directory, configPath: filepath.Join(directory, "config.yaml")},
		defaultCLITestURL,
		filepath.Join(directory, "core.sock"),
		nil,
		nil,
	)
	if err := runtime.restoreHistory(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(directory, tuiHistoryFilename)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeSys, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("History stat is not a linux Stat_t")
	}
	if err := runtime.persistHistory(false); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	afterSys, ok := after.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("History stat after persist is not a linux Stat_t")
	}
	if afterSys.Ino != beforeSys.Ino || !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("unchanged History rewrote the on-disk file")
	}

	runtime.recordHistoryUpdate(append([]tuiRequest(nil), entries...))
	if err := runtime.persistHistory(false); err != nil {
		t.Fatal(err)
	}
	changed, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	changedSys, ok := changed.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("History stat after change is not a linux Stat_t")
	}
	if changedSys.Ino == beforeSys.Ino && changed.ModTime().Equal(before.ModTime()) {
		t.Fatal("changed History was not written to disk")
	}
}

func TestTUIHistoryPersistsRestoresAndClears(t *testing.T) {
	directory := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	entries := []tuiRequest{{
		tuiConnection: tuiConnection{
			ID:      "connection-1",
			Host:    "example.test",
			Network: "tcp",
			Chain:   "PROXY",
		},
		FirstSeen: now.Add(-time.Minute),
		LastSeen:  now,
		Active:    true,
	}}
	if err := saveTUIHistory(directory, entries); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(directory, tuiHistoryFilename))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("History mode = %o, want 600", info.Mode().Perm())
	}
	restored, err := loadTUIHistory(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored) != 1 || restored[0].ID != entries[0].ID || restored[0].Active {
		t.Fatalf("restored History = %+v", restored)
	}
	runtime := newTUIServiceRuntime(
		cliPaths{homeDir: directory, configPath: filepath.Join(directory, "config.yaml")},
		defaultCLITestURL,
		filepath.Join(directory, "core.sock"),
		nil,
		nil,
	)
	if err := runtime.restoreHistory(); err != nil {
		t.Fatal(err)
	}
	changed, err := runtime.clearPersistentHistory()
	if err != nil || !changed {
		t.Fatalf("clear History = %t, %v", changed, err)
	}
	restored, err = loadTUIHistory(directory)
	if err != nil || len(restored) != 0 {
		t.Fatalf("cleared persisted History = %+v, %v", restored, err)
	}
}

func TestFilterCLIHistoryCombinesStateSearchAndLimit(t *testing.T) {
	history := []tuiRequest{
		{tuiConnection: tuiConnection{ID: "1", Host: "api.example", Process: "curl", Network: "tcp", Chain: "PROXY"}, Active: true},
		{tuiConnection: tuiConnection{ID: "2", Host: "other.example", Process: "browser", Network: "tcp", Chain: "DIRECT"}},
		{tuiConnection: tuiConnection{ID: "3", Host: "cdn.example", Process: "curl", Network: "udp", Chain: "PROXY"}},
	}
	filtered := filterCLIHistory(history, "done", "curl", 1)
	if len(filtered) != 1 || filtered[0].ID != "3" {
		t.Fatalf("filtered History = %+v", filtered)
	}
}

func TestLoadTUIHistoryRejectsCorruptState(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(directory, tuiHistoryFilename),
		[]byte("not-json"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTUIHistory(directory); err == nil {
		t.Fatal("corrupt History was accepted")
	}
}

func TestTUIHistoryRefreshAndClearAreSerialized(t *testing.T) {
	runtime := newTestTUIServiceRuntime(t)
	runtime.mu.Lock()
	runtime.history = []tuiRequest{{
		tuiConnection: tuiConnection{
			ID:   "old",
			Host: "old.example",
		},
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}}
	runtime.mu.Unlock()

	runtime.historyUpdateMu.Lock()
	refreshDone := make(chan struct{})
	go func() {
		_ = runtime.historyStatus("")
		close(refreshDone)
	}()
	select {
	case <-refreshDone:
		t.Fatal("History refresh bypassed the update serialization lock")
	case <-time.After(25 * time.Millisecond):
	}
	runtime.historyUpdateMu.Unlock()
	select {
	case <-refreshDone:
	case <-time.After(time.Second):
		t.Fatal("History refresh did not resume after the lock was released")
	}

	runtime.historyUpdateMu.Lock()
	clearDone := make(chan error, 1)
	go func() {
		_, err := runtime.clearPersistentHistory()
		clearDone <- err
	}()
	select {
	case err := <-clearDone:
		t.Fatalf("History clear bypassed the update serialization lock: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	runtime.historyUpdateMu.Unlock()
	select {
	case err := <-clearDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("History clear did not resume after the lock was released")
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if len(runtime.history) != 0 {
		t.Fatalf("History was repopulated after clear: %+v", runtime.history)
	}
}

func TestTUIHistoryMarksEntriesCompleteWhenCoreStops(t *testing.T) {
	runtime := newTestTUIServiceRuntime(t)
	runtime.mu.Lock()
	runtime.history = []tuiRequest{{
		tuiConnection: tuiConnection{ID: "connection-1"},
		Active:        true,
	}}
	runtime.mu.Unlock()

	status := runtime.historyStatus("")
	if len(status.History) != 1 || status.History[0].Active {
		t.Fatalf("stopped Core returned active History: %+v", status.History)
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if len(runtime.history) != 1 || runtime.history[0].Active {
		t.Fatalf("stopped Core retained active persistent History: %+v", runtime.history)
	}
}
