//go:build linux && !cgo && cli

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"
)

const (
	tuiHistoryFilename = ".flclash-cli-history.json"
	tuiHistoryVersion  = 1
)

type tuiPersistentHistory struct {
	Version int          `json:"version"`
	Entries []tuiRequest `json:"entries"`
}

func loadTUIHistory(homeDir string) ([]tuiRequest, error) {
	path := filepath.Join(homeDir, tuiHistoryFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var saved tuiPersistentHistory
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("parse saved History: %w", err)
	}
	if saved.Version != tuiHistoryVersion {
		return nil, fmt.Errorf("unsupported History version %d", saved.Version)
	}
	entries := make([]tuiRequest, 0, minTUI(len(saved.Entries), tuiRequestHistoryLimit))
	for _, entry := range saved.Entries {
		if entry.ID == "" || entry.FirstSeen.IsZero() || entry.LastSeen.IsZero() {
			continue
		}
		// No connection survives a Backend restart. A restored entry is recent
		// history until Mihomo reports the same ID again.
		entry.Active = false
		entries = append(entries, entry)
		if len(entries) == tuiRequestHistoryLimit {
			break
		}
	}
	return entries, nil
}

func saveTUIHistory(homeDir string, entries []tuiRequest) error {
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		return err
	}
	if len(entries) > tuiRequestHistoryLimit {
		entries = entries[:tuiRequestHistoryLimit]
	}
	data, err := json.MarshalIndent(tuiPersistentHistory{
		Version: tuiHistoryVersion,
		Entries: entries,
	}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	file, err := os.CreateTemp(homeDir, ".flclash-cli-history-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(homeDir, tuiHistoryFilename)); err != nil {
		return err
	}
	committed = true
	return nil
}

func (r *tuiServiceRuntime) restoreHistory() error {
	r.mu.RLock()
	homeDir := r.paths.homeDir
	r.mu.RUnlock()
	entries, err := loadTUIHistory(homeDir)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.history = entries
	r.historyVersion = 1
	r.persistedHistoryVersion = 1
	r.mu.Unlock()
	return nil
}

func (r *tuiServiceRuntime) persistHistory(force bool) error {
	r.historyPersistMu.Lock()
	defer r.historyPersistMu.Unlock()
	r.mu.RLock()
	version := r.historyVersion
	if !force && version == r.persistedHistoryVersion {
		r.mu.RUnlock()
		return nil
	}
	homeDir := r.paths.homeDir
	entries := append([]tuiRequest(nil), r.history...)
	r.mu.RUnlock()
	if err := saveTUIHistory(homeDir, entries); err != nil {
		return err
	}
	r.mu.Lock()
	if version > r.persistedHistoryVersion {
		r.persistedHistoryVersion = version
	}
	r.mu.Unlock()
	return nil
}

func (r *tuiServiceRuntime) clearPersistentHistory() (bool, error) {
	r.historyUpdateMu.Lock()
	defer r.historyUpdateMu.Unlock()
	r.mu.Lock()
	previous := append([]tuiRequest(nil), r.history...)
	changed := len(previous) > 0
	r.history = nil
	r.historyVersion++
	r.mu.Unlock()
	if err := r.persistHistory(true); err != nil {
		r.mu.Lock()
		r.history = previous
		r.historyVersion++
		r.mu.Unlock()
		return false, errors.New("persist cleared History: " + err.Error())
	}
	return changed, nil
}

func (r *tuiServiceRuntime) recordHistoryUpdate(entries []tuiRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if slices.Equal(r.history, entries) {
		return
	}
	r.history = entries
	r.historyVersion++
}

const tuiHistoryCollectorInterval = 2 * time.Second

func historyPersistenceInterval() time.Duration {
	return 2 * time.Second
}
