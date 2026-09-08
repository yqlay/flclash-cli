//go:build linux && !cgo && cli

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseOpenSSHConfigFileImportsConcreteHosts(t *testing.T) {
	directory := t.TempDir()
	included := filepath.Join(directory, "extra.conf")
	if err := os.WriteFile(included, []byte("Host jump\n  HostName bastion.example.edu\n  User jumpuser\n  Port 2222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "config")
	content := strings.Join([]string{
		"Host *",
		"  Compression yes",
		"Host school school.example.edu",
		"  HostName ssh.example.edu",
		"  User student",
		"  Port 2222",
		"  IdentityFile ~/.ssh/id_ed25519",
		"  ProxyJump jump",
		"Host wild-*",
		"  User nobody",
		"Include extra.conf",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := parseOpenSSHConfigFile(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("parsed hosts = %#v", entries)
	}
	if entries[0].Name != "school" || entries[0].HostName != "ssh.example.edu" ||
		entries[0].User != "student" || entries[0].Port != 2222 ||
		entries[0].Jump != "jump" || !strings.HasSuffix(entries[0].Identity, ".ssh/id_ed25519") {
		t.Fatalf("school host = %+v", entries[0])
	}
	if entries[1].Name != "school.example.edu" || entries[1].User != "student" || entries[1].Port != 2222 {
		t.Fatalf("second alias = %+v", entries[1])
	}
	if entries[2].Name != "jump" || entries[2].HostName != "bastion.example.edu" ||
		entries[2].User != "jumpuser" || entries[2].Port != 2222 {
		t.Fatalf("included host = %+v", entries[2])
	}
}

func TestSplitOpenSSHConfigWhitespaceAndQuotes(t *testing.T) {
	for _, line := range []string{"User\tstudent", "User = student", "User=student", "User\t=\tstudent # comment", "User \"student\" # comment"} {
		key, value, ok := splitOpenSSHConfigLine(line)
		if !ok || key != "User" || value != "student" {
			t.Fatalf("%q parsed as %q %q %t", line, key, value, ok)
		}
	}
	_, value, ok := splitOpenSSHConfigLine("IdentityFile \"/tmp/key #1\" # comment")
	if !ok || value != "/tmp/key #1" {
		t.Fatalf("quoted hash parsed as %q", value)
	}
}

func TestSSHImportReportsMissingRequestedHost(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("Host school\n User student\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	imported, skipped, err := importCLISSHConfigHosts(path, []string{"typo"})
	if err != nil || len(imported) != 0 || len(skipped) != 1 || !strings.Contains(skipped[0], "typo") {
		t.Fatalf("imported=%v skipped=%v err=%v", imported, skipped, err)
	}
}

func TestImportSSHUsesOpenSSHDefaultsAndPrecedence(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH is required")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("Host school alias\n HostName school.example\n Port 2222\nHost *\n User student\n Port 22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	imported, skipped, err := importCLISSHConfigHosts(path, nil)
	if err != nil || len(imported) != 2 || len(skipped) != 0 {
		t.Fatalf("imported %v skipped %v: %v", imported, skipped, err)
	}
	for _, name := range imported {
		profile, err := loadCLISSHProfile(name)
		if err != nil || profile.Username != "student" || profile.Port != 2222 || profile.Host != name || !cliSSHOptionConfigured(profile.Options, "HostName") {
			t.Fatalf("profile %s: host=%s user=%s port=%d err=%v", name, profile.Host, profile.Username, profile.Port, err)
		}
	}
}

func TestImportedAliasKeepsOpenSSHControlPath(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH is required")
	}
	directory := t.TempDir()
	config := filepath.Join(directory, "config")
	if err := os.WriteFile(config, []byte("Host school\n ControlMaster auto\n ControlPath "+directory+"/cm-%h-%n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(directory, "ssh")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexec '"+ssh+"' -F '"+config+"' \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	profile, reason := cliSSHProfileFromOpenSSHHost(openSSHHostConfig{Name: "school", HostName: "gateway.example", User: "student", Port: 22})
	if reason != "" {
		t.Fatal(reason)
	}
	want := filepath.Join(directory, "cm-gateway.example-school")
	if got := cliSSHConfigControlPath(wrapper, profile); got != want {
		t.Fatalf("control path = %q, want %q", got, want)
	}
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	var restored cliSSHProfile
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if got := cliSSHConfigControlPath(wrapper, restored); got != want {
		t.Fatalf("saved profile lost alias resolution: %q", got)
	}
}

func TestImportCLISSHConfigHostsSkipsExistingAndPatterns(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	directory := t.TempDir()
	path := filepath.Join(directory, "config")
	content := strings.Join([]string{
		"Host school",
		"  HostName ssh.example.edu",
		"  User student",
		"Host home",
		"  HostName home.example.edu",
		"  User user",
		"Host *",
		"  User ignore",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := addCLISSHProfile(cliSSHProfile{
		Name:     "school",
		Username: "student",
		Host:     "already.example.edu",
		Port:     22,
	}); err != nil {
		t.Fatal(err)
	}
	imported, skipped, err := importCLISSHConfigHosts(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(imported) != 1 || imported[0] != "home" {
		t.Fatalf("imported = %v", imported)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "school") {
		t.Fatalf("skipped = %v", skipped)
	}
	profile, err := loadCLISSHProfile("home")
	if err != nil {
		t.Fatal(err)
	}
	if profile.Host != "home" || profile.Username != "user" || strings.Join(profile.Options, ",") != "HostName=home.example.edu" {
		t.Fatalf("imported profile = %+v", profile)
	}
}
