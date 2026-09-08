//go:build linux && !cgo && cli

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type openSSHHostConfig struct {
	Name     string
	HostName string
	User     string
	Port     int
	Identity string
	Jump     string
}

func cliSSHImportCommand(args []string) error {
	if cliSubcommandHelp(args) {
		fmt.Println("Usage: flclash ssh import [HOST...] [--file PATH]")
		fmt.Println("Import Host entries from an OpenSSH config into FlClash SSH profiles.")
		return nil
	}
	filePath := ""
	hosts := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--file":
			if index+1 >= len(args) || strings.TrimSpace(args[index+1]) == "" {
				return errors.New("usage: flclash ssh import [HOST...] [--file PATH]")
			}
			index++
			filePath = args[index]
		case strings.HasPrefix(argument, "--file="):
			filePath = strings.TrimPrefix(argument, "--file=")
		case strings.HasPrefix(argument, "-"):
			return fmt.Errorf("unknown SSH import option %q", argument)
		default:
			hosts = append(hosts, argument)
		}
	}
	imported, skipped, err := importCLISSHConfigHosts(filePath, hosts)
	if err != nil {
		return err
	}
	if len(imported) == 0 && len(skipped) == 0 {
		fmt.Println("No importable OpenSSH Host entries found")
		return nil
	}
	for _, name := range imported {
		fmt.Printf("SSH profile %s imported\n", name)
	}
	for _, message := range skipped {
		fmt.Printf("skipped: %s\n", message)
	}
	if len(imported) == 0 {
		return errors.New("no SSH profiles were imported")
	}
	return nil
}

func importCLISSHConfigHosts(filePath string, wanted []string) ([]string, []string, error) {
	if strings.TrimSpace(filePath) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, nil, err
		}
		filePath = filepath.Join(home, ".ssh", "config")
	}
	entries, err := parseOpenSSHConfigFile(expandCLISSHIdentityPath(filePath), 0)
	if err != nil {
		return nil, nil, err
	}
	wantedSet := map[string]bool{}
	for _, name := range wanted {
		wantedSet[strings.ToLower(strings.TrimSpace(name))] = true
	}
	imported := make([]string, 0, len(entries))
	skipped := make([]string, 0)
	seen := make(map[string]bool)
	for _, entry := range entries {
		key := strings.ToLower(entry.Name)
		if seen[key] || (len(wantedSet) > 0 && !wantedSet[key]) {
			continue
		}
		seen[key] = true
		resolved, resolveErr := resolveCLIImportedSSHHost(filePath, entry)
		if resolveErr != nil {
			skipped = append(skipped, entry.Name+": "+resolveErr.Error())
			continue
		}
		entry = resolved
		profile, skipReason := cliSSHProfileFromOpenSSHHost(entry)
		if skipReason != "" {
			skipped = append(skipped, entry.Name+": "+skipReason)
			continue
		}
		if err := addCLISSHProfile(profile); err != nil {
			skipped = append(skipped, profile.Name+": "+err.Error())
			continue
		}
		imported = append(imported, profile.Name)
	}
	for _, name := range wanted {
		if !seen[strings.ToLower(name)] {
			skipped = append(skipped, name+": no concrete OpenSSH Host entry found")
		}
	}
	return imported, skipped, nil
}

// Let OpenSSH evaluate first-value precedence, Host patterns, Include and Match
// rather than interpreting the collected concrete Host blocks as full configs.
func resolveCLIImportedSSHHost(filePath string, entry openSSHHostConfig) (openSSHHostConfig, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "ssh", "-G", "-F", expandCLISSHIdentityPath(filePath), entry.Name)
	command.WaitDelay = time.Second
	prepareCLISSHNonInteractiveCommand(command)
	var stdout, stderr cliSSHCappedBuffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return entry, fmt.Errorf("resolve OpenSSH Host %q: %w: %s", entry.Name, err, cliSSHOutputSummary(stderr.String()))
	}
	for _, line := range strings.Split(stdout.String(), "\n") {
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "hostname":
			entry.HostName = value
		case "user":
			entry.User = value
		case "port":
			port, err := strconv.Atoi(value)
			if err != nil {
				return entry, fmt.Errorf("invalid resolved SSH port %q", value)
			}
			entry.Port = port
		case "proxyjump":
			entry.Jump = value
			if value == "none" {
				entry.Jump = ""
			}
		case "identityfile":
			if entry.Identity == "" && value != "none" {
				identity := expandCLISSHIdentityPath(value)
				if info, err := os.Stat(identity); err == nil && info.Mode().IsRegular() {
					entry.Identity = identity
				}
			}
		}
	}
	return entry, nil
}

func cliSSHProfileFromOpenSSHHost(entry openSSHHostConfig) (cliSSHProfile, string) {
	name := sanitizeCLISSHImportedName(entry.Name)
	if name == "" {
		return cliSSHProfile{}, "Host alias is not a valid FlClash profile name"
	}
	// Keep the original alias for Host-specific OpenSSH settings (notably
	// ControlPath). Pin its resolved destination separately for custom imports.
	host := strings.TrimSpace(entry.Name)
	port := entry.Port
	if port == 0 {
		port = 22
	}
	profile := normalizeCLISSHProfile(cliSSHProfile{
		Name:     name,
		Username: strings.TrimSpace(entry.User),
		Host:     host,
		Port:     port,
		Jump:     strings.TrimSpace(entry.Jump),
		Identity: strings.TrimSpace(entry.Identity),
	})
	if hostname := strings.TrimSpace(entry.HostName); hostname != "" && hostname != host {
		profile.Options = append(profile.Options, "HostName="+hostname)
	}
	if err := validateCLISSHProfile(profile); err != nil {
		return cliSSHProfile{}, err.Error()
	}
	return profile, ""
}

func sanitizeCLISSHImportedName(name string) string {
	var builder strings.Builder
	for _, value := range strings.TrimSpace(name) {
		switch {
		case unicode.IsLetter(value) || unicode.IsDigit(value) || value == '.' || value == '_' || value == '-':
			builder.WriteRune(value)
		default:
			if builder.Len() > 0 && !strings.HasSuffix(builder.String(), "-") {
				builder.WriteByte('-')
			}
		}
	}
	return strings.Trim(builder.String(), "-")
}

func parseOpenSSHConfigFile(path string, depth int) ([]openSSHHostConfig, error) {
	if depth > 8 {
		return nil, fmt.Errorf("OpenSSH config include depth exceeded at %q", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read OpenSSH config %q: %w", path, err)
	}
	defer file.Close()
	var (
		entries []openSSHHostConfig
		current []int
	)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		keyword, value, ok := splitOpenSSHConfigLine(scanner.Text())
		if !ok {
			continue
		}
		switch strings.ToLower(keyword) {
		case "host":
			current = nil
			for _, alias := range strings.Fields(value) {
				if openSSHHostPattern(alias) {
					continue
				}
				entries = append(entries, openSSHHostConfig{Name: alias})
				current = append(current, len(entries)-1)
			}
		case "match":
			current = nil
		case "include":
			included, includeErr := parseOpenSSHConfigIncludes(path, value, depth)
			if includeErr != nil {
				return nil, includeErr
			}
			entries = append(entries, included...)
			current = nil
		case "hostname":
			for _, index := range current {
				entries[index].HostName = value
			}
		case "user":
			for _, index := range current {
				entries[index].User = value
			}
		case "port":
			if current == nil {
				continue
			}
			port, convErr := strconv.Atoi(value)
			if convErr != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid Port %q for Host %q", value, entries[current[0]].Name)
			}
			for _, index := range current {
				entries[index].Port = port
			}
		case "identityfile":
			for _, index := range current {
				if entries[index].Identity == "" {
					entries[index].Identity = expandCLISSHIdentityPath(value)
				}
			}
		case "proxyjump", "jumphost":
			for _, index := range current {
				if entries[index].Jump == "" {
					entries[index].Jump = value
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read OpenSSH config %q: %w", path, err)
	}
	return entries, nil
}

func parseOpenSSHConfigIncludes(parent, spec string, depth int) ([]openSSHHostConfig, error) {
	var entries []openSSHHostConfig
	for _, pattern := range strings.Fields(spec) {
		pattern = expandCLISSHIdentityPath(unquoteOpenSSHConfigValue(pattern))
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(filepath.Dir(parent), pattern)
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("expand OpenSSH Include %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			if info, statErr := os.Stat(pattern); statErr == nil && info.Mode().IsRegular() {
				matches = []string{pattern}
			}
		}
		for _, match := range matches {
			included, includeErr := parseOpenSSHConfigFile(match, depth+1)
			if includeErr != nil {
				if errors.Is(includeErr, os.ErrNotExist) {
					continue
				}
				return nil, includeErr
			}
			entries = append(entries, included...)
		}
	}
	return entries, nil
}

func splitOpenSSHConfigLine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	if strings.HasPrefix(line, "=") {
		return "", "", false
	}
	separator := strings.IndexFunc(line, func(r rune) bool {
		return unicode.IsSpace(r) || r == '='
	})
	if separator < 1 {
		return "", "", false
	}
	keyword := line[:separator]
	value := strings.TrimSpace(line[separator:])
	value = unquoteOpenSSHConfigValue(strings.TrimSpace(strings.TrimPrefix(value, "=")))
	if keyword == "" || value == "" {
		return "", "", false
	}
	return keyword, value, true
}

func unquoteOpenSSHConfigValue(value string) string {
	value = strings.TrimSpace(value)
	var quote rune
	escaped := false
	for index, r := range value {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
		} else if r == '"' || r == '\'' {
			quote = r
		} else if r == '#' {
			value = strings.TrimSpace(value[:index])
			break
		}
	}
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func openSSHHostPattern(alias string) bool {
	return strings.ContainsAny(alias, "*?!")
}
