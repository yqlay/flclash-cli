//go:build linux && !cgo && cli

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const cliVersion = "0.5.28"

type cliPaths struct {
	homeDir    string
	configPath string
}

type controllerOptions struct {
	address    string
	unixSocket string
	secret     string
}

func main() {
	applyCLIGoMemoryPolicy()
	program := filepath.Base(os.Args[0])
	err := dispatchCLI(program, os.Args[1:])

	if err != nil {
		if program != "flc" {
			program = "flclash"
		}
		if err.Error() != "" {
			fmt.Fprintf(os.Stderr, "%s: %v\n", program, err)
		}
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		var exitCoder interface{ ExitCode() int }
		if errors.As(err, &exitCoder) {
			os.Exit(exitCoder.ExitCode())
		}
		os.Exit(1)
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "FlClash TUI - one backend, multiple terminal clients")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  flclash                         Open a TUI frontend")
	fmt.Fprintln(w, "  flclash COMMAND [OPTIONS]       Manage the shared backend")
	fmt.Fprintln(w, "  flc COMMAND [ARG...]            Run a command through FlClash")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Dashboard commands:")
	fmt.Fprintln(w, "  core              Start, stop, restart, reload, or inspect Core")
	fmt.Fprintln(w, "  sys               Turn System proxy on/off or inspect it")
	fmt.Fprintln(w, "  tun               Turn TUN on/off or inspect it")
	fmt.Fprintln(w, "  mode              Select rule/global/direct/silent mode")
	fmt.Fprintln(w, "  port              Get, set, or disable the normal Proxy port")
	fmt.Fprintln(w, "  flc               Inspect silent flc; Proxies selection sets its group")
	fmt.Fprintln(w, "  ssh               Manage independent SSH SOCKS5 profiles and tunnels")
	fmt.Fprintln(w, "  net               Show or test Dashboard network detection")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Lifecycle shortcuts:")
	fmt.Fprintln(w, "  start             Alias for core start")
	fmt.Fprintln(w, "  stop              Alias for core stop; keep the backend available")
	fmt.Fprintln(w, "  restart           Alias for core restart")
	fmt.Fprintln(w, "  reload            Alias for core reload")
	fmt.Fprintln(w, "  status            Show backend, Core, profile, port, and frontend state")
	fmt.Fprintln(w, "  logs              Read or follow the managed backend log")
	fmt.Fprintln(w, "  backend           Manage the per-user Backend process")
	fmt.Fprintln(w, "  shutdown          Stop Backend and Core; disconnect all frontends")
	fmt.Fprintln(w, "  exit              Fully exit frontends, Backend, Core, and SSH tunnels")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Configuration and runtime:")
	fmt.Fprintln(w, "  profile           Import, select, update, rename, edit, or list profiles")
	fmt.Fprintln(w, "  proxy             List groups/nodes, select nodes, or run tests")
	fmt.Fprintln(w, "  config            Inspect, validate, edit, back up, or restore config")
	fmt.Fprintln(w, "  history           Show, follow, or clear recent connection history")
	fmt.Fprintln(w, "  connections       List or close active connections")
	fmt.Fprintln(w, "  geo               Inspect or update Mihomo Geo resources")
	fmt.Fprintln(w, "  env               Print the active proxy environment")
	fmt.Fprintln(w, "  doctor            Diagnose backend, Core, port, and configuration")
	fmt.Fprintln(w, "  completion        Generate shell completion scripts")
	fmt.Fprintln(w, "  check, validate   Validate a Clash/Mihomo YAML configuration")
	fmt.Fprintln(w, "  update, upgrade   Check and securely install a GitHub Release")
	fmt.Fprintln(w, "  exec              Compatibility alias for flc")
	fmt.Fprintln(w, "  run               Run the Core in the foreground (advanced)")
	fmt.Fprintln(w, "  version           Print the version")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Help:")
	fmt.Fprintln(w, "  flclash -help | --help | help")
	fmt.Fprintln(w, "  flclash COMMAND -help")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Unknown flclash commands are rejected. Use flc for external commands.")
}

func runCommand(args []string) error {
	if cliSubcommandHelp(args) {
		fmt.Println("Usage: flclash run [--config PATH] [--directory PATH]")
		fmt.Println("Run Core in the foreground. This advanced mode does not use the shared backend.")
		return nil
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configArg := fs.String("config", "", "path to config.yaml")
	directoryArg := fs.String("directory", "", "FlClash data directory")
	testURL := fs.String("test-url", "https://www.gstatic.com/generate_204", "URL used by proxy-group delay tests")
	if err := fs.Parse(args); err != nil {
		return err
	}

	paths, err := resolvePaths(*configArg, *directoryArg)
	if err != nil {
		return err
	}
	backendLock, err := acquireCLIBackendLock(cliProcessOwner{
		Kind:       "foreground",
		HomeDir:    paths.homeDir,
		ConfigPath: paths.configPath,
	})
	if err != nil {
		return err
	}
	defer backendLock.release()
	if _, err := startCore(paths, *testURL, "", ""); err != nil {
		return err
	}
	setupParams, err := json.Marshal(SetupParams{TestURL: *testURL, SelectedMap: map[string]string{}})
	if err != nil {
		return err
	}

	fmt.Printf("FlClash TUI is running\n")
	fmt.Printf("  config: %s\n", paths.configPath)
	fmt.Printf("  data:   %s\n", paths.homeDir)
	fmt.Println("Press Ctrl-C to stop.")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(interrupt)
	defer signal.Stop(reload)

	for {
		select {
		case <-interrupt:
			handleShutdown()
			return nil
		case <-reload:
			if message := handleSetupConfig(setupParams); message != "" {
				fmt.Fprintf(os.Stderr, "flclash: reload failed: %s\n", message)
			} else {
				fmt.Println("configuration reloaded")
			}
		}
	}
}

func checkCommand(args []string) error {
	if cliSubcommandHelp(args) {
		fmt.Println("Usage: flclash check --config PATH")
		fmt.Println("Validate a Clash/Mihomo YAML configuration without starting Core.")
		return nil
	}
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configArg := fs.String("config", "", "path to config.yaml")
	directoryArg := fs.String("directory", "", "directory used to resolve config.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths, err := resolvePaths(*configArg, *directoryArg)
	if err != nil {
		return err
	}
	if _, err := os.Stat(paths.configPath); err != nil {
		return fmt.Errorf("config file %q: %w", paths.configPath, err)
	}
	if message := handleValidateConfig(paths.configPath); message != "" {
		return errors.New(message)
	}
	fmt.Printf("configuration is valid: %s\n", paths.configPath)
	return nil
}

func resolvePaths(configArg, directoryArg string) (cliPaths, error) {
	var homeDir string
	var configPath string

	if directoryArg != "" {
		homeDir = directoryArg
		if configArg == "" {
			configArg = "config.yaml"
		}
		if !filepath.IsAbs(configArg) {
			configArg = filepath.Join(homeDir, configArg)
		}
	} else if configArg != "" {
		configPath = configArg
		homeDir = filepath.Dir(configArg)
	} else {
		configRoot, err := os.UserConfigDir()
		if err != nil {
			return cliPaths{}, fmt.Errorf("resolve user config directory: %w", err)
		}
		homeDir = filepath.Join(configRoot, "flclash")
		configPath = filepath.Join(homeDir, "config.yaml")
	}

	absoluteHome, err := filepath.Abs(homeDir)
	if err != nil {
		return cliPaths{}, err
	}
	if configPath == "" {
		configPath = configArg
	}
	absoluteConfig, err := filepath.Abs(configPath)
	if err != nil {
		return cliPaths{}, err
	}
	return cliPaths{homeDir: absoluteHome, configPath: absoluteConfig}, nil
}

func proxyCommand(args []string) error {
	if len(args) == 0 || cliSubcommandHelp(args) {
		fmt.Println("Usage: flclash proxy groups|nodes|select|delay|speed [OPTIONS]")
		fmt.Println("  groups [--json]                  List proxy groups")
		fmt.Println("  nodes GROUP [--json]             List nodes in a group")
		fmt.Println("  select GROUP NODE                Select a node")
		fmt.Println("  delay NODE [--test-url URL]      Test node delay")
		fmt.Println("  speed NODE                       Test node download speed")
		return nil
	}
	fs := flag.NewFlagSet("proxy "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	address := fs.String("controller", "", "Mihomo external controller address")
	secret := fs.String("secret", "", "Mihomo external controller secret")
	jsonOutput := fs.Bool("json", false, "print raw JSON")
	testURL := fs.String("test-url", defaultCLITestURL, "delay test URL")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	var client controllerClient
	var service *tuiServiceClient
	if *address != "" {
		client = controllerClient{options: controllerOptions{address: *address, secret: *secret}}
	} else {
		managedService, status, err := currentManagedService()
		if err != nil {
			return err
		}
		service = managedService
		client = managedController(status)
	}

	switch args[0] {
	case "list", "groups":
		if *jsonOutput {
			data, err := client.request(http.MethodGet, "/proxies", nil)
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(append(data, '\n'))
			return err
		}
		return client.listProxies()
	case "nodes":
		positional := fs.Args()
		if len(positional) != 1 {
			return errors.New("usage: flclash proxy nodes GROUP")
		}
		return client.listProxyNodes(positional[0], *jsonOutput)
	case "select":
		positional := fs.Args()
		if len(positional) != 2 {
			return errors.New("usage: flclash proxy select GROUP NODE")
		}
		if service == nil {
			return client.selectProxy(positional[0], positional[1])
		}
		status, err := service.status()
		if err != nil {
			return err
		}
		status, err = service.selectProxy(
			positional[0],
			positional[1],
			status.Revision,
		)
		if err != nil {
			return err
		}
		if strings.EqualFold(status.Mode, tuiSilentMode) {
			fmt.Printf(
				"selected %q in %q · flc follows %q (revision %d)\n",
				positional[1],
				positional[0],
				status.FLCOutbound,
				status.Revision,
			)
			return nil
		}
		fmt.Printf(
			"selected %q in %q (revision %d)\n",
			positional[1],
			positional[0],
			status.Revision,
		)
		return nil
	case "delay":
		positional := fs.Args()
		if len(positional) != 1 {
			return errors.New("usage: flclash proxy delay NODE")
		}
		delay, err := testTUIProxyDelaySamples(client, positional[0], *testURL)
		if err != nil {
			return err
		}
		fmt.Printf("%s: %s\n", positional[0], formatTUIDelay(delay))
		return nil
	case "speed":
		positional := fs.Args()
		if len(positional) != 1 {
			return errors.New("usage: flclash proxy speed NODE")
		}
		if service == nil {
			return errors.New("proxy speed requires the managed FlClash backend")
		}
		result, err := service.testProxySpeed(positional[0])
		if err != nil {
			return err
		}
		fmt.Printf("%s: %s\n", positional[0], formatTUISpeed(result))
		return nil
	default:
		return fmt.Errorf("unknown proxy command %q; use `flclash proxy -help`", args[0])
	}
}

func (c controllerClient) listProxyNodes(group string, jsonOutput bool) error {
	data, err := c.request(http.MethodGet, "/proxies", nil)
	if err != nil {
		return err
	}
	var response tuiProxyResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return err
	}
	proxy, ok := response.Proxies[group]
	if !ok || len(proxy.All) == 0 {
		return fmt.Errorf("proxy group %q was not found or has no nodes", group)
	}
	if jsonOutput {
		return writeCLIJSON(os.Stdout, map[string]any{
			"group": group,
			"now":   proxy.Now,
			"nodes": proxy.All,
		})
	}
	for _, node := range proxy.All {
		marker := " "
		if node == proxy.Now {
			marker = "*"
		}
		fmt.Printf("%s %s\n", marker, node)
	}
	return nil
}

func profileCommand(args []string) error {
	if len(args) == 0 || cliSubcommandHelp(args) {
		fmt.Println("Usage: flclash profile list|import|import-file|current|use|update|rename|edit|delete|link")
		fmt.Println("Import accepts Mihomo YAML, URI/Base64 lists, supported JSON, and common client proxy lines.")
		fmt.Println("Profile names resolve inside the active FlClash data directory.")
		return nil
	}
	command := args[0]
	fs := flag.NewFlagSet("profile "+command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configArg := fs.String("config", "", "profile YAML path")
	directoryArg := fs.String("directory", "", "FlClash data directory")
	jsonOutput := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	paths, err := resolvePaths(*configArg, *directoryArg)
	if err != nil {
		return err
	}
	if *configArg == "" && *directoryArg == "" {
		_, status, statusErr := currentManagedService()
		if statusErr == nil {
			paths.homeDir = status.HomeDir
			paths.configPath = status.ConfigPath
		} else if restored, restoreErr := restoreTUIActiveProfile(paths); restoreErr == nil {
			paths = restored
		}
	}
	positional := fs.Args()
	switch command {
	case "list":
		profiles, err := listCLIProfiles(paths)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return writeCLIJSON(os.Stdout, profiles)
		}
		for _, profile := range profiles {
			marker := " "
			if profile.Current {
				marker = "*"
			}
			kind := "local"
			if profile.SubscriptionURL != "" {
				kind = "subscription"
			}
			fmt.Printf("%s %-32s %s\n", marker, profile.Name, kind)
		}
		return nil
	case "current":
		fmt.Println(paths.configPath)
		return nil
	case "import":
		if len(positional) != 1 {
			return errors.New("usage: flclash profile import URL")
		}
		payload, err := fetchTUISubscriptionDetails(positional[0])
		if err != nil {
			return err
		}
		client, status, err := currentManagedService()
		if err != nil {
			return err
		}
		path, err := tuiSubscriptionImportPath(status.HomeDir, payload)
		if err != nil {
			return err
		}
		status, err = client.putProfile(
			path,
			payload.Data,
			"",
			true,
			&positional[0],
			status.Revision,
		)
		if err != nil {
			return err
		}
		fmt.Println(status.ResultPath)
		return nil
	case "import-file":
		if len(positional) != 1 {
			return errors.New("usage: flclash profile import-file PATH")
		}
		data, name, err := readTUILocalProfile(positional[0])
		if err != nil {
			appendCLIApplicationLog(paths.homeDir, "ERROR", "profile_import_file", "local profile validation failed")
			return err
		}
		client, status, err := currentManagedService()
		if err != nil {
			return err
		}
		path, err := nextTUIImportedProfilePath(status.HomeDir, name)
		if err != nil {
			return err
		}
		status, err = client.putProfile(
			path,
			data,
			"",
			true,
			nil,
			status.Revision,
		)
		if err != nil {
			return err
		}
		fmt.Println(status.ResultPath)
		return nil
	case "use":
		if len(positional) != 1 {
			return errors.New("usage: flclash profile use NAME")
		}
		target, err := resolveCLIProfile(paths.homeDir, positional[0])
		if err != nil {
			return err
		}
		client, status, err := currentManagedService()
		if err != nil {
			return err
		}
		status, err = client.reloadAtRevision(target, status.Revision)
		if err != nil {
			return err
		}
		fmt.Printf("Active profile: %s (revision %d)\n", filepath.Base(target), status.Revision)
		return nil
	case "update":
		target, err := cliProfileTarget(paths, positional)
		if err != nil {
			return err
		}
		sourceURL, err := loadTUISubscriptionSource(paths.homeDir, target)
		if err != nil {
			return err
		}
		previous, err := os.ReadFile(target)
		if err != nil {
			return err
		}
		updated, err := fetchTUISubscription(sourceURL)
		if err != nil {
			return err
		}
		if previousSettings := loadTUIConfiguredSettings(target, true); previousSettings != nil {
			updated, err = applyTUISettingsToConfig(updated, *previousSettings)
			if err != nil {
				return fmt.Errorf("preserve local settings: %w", err)
			}
		}
		client, status, err := currentManagedService()
		if err != nil {
			return err
		}
		if _, err := client.putProfile(
			target,
			updated,
			tuiBytesSHA256(previous),
			false,
			nil,
			status.Revision,
		); err != nil {
			return err
		}
		fmt.Printf("Updated %s\n", filepath.Base(target))
		return nil
	case "rename":
		if len(positional) != 2 {
			return errors.New("usage: flclash profile rename NAME NEW_NAME")
		}
		target, err := resolveCLIProfile(paths.homeDir, positional[0])
		if err != nil {
			return err
		}
		if filepath.Clean(target) == filepath.Clean(paths.configPath) {
			return errors.New("activate another profile before renaming the current profile")
		}
		client, status, err := currentManagedService()
		if err != nil {
			return err
		}
		status, err = client.renameProfile(target, positional[1], status.Revision)
		if err != nil {
			return err
		}
		fmt.Println(status.ResultPath)
		return nil
	case "edit":
		target, err := cliProfileTarget(paths, positional)
		if err != nil {
			return err
		}
		return editManagedConfig(target)
	case "delete":
		if len(positional) != 1 {
			return errors.New("usage: flclash profile delete NAME")
		}
		target, err := resolveCLIProfile(paths.homeDir, positional[0])
		if err != nil {
			return err
		}
		if filepath.Clean(target) == filepath.Clean(paths.configPath) {
			return errors.New("cannot delete the active profile")
		}
		client, status, err := currentManagedService()
		if err != nil {
			return err
		}
		if _, err := client.deleteProfile(target, status.Revision); err != nil {
			return err
		}
		fmt.Printf("Deleted %s\n", filepath.Base(target))
		return nil
	case "link":
		if len(positional) != 1 {
			return errors.New("usage: flclash profile link [--config PATH] URL")
		}
		if _, err := os.Stat(paths.configPath); err != nil {
			return err
		}
		sourceURL := positional[0]
		if _, err := newTUISubscriptionRequest(sourceURL); err != nil {
			return err
		}
		client, status, err := currentManagedService()
		if err != nil {
			return err
		}
		if _, err := client.linkProfile(
			paths.configPath,
			sourceURL,
			status.Revision,
		); err != nil {
			return err
		}
		fmt.Printf("Linked %s to its subscription source\n", filepath.Base(paths.configPath))
		return nil
	default:
		return fmt.Errorf("unknown profile command %q; use `flclash profile -help`", command)
	}
}

func listCLIProfiles(paths cliPaths) ([]tuiProfile, error) {
	entries, err := os.ReadDir(paths.homeDir)
	if err != nil {
		return nil, err
	}
	sources := loadTUISubscriptionSources(paths.homeDir)
	profiles := make([]tuiProfile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if isTUIRuntimeProfileName(entry.Name()) {
			continue
		}
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if extension != ".yaml" && extension != ".yml" {
			continue
		}
		path := filepath.Join(paths.homeDir, entry.Name())
		profiles = append(profiles, tuiProfile{
			Name:            entry.Name(),
			Path:            path,
			Current:         filepath.Clean(path) == filepath.Clean(paths.configPath),
			SubscriptionURL: sources[entry.Name()],
		})
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })
	return profiles, nil
}

func resolveCLIProfile(homeDir, value string) (string, error) {
	if value == "" {
		return "", errors.New("profile name must not be empty")
	}
	path := value
	if !filepath.IsAbs(path) {
		path = filepath.Join(homeDir, path)
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if _, err := tuiProfileStateKey(homeDir, path); err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("profile must be a regular file")
	}
	return path, nil
}

func cliProfileTarget(paths cliPaths, positional []string) (string, error) {
	if len(positional) == 0 {
		return paths.configPath, nil
	}
	if len(positional) != 1 {
		return "", errors.New("expected at most one profile name")
	}
	return resolveCLIProfile(paths.homeDir, positional[0])
}

type controllerClient struct {
	options controllerOptions
	client  *http.Client
}

func (c controllerClient) closeIdleConnections() {
	if c.client != nil {
		c.client.CloseIdleConnections()
	}
}

func (c controllerClient) httpClient() *http.Client {
	if c.client != nil {
		return c.client
	}
	if c.options.unixSocket != "" {
		return controllerHTTPClientForOptions(c.options, controllerRequestTimeout)
	}
	return controllerHTTPClient
}

func (c controllerClient) request(method, path string, body io.Reader) ([]byte, error) {
	return c.requestWithClient(c.httpClient(), method, path, body)
}

func (c controllerClient) requestWithTimeout(
	timeout time.Duration,
	method,
	path string,
	body io.Reader,
) ([]byte, error) {
	client := *c.httpClient()
	client.Timeout = timeout
	return c.requestWithClient(&client, method, path, body)
}

func (c controllerClient) requestWithClient(
	client *http.Client,
	method,
	path string,
	body io.Reader,
) ([]byte, error) {
	base := c.baseURL()
	req, err := http.NewRequest(method, strings.TrimRight(base, "/")+path, body)
	if err != nil {
		return nil, err
	}
	if c.options.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.options.secret)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("controller returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return data, nil
}

const controllerRequestTimeout = 5 * time.Second

var controllerHTTPClient = &http.Client{Timeout: controllerRequestTimeout}

func (c controllerClient) baseURL() string {
	if c.options.unixSocket != "" {
		return "http://unix"
	}
	base := c.options.address
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	return strings.TrimRight(base, "/")
}

func (c controllerClient) displayAddress() string {
	if c.options.unixSocket != "" {
		return "private Unix socket"
	}
	return c.options.address
}

func controllerHTTPClientForOptions(options controllerOptions, timeout time.Duration) *http.Client {
	if options.unixSocket == "" {
		return &http.Client{Timeout: timeout}
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: timeout}
			return dialer.DialContext(ctx, "unix", options.unixSocket)
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

func controllerDialAddress(address string) (string, bool) {
	base := address
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	return parsed.Host, true
}

func ensureControllerFree(address string) error {
	dialAddress, ok := controllerDialAddress(address)
	if !ok {
		return nil
	}
	connection, err := net.DialTimeout("tcp", dialAddress, 100*time.Millisecond)
	if err != nil {
		return nil
	}
	_ = connection.Close()
	return fmt.Errorf("controller address %q is already in use; use --no-start to connect to an existing core or choose another port", address)
}

func (c controllerClient) listProxies() error {
	data, err := c.request(http.MethodGet, "/proxies", nil)
	if err != nil {
		return err
	}
	var response struct {
		Proxies map[string]struct {
			Type string   `json:"type"`
			Now  string   `json:"now"`
			All  []string `json:"all"`
		} `json:"proxies"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return err
	}
	groups := make([]string, 0, len(response.Proxies))
	for name := range response.Proxies {
		groups = append(groups, name)
	}
	sort.Strings(groups)
	for _, name := range groups {
		proxy := response.Proxies[name]
		if len(proxy.All) == 0 {
			continue
		}
		fmt.Printf("%s (%s) -> %s\n", name, proxy.Type, proxy.Now)
		for _, item := range proxy.All {
			fmt.Printf("  - %s\n", item)
		}
	}
	return nil
}

func (c controllerClient) selectProxy(group, proxy string) error {
	if err := c.setProxy(group, proxy); err != nil {
		return err
	}
	fmt.Printf("selected %q in %q\n", proxy, group)
	return nil
}

func (c controllerClient) setProxy(group, proxy string) error {
	body, err := json.Marshal(map[string]string{"name": proxy})
	if err != nil {
		return err
	}
	path := "/proxies/" + url.PathEscape(group)
	if _, err := c.request(http.MethodPut, path, strings.NewReader(string(body))); err != nil {
		return err
	}
	return nil
}

func (c controllerClient) testProxyDelay(
	proxy,
	testURL string,
) (int, error) {
	query := url.Values{}
	query.Set("timeout", "5000")
	query.Set("url", testURL)
	path := "/proxies/" + url.PathEscape(proxy) + "/delay?" + query.Encode()
	data, err := c.requestWithTimeout(
		6*time.Second,
		http.MethodGet,
		path,
		nil,
	)
	if err != nil {
		return 0, err
	}
	var result struct {
		Delay int `json:"delay"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return 0, err
	}
	if result.Delay <= 0 {
		return 0, errors.New("delay test returned no usable result")
	}
	return result.Delay, nil
}

func (c controllerClient) closeAllConnections() error {
	_, err := c.request(http.MethodDelete, "/connections", nil)
	return err
}

func (c controllerClient) closeConnection(id string) error {
	_, err := c.request(http.MethodDelete, "/connections/"+url.PathEscape(id), nil)
	return err
}

func (c controllerClient) patchConfig(values map[string]interface{}) error {
	body, err := json.Marshal(values)
	if err != nil {
		return err
	}
	_, err = c.request(http.MethodPatch, "/configs", strings.NewReader(string(body)))
	return err
}

func (c controllerClient) reloadConfigPayload(data []byte) error {
	body, err := json.Marshal(map[string]string{"payload": string(data)})
	if err != nil {
		return err
	}
	_, err = c.request(
		http.MethodPut,
		"/configs?force=true",
		strings.NewReader(string(body)),
	)
	return err
}

func (c controllerClient) updateProvider(name string) error {
	path := "/providers/proxies/" + url.PathEscape(name)
	_, err := c.request(http.MethodPut, path, nil)
	return err
}

func (c controllerClient) updateGeo() error {
	_, err := c.request(http.MethodPost, "/configs/geo", nil)
	return err
}
