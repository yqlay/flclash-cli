//go:build linux && !cgo && cli

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	nethttp "net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/metacubex/mihomo/config"
	logrus "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	tuiRefreshInterval = 2 * time.Second
	tuiProgramFPS      = 15
)

const (
	tuiSubscriptionUserAgent = "mihomo"
	tuiSubscriptionMaxBytes  = 32 << 20
)

type tuiTickMsg time.Time

// tuiIdleTickPlan is the work a periodic tick may start. Public-IP / delay /
// speed probes are never part of a tick; they stay user- or event-triggered.
type tuiIdleTickPlan struct {
	RefreshSnapshot bool
	FetchHistory    bool
	FetchLogs       bool
	SampleMemory    bool
	PollSSH         bool
	CheckNetwork    bool
}

func tuiIdleTickPlanFor(page tuiPage) tuiIdleTickPlan {
	switch page {
	case tuiPageDashboard:
		return tuiIdleTickPlan{RefreshSnapshot: true, SampleMemory: true}
	case tuiPageProxies, tuiPageConnections:
		return tuiIdleTickPlan{RefreshSnapshot: true}
	case tuiPageRequests:
		return tuiIdleTickPlan{RefreshSnapshot: true, FetchHistory: true}
	case tuiPageLogs:
		return tuiIdleTickPlan{RefreshSnapshot: true, FetchLogs: true}
	case tuiPageSSH:
		return tuiIdleTickPlan{PollSSH: true}
	default:
		return tuiIdleTickPlan{}
	}
}

type tuiInterruptSignalMsg struct{}
type tuiTerminalExitSignalMsg struct{}

// tuiTerminalInput preserves the terminal file descriptor Bubble Tea needs
// for raw mode and cancellable reads while reporting EOF separately. Bubble
// Tea deliberately treats EOF as a completed input reader, not as a request
// to terminate the Program, which can otherwise leave a TUI alive after its
// PTY disappears.
type tuiTerminalInput struct {
	file        *os.File
	terminalEOF chan<- struct{}
	eofOnce     sync.Once
}

func newTUITerminalInput(
	file *os.File,
	terminalEOF chan<- struct{},
) *tuiTerminalInput {
	return &tuiTerminalInput{
		file:        file,
		terminalEOF: terminalEOF,
	}
}

func (input *tuiTerminalInput) Read(buffer []byte) (int, error) {
	count, err := input.file.Read(buffer)
	if errors.Is(err, io.EOF) {
		input.eofOnce.Do(func() {
			select {
			case input.terminalEOF <- struct{}{}:
			default:
			}
		})
	}
	return count, err
}

func (input *tuiTerminalInput) Write(buffer []byte) (int, error) {
	return input.file.Write(buffer)
}

func (input *tuiTerminalInput) Close() error {
	// Bubble Tea only requires this method to create its cancellable reader.
	// It must not close process-wide stdin during normal TUI cleanup.
	return nil
}

func (input *tuiTerminalInput) Fd() uintptr {
	return input.file.Fd()
}

func (input *tuiTerminalInput) Name() string {
	return input.file.Name()
}

type tuiServiceWatchMsg struct {
	status tuiServiceStatus
	err    error
}

type tuiShutdownResultMsg struct {
	err error
}

type tuiNetworkResultMsg struct {
	info  tuiNetworkInfo
	route string
}

type tuiMemoryResultMsg struct {
	info tuiMemoryInfo
}

type tuiCoreMemoryMsg struct {
	update tuiCoreMemoryUpdate
}

type tuiTrafficMsg struct {
	update tuiTrafficUpdate
}

type tuiRefreshResultMsg struct {
	sequence      uint64
	snapshot      tuiSnapshot
	serviceStatus *tuiServiceStatus
}

type tuiOperationState struct {
	snapshot           tuiSnapshot
	paths              cliPaths
	setupParams        []byte
	coreRunning        bool
	systemProxyManaged bool
	pendingMixedPort   *int
	stagedSettings     *tuiSettings
	settingsDirty      bool
	backendRevision    uint64
	profileSelection   string
	networkChanged     bool
}

type tuiOperationResultMsg struct {
	state tuiOperationState
}

type tuiProxyGroupSpeedResultMsg struct {
	groupName string
	node      string
	result    tuiSpeedResult
	remaining []string
	total     int
	successes int
}

type tuiEditorResultMsg struct {
	err error
}

type tuiSSHCommandResultMsg struct {
	action       string
	status       string
	selectedName string
	err          error
}

type tuiSSHCaptureResultMsg struct {
	generation uint64
	names      []string
	options    []string
	selected   int
}

type tuiSSHRelayStatsMsg struct {
	name  string
	stats cliSSHRelayStats
	at    time.Time
	err   error
}

type tuiSSHNetworkResultMsg struct {
	name   string
	direct bool
	info   tuiNetworkInfo
}

type tuiSSHDelayResultMsg struct {
	name   string
	direct bool
	result tuiDelayResult
	err    error
}

type tuiSSHSpeedResultMsg struct {
	name   string
	direct bool
	result tuiSpeedResult
	err    error
}

type tuiSSHDirectProbeResultMsg struct {
	name  string
	probe cliSSHRemoteProbe
	err   error
}

type tuiInputMode byte

const (
	tuiInputNone tuiInputMode = iota
	tuiInputMixedPort
	tuiInputSubscription
	tuiInputProfileFile
	tuiInputProfileName
	tuiInputHistorySearch
	tuiInputConnectionsSearch
	tuiInputLogsSearch
)

var tuiTrafficModes = []string{
	"rule",
	tuiSilentMode,
	"global",
	"direct",
}

type tuiModel struct {
	snapshot                 tuiSnapshot
	client                   controllerClient
	service                  *tuiServiceClient
	paths                    cliPaths
	setupParams              []byte
	ownsCore                 bool
	coreRunning              bool
	systemProxyManaged       bool
	width                    int
	height                   int
	refreshSequence          uint64
	refreshInFlight          bool
	refreshIncludesHistory   bool
	refreshIncludesLogs      bool
	lastIdleTick             tuiIdleTickPlan
	busy                     bool
	inputMode                tuiInputMode
	inputValue               []rune
	inputCursor              int
	inputSelectAll           bool
	modeSelectionOpen        bool
	selectedMode             int
	renameProfilePath        string
	editorPath               string
	editorTempPath           string
	editorBackup             tuiProfileBackup
	pendingMixedPort         *int
	stagedSettings           *tuiSettings
	settingsDirty            bool
	backendRevision          uint64
	networkCheckActive       bool
	memoryRefreshActive      bool
	coreMemoryUpdates        <-chan tuiCoreMemoryUpdate
	stopCoreMemory           func()
	trafficUpdates           <-chan tuiTrafficUpdate
	stopTraffic              func()
	stopServiceOnExit        bool // Legacy test visibility; managed frontends always leave this false.
	frontendExitRequested    bool
	shutdownRequested        bool
	notifications            []tuiNotification
	notificationDetailOpen   bool
	notificationSelected     int
	notificationScroll       int
	sshFormOpen              bool
	sshFormExisting          bool
	sshFormReadOnly          bool
	sshFormOriginalName      string
	sshFormFingerprint       string
	sshForm                  cliSSHProfile
	sshFormSelected          int
	sshFormFieldEditing      bool
	sshFormInput             []rune
	sshFormCursor            int
	sshFormSelectAll         bool
	sshFormAddingOption      bool
	sshFormPassphraseChanged bool
	sshFormPassphraseCleared bool
	sshFormPassphraseConfirm bool
	sshFormPassphraseFirst   string
	sshFormPasswordChanged   bool
	sshFormPasswordCleared   bool
	sshFormPasswordConfirm   bool
	sshFormPasswordFirst     string
	sshFormIdentityKind      cliSSHIdentityKind
	sshFormIdentityError     string
	sshDeleteConfirmOpen     bool
	sshDeleteName            string
	sshCredentialPromptOpen  bool
	sshCredentialProfile     string
	sshCredentialIdentity    string
	sshCredentialInput       []rune
	sshCaptureOpen           bool
	sshCaptureGeneration     uint64
	sshCaptureNames          []string
	sshCaptureOptions        []string
	sshCaptureSelected       int
	sshLastStats             cliSSHRelayStats
	sshLastStatsAt           time.Time
	sshLastStatsName         string
	profileDeleteOpen        bool
	profileDeletePath        string
	profileDeleteName        string
	profileDeleteKind        string
	dangerConfirmOpen        bool
	dangerConfirmTitle       string
	dangerConfirmMessage     string
	dangerConfirmKey         tuiKey
	dangerConfirmTarget      string
	dangerConfirmed          bool
}

func newTUIModel(
	client controllerClient,
	paths cliPaths,
	setupParams []byte,
	ownsCore bool,
) *tuiModel {
	width, height := tuiTerminalSize()
	stagedSettings := loadTUIConfiguredSettings(paths.configPath, ownsCore)
	settings := tuiSettings{}
	var pendingMixedPort *int
	if stagedSettings != nil {
		settings = *stagedSettings
		port := settings.MixedPort
		pendingMixedPort = &port
	}
	return &tuiModel{
		snapshot: tuiSnapshot{
			Status:            "Loading...",
			GroupOrder:        loadTUIProxyGroupOrder(paths.configPath),
			Settings:          settings,
			SelectedGroup:     0,
			SelectedNode:      0,
			SelectedRow:       tuiProfileImportSubscriptionRow,
			SelectedMenu:      int(tuiPageDashboard),
			SelectedDashboard: tuiDashboardServiceRow,
			FocusSidebar:      true,
		},
		client:           client,
		paths:            paths,
		setupParams:      append([]byte(nil), setupParams...),
		ownsCore:         ownsCore,
		coreRunning:      false,
		width:            width,
		height:           height,
		pendingMixedPort: pendingMixedPort,
		stagedSettings:   stagedSettings,
	}
}

func loadTUIConfiguredSettings(path string, ownsCore bool) *tuiSettings {
	if !ownsCore {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	rawConfig, err := config.UnmarshalRawConfig(data)
	if err != nil {
		return nil
	}
	return &tuiSettings{
		Mode:          rawConfig.Mode.String(),
		MixedPort:     rawConfig.MixedPort,
		AllowLAN:      rawConfig.AllowLan,
		IPv6:          rawConfig.IPv6,
		UnifiedDelay:  rawConfig.UnifiedDelay,
		TCPConcurrent: rawConfig.TCPConcurrent,
		LogLevel:      rawConfig.LogLevel.String(),
		TunEnabled:    rawConfig.Tun.Enable,
	}
}

func runTUI(
	client controllerClient,
	paths cliPaths,
	setupParams []byte,
	ownsCore bool,
	service *tuiServiceClient,
	coreRunning bool,
	startupNotice string,
	interrupt <-chan os.Signal,
) error {
	if !isInteractiveTUI() {
		return errors.New("TUI requires an interactive terminal; use run or proxy commands in non-interactive shells")
	}

	logrus.SetOutput(io.Discard)
	handleStartLog()
	defer handleStopLog()

	model := newTUIModel(client, paths, setupParams, ownsCore)
	model.service = service
	if service != nil {
		if status, statusErr := service.status(); statusErr == nil {
			model.backendRevision = status.Revision
			model.snapshot.Settings.SystemProxy = status.SystemProxy
			model.snapshot.Settings.Mode = status.Mode
			model.snapshot.Settings.MixedPort = status.ConfiguredProxyPort
			model.snapshot.ConfiguredProxyPort = status.ConfiguredProxyPort
			model.snapshot.ActiveProxyPort = status.ActiveProxyPort
			model.snapshot.Settings.TunEnabled = status.TunState == "on"
			model.snapshot.Settings.TunScope = status.TunScope
			if status.Mode == tuiSilentMode {
				model.snapshot.Settings.TunEnabled = false
			}
			model.snapshot.FLCEnabled = status.FLCEnabled
			model.snapshot.FLCOutbound = status.FLCOutbound
		}
	}
	model.initializeCoreRuntime(coreRunning)
	model.snapshot.ManagedService = service != nil
	model.snapshot.Frontends, _ = listCLIFrontends()
	if startupNotice != "" {
		model.enqueueNotification(tuiNotification{
			level:   tuiNotificationInfo,
			title:   "Shared backend",
			message: startupNotice,
		})
	}
	defer model.stopCoreMemoryMonitor()
	defer model.stopTrafficMonitor()
	terminalEOF := make(chan struct{}, 1)
	programOptions := append(
		tuiProgramOptions(),
		tea.WithInput(newTUITerminalInput(os.Stdin, terminalEOF)),
	)
	program := tea.NewProgram(model, programOptions...)
	terminalExit := make(chan os.Signal, 1)
	signal.Notify(terminalExit, syscall.SIGHUP, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-interrupt:
				program.Send(tuiInterruptSignalMsg{})
			case <-terminalExit:
				program.Send(tuiTerminalExitSignalMsg{})
			case <-terminalEOF:
				program.Send(tuiTerminalExitSignalMsg{})
			case <-done:
				return
			}
		}
	}()

	_, runErr := program.Run()
	close(done)
	signal.Stop(terminalExit)
	model.shutdown()
	logrus.SetOutput(os.Stdout)
	if runErr != nil && !errors.Is(runErr, tea.ErrProgramKilled) {
		return fmt.Errorf("run TUI: %w", runErr)
	}
	return nil
}

func (m *tuiModel) initializeCoreRuntime(coreRunning bool) {
	m.coreRunning = coreRunning
	if !coreRunning {
		m.reconcileStoppedCoreState()
		return
	}
	m.pendingMixedPort = nil
	m.stagedSettings = nil
	m.settingsDirty = false
	m.snapshot.Settings = tuiSettings{}
}

// reconcileStoppedCoreState prevents a stopped Core from leaving stale active
// connections or ACTIVE History rows on screen while an asynchronous refresh
// is pending. Persistent History remains available, but every entry is closed.
func (m *tuiModel) reconcileStoppedCoreState() {
	if m.coreRunning {
		return
	}
	m.snapshot.Connections = nil
	m.snapshot.SelectedConnection = -1
	m.snapshot.ConnectionsDetailOpen = false
	m.snapshot.Requests, _ = markTUIRequestHistoryInactive(m.snapshot.Requests)
}

func tuiProgramOptions() []tea.ProgramOption {
	return []tea.ProgramOption{
		tea.WithAltScreen(),
		tea.WithFPS(tuiProgramFPS),
		tea.WithoutSignalHandler(),
	}
}

func tuiPageShowsLiveCoreStats(page tuiPage) bool {
	return page == tuiPageDashboard
}

func (m *tuiModel) syncLiveMonitors() []tea.Cmd {
	if !tuiPageShowsLiveCoreStats(m.snapshot.Page) {
		m.stopTrafficMonitor()
		m.stopCoreMemoryMonitor()
		return nil
	}
	startedTraffic := m.stopTraffic == nil
	startedMemory := m.stopCoreMemory == nil
	m.startTrafficMonitor()
	m.startCoreMemoryMonitor()
	var cmds []tea.Cmd
	if startedTraffic && m.stopTraffic != nil {
		cmds = append(cmds, m.waitTrafficUpdate())
	}
	if startedMemory && m.stopCoreMemory != nil {
		cmds = append(cmds, m.waitCoreMemoryUpdate())
	}
	return cmds
}

func (m *tuiModel) changeVisiblePage(page tuiPage) []tea.Cmd {
	m.snapshot.Page = page
	return m.syncLiveMonitors()
}

func (m *tuiModel) Init() tea.Cmd {
	cmds := []tea.Cmd{
		tuiTickCommand(),
		m.startRefresh(),
		m.startNetworkCheck(),
		m.startMemoryRefresh(),
		m.waitServiceUpdate(),
	}
	cmds = append(cmds, m.syncLiveMonitors()...)
	return tea.Batch(cmds...)
}

func (m *tuiModel) update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width = message.Width
		m.height = message.Height
		return m, nil
	case tuiTickMsg:
		return m, m.idleTickCommand()
	case tuiInterruptSignalMsg:
		return m, m.handleKey(tuiKeyInterrupt)
	case tuiTerminalExitSignalMsg:
		return m, m.handleKey(tuiKeyQuit)
	case tuiServiceWatchMsg:
		if message.err != nil {
			m.snapshot.Status = "Backend watch interrupted: " + message.err.Error()
			retry := m.waitServiceUpdate()
			return m, tea.Tick(time.Second, func(time.Time) tea.Msg {
				if retry == nil {
					return tuiServiceWatchMsg{}
				}
				return retry()
			})
		}
		if message.status.ShuttingDown {
			m.snapshot.Status = "Backend is shutting down"
			return m, tea.Quit
		}
		m.backendRevision = message.status.Revision
		m.coreRunning = message.status.Running
		m.reconcileStoppedCoreState()
		m.snapshot.Settings.SystemProxy = message.status.SystemProxy
		m.snapshot.Settings.Mode = message.status.Mode
		m.snapshot.Settings.MixedPort = message.status.ConfiguredProxyPort
		m.snapshot.ConfiguredProxyPort = message.status.ConfiguredProxyPort
		m.snapshot.ActiveProxyPort = message.status.ActiveProxyPort
		m.snapshot.Settings.TunEnabled = message.status.TunState == "on"
		m.snapshot.Settings.TunScope = message.status.TunScope
		if message.status.Mode == tuiSilentMode {
			m.snapshot.Settings.TunEnabled = false
		}
		m.snapshot.FLCEnabled = message.status.FLCEnabled
		m.snapshot.FLCOutbound = message.status.FLCOutbound
		m.refreshInFlight = false
		return m, tea.Batch(m.startRefresh(), m.waitServiceUpdate())
	case tuiShutdownResultMsg:
		if message.err != nil {
			m.shutdownRequested = false
			m.snapshot.Status = "Backend shutdown failed: " + message.err.Error()
			return m, nil
		}
		m.snapshot.Status = "Backend stopped"
		return m, tea.Quit
	case tuiNetworkResultMsg:
		m.networkCheckActive = false
		if message.route != m.networkCheckRoute() {
			return m, m.startNetworkCheck()
		}
		m.snapshot.Network = message.info
		if message.info.Error != "" {
			m.snapshot.Status = "Network detection failed: " + message.info.Error
		} else if strings.HasPrefix(m.snapshot.Status, "Network detection failed: ") {
			m.snapshot.Status = "Connected"
		}
		return m, nil
	case tuiMemoryResultMsg:
		m.memoryRefreshActive = false
		if m.snapshot.Memory.CoreUpdated.After(message.info.CoreUpdated) {
			message.info.CoreRSS = m.snapshot.Memory.CoreRSS
			message.info.CoreError = m.snapshot.Memory.CoreError
			message.info.CoreUpdated = m.snapshot.Memory.CoreUpdated
		}
		m.snapshot.Memory = message.info
		return m, nil
	case tuiCoreMemoryMsg:
		if message.update.Closed {
			return m, nil
		}
		m.snapshot.Memory.ExternalCore = !m.ownsCore
		if message.update.RSS > 0 {
			m.snapshot.Memory.CoreRSS = message.update.RSS
			m.snapshot.Memory.CoreError = ""
		}
		if message.update.Error != "" {
			m.snapshot.Memory.CoreError = message.update.Error
		}
		m.snapshot.Memory.CoreUpdated = message.update.UpdatedAt
		return m, m.waitCoreMemoryUpdate()
	case tuiTrafficMsg:
		if message.update.Closed {
			return m, nil
		}
		m.snapshot.Traffic = message.update.Traffic
		m.snapshot.TrafficHistory = appendTUITrafficHistory(
			m.snapshot.TrafficHistory,
			message.update.Traffic,
		)
		m.snapshot.TotalTraffic = trafficSnapshot{
			Up:   message.update.Traffic.UpTotal,
			Down: message.update.Traffic.DownTotal,
		}
		return m, m.waitTrafficUpdate()
	case tuiSSHCaptureResultMsg:
		if !m.sshCaptureOpen || message.generation != m.sshCaptureGeneration {
			return m, nil
		}
		m.sshCaptureNames = message.names
		m.sshCaptureOptions = message.options
		m.sshCaptureSelected = message.selected
		if len(message.options) == 0 {
			m.sshCaptureOptions = []string{"No live ControlMaster matches a FlClash SSH profile"}
		}
		return m, nil
	case tuiSSHRelayStatsMsg:
		if m.selectedSSHName() != message.name {
			return m, nil
		}
		if message.err != nil {
			m.snapshot.SSHTraffic = trafficSnapshot{}
			m.snapshot.SSHConnections = 0
			return m, nil
		}
		elapsed := message.at.Sub(m.sshLastStatsAt).Seconds()
		traffic := trafficSnapshot{
			UpTotal:   message.stats.Upload,
			DownTotal: message.stats.Download,
		}
		if m.sshLastStatsName == message.name && elapsed > 0 {
			traffic.Up = maxTUIInt64(0, int64(float64(message.stats.Upload-m.sshLastStats.Upload)/elapsed))
			traffic.Down = maxTUIInt64(0, int64(float64(message.stats.Download-m.sshLastStats.Download)/elapsed))
		}
		m.sshLastStats = message.stats
		m.sshLastStatsAt = message.at
		m.sshLastStatsName = message.name
		m.snapshot.SSHTraffic = traffic
		m.snapshot.SSHTotalTraffic = trafficSnapshot{Up: message.stats.Upload, Down: message.stats.Download}
		m.snapshot.SSHConnections = message.stats.Connections
		m.snapshot.SSHTrafficHistory = appendTUITrafficHistory(m.snapshot.SSHTrafficHistory, traffic)
		return m, nil
	case tuiSSHNetworkResultMsg:
		if m.selectedSSHName() == message.name {
			if message.direct {
				m.snapshot.SSHDirectNetwork = message.info
			} else {
				m.snapshot.SSHNetwork = message.info
			}
			if message.info.Error != "" {
				prefix := "SSH network detection"
				if message.direct {
					prefix = "SSH direct network detection"
				}
				m.snapshot.Status = prefix + " failed: " + message.info.Error
			} else {
				if message.direct {
					m.snapshot.Status = "SSH direct exit network refreshed"
				} else {
					m.snapshot.Status = "SSH managed exit network refreshed"
				}
			}
		}
		return m, nil
	case tuiSSHDirectProbeResultMsg:
		if m.selectedSSHName() != message.name {
			return m, nil
		}
		if message.err != nil {
			m.snapshot.SSHDirectProbe = cliSSHRemoteProbe{Reason: message.err.Error()}
			m.snapshot.SSHDirectNetwork = tuiNetworkInfo{Error: message.err.Error(), CheckedAt: time.Now()}
			m.snapshot.Status = "SSH direct exit unavailable: " + message.err.Error()
			return m, nil
		}
		m.snapshot.SSHDirectProbe = message.probe
		if !message.probe.DirectAllowed {
			reason := cliDisplayValue(message.probe.Reason)
			m.snapshot.SSHDirectNetwork = tuiNetworkInfo{Error: reason, CheckedAt: time.Now()}
			m.snapshot.Status = "SSH direct exit unavailable: " + reason
			return m, nil
		}
		m.snapshot.Status = "SSH direct exit verified · testing its network path"
		return m, m.refreshSelectedSSHNetworkFor(true)
	case tuiSSHDelayResultMsg:
		if m.selectedSSHName() == message.name {
			if message.err != nil {
				if message.direct {
					m.snapshot.SSHDirectDelay = tuiDelayResult{Error: message.err.Error()}
					m.snapshot.Status = "SSH direct route delay failed: " + message.err.Error()
				} else {
					m.snapshot.SSHDelay = tuiDelayResult{Error: message.err.Error()}
					m.snapshot.Status = "SSH managed route delay failed: " + message.err.Error()
				}
			} else {
				if message.direct {
					m.snapshot.SSHDirectDelay = message.result
					m.snapshot.Status = "SSH direct route delay: " + formatTUIDelay(message.result)
				} else {
					m.snapshot.SSHDelay = message.result
					m.snapshot.Status = "SSH managed route delay: " + formatTUIDelay(message.result)
				}
			}
		}
		return m, nil
	case tuiSSHSpeedResultMsg:
		if m.selectedSSHName() == message.name {
			if message.err != nil {
				if message.direct {
					m.snapshot.SSHDirectSpeed = tuiSpeedResult{Error: message.err.Error()}
					m.snapshot.Status = "SSH direct route speed failed: " + message.err.Error()
				} else {
					m.snapshot.SSHSpeed = tuiSpeedResult{Error: message.err.Error()}
					m.snapshot.Status = "SSH managed route speed failed: " + message.err.Error()
				}
			} else {
				if message.direct {
					m.snapshot.SSHDirectSpeed = message.result
					m.snapshot.Status = "SSH direct route speed: " + formatTUISpeed(message.result)
				} else {
					m.snapshot.SSHSpeed = message.result
					m.snapshot.Status = "SSH managed route speed: " + formatTUISpeed(message.result)
				}
			}
		}
		return m, nil
	case tuiRefreshResultMsg:
		if message.sequence != m.refreshSequence {
			return m, nil
		}
		m.refreshInFlight = false
		m.snapshot = mergeTUIRefresh(m.snapshot, message.snapshot)
		if message.serviceStatus != nil {
			m.backendRevision = message.serviceStatus.Revision
			m.coreRunning = message.serviceStatus.Running
			m.reconcileStoppedCoreState()
			m.snapshot.Settings.SystemProxy = message.serviceStatus.SystemProxy
			m.snapshot.Settings.Mode = message.serviceStatus.Mode
			m.snapshot.Settings.MixedPort = message.serviceStatus.ConfiguredProxyPort
			m.snapshot.ConfiguredProxyPort = message.serviceStatus.ConfiguredProxyPort
			m.snapshot.ActiveProxyPort = message.serviceStatus.ActiveProxyPort
			m.snapshot.Settings.TunEnabled = message.serviceStatus.TunState == "on"
			m.snapshot.Settings.TunScope = message.serviceStatus.TunScope
			if message.serviceStatus.Mode == tuiSilentMode {
				m.snapshot.Settings.TunEnabled = false
			}
			m.snapshot.FLCEnabled = message.serviceStatus.FLCEnabled
			m.snapshot.FLCOutbound = message.serviceStatus.FLCOutbound
		}
		if !m.coreRunning && m.stagedSettings != nil {
			systemProxy := m.snapshot.Settings.SystemProxy
			m.snapshot.Settings = *m.stagedSettings
			m.snapshot.Settings.SystemProxy = systemProxy
			if message.serviceStatus != nil {
				m.snapshot.Settings.Mode = message.serviceStatus.Mode
				m.snapshot.Settings.TunEnabled =
					message.serviceStatus.TunState == "on"
				m.snapshot.Settings.TunScope = message.serviceStatus.TunScope
				if message.serviceStatus.Mode == tuiSilentMode {
					m.snapshot.Settings.TunEnabled = false
				}
			}
		}
		if m.ownsCore && !m.coreRunning && m.snapshot.Status == "Connected" {
			m.snapshot.Status = "Ready; start Core or enable System proxy on Dashboard"
		}
		return m, nil
	case tuiOperationResultMsg:
		previousRoute := m.networkCheckRoute()
		m.busy = false
		m.snapshot = mergeTUIOperation(m.snapshot, message.state.snapshot)
		m.paths = message.state.paths
		m.setupParams = append(m.setupParams[:0], message.state.setupParams...)
		m.coreRunning = message.state.coreRunning
		m.reconcileStoppedCoreState()
		m.systemProxyManaged = message.state.systemProxyManaged
		m.pendingMixedPort = cloneTUIOptionalInt(message.state.pendingMixedPort)
		m.stagedSettings = cloneTUISettings(message.state.stagedSettings)
		m.settingsDirty = message.state.settingsDirty
		m.backendRevision = message.state.backendRevision
		if message.state.profileSelection != "" {
			m.snapshot.SelectedRow = findTUIProfile(
				m.snapshot.Profiles,
				message.state.profileSelection,
			)
		}
		commands := []tea.Cmd{m.startRefresh()}
		if message.state.networkChanged ||
			m.networkCheckRoute() != previousRoute {
			commands = append(commands, m.startNetworkCheck())
		}
		return m, tea.Batch(commands...)
	case tuiProxyGroupSpeedResultMsg:
		if message.result.Error == "" {
			message.successes++
		}
		setTUIGroupSpeed(
			&m.snapshot,
			message.groupName,
			message.node,
			message.result,
		)
		completed := message.total - len(message.remaining)
		if len(message.remaining) > 0 {
			m.snapshot.Status = fmt.Sprintf(
				"%s speed tests: %d/%d complete · testing %s next",
				message.groupName,
				completed,
				message.total,
				message.remaining[0],
			)
			return m, m.testNextProxyGroupSpeed(
				message.groupName,
				message.remaining,
				message.total,
				message.successes,
			)
		}
		m.busy = false
		m.snapshot.Status = fmt.Sprintf(
			"%s speed tests complete: %d/%d succeeded",
			message.groupName,
			message.successes,
			message.total,
		)
		return m, m.startRefresh()
	case tuiEditorResultMsg:
		m.busy = false
		editorPath := m.editorPath
		editorTempPath := m.editorTempPath
		editorBackup := m.editorBackup
		m.editorPath = ""
		m.editorTempPath = ""
		m.editorBackup = tuiProfileBackup{}
		defer os.Remove(editorTempPath)
		if message.err != nil {
			m.snapshot.Status = "Editor failed: " + message.err.Error()
			return m, nil
		}
		edited, readErr := os.ReadFile(editorTempPath)
		if readErr != nil {
			m.snapshot.Status = "Edited configuration could not be read: " + readErr.Error()
			return m, nil
		}
		if validationMessage := validateConfigBytes(edited); validationMessage != "" {
			m.snapshot.Status = "Edited configuration is invalid: " + validationMessage
			return m, nil
		}
		return m, m.startOperation(func(state *tuiOperationState) {
			if !prepareTUIBackendRevision(state, m.service) {
				return
			}
			status, err := m.service.putProfile(
				editorPath,
				edited,
				tuiBytesSHA256(editorBackup.data),
				false,
				nil,
				state.backendRevision,
			)
			if err != nil {
				state.snapshot.Status = "Edited configuration was not committed: " + err.Error()
				return
			}
			applyTUIOperationServiceStatus(state, status)
			if filepath.Clean(editorPath) == filepath.Clean(state.paths.configPath) {
				state.snapshot.Status = "Configuration saved and hot-reloaded"
				syncStoppedTUISettings(state)
				state.networkChanged = true
			} else {
				state.snapshot.Status = "Configuration saved: " + filepath.Base(editorPath) +
					" · activate it to apply"
			}
			refreshTUIProfiles(&state.snapshot, state.paths)
		})
	case tuiSSHCommandResultMsg:
		m.busy = false
		var credentialRequired *cliSSHCredentialRequiredError
		if message.action == "connect" && errors.As(message.err, &credentialRequired) {
			m.beginSSHCredentialPrompt(
				credentialRequired.Profile,
				credentialRequired.Identity,
			)
			return m, nil
		}
		if message.err == nil && (message.action == "add" || message.action == "edit") {
			m.resetSSHForm()
		}
		refreshTUISSH(&m.snapshot)
		if message.selectedName != "" {
			for index, profile := range m.snapshot.SSHProfiles {
				if strings.EqualFold(profile.Name, message.selectedName) {
					m.snapshot.SelectedSSH = index
					break
				}
			}
		}
		if message.err != nil {
			m.snapshot.Status = "SSH " + message.action + " failed: " + message.err.Error()
		} else if message.status != "" {
			m.snapshot.Status = message.status
		} else {
			m.snapshot.Status = "SSH " + message.action + " complete"
		}
		commands := []tea.Cmd{m.startRefresh()}
		if message.err == nil {
			switch message.action {
			case "connect":
				m.resetSelectedSSHMetrics()
				commands = append(commands, m.refreshSelectedSSHDashboard())
			case "disconnect":
				m.resetSelectedSSHMetrics()
			}
		}
		return m, tea.Batch(commands...)
	case tea.KeyMsg:
		if message.String() == "ctrl+n" || m.notificationDetailOpen {
			return m, m.handleTeaKey(message)
		}
		if m.profileDeleteOpen {
			return m, m.handleProfileDeleteConfirm(message)
		}
		if m.dangerConfirmOpen {
			return m, m.handleDangerConfirm(message)
		}
		if m.inputMode != tuiInputNone {
			return m, m.handleInput(message)
		}
		if m.sshCredentialPromptOpen {
			return m, m.handleSSHCredentialPrompt(message)
		}
		if m.sshDeleteConfirmOpen {
			return m, m.handleSSHDeleteConfirm(message)
		}
		if m.sshFormOpen {
			return m, m.handleSSHForm(message)
		}
		if m.sshCaptureOpen {
			return m, m.handleSSHCapture(message)
		}
		if m.modeSelectionOpen {
			return m, m.handleModeSelection(message)
		}
		if message.Type == tea.KeyRunes && len(message.Runes) > 1 && !message.Paste {
			commands := make([]tea.Cmd, 0, len(message.Runes))
			for _, value := range message.Runes {
				command := m.handleTeaKey(tea.KeyMsg{
					Type:  tea.KeyRunes,
					Runes: []rune{value},
				})
				if command != nil {
					commands = append(commands, command)
				}
			}
			return m, tea.Batch(commands...)
		}
		return m, m.handleTeaKey(message)
	default:
		return m, nil
	}
}

func (m *tuiModel) handleTeaKey(message tea.KeyMsg) tea.Cmd {
	key, ok := tuiKeyFromTea(message)
	if !ok {
		return nil
	}
	if message.String() == "v" &&
		(m.snapshot.Page == tuiPageDashboard ||
			m.snapshot.Page == tuiPageProxies ||
			m.snapshot.Page == tuiPageSSH && m.snapshot.SSHDashboardFocus) {
		key = tuiKeySpeedTest
	}
	if key == tuiKeyNotifications {
		m.toggleNotificationDetails()
		return nil
	}
	if m.notificationDetailOpen &&
		key != tuiKeyQuit &&
		key != tuiKeyInterrupt {
		m.handleNotificationDetailKey(key)
		return nil
	}
	if m.snapshot.ShowHelp &&
		key != tuiKeyHelp &&
		key != tuiKeyQuit &&
		key != tuiKeyInterrupt {
		m.snapshot.ShowHelp = false
		return nil
	}
	previousPage := m.snapshot.Page
	if handleTUIFocusNavigation(&m.snapshot, key) {
		var cmds []tea.Cmd
		if previousPage != tuiPageSSH && m.snapshot.Page == tuiPageSSH {
			m.resetSelectedSSHMetrics()
			cmds = append(cmds, m.refreshSelectedSSHDashboard())
		}
		if previousPage != m.snapshot.Page {
			m.refreshInFlight = false
			cmds = append(cmds, m.syncLiveMonitors()...)
			cmds = append(cmds, m.startRefresh())
		}
		return tea.Batch(cmds...)
	}
	if m.busy && !tuiKeyAllowedWhileBusy(key) {
		m.snapshot.Status = "Operation in progress; navigation remains available"
		return nil
	}
	return m.handleKey(key)
}

func tuiKeyAllowedWhileBusy(key tuiKey) bool {
	switch key {
	case tuiKeyQuit,
		tuiKeyInterrupt,
		tuiKeyNotifications,
		tuiKeyHelp,
		tuiKeyBack,
		tuiKeyUp,
		tuiKeyDown,
		tuiKeyLeft,
		tuiKeyRight,
		tuiKeyViewPrevious,
		tuiKeyViewNext,
		tuiKeyPageUp,
		tuiKeyPageDown:
		return true
	default:
		return false
	}
}

func (m *tuiModel) View() string {
	snapshot := m.snapshot
	snapshot.DangerConfirmOpen = m.dangerConfirmOpen
	snapshot.DangerConfirmTitle = m.dangerConfirmTitle
	snapshot.DangerConfirmMessage = m.dangerConfirmMessage
	snapshot.SSHForm = m.sshFormView()
	snapshot.SSHCredentialPrompt = tuiSSHCredentialPromptView{
		Open:     m.sshCredentialPromptOpen,
		Profile:  m.sshCredentialProfile,
		Identity: m.sshCredentialIdentity,
		Value:    strings.Repeat("•", len(m.sshCredentialInput)),
	}
	snapshot.ProfileDelete = tuiProfileDeleteView{
		Open: m.profileDeleteOpen,
		Name: m.profileDeleteName,
		Kind: m.profileDeleteKind,
	}
	snapshot.Notifications = append(
		[]tuiNotification(nil),
		m.notifications...,
	)
	snapshot.NotificationDetailOpen = m.notificationDetailOpen
	snapshot.NotificationSelected = m.notificationSelected
	snapshot.NotificationScroll = m.notificationScroll
	if m.notificationDetailOpen {
		snapshot.Status = "Notifications · ↑↓ select · PgUp/PgDn scroll · Enter confirm · Esc close"
	} else if m.sshCaptureOpen {
		snapshot.SelectionTitle = "Capture existing SSH"
		snapshot.SelectionOptions = append([]string(nil), m.sshCaptureOptions...)
		snapshot.SelectedOption = m.sshCaptureSelected
		snapshot.SelectionHint = "Reuses a live OpenSSH ControlMaster for SOCKS reverse proxy. Does not start a second login. Ordinary interactive ssh cannot be captured."
		snapshot.Status = "Capture existing SSH · ↑↓/ws choose · Enter attach · Esc cancel"
	} else if m.modeSelectionOpen {
		snapshot.SelectionTitle = "Select outbound mode"
		snapshot.SelectionOptions = append(
			[]string(nil),
			tuiTrafficModes...,
		)
		snapshot.SelectedOption = m.selectedMode
		snapshot.SelectionHint = "rule uses routing rules · silent proxies only flc commands · global proxies all traffic · direct bypasses proxies"
		snapshot.Status = "Selecting mode · ↑↓/ws choose · Enter confirm · Esc cancel"
	} else if m.inputMode != tuiInputNone {
		cursor := m.inputCursor
		if cursor < 0 {
			cursor = 0
		}
		if cursor > len(m.inputValue) {
			cursor = len(m.inputValue)
		}
		snapshot.InputTitle, snapshot.InputHint = m.inputPresentation()
		snapshot.InputValue = tuiInputViewport(
			m.inputValue,
			cursor,
			maxTUIWidth(m.width-36, 20),
		)
		snapshot.Status = "Editing input · Enter confirm · Esc cancel"
	}
	return renderTUIAtSize(
		snapshot,
		m.paths,
		m.client.displayAddress(),
		m.ownsCore,
		m.coreRunning,
		m.width,
		m.height,
	)
}

func (m *tuiModel) sshFormView() tuiSSHFormView {
	profile := normalizeCLISSHProfile(m.sshForm)
	view := tuiSSHFormView{
		Open:              m.sshFormOpen,
		Existing:          m.sshFormExisting,
		ReadOnly:          m.sshFormReadOnly,
		Name:              profile.Name,
		Username:          profile.Username,
		Host:              profile.Host,
		Destination:       profile.Destination,
		Jump:              profile.Jump,
		Port:              m.sshForm.Port,
		LocalPort:         m.sshForm.LocalPort,
		Identity:          m.sshForm.Identity,
		IdentityKind:      m.sshFormIdentityKind,
		IdentityError:     m.sshFormIdentityError,
		PassphraseSet:     m.sshForm.IdentityPassphrase != "",
		PassphraseChanged: m.sshFormPassphraseChanged,
		PassphraseCleared: m.sshFormPassphraseCleared,
		PasswordSet:       m.sshForm.Password != "",
		PasswordChanged:   m.sshFormPasswordChanged,
		PasswordCleared:   m.sshFormPasswordCleared,
		Options:           append([]string(nil), m.sshForm.Options...),
		Selected:          m.sshFormSelected,
		FieldEditing:      m.sshFormFieldEditing,
		PassphraseConfirm: m.sshFormPassphraseConfirm,
		PasswordConfirm:   m.sshFormPasswordConfirm,
		DeleteConfirmOpen: m.sshDeleteConfirmOpen,
		DeleteName:        m.sshDeleteName,
	}
	if m.sshFormFieldEditing {
		value := m.sshFormInput
		if m.sshFormSelected == tuiSSHFormPassphraseRow ||
			m.sshFormSelected == tuiSSHFormPasswordRow {
			value = []rune(strings.Repeat("•", len(m.sshFormInput)))
		}
		view.FieldInput = tuiInputViewport(
			value,
			m.sshFormCursor,
			maxTUIWidth(m.width-48, 16),
		)
	}
	return view
}

func (m *tuiModel) inputPresentation() (string, string) {
	switch m.inputMode {
	case tuiInputMixedPort:
		return "Set proxy port", "Type 0-65535; silent mode keeps it closed"
	case tuiInputSubscription:
		return "Import subscription", "Paste a YAML, URI, Base64, JSON, or client-format URL"
	case tuiInputProfileFile:
		return "Import local profile", "Type a YAML, URI, Base64, JSON, or client-format file path"
	case tuiInputProfileName:
		return "Rename profile", "Type a file name; .yaml is added automatically"
	case tuiInputHistorySearch:
		return "Search History", "Match host, process, network, route, or connection ID"
	case tuiInputConnectionsSearch:
		return "Search Connections", "Match host, process, network, route, or connection ID"
	case tuiInputLogsSearch:
		return "Search Logs", "Case-insensitive text search; empty clears the search"
	default:
		return "Input", ""
	}
}

func tuiInputViewport(value []rune, cursor, width int) string {
	if width <= 0 {
		return ""
	}
	if cursor < 0 {
		cursor = 0
	}
	if cursor > len(value) {
		cursor = len(value)
	}
	start := cursor
	used := 1
	for start > 0 {
		runeWidth := tuiRuneWidth(value[start-1])
		reservedPrefix := 0
		if start-1 > 0 {
			reservedPrefix = 1
		}
		if used+runeWidth+reservedPrefix > width {
			break
		}
		start--
		used += runeWidth
	}
	used = 1 + tuiDisplayWidth(string(value[start:cursor]))
	if start > 0 {
		used++
	}
	end := cursor
	for end < len(value) {
		runeWidth := tuiRuneWidth(value[end])
		reservedSuffix := 0
		if end+1 < len(value) {
			reservedSuffix = 1
		}
		if used+runeWidth+reservedSuffix > width {
			break
		}
		end++
		used += runeWidth
	}
	var output strings.Builder
	if start > 0 {
		output.WriteRune('…')
	}
	output.WriteString(string(value[start:cursor]))
	output.WriteRune('█')
	output.WriteString(string(value[cursor:end]))
	if end < len(value) {
		output.WriteRune('…')
	}
	return output.String()
}

func (m *tuiModel) shutdown() {
	m.editorBackup.release()
	if m.editorTempPath != "" {
		_ = os.Remove(m.editorTempPath)
	}
	if m.frontendExitRequested || !m.shutdownRequested || !m.ownsCore {
		return
	}
	if m.service != nil {
		return
	}
	if m.ownsCore {
		handleShutdown()
	}
}

func tuiTickCommand() tea.Cmd {
	return tea.Tick(tuiRefreshInterval, func(value time.Time) tea.Msg {
		return tuiTickMsg(value)
	})
}

func (m *tuiModel) idleTickCommand() tea.Cmd {
	plan := tuiIdleTickPlanFor(m.snapshot.Page)
	m.lastIdleTick = plan
	if !plan.RefreshSnapshot && !plan.FetchHistory && !plan.FetchLogs {
		m.refreshIncludesHistory = false
		m.refreshIncludesLogs = false
	}
	cmds := []tea.Cmd{tuiTickCommand()}
	if plan.RefreshSnapshot || plan.FetchHistory || plan.FetchLogs {
		cmds = append(cmds, m.startRefresh())
	}
	if plan.SampleMemory {
		cmds = append(cmds, m.startMemoryRefresh())
	}
	if plan.PollSSH {
		cmds = append(cmds, m.pollSelectedSSHRelay())
	}
	return tea.Batch(cmds...)
}

func (m *tuiModel) waitServiceUpdate() tea.Cmd {
	if m.service == nil {
		return nil
	}
	service := m.service
	revision := m.backendRevision
	return func() tea.Msg {
		status, err := service.watch(revision, 30*time.Second)
		return tuiServiceWatchMsg{status: status, err: err}
	}
}

func (m *tuiModel) startRefresh() tea.Cmd {
	if m.refreshInFlight || m.busy {
		return nil
	}
	m.refreshInFlight = true
	m.refreshSequence++
	sequence := m.refreshSequence
	scope := tuiIdleTickPlanFor(m.snapshot.Page)
	m.refreshIncludesHistory = scope.FetchHistory
	m.refreshIncludesLogs = scope.FetchLogs
	snapshot := m.snapshot
	clearTUITransientRefreshStatus(&snapshot)
	previousLogs := append([]string(nil), m.snapshot.Logs...)
	client := m.client
	paths := m.paths
	service := m.service
	fetchHistory := scope.FetchHistory
	fetchLogs := scope.FetchLogs
	return func() tea.Msg {
		refreshTUISnapshot(&snapshot, client)
		refreshTUIProfiles(&snapshot, paths)
		refreshTUISSH(&snapshot)
		snapshot.Frontends, _ = listCLIFrontends()
		refreshIssues := make([]string, 0, 2)
		var serviceStatus *tuiServiceStatus
		if service != nil {
			if status, err := service.status(); err == nil {
				serviceStatus = &status
			} else {
				refreshIssues = append(refreshIssues, "Status: "+err.Error())
			}
			if fetchHistory {
				if status, err := service.history(); err == nil {
					snapshot.Requests = append([]tuiRequest(nil), status.History...)
				} else {
					refreshIssues = append(refreshIssues, "History: "+err.Error())
				}
			}
		}
		if fetchLogs {
			if service != nil {
				if status, err := service.logs(1000); err == nil {
					localLogs := cliLogSnapshot()
					snapshot.Logs = append(append([]string(nil), status.Logs...), localLogs...)
					if len(snapshot.Logs) > 1500 {
						snapshot.Logs = snapshot.Logs[len(snapshot.Logs)-1500:]
					}
				} else {
					snapshot.Logs = previousLogs
					refreshIssues = append(refreshIssues, "Logs: "+err.Error())
				}
			} else {
				snapshot.Logs = cliLogSnapshot()
			}
		}
		if len(refreshIssues) > 0 && (snapshot.Status == "" || snapshot.Status == "Connected" || snapshot.Status == "Loading...") {
			snapshot.Status = "Refresh incomplete · " + strings.Join(refreshIssues, " · ")
		}
		return tuiRefreshResultMsg{
			sequence:      sequence,
			snapshot:      snapshot,
			serviceStatus: serviceStatus,
		}
	}
}

func (m *tuiModel) startOperation(action func(*tuiOperationState)) tea.Cmd {
	if m.busy {
		m.snapshot.Status = "Another operation is still running"
		return nil
	}
	m.busy = true
	m.refreshInFlight = false
	m.refreshSequence++
	state := tuiOperationState{
		snapshot:           m.snapshot,
		paths:              m.paths,
		setupParams:        append([]byte(nil), m.setupParams...),
		coreRunning:        m.coreRunning,
		systemProxyManaged: m.systemProxyManaged,
		pendingMixedPort:   cloneTUIOptionalInt(m.pendingMixedPort),
		stagedSettings:     cloneTUISettings(m.stagedSettings),
		settingsDirty:      m.settingsDirty,
		backendRevision:    m.backendRevision,
	}
	m.snapshot.Status = "Working..."
	return func() tea.Msg {
		action(&state)
		return tuiOperationResultMsg{state: state}
	}
}

func cloneTUIOptionalInt(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneTUISettings(value *tuiSettings) *tuiSettings {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func mergeTUIRefresh(current, refreshed tuiSnapshot) tuiSnapshot {
	refreshed.Traffic = current.Traffic
	refreshed.TrafficHistory = append(
		[]trafficSnapshot(nil),
		current.TrafficHistory...,
	)
	refreshed.TotalTraffic = current.TotalTraffic
	refreshed = preserveTUIInteraction(current, refreshed)
	if !current.UpdatedAt.IsZero() {
		refreshed.Settings.SystemProxy = current.Settings.SystemProxy
	}
	if !tuiStatusIsControllerError(refreshed.Status) &&
		!tuiStatusIsControllerError(current.Status) &&
		current.Status != "" &&
		current.Status != "Connected" &&
		current.Status != "Loading..." {
		refreshed.Status = current.Status
	}
	return refreshed
}

func tuiStatusIsControllerError(status string) bool {
	return strings.HasPrefix(status, "Controller unavailable:") ||
		strings.HasPrefix(status, "Invalid controller response:") ||
		strings.HasPrefix(status, "Connections refresh failed:") ||
		strings.HasPrefix(status, "Refresh incomplete ·") ||
		strings.HasPrefix(status, "SSH profiles unavailable:")
}

func clearTUITransientRefreshStatus(snapshot *tuiSnapshot) {
	if tuiStatusIsControllerError(snapshot.Status) {
		snapshot.Status = "Loading..."
	}
}

func mergeTUIOperation(current, result tuiSnapshot) tuiSnapshot {
	// Traffic updates arrive independently while an operation is running. The
	// operation snapshot was captured before those updates, so never replace the
	// live counters with its stale copy when the result is applied.
	result.Traffic = current.Traffic
	result.TrafficHistory = append(
		[]trafficSnapshot(nil),
		current.TrafficHistory...,
	)
	result.TotalTraffic = current.TotalTraffic
	return preserveTUIInteraction(current, result)
}

func preserveTUIInteraction(current, updated tuiSnapshot) tuiSnapshot {
	selectedGroupName := ""
	selectedNodeName := ""
	if current.SelectedGroup >= 0 && current.SelectedGroup < len(current.Groups) {
		selectedGroup := current.Groups[current.SelectedGroup]
		selectedGroupName = selectedGroup.Name
		if current.SelectedNode >= 0 && current.SelectedNode < len(selectedGroup.Nodes) {
			selectedNodeName = selectedGroup.Nodes[current.SelectedNode]
		}
	}
	selectedConnectionID := ""
	if current.SelectedConnection >= 0 && current.SelectedConnection < len(current.Connections) {
		selectedConnectionID = current.Connections[current.SelectedConnection].ID
	}
	selectedRequestID := ""
	if current.SelectedRequest >= 0 && current.SelectedRequest < len(current.Requests) {
		selectedRequestID = current.Requests[current.SelectedRequest].ID
	}
	selectedLog := ""
	if current.SelectedLog >= 0 && current.SelectedLog < len(current.Logs) {
		selectedLog = current.Logs[current.SelectedLog]
	}
	selectedProviderName := ""
	if current.SelectedProvider >= 0 && current.SelectedProvider < len(current.Providers) {
		selectedProviderName = current.Providers[current.SelectedProvider].Name
	}
	selectedProfilePath := ""
	importSelected := current.SelectedRow < 0
	if current.SelectedRow >= 0 && current.SelectedRow < len(current.Profiles) {
		selectedProfilePath = current.Profiles[current.SelectedRow].Path
	}
	selectedSSHName := ""
	captureSelected := current.SelectedSSH == tuiSSHCaptureRow
	if current.SelectedSSH >= 0 && current.SelectedSSH < len(current.SSHProfiles) {
		selectedSSHName = current.SSHProfiles[current.SelectedSSH].Name
	}

	updated.Page = current.Page
	updated.SelectedMenu = current.SelectedMenu
	updated.SelectedDashboard = current.SelectedDashboard
	updated.SelectedSetting = current.SelectedSetting
	updated.SelectedTool = current.SelectedTool
	updated.SelectedMaintenance = current.SelectedMaintenance
	updated.ProxyView = current.ProxyView
	updated.ProxyNodeFocus = current.ProxyNodeFocus
	updated.SSHDashboardFocus = current.SSHDashboardFocus
	updated.SelectedSSHDetail = current.SelectedSSHDetail
	updated.ManagedService = current.ManagedService
	updated.FocusSidebar = current.FocusSidebar
	updated.ShowHelp = current.ShowHelp
	updated.SSHNetwork = current.SSHNetwork
	updated.SSHDelay = current.SSHDelay
	updated.SSHSpeed = current.SSHSpeed
	updated.SSHDirectProbe = current.SSHDirectProbe
	updated.SSHDirectNetwork = current.SSHDirectNetwork
	updated.SSHDirectDelay = current.SSHDirectDelay
	updated.SSHDirectSpeed = current.SSHDirectSpeed
	updated.SSHTraffic = current.SSHTraffic
	updated.SSHTrafficHistory = append(
		[]trafficSnapshot(nil),
		current.SSHTrafficHistory...,
	)
	updated.SSHTotalTraffic = current.SSHTotalTraffic
	updated.SSHConnections = current.SSHConnections
	if len(current.GroupOrder) > 0 {
		updated.GroupOrder = append([]string(nil), current.GroupOrder...)
		orderTUIGroups(updated.Groups, updated.GroupOrder)
	}
	if current.Network.Loading ||
		current.Network.CheckedAt.After(updated.Network.CheckedAt) {
		updated.Network = current.Network
	}
	if current.Memory.UpdatedAt.After(updated.Memory.UpdatedAt) ||
		current.Memory.CoreUpdated.After(updated.Memory.CoreUpdated) {
		updated.Memory = current.Memory
	}
	mergeTUIGroupDelays(current.Groups, updated.Groups)

	updated.SelectedGroup = findTUIGroupExact(updated.Groups, selectedGroupName)
	if selectedGroupName == "" {
		updated.SelectedGroup = clampTUISelection(current.SelectedGroup, len(updated.Groups))
	}
	if updated.SelectedGroup >= 0 && updated.SelectedGroup < len(updated.Groups) {
		updated.SelectedNode = findTUIStringExact(
			updated.Groups[updated.SelectedGroup].Nodes,
			selectedNodeName,
		)
		if selectedNodeName == "" {
			updated.SelectedNode = clampTUISelection(
				current.SelectedNode,
				len(updated.Groups[updated.SelectedGroup].Nodes),
			)
		}
		if updated.SelectedNode < 0 {
			updated.ProxyNodeFocus = false
		}
	} else {
		updated.SelectedNode = -1
		updated.ProxyNodeFocus = false
	}
	updated.SelectedConnection = findTUIConnection(updated.Connections, selectedConnectionID)
	if selectedConnectionID == "" {
		updated.SelectedConnection = clampTUISelection(
			current.SelectedConnection,
			len(updated.Connections),
		)
		if current.ConnectionsDetailOpen {
			updated.ConnectionsDetailOpen = false
		}
	}
	if updated.SelectedConnection < 0 {
		updated.ConnectionsDetailOpen = false
	}
	updated.SelectedRequest = findTUIRequest(updated.Requests, selectedRequestID)
	if selectedRequestID == "" {
		updated.SelectedRequest = clampTUISelection(
			current.SelectedRequest,
			len(updated.Requests),
		)
		if current.HistoryDetailOpen {
			updated.HistoryDetailOpen = false
		}
	}
	if updated.SelectedRequest < 0 {
		updated.HistoryDetailOpen = false
	}
	updated.SelectedLog = findTUILog(updated.Logs, selectedLog)
	selectedLogFound := updated.SelectedLog >= 0
	if selectedLog == "" || updated.SelectedLog < 0 {
		updated.SelectedLog = firstTUILogMatch(updated)
	}
	if current.LogDetailOpen && !selectedLogFound ||
		updated.SelectedLog < 0 ||
		findTUIInt(matchedTUILogIndexes(updated), updated.SelectedLog) < 0 {
		updated.LogDetailOpen = false
	}
	updated.SelectedProvider = findTUIProvider(updated.Providers, selectedProviderName)
	if selectedProviderName == "" {
		updated.SelectedProvider = clampTUISelection(
			current.SelectedProvider,
			len(updated.Providers),
		)
	}
	if importSelected {
		updated.SelectedRow = current.SelectedRow
	} else if selectedProfilePath != "" {
		updated.SelectedRow = findTUIProfileExact(
			updated.Profiles,
			selectedProfilePath,
		)
		if updated.SelectedRow < 0 {
			updated.SelectedRow = tuiProfileImportSubscriptionRow
		}
	} else {
		updated.SelectedRow = clampTUISelection(current.SelectedRow, len(updated.Profiles))
	}
	if !importSelected && len(updated.Profiles) == 0 {
		updated.SelectedRow = tuiProfileImportSubscriptionRow
	}
	if captureSelected || len(updated.SSHProfiles) == 0 {
		updated.SelectedSSH = tuiSSHCaptureRow
	} else {
		updated.SelectedSSH = findTUISSHProfile(updated.SSHProfiles, selectedSSHName)
		if selectedSSHName == "" {
			updated.SelectedSSH = clampTUISelection(
				current.SelectedSSH,
				len(updated.SSHProfiles),
			)
		}
	}
	return updated
}

func findTUISSHProfile(profiles []tuiSSHProfile, name string) int {
	for index, profile := range profiles {
		if strings.EqualFold(profile.Name, name) {
			return index
		}
	}
	return -1
}

func findTUIGroupExact(groups []tuiGroup, name string) int {
	if name == "" {
		return -1
	}
	for index, group := range groups {
		if group.Name == name {
			return index
		}
	}
	return -1
}

func findTUIStringExact(values []string, value string) int {
	if value == "" {
		return -1
	}
	for index, candidate := range values {
		if candidate == value {
			return index
		}
	}
	return -1
}

func findTUIProfileExact(profiles []tuiProfile, path string) int {
	if path == "" {
		return -1
	}
	for index, profile := range profiles {
		if filepath.Clean(profile.Path) == filepath.Clean(path) {
			return index
		}
	}
	return -1
}

func findTUILog(logs []string, line string) int {
	if line == "" {
		return -1
	}
	for index := len(logs) - 1; index >= 0; index-- {
		if logs[index] == line {
			return index
		}
	}
	return -1
}

func mergeTUIGroupDelays(current, updated []tuiGroup) {
	currentByName := make(map[string]tuiGroup, len(current))
	for _, group := range current {
		currentByName[group.Name] = group
	}
	for index := range updated {
		previous, ok := currentByName[updated[index].Name]
		if !ok {
			continue
		}
		if len(previous.Delays) > 0 {
			delays := make(
				map[string]tuiDelayResult,
				len(updated[index].Delays)+len(previous.Delays),
			)
			for node, delay := range updated[index].Delays {
				delays[node] = delay
			}
			for node, delay := range previous.Delays {
				if _, exists := delays[node]; !exists {
					delays[node] = delay
				}
			}
			updated[index].Delays = delays
		}
		if len(previous.Speeds) > 0 {
			speeds := make(
				map[string]tuiSpeedResult,
				len(updated[index].Speeds)+len(previous.Speeds),
			)
			for node, speed := range updated[index].Speeds {
				speeds[node] = speed
			}
			for node, speed := range previous.Speeds {
				if _, exists := speeds[node]; !exists {
					speeds[node] = speed
				}
			}
			updated[index].Speeds = speeds
		}
	}
}

func findTUIProfile(profiles []tuiProfile, path string) int {
	for index, profile := range profiles {
		if filepath.Clean(profile.Path) == filepath.Clean(path) {
			return index
		}
	}
	return 0
}

func clampTUISelection(index, total int) int {
	if total <= 0 {
		return 0
	}
	if index < 0 {
		return 0
	}
	if index >= total {
		return total - 1
	}
	return index
}

func (m *tuiModel) handleKey(key tuiKey) tea.Cmd {
	switch key {
	case tuiKeyQuit:
		m.frontendExitRequested = true
		m.stopCoreMemoryMonitor()
		m.stopTrafficMonitor()
		return tea.Quit
	case tuiKeyInterrupt:
		if m.shutdownRequested {
			return nil
		}
		m.shutdownRequested = true
		m.snapshot.Status = "Shutting down all frontends, Backend, and Core..."
		return func() tea.Msg {
			return tuiShutdownResultMsg{
				err: completeCLIExitForTUI(os.Getpid()),
			}
		}
	case tuiKeyBack:
		if m.snapshot.Page == tuiPageSSH && m.snapshot.SSHDashboardFocus {
			m.snapshot.SSHDashboardFocus = false
			m.snapshot.Status = "SSH profiles · Enter connects or focuses Dashboard"
		} else if m.snapshot.Page == tuiPageRequests && m.snapshot.HistoryDetailOpen {
			m.snapshot.HistoryDetailOpen = false
		} else if m.snapshot.Page == tuiPageConnections && m.snapshot.ConnectionsDetailOpen {
			m.snapshot.ConnectionsDetailOpen = false
		} else if m.snapshot.Page == tuiPageLogs && m.snapshot.LogDetailOpen {
			m.snapshot.LogDetailOpen = false
		} else if !m.snapshot.FocusSidebar &&
			m.snapshot.Page == tuiPageProxies &&
			m.snapshot.ProxyView == tuiProxyViewGroups &&
			m.snapshot.ProxyNodeFocus {
			m.snapshot.ProxyNodeFocus = false
			m.snapshot.Status = "Proxy groups · Enter opens nodes · d node RTT (5 samples) · v speed"
		} else if !m.snapshot.FocusSidebar {
			m.snapshot.FocusSidebar = true
			m.snapshot.SelectedMenu = int(m.snapshot.Page)
		}
		return nil
	case tuiKeyRefresh:
		m.refreshInFlight = false
		m.refreshSequence++
		return m.startRefresh()
	case tuiKeyReload:
		return m.startOperation(func(state *tuiOperationState) {
			if reloadErr := reloadTUIOperationConfig(
				state,
				m.service,
				m.client,
				m.ownsCore,
			); reloadErr != nil {
				state.snapshot.Status = "Reload failed: " + reloadErr.Error()
			} else {
				state.snapshot.Status = "Configuration reloaded"
				syncStoppedTUISettings(state)
			}
		})
	case tuiKeyHelp:
		m.snapshot.ShowHelp = !m.snapshot.ShowHelp
	case tuiKeySearch:
		switch m.snapshot.Page {
		case tuiPageRequests:
			m.beginInput(tuiInputHistorySearch)
		case tuiPageConnections:
			m.beginInput(tuiInputConnectionsSearch)
		case tuiPageLogs:
			m.beginInput(tuiInputLogsSearch)
		}
	case tuiKeyFilter:
		switch m.snapshot.Page {
		case tuiPageRequests:
			filters := []string{"all", "active", "completed"}
			current := findTUIString(filters, tuiDefaultValue(m.snapshot.HistoryFilter, "all"))
			m.snapshot.HistoryFilter = filters[wrapTUIIndex(current, 1, len(filters))]
			m.snapshot.SelectedRequest = firstTUIRequestMatch(m.snapshot)
			m.snapshot.HistoryDetailOpen = false
			m.snapshot.Status = "History filter: " + m.snapshot.HistoryFilter
		case tuiPageLogs:
			levels := []string{"ALL", "ERROR", "WARN", "INFO", "DEBUG"}
			current := findTUIString(levels, tuiDefaultValue(m.snapshot.LogsLevel, "ALL"))
			m.snapshot.LogsLevel = levels[wrapTUIIndex(current, 1, len(levels))]
			m.snapshot.SelectedLog = firstTUILogMatch(m.snapshot)
			m.snapshot.LogDetailOpen = false
			m.snapshot.Status = "Log level filter: " + m.snapshot.LogsLevel
		}
	case tuiKeyCloseConnections:
		if m.snapshot.Page == tuiPageSSH {
			if m.snapshot.FocusSidebar || m.snapshot.SSHDashboardFocus {
				m.snapshot.Status = "Focus SSH profiles before deleting"
				return nil
			}
			m.beginSSHDeleteConfirm()
			return nil
		} else if m.snapshot.Page == tuiPageProfiles {
			m.beginProfileDeleteConfirm()
			return nil
		} else if m.snapshot.Page == tuiPageRequests {
			if !m.dangerConfirmed {
				m.beginDangerConfirm("Clear shared History?", "Delete all persisted active and completed History entries from the Backend.", key)
				return nil
			}
			if m.service != nil {
				return m.startOperation(func(state *tuiOperationState) {
					if !prepareTUIBackendRevision(state, m.service) {
						return
					}
					status, err := m.service.clearHistory(state.backendRevision)
					if err != nil {
						state.snapshot.Status = "Clear History failed: " + err.Error()
						return
					}
					state.backendRevision = status.Revision
					state.snapshot.Requests = nil
					state.snapshot.SelectedRequest = -1
					state.snapshot.HistoryDetailOpen = false
					state.snapshot.Status = "Shared History cleared"
				})
			}
			m.snapshot.Requests = nil
			m.snapshot.SelectedRequest = -1
			m.snapshot.HistoryDetailOpen = false
			m.snapshot.Status = "History cleared"
		} else if m.snapshot.Page == tuiPageLogs {
			if !m.dangerConfirmed {
				m.beginDangerConfirm("Clear shared logs?", "Delete the Backend log and its rotated backup, plus this TUI's in-memory log entries.", key)
				return nil
			}
			if m.service != nil {
				return m.startOperation(func(state *tuiOperationState) {
					if !prepareTUIBackendRevision(state, m.service) {
						return
					}
					status, err := m.service.clearLogs(state.backendRevision)
					if err != nil {
						state.snapshot.Status = "Clear logs failed: " + err.Error()
						return
					}
					state.backendRevision = status.Revision
					clearTUILogs()
					state.snapshot.Logs = nil
					state.snapshot.SelectedLog = -1
					state.snapshot.LogDetailOpen = false
					state.snapshot.Status = "Shared logs cleared"
				})
			}
			clearTUILogs()
			m.snapshot.Logs = nil
			m.snapshot.SelectedLog = -1
			m.snapshot.LogDetailOpen = false
			m.snapshot.Status = "Logs cleared"
		} else if m.snapshot.Page == tuiPageConnections {
			if !m.dangerConfirmed {
				m.beginDangerConfirm("Close all connections?", "Immediately close every active connection visible to this managed Core.", key)
				return nil
			}
			return m.startOperation(func(state *tuiOperationState) {
				var err error
				if m.service != nil {
					if !prepareTUIBackendRevision(state, m.service) {
						return
					}
					var status tuiServiceStatus
					status, err = m.service.closeAllConnectionsManaged(state.backendRevision)
					if err == nil {
						state.backendRevision = status.Revision
					}
				} else {
					err = closeTUIVisibleConnections(m.client, uint32(os.Getuid()), state.snapshot.Settings.TunEnabled && state.snapshot.Settings.TunScope == tuiTunScopeSystem, "")
				}
				if err != nil {
					state.snapshot.Status = "Close connections failed: " + err.Error()
				} else {
					state.snapshot.Status = "All connections closed"
				}
			})
		}
	case tuiKeyCloseConnection:
		if m.snapshot.Page == tuiPageSSH {
			if !m.snapshot.FocusSidebar && m.snapshot.SSHDashboardFocus {
				return m.testSelectedSSHDelayFor(
					tuiSSHDashboardRowIsDirect(m.snapshot.SelectedSSHDetail),
				)
			}
			m.snapshot.Status = "Focus SSH Dashboard before testing route delay"
			return nil
		}
		if m.snapshot.Page == tuiPageDashboard {
			return m.testDashboardDelay()
		}
		if !m.snapshot.FocusSidebar &&
			m.snapshot.Page == tuiPageProxies &&
			m.snapshot.ProxyView == tuiProxyViewGroups {
			if m.snapshot.ProxyNodeFocus {
				return m.testSelectedProxyDelay()
			}
			return m.testSelectedProxyGroupDelays()
		}
		if m.snapshot.Page == tuiPageConnections &&
			m.snapshot.SelectedConnection >= 0 &&
			m.snapshot.SelectedConnection < len(m.snapshot.Connections) {
			if !m.dangerConfirmed {
				connection := m.snapshot.Connections[m.snapshot.SelectedConnection]
				m.beginDangerConfirm("Close selected connection?", "Close "+cliDisplayValue(connection.Host)+" ("+connection.ID+").", key)
				m.dangerConfirmTarget = connection.ID
				return nil
			}
			connectionID := m.snapshot.Connections[m.snapshot.SelectedConnection].ID
			if m.dangerConfirmTarget != "" {
				connectionID = m.dangerConfirmTarget
			}
			return m.startOperation(func(state *tuiOperationState) {
				var err error
				if m.service != nil {
					if !prepareTUIBackendRevision(state, m.service) {
						return
					}
					var status tuiServiceStatus
					status, err = m.service.closeConnectionManaged(connectionID, state.backendRevision)
					if err == nil {
						state.backendRevision = status.Revision
					}
				} else {
					err = closeTUIVisibleConnections(m.client, uint32(os.Getuid()), state.snapshot.Settings.TunEnabled && state.snapshot.Settings.TunScope == tuiTunScopeSystem, connectionID)
				}
				if err != nil {
					state.snapshot.Status = "Close connection failed: " + err.Error()
				} else {
					state.snapshot.Status = "Connection closed"
				}
			})
		}
		if m.snapshot.Page == tuiPageConnections {
			m.snapshot.Status = "Select an active connection before closing it"
		}
	case tuiKeyCoreToggle:
		return m.startOperation(func(state *tuiOperationState) {
			if !m.ownsCore {
				state.snapshot.Status = "Core lifecycle is owned by the external process"
			} else if state.coreRunning {
				stopTUIManagedCore(state, m.service)
			} else {
				startTUIManagedCore(state, m.service)
			}
		})
	case tuiKeyEdit:
		switch m.snapshot.Page {
		case tuiPageSSH:
			if m.snapshot.FocusSidebar || m.snapshot.SSHDashboardFocus {
				m.snapshot.Status = "Focus SSH profiles before editing"
				return nil
			}
			m.beginSSHForm(true)
			return nil
		case tuiPageProfiles:
			if m.snapshot.SelectedRow < 0 ||
				m.snapshot.SelectedRow >= len(m.snapshot.Profiles) {
				m.snapshot.Status = "Select a profile before editing its YAML"
				return nil
			}
			return m.startEditor(m.snapshot.Profiles[m.snapshot.SelectedRow].Path)
		case tuiPageLogs:
			return m.startOperation(func(state *tuiOperationState) {
				path, err := exportTUILogs(state.paths.homeDir, state.snapshot.Logs)
				if err != nil {
					state.snapshot.Status = "Export logs failed: " + err.Error()
				} else {
					state.snapshot.Status = "Logs exported: " + path
				}
			})
		case tuiPageMaintenance:
			return m.startEditor(m.paths.configPath)
		default:
			m.snapshot.Status = "Edit YAML is available in Profiles and Maintenance"
		}
	case tuiKeyNewProfile:
		if m.snapshot.Page == tuiPageSSH {
			if !m.snapshot.FocusSidebar && m.snapshot.SSHDashboardFocus {
				return m.refreshSelectedSSHDashboard()
			}
			if m.snapshot.FocusSidebar {
				m.snapshot.Status = "Focus SSH profiles before adding a profile"
				return nil
			}
			m.beginSSHForm(false)
			return nil
		} else if m.snapshot.Page == tuiPageProfiles {
			m.beginInput(tuiInputSubscription)
		} else if m.snapshot.Page == tuiPageDashboard {
			return m.startNetworkCheck()
		}
	case tuiKeyRenameProfile:
		if m.snapshot.Page == tuiPageSSH {
			return m.toggleSelectedSSHDefault()
		}
		if m.snapshot.Page == tuiPageProfiles {
			m.beginProfileRename()
		}
	case tuiKeyUpdateProfile:
		if m.snapshot.Page == tuiPageProfiles {
			return m.updateSelectedProfileSubscription()
		}
	case tuiKeyProviders:
		cmds := m.changeVisiblePage(tuiPageProxies)
		m.snapshot.SelectedMenu = int(tuiPageProxies)
		m.snapshot.FocusSidebar = false
		m.snapshot.ProxyView = tuiProxyViewProviders
		m.snapshot.ProxyNodeFocus = false
		m.snapshot.Status = "Providers view · Enter updates the selected provider"
		return tea.Batch(cmds...)
	case tuiKeyBackup:
		if m.snapshot.Page == tuiPageMaintenance {
			return m.runTool(1)
		}
	case tuiKeyRestore:
		if m.snapshot.Page == tuiPageMaintenance {
			return m.runTool(2)
		}
	case tuiKeyGeoUpdate:
		if m.snapshot.Page == tuiPageMaintenance {
			return m.runTool(3)
		}
	case tuiKeyResetTraffic:
		if m.snapshot.Page == tuiPageMaintenance {
			return m.runTool(4)
		}
	case tuiKeyUp:
		return m.moveSelection(-1)
	case tuiKeyDown:
		return m.moveSelection(1)
	case tuiKeyDelayTest:
		if !m.snapshot.FocusSidebar &&
			m.snapshot.Page == tuiPageProxies &&
			m.snapshot.ProxyView == tuiProxyViewGroups {
			if m.snapshot.ProxyNodeFocus {
				return m.testSelectedProxyDelay()
			}
			return m.testSelectedProxyGroupDelays()
		}
	case tuiKeyDelayTestAll:
		if !m.snapshot.FocusSidebar &&
			m.snapshot.Page == tuiPageProxies &&
			m.snapshot.ProxyView == tuiProxyViewGroups {
			return m.testSelectedProxyGroupDelays()
		}
	case tuiKeySpeedTest:
		if m.snapshot.Page == tuiPageDashboard {
			return m.testDashboardSpeed()
		}
		if m.snapshot.Page == tuiPageSSH &&
			!m.snapshot.FocusSidebar &&
			m.snapshot.SSHDashboardFocus {
			return m.testSelectedSSHSpeedFor(
				tuiSSHDashboardRowIsDirect(m.snapshot.SelectedSSHDetail),
			)
		}
		if !m.snapshot.FocusSidebar &&
			m.snapshot.Page == tuiPageProxies &&
			m.snapshot.ProxyView == tuiProxyViewGroups {
			if m.snapshot.ProxyNodeFocus {
				return m.testSelectedProxySpeed()
			}
			return m.testSelectedProxyGroupSpeeds()
		}
	case tuiKeyViewPrevious, tuiKeyViewNext:
		if !m.snapshot.FocusSidebar && m.snapshot.Page == tuiPageProxies {
			delta := 1
			if key == tuiKeyViewPrevious {
				delta = -1
			}
			m.snapshot.ProxyView = wrapTUIIndex(
				m.snapshot.ProxyView,
				delta,
				tuiProxyViewCount,
			)
			if m.snapshot.ProxyView == tuiProxyViewProviders {
				m.snapshot.ProxyNodeFocus = false
				m.snapshot.Status = "Providers view · Enter updates the selected provider"
			} else {
				m.snapshot.ProxyNodeFocus = false
				m.snapshot.Status = "Proxy groups · Enter nodes · d node RTT group · v speed group"
			}
		}
	case tuiKeyPageUp:
		if m.snapshot.Page == tuiPageDashboard {
			step := maxTUIWidth(m.dashboardViewportLimit()-1, 1)
			m.snapshot.DashboardScroll = maxTUIIndex(
				m.snapshot.DashboardScroll - step,
			)
		}
	case tuiKeyPageDown:
		if m.snapshot.Page == tuiPageDashboard {
			limit := m.dashboardViewportLimit()
			maxScroll := maxTUIIndex(
				len(tuiCompactDashboardRows(
					m.snapshot,
					m.paths,
					maxTUIWidth(m.width-2, 1),
					m.dashboardPageHeight(),
				)) -
					limit,
			)
			m.snapshot.DashboardScroll = minTUI(
				m.snapshot.DashboardScroll+
					maxTUIWidth(limit-1, 1),
				maxScroll,
			)
		}
	case tuiKeySelect:
		return m.selectCurrent()
	case tuiKeyPortUp, tuiKeyPortDown:
		if m.snapshot.Page == tuiPageDashboard {
			if m.service == nil && m.ownsCore && !m.coreRunning {
				m.stageTUIAdjustedPort(key)
				return nil
			}
			return m.startOperation(func(state *tuiOperationState) {
				applyTUIOperationSetting(state, m.service, m.client, key)
			})
		}
	case tuiKeyMode:
		if m.snapshot.Page == tuiPageDashboard {
			m.beginModeSelection()
		}
	case tuiKeyAllowLAN, tuiKeyIPv6, tuiKeyUnifiedDelay, tuiKeyTCPConcurrent,
		tuiKeyTun, tuiKeyLogLevel:
		if key == tuiKeyAllowLAN && m.snapshot.Page == tuiPageSSH {
			return m.attachSelectedSSH()
		}
		settingsKey := m.snapshot.Page == tuiPageTools && key != tuiKeyTun
		dashboardTun := m.snapshot.Page == tuiPageDashboard && key == tuiKeyTun
		if settingsKey || dashboardTun {
			if m.service == nil && m.ownsCore && !m.coreRunning {
				m.stageTUISetting(key)
				return nil
			}
			return m.startOperation(func(state *tuiOperationState) {
				applyTUIOperationSetting(state, m.service, m.client, key)
			})
		}
	case tuiKeyTunScope:
		if m.snapshot.Page == tuiPageTools {
			return m.startOperation(func(state *tuiOperationState) {
				applyTUITunScope(state, m.service)
			})
		}
	case tuiKeySetPort:
		if m.snapshot.Page == tuiPageDashboard {
			m.beginInput(tuiInputMixedPort)
		}
	case tuiKeySystemProxy:
		if m.snapshot.Page == tuiPageDashboard {
			if m.service == nil {
				m.snapshot.Status = "System proxy changes require the managed backend"
				return nil
			}
			return m.startOperation(func(state *tuiOperationState) {
				enabled := !state.snapshot.Settings.SystemProxy
				if enabled && state.snapshot.Settings.Mode == tuiSilentMode {
					state.snapshot.Status = "System proxy cannot be enabled in silent mode; switch mode first"
					return
				}
				autoStarted := false
				if m.ownsCore && !state.coreRunning {
					if !startTUIManagedCore(state, m.service) {
						return
					}
					autoStarted = true
				}
				if !prepareTUIBackendRevision(state, m.service) {
					return
				}
				status, err := m.service.setSystemProxy(
					enabled,
					state.backendRevision,
				)
				proxyUpdated := err == nil
				if err != nil {
					state.snapshot.Status = "System proxy update failed: " + err.Error()
				} else {
					applyTUIOperationServiceStatus(state, status)
					state.snapshot.Status = "System proxy " + cliOnOff(status.SystemProxy)
				}
				if proxyUpdated {
					state.systemProxyManaged = state.snapshot.Settings.SystemProxy
					if autoStarted && state.snapshot.Settings.SystemProxy {
						state.snapshot.Status = fmt.Sprintf(
							"Core started on port %d; system proxy enabled",
							state.snapshot.Settings.MixedPort,
						)
					}
				} else if autoStarted {
					proxyError := state.snapshot.Status
					if stopTUIManagedCore(state, m.service) {
						state.snapshot.Status = proxyError +
							"; automatic Core start rolled back"
					}
				}
			})
		}
	}
	return nil
}

func (m *tuiModel) beginDangerConfirm(title, message string, key tuiKey) {
	m.dangerConfirmOpen = true
	m.dangerConfirmTitle = title
	m.dangerConfirmMessage = message
	m.dangerConfirmKey = key
	m.snapshot.Status = title + " · Enter confirm · Esc cancel"
}

func (m *tuiModel) handleDangerConfirm(message tea.KeyMsg) tea.Cmd {
	key, ok := tuiKeyFromTea(message)
	if !ok {
		return nil
	}
	switch key {
	case tuiKeyQuit, tuiKeyInterrupt:
		m.dangerConfirmOpen = false
		return m.handleKey(key)
	case tuiKeyBack:
		m.dangerConfirmOpen = false
		m.dangerConfirmTarget = ""
		m.snapshot.Status = "Operation cancelled"
		return nil
	case tuiKeySelect:
		action := m.dangerConfirmKey
		m.dangerConfirmOpen = false
		m.dangerConfirmed = true
		command := m.handleKey(action)
		m.dangerConfirmed = false
		m.dangerConfirmTarget = ""
		return command
	default:
		return nil
	}
}

func (m *tuiModel) dashboardViewportLimit() int {
	return maxTUIWidth(m.dashboardPageHeight()-3, 1)
}

func (m *tuiModel) dashboardPageHeight() int {
	pageHeight := m.height - 4
	if m.width < 88 || m.height < 18 {
		pageHeight = m.height - 2
	}
	return maxTUIWidth(pageHeight, 1)
}

func (m *tuiModel) revealDashboardSelection() {
	rows := tuiCompactDashboardRows(
		m.snapshot,
		m.paths,
		maxTUIWidth(m.width-2, 1),
		m.dashboardPageHeight(),
	)
	selectedRow := -1
	for index, row := range rows {
		if row.selected {
			selectedRow = index
			break
		}
	}
	if selectedRow < 0 {
		return
	}
	limit := m.dashboardViewportLimit()
	switch {
	case selectedRow < m.snapshot.DashboardScroll:
		m.snapshot.DashboardScroll = selectedRow
	case selectedRow >= m.snapshot.DashboardScroll+limit:
		m.snapshot.DashboardScroll = maxTUIIndex(selectedRow - limit + 1)
	}
}

func (m *tuiModel) moveSelection(delta int) tea.Cmd {
	switch m.snapshot.Page {
	case tuiPageSSH:
		if m.snapshot.SSHDashboardFocus {
			if m.snapshot.SelectedSSH == tuiSSHCaptureRow {
				m.snapshot.SSHDashboardFocus = false
				break
			}
			m.snapshot.SelectedSSHDetail = wrapTUIIndex(
				m.snapshot.SelectedSSHDetail,
				delta,
				tuiSSHDashboardRowCount,
			)
		} else {
			previousName := m.selectedSSHName()
			listLen := len(m.snapshot.SSHProfiles) + 1
			position := wrapTUIIndex(m.snapshot.SelectedSSH+1, delta, listLen)
			m.snapshot.SelectedSSH = position - 1
			if m.snapshot.SelectedSSH == tuiSSHCaptureRow {
				m.resetSelectedSSHMetrics()
				m.snapshot.Status = "Enter captures a live ControlMaster without a new SSH login"
				return nil
			}
			if m.selectedSSHName() != previousName {
				m.resetSelectedSSHMetrics()
				return m.refreshSelectedSSHDashboard()
			}
		}
	case tuiPageProfiles:
		moveTUIProfile(&m.snapshot, delta)
		if m.snapshot.SelectedRow == tuiProfileImportSubscriptionRow {
			m.snapshot.Status = "Enter to import a subscription URL"
		} else if m.snapshot.SelectedRow == tuiProfileImportFileRow {
			m.snapshot.Status = "Enter to convert and import a local profile file"
		} else if m.snapshot.SelectedRow < len(m.snapshot.Profiles) {
			profile := m.snapshot.Profiles[m.snapshot.SelectedRow]
			if profile.Current {
				if profile.SubscriptionURL != "" {
					m.snapshot.Status = "Active subscription · U refreshes · e edits YAML"
				} else {
					m.snapshot.Status = "Active local profile · e edits YAML"
				}
			} else {
				if profile.SubscriptionURL != "" {
					m.snapshot.Status = "Enter activates · U refreshes · F2/u renames · e edits"
				} else {
					m.snapshot.Status = "Enter activates · F2/u renames · e edits"
				}
			}
		}
	case tuiPageConnections:
		moveTUIConnectionMatch(&m.snapshot, delta)
	case tuiPageRequests:
		moveTUIRequestMatch(&m.snapshot, delta)
	case tuiPageLogs:
		moveTUILogMatch(&m.snapshot, delta)
	case tuiPageProxies:
		if m.snapshot.ProxyView == tuiProxyViewProviders {
			moveTUIProvider(&m.snapshot, delta)
		} else if m.snapshot.ProxyNodeFocus {
			moveTUINode(&m.snapshot, delta)
		} else {
			moveTUIGroup(&m.snapshot, delta)
		}
	case tuiPageDashboard:
		m.snapshot.SelectedDashboard = wrapTUIIndex(
			m.snapshot.SelectedDashboard,
			delta,
			tuiDashboardRowCount,
		)
		m.revealDashboardSelection()
	case tuiPageTools:
		m.snapshot.SelectedTool = wrapTUIIndex(
			m.snapshot.SelectedTool,
			delta,
			tuiSettingsRowCount,
		)
	case tuiPageMaintenance:
		m.snapshot.SelectedMaintenance = wrapTUIIndex(
			m.snapshot.SelectedMaintenance,
			delta,
			tuiMaintenanceRowCount,
		)
	}
	return nil
}

func (m *tuiModel) stageTUIAdjustedPort(key tuiKey) {
	port := m.snapshot.Settings.MixedPort
	switch key {
	case tuiKeyPortUp:
		if port >= 65535 {
			m.snapshot.Status = "Proxy port is already at 65535"
			return
		}
		port++
	case tuiKeyPortDown:
		if port > 0 {
			port--
		}
	}
	m.pendingMixedPort = &port
	m.snapshot.Settings.MixedPort = port
	m.stagedSettings = cloneTUISettings(&m.snapshot.Settings)
	m.settingsDirty = true
	m.snapshot.Status = fmt.Sprintf(
		"Proxy port %d staged; enable System proxy or start Core to apply",
		port,
	)
	m.persistStagedTUISettings()
}

func (m *tuiModel) stageTUISetting(key tuiKey) {
	switch key {
	case tuiKeyAllowLAN:
		m.snapshot.Settings.AllowLAN = !m.snapshot.Settings.AllowLAN
	case tuiKeyIPv6:
		m.snapshot.Settings.IPv6 = !m.snapshot.Settings.IPv6
	case tuiKeyUnifiedDelay:
		m.snapshot.Settings.UnifiedDelay = !m.snapshot.Settings.UnifiedDelay
	case tuiKeyTCPConcurrent:
		m.snapshot.Settings.TCPConcurrent = !m.snapshot.Settings.TCPConcurrent
	case tuiKeyTun:
		m.snapshot.Settings.TunEnabled = !m.snapshot.Settings.TunEnabled
	case tuiKeyLogLevel:
		levels := []string{"silent", "error", "warning", "info", "debug"}
		current := findTUIString(levels, strings.ToLower(m.snapshot.Settings.LogLevel))
		m.snapshot.Settings.LogLevel = levels[wrapTUIIndex(current, 1, len(levels))]
	default:
		return
	}
	port := m.snapshot.Settings.MixedPort
	m.pendingMixedPort = &port
	m.stagedSettings = cloneTUISettings(&m.snapshot.Settings)
	m.settingsDirty = true
	m.snapshot.Status = "Settings staged; enable System proxy or start Core to apply"
	m.persistStagedTUISettings()
}

func (m *tuiModel) persistStagedTUISettings() {
	if m.stagedSettings == nil {
		return
	}
	if m.service != nil {
		m.settingsDirty = true
		m.snapshot.Status += "; pending backend commit"
		return
	}
	m.settingsDirty = true
	m.snapshot.Status += "; not saved without Backend"
}

func applyTUIOperationSetting(
	state *tuiOperationState,
	service *tuiServiceClient,
	client controllerClient,
	key tuiKey,
) {
	if service == nil {
		state.snapshot.Status = "Changing shared settings requires the managed backend"
		return
	}
	if key == tuiKeyTun {
		if !prepareTUIBackendRevision(state, service) {
			return
		}
		scope := state.snapshot.Settings.TunScope
		if scope == "" {
			scope = tuiTunScopeUser
		}
		status, err := service.setTun(
			!state.snapshot.Settings.TunEnabled,
			scope,
			state.backendRevision,
		)
		if err != nil {
			state.snapshot.Status = "TUN update failed: " + err.Error()
			return
		}
		applyTUIOperationServiceStatus(state, status)
		state.snapshot.Status = "TUN " + strings.ToUpper(status.TunScope) + " " + strings.ToUpper(status.TunState)
		state.networkChanged = true
		return
	}
	settings := state.snapshot.Settings
	if !changeTUISettingsValue(&settings, key) {
		state.snapshot.Status = "Setting is already at its limit"
		return
	}
	commitTUIOperationSettings(state, service, client, settings)
}

func applyTUITunScope(state *tuiOperationState, service *tuiServiceClient) {
	if service == nil {
		state.snapshot.Status = "Changing TUN scope requires the managed Backend"
		return
	}
	if state.snapshot.Settings.TunEnabled {
		state.snapshot.Status = "Turn TUN off before changing its scope"
		return
	}
	if !prepareTUIBackendRevision(state, service) {
		return
	}
	scope := tuiEffectiveTunScope(state.snapshot.Settings.TunScope)
	if scope == tuiTunScopeUser {
		scope = tuiTunScopeSystem
	} else {
		scope = tuiTunScopeUser
	}
	status, err := service.setTun(false, scope, state.backendRevision)
	if err != nil {
		state.snapshot.Status = "TUN scope update failed: " + err.Error()
		return
	}
	applyTUIOperationServiceStatus(state, status)
	state.snapshot.Status = "TUN scope " + strings.ToUpper(status.TunScope)
}

func commitTUIOperationSettings(
	state *tuiOperationState,
	service *tuiServiceClient,
	client controllerClient,
	settings tuiSettings,
) {
	if !prepareTUIBackendRevision(state, service) {
		return
	}
	profileSettings, err := tuiProfileSettingsForCommit(state, settings)
	if err != nil {
		state.snapshot.Status = "Settings commit failed: " + err.Error()
		return
	}
	status, err := service.applySettings(profileSettings, state.backendRevision)
	if err != nil {
		state.snapshot.Status = "Settings commit failed: " + err.Error()
		return
	}
	state.snapshot.Settings = profileSettings
	state.settingsDirty = false
	state.stagedSettings = nil
	state.pendingMixedPort = nil
	state.snapshot.Status = fmt.Sprintf(
		"Settings committed at revision %d",
		status.Revision,
	)
	refreshTUISnapshot(&state.snapshot, client)
	applyTUIOperationServiceStatus(state, status)
	state.networkChanged = true
}

func tuiProfileSettingsForCommit(
	state *tuiOperationState,
	settings tuiSettings,
) (tuiSettings, error) {
	configured := loadTUIConfiguredSettings(state.paths.configPath, true)
	if configured == nil || strings.EqualFold(configured.Mode, tuiSilentMode) {
		return tuiSettings{}, errors.New(
			"could not load native mode and TUN settings from the active YAML profile",
		)
	}
	// Mode and TUN are Backend-owned controls. The snapshot contains their
	// effective display state (including FlClash-only silent mode and system
	// TUN), which must never be serialized back into the shared YAML by an
	// unrelated settings or port edit.
	settings.Mode = configured.Mode
	settings.TunEnabled = configured.TunEnabled
	return settings, nil
}

func prepareTUIBackendRevision(
	state *tuiOperationState,
	service *tuiServiceClient,
) bool {
	if state.backendRevision > 0 {
		return true
	}
	status, err := service.status()
	if err != nil {
		state.snapshot.Status = "Cannot read backend state: " + err.Error()
		return false
	}
	applyTUIOperationServiceStatus(state, status)
	return true
}

func applyTUIOperationServiceStatus(
	state *tuiOperationState,
	status tuiServiceStatus,
) {
	state.backendRevision = status.Revision
	state.coreRunning = status.Running
	if status.ConfigPath != "" {
		state.paths.configPath = status.ConfigPath
	}
	state.snapshot.Settings.SystemProxy = status.SystemProxy
	if status.Mode != "" {
		state.snapshot.Settings.Mode = status.Mode
	}
	state.snapshot.Settings.MixedPort = status.ConfiguredProxyPort
	state.snapshot.ConfiguredProxyPort = status.ConfiguredProxyPort
	state.snapshot.ActiveProxyPort = status.ActiveProxyPort
	if status.TunState != "" {
		state.snapshot.Settings.TunEnabled = status.TunState == "on"
	}
	if status.TunScope != "" {
		state.snapshot.Settings.TunScope = status.TunScope
	}
	if status.Mode == tuiSilentMode {
		state.snapshot.Settings.TunEnabled = false
	}
	state.snapshot.FLCEnabled = status.FLCEnabled
	state.snapshot.FLCOutbound = status.FLCOutbound
}

func changeTUISettingsValue(settings *tuiSettings, key tuiKey) bool {
	switch key {
	case tuiKeyAllowLAN:
		settings.AllowLAN = !settings.AllowLAN
	case tuiKeyIPv6:
		settings.IPv6 = !settings.IPv6
	case tuiKeyUnifiedDelay:
		settings.UnifiedDelay = !settings.UnifiedDelay
	case tuiKeyTCPConcurrent:
		settings.TCPConcurrent = !settings.TCPConcurrent
	case tuiKeyTun:
		settings.TunEnabled = !settings.TunEnabled
	case tuiKeyLogLevel:
		levels := []string{"silent", "error", "warning", "info", "debug"}
		current := findTUIString(levels, strings.ToLower(settings.LogLevel))
		settings.LogLevel = levels[wrapTUIIndex(current, 1, len(levels))]
	case tuiKeyPortUp:
		if settings.MixedPort >= 65535 {
			return false
		}
		settings.MixedPort++
	case tuiKeyPortDown:
		if settings.MixedPort <= 0 {
			return false
		}
		settings.MixedPort--
	default:
		return false
	}
	return true
}

func syncStoppedTUISettings(state *tuiOperationState) {
	if state.coreRunning {
		return
	}
	settings := loadTUIConfiguredSettings(state.paths.configPath, true)
	if settings == nil {
		state.snapshot.Status += "; could not reload settings from YAML"
		return
	}
	backendMode := state.snapshot.Settings.Mode
	backendTunEnabled := state.snapshot.Settings.TunEnabled
	backendTunScope := state.snapshot.Settings.TunScope
	settings.SystemProxy = state.snapshot.Settings.SystemProxy
	state.stagedSettings = cloneTUISettings(settings)
	state.snapshot.Settings = *settings
	if strings.EqualFold(backendMode, tuiSilentMode) {
		state.snapshot.Settings.Mode = tuiSilentMode
	}
	state.snapshot.Settings.TunEnabled = backendTunEnabled
	state.snapshot.Settings.TunScope = backendTunScope
	state.settingsDirty = false
	port := settings.MixedPort
	state.pendingMixedPort = &port
}

func reloadTUIOperationConfig(
	state *tuiOperationState,
	service *tuiServiceClient,
	client controllerClient,
	ownsCore bool,
) error {
	return reloadTUIOperationConfigExpected(
		state,
		service,
		client,
		ownsCore,
		"",
	)
}

func reloadTUIOperationConfigExpected(
	state *tuiOperationState,
	service *tuiServiceClient,
	client controllerClient,
	ownsCore bool,
	expectedSHA256 string,
) error {
	if service != nil {
		if !prepareTUIBackendRevision(state, service) {
			return errors.New("backend revision is unavailable")
		}
		var status tuiServiceStatus
		var err error
		if expectedSHA256 == "" {
			status, err = service.reloadAtRevision(
				state.paths.configPath,
				state.backendRevision,
			)
		} else {
			status, err = service.reloadAtRevisionWithDigest(
				state.paths.configPath,
				state.backendRevision,
				expectedSHA256,
			)
		}
		if err != nil {
			return err
		}
		applyTUIOperationServiceStatus(state, status)
		state.snapshot.GroupOrder = loadTUIProxyGroupOrder(state.paths.configPath)
		return nil
	}
	if ownsCore {
		if message := handleSetupConfig(state.setupParams); message != "" {
			return errors.New(message)
		}
		state.snapshot.GroupOrder = loadTUIProxyGroupOrder(state.paths.configPath)
		return nil
	}
	data, err := os.ReadFile(state.paths.configPath)
	if err != nil {
		return err
	}
	if message := validateConfigBytes(data); message != "" {
		return errors.New(message)
	}
	if err := client.reloadConfigPayload(data); err != nil {
		return err
	}
	state.snapshot.GroupOrder = loadTUIProxyGroupOrder(state.paths.configPath)
	return nil
}

func persistTUISettings(path string, settings tuiSettings) error {
	writePath := path
	fileInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		writePath, err = filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
	}
	fileInfo, err = os.Stat(writePath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(writePath)
	if err != nil {
		return err
	}
	updated, err := applyTUISettingsToConfig(data, settings)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(
		filepath.Dir(writePath),
		"."+filepath.Base(writePath)+".tmp-*",
	)
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(fileInfo.Mode().Perm()); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(updated); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, writePath); err != nil {
		return err
	}
	return nil
}

func applyTUISettingsToConfig(
	data []byte,
	settings tuiSettings,
) ([]byte, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	if len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("configuration root must be a YAML mapping")
	}
	root := document.Content[0]
	setTUIYAMLScalar(root, "mode", settings.Mode, "!!str")
	setTUIYAMLScalar(root, "mixed-port", strconv.Itoa(settings.MixedPort), "!!int")
	setTUIYAMLScalar(root, "allow-lan", strconv.FormatBool(settings.AllowLAN), "!!bool")
	setTUIYAMLScalar(root, "ipv6", strconv.FormatBool(settings.IPv6), "!!bool")
	setTUIYAMLScalar(
		root,
		"unified-delay",
		strconv.FormatBool(settings.UnifiedDelay),
		"!!bool",
	)
	setTUIYAMLScalar(
		root,
		"tcp-concurrent",
		strconv.FormatBool(settings.TCPConcurrent),
		"!!bool",
	)
	setTUIYAMLScalar(root, "log-level", settings.LogLevel, "!!str")
	tun := tuiYAMLMappingValue(root, "tun")
	if tun == nil {
		root.Content = append(
			root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tun"},
			&yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"},
		)
		tun = root.Content[len(root.Content)-1]
	}
	if tun.Kind != yaml.MappingNode {
		return nil, errors.New("TUN configuration must be a YAML mapping")
	}
	setTUIYAMLScalar(tun, "enable", strconv.FormatBool(settings.TunEnabled), "!!bool")

	updated, err := yaml.Marshal(&document)
	if err != nil {
		return nil, fmt.Errorf("encode YAML: %w", err)
	}
	if message := validateConfigBytes(updated); message != "" {
		return nil, errors.New(message)
	}
	return updated, nil
}

func ensureTUIFlClashDefaults(path string) error {
	homeDir := filepath.Dir(path)
	lease, err := acquireTUIProfileLocks(homeDir, path)
	if err != nil {
		return err
	}
	defer lease.release()
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}
	if len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return errors.New("configuration root must be a YAML mapping")
	}
	root := document.Content[0]
	missingIPv6 := tuiYAMLMappingValue(root, "ipv6") == nil
	missingUnifiedDelay := tuiYAMLMappingValue(root, "unified-delay") == nil
	missingTCPConcurrent := tuiYAMLMappingValue(root, "tcp-concurrent") == nil
	if !missingIPv6 && !missingUnifiedDelay && !missingTCPConcurrent {
		return nil
	}
	settings := loadTUIConfiguredSettings(path, true)
	if settings == nil {
		return errors.New("could not load current settings")
	}
	if missingIPv6 {
		settings.IPv6 = false
	}
	if missingUnifiedDelay {
		settings.UnifiedDelay = true
	}
	if missingTCPConcurrent {
		settings.TCPConcurrent = true
	}
	return persistTUISettings(path, *settings)
}

func tuiYAMLMappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func setTUIYAMLScalar(mapping *yaml.Node, key, value, tag string) {
	node := tuiYAMLMappingValue(mapping, key)
	if node == nil {
		mapping.Content = append(
			mapping.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value},
		)
		return
	}
	node.Kind = yaml.ScalarNode
	node.Tag = tag
	node.Value = value
	node.Content = nil
}

func stageTUICoreSettings(settings tuiSettings) string {
	data, err := json.Marshal(map[string]interface{}{
		"mode":           settings.Mode,
		"mixed-port":     settings.MixedPort,
		"allow-lan":      settings.AllowLAN,
		"ipv6":           settings.IPv6,
		"unified-delay":  settings.UnifiedDelay,
		"tcp-concurrent": settings.TCPConcurrent,
		"log-level":      settings.LogLevel,
		"tun": map[string]bool{
			"enable": settings.TunEnabled,
		},
	})
	if err != nil {
		return err.Error()
	}
	return handleUpdateConfig(data)
}

func startTUIManagedCore(
	state *tuiOperationState,
	service *tuiServiceClient,
) bool {
	if state.coreRunning {
		return true
	}
	mode := strings.ToLower(state.snapshot.Settings.Mode)
	if service == nil {
		if mode == tuiSilentMode {
			state.snapshot.Status = "Silent mode requires the managed backend"
			return false
		}
		if state.snapshot.Settings.MixedPort <= 0 {
			state.snapshot.Status = "Choose a positive Proxy port before starting"
			return false
		}
		if err := ensureTUIProxyPortFree(state.snapshot.Settings.MixedPort); err != nil {
			state.snapshot.Status = "Cannot start: " + err.Error()
			return false
		}
	}
	port := state.snapshot.Settings.MixedPort
	if state.stagedSettings != nil && state.settingsDirty {
		if service != nil {
			if !prepareTUIBackendRevision(state, service) {
				return false
			}
			profileSettings, profileErr := tuiProfileSettingsForCommit(
				state,
				*state.stagedSettings,
			)
			if profileErr != nil {
				state.snapshot.Status = "Cannot commit staged settings: " + profileErr.Error()
				return false
			}
			status, err := service.applySettings(
				profileSettings,
				state.backendRevision,
			)
			if err != nil {
				state.snapshot.Status = "Cannot commit staged settings: " + err.Error()
				return false
			}
			applyTUIOperationServiceStatus(state, status)
		}
		if service == nil {
			if message := stageTUICoreSettings(*state.stagedSettings); message != "" {
				state.snapshot.Status = "Cannot apply staged settings: " + message
				return false
			}
		}
	}
	if service != nil {
		if !prepareTUIBackendRevision(state, service) {
			return false
		}
		status, err := service.startAtRevision(state.backendRevision)
		if err != nil {
			state.snapshot.Status = "Cannot start core listeners: " + err.Error()
			return false
		}
		applyTUIOperationServiceStatus(state, status)
	} else if !handleStartListener() {
		state.snapshot.Status = "Cannot start core listeners"
		return false
	}
	state.coreRunning = true
	state.pendingMixedPort = nil
	state.stagedSettings = nil
	state.settingsDirty = false
	if mode == tuiSilentMode {
		if outbound := strings.TrimSpace(state.snapshot.FLCOutbound); outbound != "" {
			state.snapshot.Status = "Core started in silent mode · FLC " + outbound + " · only flc uses the private listener"
		} else {
			state.snapshot.Status = "Core started in silent mode; only flc uses the private listener"
		}
	} else {
		state.snapshot.Status = fmt.Sprintf("Core listeners started on port %d", port)
	}
	return true
}

func stopTUIManagedCore(
	state *tuiOperationState,
	service *tuiServiceClient,
) bool {
	if !state.coreRunning {
		return true
	}
	if service != nil {
		if !prepareTUIBackendRevision(state, service) {
			return false
		}
		status, err := service.stopAtRevision(state.backendRevision)
		if err != nil {
			state.snapshot.Status = "Cannot stop core listeners: " + err.Error()
			return false
		}
		applyTUIOperationServiceStatus(state, status)
	} else if !handleStopListener() {
		state.snapshot.Status = "Cannot stop core listeners"
		return false
	}
	state.coreRunning = false
	state.snapshot.Status = "Core listeners stopped"
	syncStoppedTUISettings(state)
	return true
}

func (m *tuiModel) selectCurrent() tea.Cmd {
	switch m.snapshot.Page {
	case tuiPageDashboard:
		switch m.snapshot.SelectedDashboard {
		case tuiDashboardServiceRow:
			return m.handleKey(tuiKeyCoreToggle)
		case tuiDashboardSystemProxyRow:
			return m.handleKey(tuiKeySystemProxy)
		case tuiDashboardTunRow:
			return m.handleKey(tuiKeyTun)
		case tuiDashboardModeRow:
			return m.handleKey(tuiKeyMode)
		case tuiDashboardFLCOutboundRow:
			return m.openProxiesForFLCOutbound()
		case tuiDashboardMixedPortRow:
			m.beginInput(tuiInputMixedPort)
		case tuiDashboardDelayRow:
			return m.testDashboardDelay()
		case tuiDashboardSpeedRow:
			return m.testDashboardSpeed()
		}
	case tuiPageProxies:
		if m.snapshot.ProxyView == tuiProxyViewProviders {
			return m.startOperation(func(state *tuiOperationState) {
				updateTUIProvider(&state.snapshot, m.client)
			})
		}
		if !m.snapshot.ProxyNodeFocus {
			if m.snapshot.SelectedGroup < 0 ||
				m.snapshot.SelectedGroup >= len(m.snapshot.Groups) {
				m.snapshot.Status = "Select a proxy group first"
				return nil
			}
			m.snapshot.ProxyNodeFocus = true
			group := m.snapshot.Groups[m.snapshot.SelectedGroup]
			m.snapshot.SelectedNode = findTUIString(group.Nodes, group.Now)
			m.snapshot.Status = "Nodes in " + group.Name +
				" · ↑↓/ws select · Enter apply · Esc back"
			return nil
		}
		group := m.snapshot.Groups[m.snapshot.SelectedGroup]
		if m.snapshot.SelectedNode < 0 ||
			m.snapshot.SelectedNode >= len(group.Nodes) {
			m.snapshot.Status = "Select a proxy node before applying it"
			return nil
		}
		return m.startOperation(func(state *tuiOperationState) {
			if m.service != nil {
				selectTUIServiceProxy(state, m.service, m.client)
			} else if selectTUIProxy(
				&state.snapshot,
				m.client,
				state.paths.homeDir,
			) {
				state.networkChanged = true
			}
		})
	case tuiPageProfiles:
		if m.snapshot.SelectedRow == tuiProfileImportSubscriptionRow {
			m.beginInput(tuiInputSubscription)
			return nil
		}
		if m.snapshot.SelectedRow == tuiProfileImportFileRow {
			m.beginInput(tuiInputProfileFile)
			return nil
		}
		if m.snapshot.SelectedRow < 0 ||
			m.snapshot.SelectedRow >= len(m.snapshot.Profiles) {
			m.snapshot.Status = "Select a profile before activating it"
			return nil
		}
		if m.service == nil {
			m.snapshot.Status = "Profile activation requires the managed backend"
			return nil
		}
		return m.startOperation(func(state *tuiOperationState) {
			switchTUIServiceProfile(state, m.service, m.client)
			state.pendingMixedPort = nil
			state.stagedSettings = nil
			state.settingsDirty = false
			syncStoppedTUISettings(state)
		})
	case tuiPageSSH:
		if m.snapshot.SelectedSSH == tuiSSHCaptureRow {
			return m.beginSSHCapture()
		}
		if m.snapshot.SelectedSSH < 0 ||
			m.snapshot.SelectedSSH >= len(m.snapshot.SSHProfiles) {
			m.snapshot.Status = "Press n to add an SSH profile, or a to capture live SSH"
			return nil
		}
		profile := m.snapshot.SSHProfiles[m.snapshot.SelectedSSH]
		if profile.NeedsUsername {
			m.beginSSHForm(true)
			if m.sshFormOpen {
				m.sshFormSelected = tuiSSHFormUsernameRow
				m.snapshot.Status = "Legacy SSH profile · enter Username before connecting"
			}
			return nil
		}
		if !m.snapshot.SSHDashboardFocus {
			if profile.Connected && profile.Ready {
				m.snapshot.SSHDashboardFocus = true
				m.snapshot.Status = "SSH Dashboard focused · Enter controls selected row"
				return m.refreshSelectedSSHDashboard()
			}
			return m.runSelectedSSHAction("connect")
		}
		switch m.snapshot.SelectedSSHDetail {
		case tuiSSHDashboardTunnelRow:
			if profile.Connected && profile.Ready {
				return m.runSelectedSSHAction("disconnect")
			}
			return m.runSelectedSSHAction("connect")
		case tuiSSHDashboardDirectExitRow,
			tuiSSHDashboardManagedIPRow:
			return m.refreshSelectedSSHDashboard()
		case tuiSSHDashboardDirectRTTRow:
			return m.testSelectedSSHDelayFor(true)
		case tuiSSHDashboardDirectSpeedRow:
			return m.testSelectedSSHSpeedFor(true)
		case tuiSSHDashboardManagedRTTRow:
			return m.testSelectedSSHDelayFor(false)
		case tuiSSHDashboardManagedSpeedRow:
			return m.testSelectedSSHSpeedFor(false)
		}
	case tuiPageRequests:
		if len(matchedTUIRequestIndexes(m.snapshot)) == 0 {
			m.snapshot.Status = "No matching History entry"
			return nil
		}
		m.snapshot.HistoryDetailOpen = true
	case tuiPageConnections:
		if len(matchedTUIConnectionIndexes(m.snapshot)) == 0 {
			m.snapshot.Status = "No matching active connection"
			return nil
		}
		m.snapshot.ConnectionsDetailOpen = true
	case tuiPageLogs:
		if len(matchedTUILogIndexes(m.snapshot)) == 0 {
			m.snapshot.Status = "No matching log entry"
			return nil
		}
		m.snapshot.LogDetailOpen = true
	case tuiPageTools:
		return m.selectTUISetting(m.snapshot.SelectedTool)
	case tuiPageMaintenance:
		switch m.snapshot.SelectedMaintenance {
		case tuiMaintenanceEditConfigRow:
			return m.startEditor(m.paths.configPath)
		case tuiMaintenanceBackupRow:
			return m.runTool(1)
		case tuiMaintenanceRestoreRow:
			return m.runTool(2)
		case tuiMaintenanceGeoUpdateRow:
			return m.runTool(3)
		case tuiMaintenanceResetTrafficRow:
			return m.runTool(4)
		case tuiMaintenanceUpdateRow:
			return m.runTool(5)
		}
	}
	return nil
}

func (m *tuiModel) openProxiesForFLCOutbound() tea.Cmd {
	cmds := m.changeVisiblePage(tuiPageProxies)
	m.snapshot.SelectedMenu = int(tuiPageProxies)
	m.snapshot.FocusSidebar = false
	m.snapshot.ProxyView = tuiProxyViewGroups
	m.snapshot.SSHDashboardFocus = false
	if name := strings.TrimSpace(m.snapshot.FLCOutbound); name != "" {
		m.snapshot.SelectedGroup = findTUIGroup(m.snapshot.Groups, name)
	}
	if m.snapshot.SelectedGroup >= 0 &&
		m.snapshot.SelectedGroup < len(m.snapshot.Groups) {
		group := m.snapshot.Groups[m.snapshot.SelectedGroup]
		m.snapshot.ProxyNodeFocus = true
		m.snapshot.SelectedNode = findTUIString(group.Nodes, group.Now)
		m.snapshot.Status = "flc uses " + group.Name + " · select a node"
		return tea.Batch(cmds...)
	}
	m.snapshot.ProxyNodeFocus = false
	m.snapshot.Status = "Select a proxy node; flc follows that group"
	return tea.Batch(cmds...)
}

func selectTUIServiceProxy(
	state *tuiOperationState,
	service *tuiServiceClient,
	client controllerClient,
) {
	if state.snapshot.SelectedGroup < 0 ||
		state.snapshot.SelectedGroup >= len(state.snapshot.Groups) {
		state.snapshot.Status = "Select a proxy group before applying it"
		return
	}
	group := state.snapshot.Groups[state.snapshot.SelectedGroup]
	if state.snapshot.SelectedNode < 0 ||
		state.snapshot.SelectedNode >= len(group.Nodes) {
		state.snapshot.Status = "Select a proxy node before applying it"
		return
	}
	node := group.Nodes[state.snapshot.SelectedNode]
	if !prepareTUIBackendRevision(state, service) {
		return
	}
	status, err := service.selectProxy(group.Name, node, state.backendRevision)
	if err != nil {
		state.snapshot.Status = "Switch failed: " + err.Error()
		return
	}
	state.snapshot.Status = fmt.Sprintf(
		"Switched %s to %s · silent flc follows this group",
		group.Name,
		node,
	)
	refreshTUISnapshot(&state.snapshot, client)
	applyTUIOperationServiceStatus(state, status)
	state.networkChanged = true
}

func switchTUIServiceProfile(
	state *tuiOperationState,
	service *tuiServiceClient,
	client controllerClient,
) {
	if state.snapshot.SelectedRow < 0 ||
		state.snapshot.SelectedRow >= len(state.snapshot.Profiles) {
		state.snapshot.Status = "Select a profile before activating it"
		return
	}
	profile := state.snapshot.Profiles[state.snapshot.SelectedRow]
	if profile.Current {
		state.snapshot.Status = "Profile is already active"
		return
	}
	if message := handleValidateConfig(profile.Path); message != "" {
		state.snapshot.Status = "Profile invalid: " + message
		return
	}
	expectedSHA256, err := tuiFileSHA256(profile.Path)
	if err != nil {
		state.snapshot.Status = "Profile read failed: " + err.Error()
		return
	}
	if !prepareTUIBackendRevision(state, service) {
		return
	}
	status, err := service.reloadAtRevisionWithDigest(
		profile.Path,
		state.backendRevision,
		expectedSHA256,
	)
	if err != nil {
		state.snapshot.Status = "Profile hot-reload failed: " + err.Error()
		return
	}
	state.paths.configPath = profile.Path
	state.snapshot.GroupOrder = loadTUIProxyGroupOrder(profile.Path)
	state.snapshot.ProxyNodeFocus = false
	state.snapshot.Status = "Active profile: " + profile.Name
	refreshTUISnapshot(&state.snapshot, client)
	applyTUIOperationServiceStatus(state, status)
	state.networkChanged = true
	refreshTUIProfiles(&state.snapshot, state.paths)
}

func (m *tuiModel) selectTUISetting(index int) tea.Cmd {
	switch index {
	case tuiSettingsAllowLANRow:
		return m.handleKey(tuiKeyAllowLAN)
	case tuiSettingsIPv6Row:
		return m.handleKey(tuiKeyIPv6)
	case tuiSettingsUnifiedDelayRow:
		return m.handleKey(tuiKeyUnifiedDelay)
	case tuiSettingsTCPConcurrentRow:
		return m.handleKey(tuiKeyTCPConcurrent)
	case tuiSettingsLogLevelRow:
		return m.handleKey(tuiKeyLogLevel)
	case tuiSettingsTunScopeRow:
		return m.handleKey(tuiKeyTunScope)
	}
	return nil
}

func (m *tuiModel) runTool(index int) tea.Cmd {
	if index == 5 {
		m.snapshot.Update.Loading = true
		m.snapshot.Update.Error = ""
	}
	return m.startOperation(func(state *tuiOperationState) {
		switch index {
		case 1:
			if m.service == nil {
				state.snapshot.Status = "Backup requires the managed backend"
				return
			}
			if !prepareTUIBackendRevision(state, m.service) {
				return
			}
			status, err := m.service.backupProfile(
				state.paths.configPath,
				state.backendRevision,
			)
			if err != nil {
				state.snapshot.Status = "Backup failed: " + err.Error()
			} else {
				state.backendRevision = status.Revision
				state.snapshot.Status = "Backup created: " + filepath.Base(status.ResultPath)
			}
		case 2:
			if m.service == nil {
				state.snapshot.Status = "Restore requires the managed backend"
				return
			}
			if !prepareTUIBackendRevision(state, m.service) {
				return
			}
			status, err := m.service.restoreProfile(
				state.paths.configPath,
				state.backendRevision,
			)
			if err != nil {
				state.snapshot.Status = "Restore failed: " + err.Error()
			} else {
				applyTUIOperationServiceStatus(state, status)
				state.snapshot.Status = "Restored and hot-reloaded: " +
					filepath.Base(status.ResultPath)
				syncStoppedTUISettings(state)
			}
		case 3:
			if err := m.client.updateGeo(); err != nil {
				state.snapshot.Status = "Geo update failed: " + err.Error()
			} else {
				state.snapshot.Status = "Geo databases update started"
			}
		case 4:
			if m.ownsCore {
				handleResetTraffic()
				state.snapshot.Status = "Traffic counters reset"
			} else {
				state.snapshot.Status = "Traffic reset requires a core started by this process"
			}
		case 5:
			checkTUIUpdate(&state.snapshot)
		}
	})
}

func (m *tuiModel) testSelectedProxyDelay() tea.Cmd {
	if m.snapshot.SelectedGroup < 0 ||
		m.snapshot.SelectedGroup >= len(m.snapshot.Groups) {
		m.snapshot.Status = "Select a proxy group first"
		return nil
	}
	group := m.snapshot.Groups[m.snapshot.SelectedGroup]
	if m.snapshot.SelectedNode < 0 ||
		m.snapshot.SelectedNode >= len(group.Nodes) {
		m.snapshot.Status = "Select a proxy node first"
		return nil
	}
	groupName := group.Name
	node := group.Nodes[m.snapshot.SelectedNode]
	testURL := m.tuiDelayTestURL()
	setTUIGroupDelay(&m.snapshot, groupName, node, tuiDelayResult{Testing: true})
	return m.startOperation(func(state *tuiOperationState) {
		delay, err := testTUIProxyDelaySamples(m.client, node, testURL)
		if err != nil {
			setTUIGroupDelay(&state.snapshot, groupName, node, tuiDelayResult{Error: err.Error()})
			state.snapshot.Status = node + " delay: Timeout · " + err.Error()
			return
		}
		setTUIGroupDelay(&state.snapshot, groupName, node, delay)
		state.snapshot.Status = node + " delay: " + formatTUIDelay(delay)
	})
}

func (m *tuiModel) testSelectedProxyGroupDelays() tea.Cmd {
	if m.snapshot.SelectedGroup < 0 ||
		m.snapshot.SelectedGroup >= len(m.snapshot.Groups) {
		m.snapshot.Status = "Select a proxy group first"
		return nil
	}
	group := m.snapshot.Groups[m.snapshot.SelectedGroup]
	if len(group.Nodes) == 0 {
		m.snapshot.Status = "Selected proxy group has no nodes"
		return nil
	}
	nodes := append([]string(nil), group.Nodes...)
	testingDelays := make(map[string]tuiDelayResult, len(nodes))
	for _, node := range nodes {
		testingDelays[node] = tuiDelayResult{Testing: true}
	}
	setTUIGroupDelays(&m.snapshot, group.Name, testingDelays)
	testURL := m.tuiDelayTestURL()
	return m.startOperation(func(state *tuiOperationState) {
		delays := testTUIProxyDelays(m.client, nodes, testURL)
		successes := 0
		for _, delay := range delays {
			if delay.MedianMillis > 0 {
				successes++
			}
		}
		setTUIGroupDelays(&state.snapshot, group.Name, delays)
		state.snapshot.Status = fmt.Sprintf(
			"%s delays complete: %d/%d reachable",
			group.Name,
			successes,
			len(nodes),
		)
	})
}

func (m *tuiModel) testDashboardDelay() tea.Cmd {
	if m.service == nil {
		m.snapshot.Status = "Dashboard delay test requires the managed backend"
		return nil
	}
	m.snapshot.DashboardDelay = tuiDelayResult{Testing: true}
	mixedPort := m.snapshot.ActiveProxyPort
	testURL := m.tuiDelayTestURL()
	return m.startOperation(func(state *tuiOperationState) {
		delay, err := m.service.testRouteDelay(mixedPort, testURL)
		if err != nil {
			state.snapshot.DashboardDelay = tuiDelayResult{Error: err.Error()}
			state.snapshot.Status = "Current route delay: Timeout · " + err.Error()
			return
		}
		state.snapshot.DashboardDelay = delay
		state.snapshot.Status = "Current route delay: " + formatTUIDelay(delay)
	})
}

func (m *tuiModel) testDashboardSpeed() tea.Cmd {
	if m.service == nil {
		m.snapshot.Status = "Dashboard speed test requires the managed backend"
		return nil
	}
	m.snapshot.DashboardSpeed = tuiSpeedResult{Testing: true}
	mixedPort := m.snapshot.ActiveProxyPort
	return m.startOperation(func(state *tuiOperationState) {
		result, err := m.service.testRouteSpeed(mixedPort)
		if err != nil {
			state.snapshot.DashboardSpeed = tuiSpeedResult{Error: err.Error()}
			state.snapshot.Status = "Current route speed failed: " + err.Error()
			return
		}
		state.snapshot.DashboardSpeed = result
		state.snapshot.Status = "Current route speed: " + formatTUISpeed(result)
	})
}

func (m *tuiModel) testSelectedProxySpeed() tea.Cmd {
	if m.service == nil {
		m.snapshot.Status = "Proxy speed testing requires the managed backend"
		return nil
	}
	if m.snapshot.SelectedGroup < 0 ||
		m.snapshot.SelectedGroup >= len(m.snapshot.Groups) {
		m.snapshot.Status = "Select a proxy group first"
		return nil
	}
	group := m.snapshot.Groups[m.snapshot.SelectedGroup]
	if m.snapshot.SelectedNode < 0 ||
		m.snapshot.SelectedNode >= len(group.Nodes) {
		m.snapshot.Status = "Select a proxy node first"
		return nil
	}
	groupName := group.Name
	node := group.Nodes[m.snapshot.SelectedNode]
	setTUIGroupSpeed(
		&m.snapshot,
		groupName,
		node,
		tuiSpeedResult{Testing: true},
	)
	return m.startOperation(func(state *tuiOperationState) {
		result, err := m.service.testProxySpeed(node)
		if err != nil {
			setTUIGroupSpeed(
				&state.snapshot,
				groupName,
				node,
				tuiSpeedResult{Error: err.Error()},
			)
			state.snapshot.Status = node + " speed failed: " + err.Error()
			return
		}
		setTUIGroupSpeed(&state.snapshot, groupName, node, result)
		state.snapshot.Status = node + " speed: " + formatTUISpeed(result)
	})
}

func (m *tuiModel) testSelectedProxyGroupSpeeds() tea.Cmd {
	if m.service == nil {
		m.snapshot.Status = "Proxy speed testing requires the managed backend"
		return nil
	}
	if m.snapshot.SelectedGroup < 0 ||
		m.snapshot.SelectedGroup >= len(m.snapshot.Groups) {
		m.snapshot.Status = "Select a proxy group first"
		return nil
	}
	group := m.snapshot.Groups[m.snapshot.SelectedGroup]
	if len(group.Nodes) == 0 {
		m.snapshot.Status = "Selected proxy group has no nodes"
		return nil
	}
	nodes := append([]string(nil), group.Nodes...)
	testingSpeeds := make(map[string]tuiSpeedResult, len(nodes))
	for _, node := range nodes {
		testingSpeeds[node] = tuiSpeedResult{Testing: true}
	}
	setTUIGroupSpeeds(&m.snapshot, group.Name, testingSpeeds)
	if m.busy {
		m.snapshot.Status = "Another operation is still running"
		return nil
	}
	m.busy = true
	m.refreshInFlight = false
	m.refreshSequence++
	m.snapshot.Status = fmt.Sprintf(
		"%s speed tests: 0/%d complete · up to %d MB total",
		group.Name,
		len(nodes),
		len(nodes)*100,
	)
	return m.testNextProxyGroupSpeed(group.Name, nodes, len(nodes), 0)
}

func (m *tuiModel) testNextProxyGroupSpeed(
	groupName string,
	nodes []string,
	total,
	successes int,
) tea.Cmd {
	if len(nodes) == 0 {
		return nil
	}
	node := nodes[0]
	remaining := append([]string(nil), nodes[1:]...)
	service := m.service
	return func() tea.Msg {
		result, err := service.testProxySpeed(node)
		if err != nil {
			result = tuiSpeedResult{Error: err.Error()}
		}
		return tuiProxyGroupSpeedResultMsg{
			groupName: groupName,
			node:      node,
			result:    result,
			remaining: remaining,
			total:     total,
			successes: successes,
		}
	}
}

func (m *tuiModel) tuiDelayTestURL() string {
	testURL := "https://www.gstatic.com/generate_204"
	params := defaultSetupParams()
	if len(m.setupParams) > 0 &&
		UnmarshalJson(m.setupParams, params) == nil &&
		params.TestURL != "" {
		testURL = params.TestURL
	}
	return testURL
}

func testTUIProxyDelays(
	client controllerClient,
	nodes []string,
	testURL string,
) map[string]tuiDelayResult {
	const parallelism = 4
	delays := make(map[string]tuiDelayResult, len(nodes))
	var mutex sync.Mutex
	var waitGroup sync.WaitGroup
	limit := make(chan struct{}, parallelism)
	for _, node := range nodes {
		node := node
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			limit <- struct{}{}
			delay, err := testTUIProxyDelaySamples(client, node, testURL)
			<-limit
			if err != nil {
				delay = tuiDelayResult{Error: err.Error()}
			}
			mutex.Lock()
			delays[node] = delay
			mutex.Unlock()
		}()
	}
	waitGroup.Wait()
	return delays
}

func setTUIGroupDelay(
	snapshot *tuiSnapshot,
	groupName,
	node string,
	delay tuiDelayResult,
) {
	setTUIGroupDelays(snapshot, groupName, map[string]tuiDelayResult{node: delay})
}

func setTUIGroupDelays(
	snapshot *tuiSnapshot,
	groupName string,
	updates map[string]tuiDelayResult,
) {
	groupIndex := -1
	for index, group := range snapshot.Groups {
		if group.Name == groupName {
			groupIndex = index
			break
		}
	}
	if groupIndex < 0 {
		return
	}
	groups := append([]tuiGroup(nil), snapshot.Groups...)
	group := groups[groupIndex]
	delays := make(map[string]tuiDelayResult, len(group.Delays)+len(updates))
	for name, value := range group.Delays {
		delays[name] = value
	}
	for node, delay := range updates {
		delays[node] = delay
	}
	group.Delays = delays
	groups[groupIndex] = group
	snapshot.Groups = groups
}

func setTUIGroupSpeed(
	snapshot *tuiSnapshot,
	groupName,
	node string,
	speed tuiSpeedResult,
) {
	setTUIGroupSpeeds(
		snapshot,
		groupName,
		map[string]tuiSpeedResult{node: speed},
	)
}

func setTUIGroupSpeeds(
	snapshot *tuiSnapshot,
	groupName string,
	updates map[string]tuiSpeedResult,
) {
	groupIndex := -1
	for index, group := range snapshot.Groups {
		if group.Name == groupName {
			groupIndex = index
			break
		}
	}
	if groupIndex < 0 {
		return
	}
	groups := append([]tuiGroup(nil), snapshot.Groups...)
	group := groups[groupIndex]
	speeds := make(
		map[string]tuiSpeedResult,
		len(group.Speeds)+len(updates),
	)
	for name, value := range group.Speeds {
		speeds[name] = value
	}
	for node, speed := range updates {
		speeds[node] = speed
	}
	group.Speeds = speeds
	groups[groupIndex] = group
	snapshot.Groups = groups
}

func formatTUISpeed(result tuiSpeedResult) string {
	megabytesPerSecond := result.BytesPerSecond / 1_000_000
	megabitsPerSecond := result.BytesPerSecond * 8 / 1_000_000
	return fmt.Sprintf(
		"%.2f MB/s · %.1f Mbps",
		megabytesPerSecond,
		megabitsPerSecond,
	)
}

func (m *tuiModel) startEditor(path string) tea.Cmd {
	if m.busy {
		m.snapshot.Status = "Another operation is still running"
		return nil
	}
	if m.service == nil {
		m.snapshot.Status = "Editing shared YAML requires the managed backend"
		return nil
	}
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	info, err := os.Lstat(path)
	if err != nil {
		m.snapshot.Status = "Editor failed: " + err.Error()
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		m.snapshot.Status = "Editor failed: configuration must be a regular file"
		return nil
	}
	backup, err := os.ReadFile(path)
	if err != nil {
		m.snapshot.Status = "Editor failed: " + err.Error()
		return nil
	}
	temporary, err := os.CreateTemp("", "flclash-tui-edit-*.yaml")
	if err != nil {
		m.snapshot.Status = "Editor failed: " + err.Error()
		return nil
	}
	temporaryPath := temporary.Name()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
		m.snapshot.Status = "Editor failed: " + err.Error()
		return nil
	}
	if _, err := temporary.Write(backup); err != nil {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
		m.snapshot.Status = "Editor failed: " + err.Error()
		return nil
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		m.snapshot.Status = "Editor failed: " + err.Error()
		return nil
	}
	command := exec.Command(
		"sh",
		"-c",
		editor+" -- \"$1\"",
		"flclash-tui-editor",
		temporaryPath,
	)
	m.editorPath = path
	m.editorTempPath = temporaryPath
	m.editorBackup = tuiProfileBackup{
		data: backup,
		mode: info.Mode(),
	}
	m.busy = true
	m.snapshot.Status = "Editor open"
	return tea.ExecProcess(command, func(err error) tea.Msg {
		return tuiEditorResultMsg{err: err}
	})
}

func (m *tuiModel) runSelectedSSHAction(action string) tea.Cmd {
	return m.runSelectedSSHActionWithCredentials(action, cliSSHCredentials{})
}

func (m *tuiModel) runSelectedSSHActionWithCredentials(
	action string,
	credentials cliSSHCredentials,
) tea.Cmd {
	if m.snapshot.SelectedSSH < 0 ||
		m.snapshot.SelectedSSH >= len(m.snapshot.SSHProfiles) {
		m.snapshot.Status = "Select an SSH profile first"
		return nil
	}
	if m.busy {
		m.snapshot.Status = "Another operation is still running"
		return nil
	}
	name := m.snapshot.SSHProfiles[m.snapshot.SelectedSSH].Name
	m.busy = true
	m.snapshot.Status = "SSH " + action + " " + name + "..."
	return func() tea.Msg {
		message := tuiSSHCommandResultMsg{action: action, selectedName: name}
		switch action {
		case "connect":
			state, alreadyConnected, err := connectCLISSHProfileWithCredentials(
				name,
				credentials,
			)
			message.err = err
			if err == nil {
				prefix := "connected"
				if alreadyConnected {
					prefix = "already connected"
				} else if state.Kind == cliSSHAttachedKind {
					prefix = "attached"
				}
				message.status = fmt.Sprintf(
					"SSH %s %s · SOCKS5 127.0.0.1:%d",
					state.Name,
					prefix,
					state.Port,
				)
			}
		case "attach":
			state, alreadyConnected, err := attachCLISSHProfile(name)
			message.err = err
			if err == nil {
				prefix := "attached"
				if alreadyConnected {
					prefix = "already connected"
				}
				message.status = fmt.Sprintf(
					"SSH %s %s · SOCKS5 127.0.0.1:%d",
					state.Name,
					prefix,
					state.Port,
				)
			}
		case "disconnect":
			state, disconnected, err := disconnectCLISSHProfile(name)
			message.err = err
			if err == nil {
				if disconnected {
					message.status = "SSH " + state.Name + " disconnected"
				} else {
					message.status = "No persistent SSH tunnel is open"
				}
			}
		case "test":
			state, latency, err := testCLISSHProfile(name)
			message.err = err
			if err == nil {
				message.status = fmt.Sprintf(
					"SSH %s ready · SOCKS5 127.0.0.1:%d · handshake %s",
					state.Name,
					state.Port,
					latency,
				)
			}
		default:
			message.err = fmt.Errorf("unsupported TUI SSH action %q", action)
		}
		return message
	}
}

func (m *tuiModel) beginSSHCapture() tea.Cmd {
	if m.snapshot.FocusSidebar {
		m.snapshot.Status = "Focus SSH profiles before capturing a live session"
		return nil
	}
	profiles := append([]tuiSSHProfile(nil), m.snapshot.SSHProfiles...)
	current := m.selectedSSHName()
	m.sshCaptureGeneration++
	generation := m.sshCaptureGeneration
	m.sshCaptureOpen = true
	m.sshCaptureNames = nil
	m.sshCaptureOptions = []string{"Checking existing SSH connections… · Esc cancel"}
	m.sshCaptureSelected = 0
	return func() tea.Msg {
		result := discoverTUISSHCapture(profiles, current)
		result.generation = generation
		return result
	}
}

func discoverTUISSHCapture(profiles []tuiSSHProfile, current string) tuiSSHCaptureResultMsg {
	names := make([]string, 0, len(profiles))
	options := make([]string, 0, len(profiles))
	selected := 0
	for _, profile := range profiles {
		if profile.NeedsUsername || (profile.Connected && profile.Ready) {
			continue
		}
		candidate := normalizeCLISSHProfile(cliSSHProfile{
			Name:     profile.Name,
			Username: profile.Username,
			Host:     profile.Host,
			Port:     profile.Port,
			Jump:     profile.Jump,
			Options:  append([]string(nil), profile.Options...),
		})
		path, ok := findCLILiveSSHMaster(candidate)
		if !ok {
			continue
		}
		if current != "" && strings.EqualFold(profile.Name, current) {
			selected = len(names)
		}
		label := fmt.Sprintf("%-16s %s", profile.Name, profile.Destination)
		if profile.Jump != "" {
			label += " · via " + profile.Jump
		}
		label += " · " + path
		names = append(names, profile.Name)
		options = append(options, label)
	}
	return tuiSSHCaptureResultMsg{names: names, options: options, selected: selected}
}

func (m *tuiModel) handleSSHCapture(message tea.KeyMsg) tea.Cmd {
	key, ok := tuiKeyFromTea(message)
	if !ok {
		return nil
	}
	switch key {
	case tuiKeyUp:
		m.sshCaptureSelected = wrapTUIIndex(
			m.sshCaptureSelected,
			-1,
			len(m.sshCaptureOptions),
		)
	case tuiKeyDown:
		m.sshCaptureSelected = wrapTUIIndex(
			m.sshCaptureSelected,
			1,
			len(m.sshCaptureOptions),
		)
	case tuiKeySelect:
		if m.sshCaptureSelected < 0 ||
			m.sshCaptureSelected >= len(m.sshCaptureNames) {
			m.sshCaptureOpen = false
			m.snapshot.Status = "No live ControlMaster to capture"
			return nil
		}
		name := m.sshCaptureNames[m.sshCaptureSelected]
		m.sshCaptureOpen = false
		for index, profile := range m.snapshot.SSHProfiles {
			if strings.EqualFold(profile.Name, name) {
				m.snapshot.SelectedSSH = index
				break
			}
		}
		return m.runSelectedSSHAction("attach")
	case tuiKeyBack:
		m.sshCaptureOpen = false
		m.snapshot.Status = "SSH capture cancelled"
	case tuiKeyQuit, tuiKeyInterrupt:
		m.sshCaptureOpen = false
		return m.handleKey(key)
	}
	return nil
}

func (m *tuiModel) attachSelectedSSH() tea.Cmd {
	return m.beginSSHCapture()
}

func (m *tuiModel) selectedSSHName() string {
	if m.snapshot.SelectedSSH < 0 || m.snapshot.SelectedSSH >= len(m.snapshot.SSHProfiles) {
		return ""
	}
	return m.snapshot.SSHProfiles[m.snapshot.SelectedSSH].Name
}

func (m *tuiModel) toggleSelectedSSHDefault() tea.Cmd {
	if m.snapshot.FocusSidebar || m.snapshot.SSHDashboardFocus {
		m.snapshot.Status = "Focus SSH profiles before setting a default"
		return nil
	}
	if m.snapshot.SelectedSSH < 0 || m.snapshot.SelectedSSH >= len(m.snapshot.SSHProfiles) {
		m.snapshot.Status = "Select an SSH profile first"
		return nil
	}
	profile := m.snapshot.SSHProfiles[m.snapshot.SelectedSSH]
	name := profile.Name
	clear := profile.Default
	m.busy = true
	m.snapshot.Status = "Updating default SSH profile..."
	return func() tea.Msg {
		message := tuiSSHCommandResultMsg{action: "default", selectedName: name}
		if clear {
			message.err = setCLISSHDefault("")
			if message.err == nil {
				message.status = "Default SSH profile cleared"
			}
			return message
		}
		message.err = setCLISSHDefault(name)
		if message.err == nil {
			message.status = "Default SSH profile " + name
		}
		return message
	}
}

func (m *tuiModel) resetSelectedSSHMetrics() {
	m.snapshot.SSHNetwork = tuiNetworkInfo{}
	m.snapshot.SSHDelay = tuiDelayResult{}
	m.snapshot.SSHSpeed = tuiSpeedResult{}
	m.snapshot.SSHDirectProbe = cliSSHRemoteProbe{}
	m.snapshot.SSHDirectNetwork = tuiNetworkInfo{}
	m.snapshot.SSHDirectDelay = tuiDelayResult{}
	m.snapshot.SSHDirectSpeed = tuiSpeedResult{}
	m.snapshot.SSHTraffic = trafficSnapshot{}
	m.snapshot.SSHTrafficHistory = nil
	m.snapshot.SSHTotalTraffic = trafficSnapshot{}
	m.snapshot.SSHConnections = 0
	m.sshLastStats = cliSSHRelayStats{}
	m.sshLastStatsAt = time.Time{}
	m.sshLastStatsName = ""
}

func (m *tuiModel) refreshSelectedSSHDashboard() tea.Cmd {
	if m.snapshot.Page != tuiPageSSH ||
		m.snapshot.SelectedSSH < 0 ||
		m.snapshot.SelectedSSH >= len(m.snapshot.SSHProfiles) {
		return nil
	}
	profile := m.snapshot.SSHProfiles[m.snapshot.SelectedSSH]
	if !profile.Connected || !profile.Ready {
		return nil
	}
	return tea.Batch(
		m.pollSelectedSSHRelay(),
		m.refreshSelectedSSHNetwork(),
		m.refreshSelectedSSHDirectProbe(),
	)
}

func (m *tuiModel) pollSelectedSSHRelay() tea.Cmd {
	if m.snapshot.Page != tuiPageSSH ||
		m.snapshot.SelectedSSH < 0 ||
		m.snapshot.SelectedSSH >= len(m.snapshot.SSHProfiles) {
		return nil
	}
	profile := m.snapshot.SSHProfiles[m.snapshot.SelectedSSH]
	if !profile.Connected || !profile.Ready {
		return nil
	}
	name := m.selectedSSHName()
	if name == "" {
		return nil
	}
	return func() tea.Msg {
		message := tuiSSHRelayStatsMsg{name: name, at: time.Now()}
		state, active, err := activeCLIPersistentSSHTunnel()
		if err != nil {
			message.err = err
			return message
		}
		if !active || !strings.EqualFold(state.Name, name) {
			message.err = errors.New("SSH tunnel is disconnected")
			return message
		}
		message.stats, message.err = queryCLISSHRelay(state, "status")
		return message
	}
}

func (m *tuiModel) selectedSSHHTTPClient() (
	string,
	*nethttp.Client,
	func(),
	error,
) {
	name := m.selectedSSHName()
	if name == "" {
		return "", nil, nil, errors.New("select an SSH profile first")
	}
	profile := m.snapshot.SSHProfiles[m.snapshot.SelectedSSH]
	if !profile.Connected || !profile.Ready || profile.SocksPort < 1 {
		return name, nil, nil, errors.New("connect this SSH profile first")
	}
	client, closeClient, err := newTUISOCKSHTTPClient(profile.SocksPort)
	return name, client, closeClient, err
}

func (m *tuiModel) refreshSelectedSSHNetwork() tea.Cmd {
	return m.refreshSelectedSSHNetworkFor(false)
}

func (m *tuiModel) refreshSelectedSSHNetworkFor(direct bool) tea.Cmd {
	name, client, closeClient, err := m.selectedSSHHTTPClient()
	if err != nil {
		info := tuiNetworkInfo{Error: err.Error(), CheckedAt: time.Now()}
		if direct {
			m.snapshot.SSHDirectNetwork = info
			m.snapshot.Status = "SSH direct network detection failed: " + err.Error()
		} else {
			m.snapshot.SSHNetwork = info
			m.snapshot.Status = "SSH network detection failed: " + err.Error()
		}
		return nil
	}
	if direct {
		m.snapshot.SSHDirectNetwork.Loading = true
	} else {
		m.snapshot.SSHNetwork.Loading = true
	}
	return func() tea.Msg {
		defer closeClient()
		return tuiSSHNetworkResultMsg{
			name:   name,
			direct: direct,
			info:   detectTUINetworkWithClient(client, "SSH · "+name),
		}
	}
}

func (m *tuiModel) testSelectedSSHDelay() tea.Cmd {
	return m.testSelectedSSHDelayFor(false)
}

func (m *tuiModel) testSelectedSSHDelayFor(direct bool) tea.Cmd {
	if direct && !m.snapshot.SSHDirectProbe.DirectAllowed {
		m.snapshot.Status = "SSH direct route unavailable: " + cliDisplayValue(m.snapshot.SSHDirectProbe.Reason)
		return nil
	}
	name, client, closeClient, err := m.selectedSSHHTTPClient()
	if err != nil {
		m.snapshot.Status = "SSH route delay failed: " + err.Error()
		return nil
	}
	if direct {
		m.snapshot.SSHDirectDelay = tuiDelayResult{Testing: true}
	} else {
		m.snapshot.SSHDelay = tuiDelayResult{Testing: true}
	}
	testURL := m.tuiDelayTestURL()
	return func() tea.Msg {
		defer closeClient()
		result, testErr := runTUIRouteDelayTest(context.Background(), client, testURL)
		return tuiSSHDelayResultMsg{name: name, direct: direct, result: result, err: testErr}
	}
}

func (m *tuiModel) testSelectedSSHSpeed() tea.Cmd {
	return m.testSelectedSSHSpeedFor(false)
}

func (m *tuiModel) testSelectedSSHSpeedFor(direct bool) tea.Cmd {
	if direct && !m.snapshot.SSHDirectProbe.DirectAllowed {
		m.snapshot.Status = "SSH direct route unavailable: " + cliDisplayValue(m.snapshot.SSHDirectProbe.Reason)
		return nil
	}
	name, client, closeClient, err := m.selectedSSHHTTPClient()
	if err != nil {
		m.snapshot.Status = "SSH route speed failed: " + err.Error()
		return nil
	}
	if direct {
		m.snapshot.SSHDirectSpeed = tuiSpeedResult{Testing: true}
	} else {
		m.snapshot.SSHSpeed = tuiSpeedResult{Testing: true}
	}
	return func() tea.Msg {
		defer closeClient()
		result, testErr := runTUIDownloadSpeedTest(context.Background(), client)
		return tuiSSHSpeedResultMsg{name: name, direct: direct, result: result, err: testErr}
	}
}

func (m *tuiModel) refreshSelectedSSHDirectProbe() tea.Cmd {
	name := m.selectedSSHName()
	if name == "" {
		return nil
	}
	profile := m.snapshot.SSHProfiles[m.snapshot.SelectedSSH]
	if !profile.Connected || !profile.Ready {
		return nil
	}
	return func() tea.Msg {
		message := tuiSSHDirectProbeResultMsg{name: name}
		state, active, err := activeCLIPersistentSSHTunnel()
		if err != nil {
			message.err = err
			return message
		}
		if !active || !strings.EqualFold(state.Name, name) {
			message.err = errors.New("SSH tunnel is disconnected")
			return message
		}
		message.probe, message.err = probeCLISSHRemote(state)
		return message
	}
}

func (m *tuiModel) beginSSHCredentialPrompt(profile, identity string) {
	m.sshCredentialPromptOpen = true
	m.sshCredentialProfile = profile
	m.sshCredentialIdentity = identity
	m.sshCredentialInput = nil
	m.snapshot.Status = "Encrypted SSH private key · enter its one-time passphrase"
}

func (m *tuiModel) resetSSHCredentialPrompt() {
	for index := range m.sshCredentialInput {
		m.sshCredentialInput[index] = 0
	}
	m.sshCredentialInput = nil
	m.sshCredentialPromptOpen = false
	m.sshCredentialProfile = ""
	m.sshCredentialIdentity = ""
}

func (m *tuiModel) handleSSHCredentialPrompt(message tea.KeyMsg) tea.Cmd {
	switch message.Type {
	case tea.KeyCtrlC:
		m.resetSSHCredentialPrompt()
		return m.handleKey(tuiKeyInterrupt)
	case tea.KeyEsc:
		m.resetSSHCredentialPrompt()
		m.snapshot.Status = "SSH connection cancelled"
		return nil
	case tea.KeyEnter:
		if len(m.sshCredentialInput) == 0 {
			m.snapshot.Status = "Private key passphrase must not be empty"
			return nil
		}
		profile := m.sshCredentialProfile
		passphrase := string(m.sshCredentialInput)
		m.resetSSHCredentialPrompt()
		for index, item := range m.snapshot.SSHProfiles {
			if strings.EqualFold(item.Name, profile) {
				m.snapshot.SelectedSSH = index
				break
			}
		}
		return m.runSelectedSSHActionWithCredentials(
			"connect",
			cliSSHCredentials{IdentityPassphrase: passphrase},
		)
	case tea.KeyBackspace, tea.KeyDelete:
		if len(m.sshCredentialInput) > 0 {
			m.sshCredentialInput[len(m.sshCredentialInput)-1] = 0
			m.sshCredentialInput = m.sshCredentialInput[:len(m.sshCredentialInput)-1]
		}
	case tea.KeyCtrlU:
		for index := range m.sshCredentialInput {
			m.sshCredentialInput[index] = 0
		}
		m.sshCredentialInput = nil
	case tea.KeyRunes:
		for _, value := range message.Runes {
			if len(m.sshCredentialInput) >= 1024 {
				break
			}
			m.sshCredentialInput = append(m.sshCredentialInput, value)
		}
	}
	return nil
}

func (m *tuiModel) beginSSHForm(existing bool) {
	profile := cliSSHProfile{Port: 22}
	originalName := ""
	readOnly := false
	fingerprint := ""
	if existing {
		if m.snapshot.SelectedSSH < 0 ||
			m.snapshot.SelectedSSH >= len(m.snapshot.SSHProfiles) {
			m.snapshot.Status = "Select an SSH profile first"
			return
		}
		selected := m.snapshot.SSHProfiles[m.snapshot.SelectedSSH]
		originalName = selected.Name
		loaded, err := loadCLISSHProfile(originalName)
		if err != nil {
			m.snapshot.Status = "SSH edit failed: " + err.Error()
			return
		}
		profile = loaded
		profile.Options = append([]string(nil), loaded.Options...)
		connected, err := cliSSHProfileConnected(originalName)
		if err != nil {
			m.snapshot.Status = "SSH edit failed: " + err.Error()
			return
		}
		readOnly = connected
		fingerprint, err = cliSSHProfileFingerprint(loaded)
		if err != nil {
			m.snapshot.Status = "SSH edit failed: " + err.Error()
			return
		}
	}
	m.sshFormOpen = true
	m.sshFormExisting = existing
	m.sshFormReadOnly = readOnly
	m.sshFormOriginalName = originalName
	m.sshFormFingerprint = fingerprint
	m.sshForm = profile
	m.sshFormSelected = tuiSSHFormNameRow
	m.sshFormFieldEditing = false
	m.sshFormPassphraseChanged = false
	m.sshFormPassphraseCleared = false
	m.sshFormPassphraseConfirm = false
	m.sshFormPassphraseFirst = ""
	m.sshFormPasswordChanged = false
	m.sshFormPasswordCleared = false
	m.sshFormPasswordConfirm = false
	m.sshFormPasswordFirst = ""
	m.sshFormAddingOption = false
	m.refreshSSHFormIdentityState()
	if readOnly {
		m.snapshot.Status = "CONNECTED · READ ONLY · disconnect this SSH profile before editing"
	} else {
		m.snapshot.Status = "Local traffic → SSH host exit · ↑↓/Tab select · Enter edit/confirm · Esc cancel"
	}
}

func (m *tuiModel) resetSSHForm() {
	m.sshFormOpen = false
	m.sshFormExisting = false
	m.sshFormReadOnly = false
	m.sshFormOriginalName = ""
	m.sshFormFingerprint = ""
	m.sshForm = cliSSHProfile{}
	m.sshFormSelected = 0
	m.sshFormFieldEditing = false
	m.sshFormInput = nil
	m.sshFormCursor = 0
	m.sshFormSelectAll = false
	m.sshFormAddingOption = false
	m.sshFormPassphraseChanged = false
	m.sshFormPassphraseCleared = false
	m.sshFormPassphraseConfirm = false
	m.sshFormPassphraseFirst = ""
	m.sshFormPasswordChanged = false
	m.sshFormPasswordCleared = false
	m.sshFormPasswordConfirm = false
	m.sshFormPasswordFirst = ""
	m.sshFormIdentityKind = cliSSHIdentityNone
	m.sshFormIdentityError = ""
}

func (m *tuiModel) refreshSSHFormIdentityState() {
	m.sshFormIdentityKind = cliSSHIdentityNone
	m.sshFormIdentityError = ""
	if strings.TrimSpace(m.sshForm.Identity) == "" {
		return
	}
	kind, err := inspectCLISSHIdentity(
		m.sshForm.Identity,
		m.sshForm.IdentityPassphrase,
	)
	m.sshFormIdentityKind = kind
	if err != nil {
		m.sshFormIdentityError = err.Error()
	}
}

func (m *tuiModel) sshFormAddOptionRow() int {
	return tuiSSHFormOptionStartRow + len(m.sshForm.Options)
}

func (m *tuiModel) sshFormSaveRow() int {
	return m.sshFormAddOptionRow() + 1
}

func (m *tuiModel) sshFormDeleteRow() int {
	if !m.sshFormExisting {
		return -1
	}
	return m.sshFormSaveRow() + 1
}

func (m *tuiModel) sshFormCancelRow() int {
	if m.sshFormExisting {
		return m.sshFormSaveRow() + 2
	}
	return m.sshFormSaveRow() + 1
}

func (m *tuiModel) sshFormRowCount() int {
	return m.sshFormCancelRow() + 1
}

func (m *tuiModel) beginSSHFormFieldEdit() {
	if m.sshFormReadOnly {
		m.snapshot.Status = "CONNECTED · READ ONLY · disconnect this SSH profile before editing"
		return
	}
	if m.sshFormSelected == tuiSSHFormPassphraseRow {
		switch {
		case strings.TrimSpace(m.sshForm.Identity) == "":
			m.snapshot.Status = "Select Identity(private key) before setting a key passphrase"
			return
		case m.sshFormIdentityKind == cliSSHIdentityUnencrypted:
			m.snapshot.Status = "This private key is not encrypted; no passphrase is required"
			return
		}
	}
	value := ""
	switch m.sshFormSelected {
	case tuiSSHFormNameRow:
		value = m.sshForm.Name
	case tuiSSHFormUsernameRow:
		value = m.sshForm.Username
	case tuiSSHFormHostRow:
		value = m.sshForm.Host
	case tuiSSHFormJumpRow:
		value = m.sshForm.Jump
	case tuiSSHFormPortRow:
		value = strconv.Itoa(m.sshForm.Port)
	case tuiSSHFormLocalPortRow:
		value = "auto"
		if m.sshForm.LocalPort > 0 {
			value = strconv.Itoa(m.sshForm.LocalPort)
		}
	case tuiSSHFormIdentityRow:
		value = m.sshForm.Identity
	case tuiSSHFormPassphraseRow:
		m.sshFormPassphraseConfirm = false
		m.sshFormPassphraseFirst = ""
	case tuiSSHFormPasswordRow:
		m.sshFormPasswordConfirm = false
		m.sshFormPasswordFirst = ""
	default:
		optionIndex := m.sshFormSelected - tuiSSHFormOptionStartRow
		if optionIndex < 0 || optionIndex >= len(m.sshForm.Options) {
			return
		}
		value = m.sshForm.Options[optionIndex]
	}
	m.sshFormFieldEditing = true
	m.sshFormInput = []rune(value)
	m.sshFormCursor = len(m.sshFormInput)
	m.sshFormSelectAll = value != ""
	m.snapshot.Status = "Editing SSH field · Enter confirm · Esc cancel"
}

func (m *tuiModel) cancelSSHFormFieldEdit() {
	if m.sshFormAddingOption {
		optionIndex := m.sshFormSelected - tuiSSHFormOptionStartRow
		if optionIndex >= 0 && optionIndex < len(m.sshForm.Options) {
			m.sshForm.Options = append(
				m.sshForm.Options[:optionIndex],
				m.sshForm.Options[optionIndex+1:]...,
			)
		}
	}
	m.sshFormFieldEditing = false
	m.sshFormInput = nil
	m.sshFormCursor = 0
	m.sshFormSelectAll = false
	m.sshFormAddingOption = false
	m.sshFormPassphraseConfirm = false
	m.sshFormPassphraseFirst = ""
	m.sshFormPasswordConfirm = false
	m.sshFormPasswordFirst = ""
}

func (m *tuiModel) commitSSHFormField() bool {
	value := string(m.sshFormInput)
	switch m.sshFormSelected {
	case tuiSSHFormNameRow:
		m.sshForm.Name = strings.TrimSpace(value)
	case tuiSSHFormUsernameRow:
		m.sshForm.Username = strings.TrimSpace(value)
	case tuiSSHFormHostRow:
		m.sshForm.Host = strings.TrimSpace(value)
	case tuiSSHFormJumpRow:
		m.sshForm.Jump = strings.TrimSpace(value)
		if err := validateCLISSHJump(m.sshForm.Jump); err != nil {
			m.snapshot.Status = err.Error()
			return false
		}
	case tuiSSHFormPortRow:
		port, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || port < 1 || port > 65535 {
			m.snapshot.Status = "SSH port must be between 1 and 65535"
			return false
		}
		m.sshForm.Port = port
	case tuiSSHFormLocalPortRow:
		port, err := parseCLISSHLocalPort(value)
		if err != nil {
			m.snapshot.Status = err.Error()
			return false
		}
		m.sshForm.LocalPort = port
	case tuiSSHFormIdentityRow:
		m.sshForm.Identity = strings.TrimSpace(value)
		m.refreshSSHFormIdentityState()
	case tuiSSHFormPassphraseRow:
		if value == "" {
			m.snapshot.Status = "Private key passphrase must not be empty; press c outside editing to clear it"
			return false
		}
		if !m.sshFormPassphraseConfirm {
			m.sshFormPassphraseFirst = value
			m.sshFormPassphraseConfirm = true
			m.sshFormInput = nil
			m.sshFormCursor = 0
			m.sshFormSelectAll = false
			m.snapshot.Status = "Confirm the private key passphrase · Enter confirm · Esc cancel"
			return false
		}
		if value != m.sshFormPassphraseFirst {
			m.sshFormPassphraseConfirm = false
			m.sshFormPassphraseFirst = ""
			m.sshFormInput = nil
			m.sshFormCursor = 0
			m.snapshot.Status = "Passphrases do not match; enter the private key passphrase again"
			return false
		}
		m.sshForm.IdentityPassphrase = value
		m.sshFormPassphraseChanged = true
		m.sshFormPassphraseCleared = false
		m.refreshSSHFormIdentityState()
	case tuiSSHFormPasswordRow:
		if value == "" {
			m.snapshot.Status = "SSH password must not be empty; press c outside editing to clear it"
			return false
		}
		if !m.sshFormPasswordConfirm {
			m.sshFormPasswordFirst = value
			m.sshFormPasswordConfirm = true
			m.sshFormInput = nil
			m.sshFormCursor = 0
			m.sshFormSelectAll = false
			m.snapshot.Status = "Confirm the new SSH password · Enter confirm · Esc cancel"
			return false
		}
		if value != m.sshFormPasswordFirst {
			m.sshFormPasswordConfirm = false
			m.sshFormPasswordFirst = ""
			m.sshFormInput = nil
			m.sshFormCursor = 0
			m.snapshot.Status = "SSH passwords do not match; enter the new password again"
			return false
		}
		m.sshForm.Password = value
		m.sshFormPasswordChanged = true
		m.sshFormPasswordCleared = false
	default:
		optionIndex := m.sshFormSelected - tuiSSHFormOptionStartRow
		value = strings.TrimSpace(value)
		if optionIndex < 0 || optionIndex >= len(m.sshForm.Options) {
			return false
		}
		if err := validateCLISSHOption(value); err != nil {
			m.snapshot.Status = "SSH option invalid: " + err.Error()
			return false
		}
		m.sshForm.Options[optionIndex] = value
		m.sshFormAddingOption = false
	}
	m.cancelSSHFormFieldEdit()
	m.snapshot.Status = "SSH profile form · select Save to commit"
	return true
}

func (m *tuiModel) handleSSHForm(message tea.KeyMsg) tea.Cmd {
	if m.sshFormFieldEditing {
		return m.handleSSHFormFieldInput(message)
	}
	if message.Type == tea.KeyRunes && len(message.Runes) == 1 && message.Runes[0] == 'q' {
		m.resetSSHForm()
		return m.handleKey(tuiKeyQuit)
	}
	if m.busy {
		if message.Type == tea.KeyCtrlC {
			m.resetSSHForm()
			return m.handleKey(tuiKeyInterrupt)
		}
		m.snapshot.Status = "SSH profile save is still running"
		return nil
	}
	switch message.Type {
	case tea.KeyCtrlC:
		m.resetSSHForm()
		return m.handleKey(tuiKeyInterrupt)
	case tea.KeyEsc:
		m.resetSSHForm()
		m.snapshot.Status = "SSH profile changes cancelled"
		return nil
	case tea.KeyUp, tea.KeyShiftTab:
		m.sshFormSelected = wrapTUIIndex(
			m.sshFormSelected,
			-1,
			m.sshFormRowCount(),
		)
		return nil
	case tea.KeyDown, tea.KeyTab:
		m.sshFormSelected = wrapTUIIndex(
			m.sshFormSelected,
			1,
			m.sshFormRowCount(),
		)
		return nil
	case tea.KeyEnter:
		return m.activateSSHFormRow()
	case tea.KeyDelete:
		return m.deleteSelectedSSHFormOption()
	case tea.KeyRunes:
		if len(message.Runes) == 1 {
			switch message.Runes[0] {
			case 'c':
				if m.sshFormSelected == tuiSSHFormPassphraseRow ||
					m.sshFormSelected == tuiSSHFormPasswordRow {
					if m.sshFormReadOnly {
						m.snapshot.Status = "CONNECTED · READ ONLY · disconnect this SSH profile before editing"
						return nil
					}
					if m.sshFormSelected == tuiSSHFormPassphraseRow {
						m.sshForm.IdentityPassphrase = ""
						m.sshFormPassphraseChanged = false
						m.sshFormPassphraseCleared = true
						m.refreshSSHFormIdentityState()
						m.snapshot.Status = "Saved private key passphrase will be cleared when the form is saved"
					} else {
						m.sshForm.Password = ""
						m.sshFormPasswordChanged = false
						m.sshFormPasswordCleared = true
						m.snapshot.Status = "Saved SSH password will be cleared when the form is saved"
					}
				}
			case 'x':
				return m.deleteSelectedSSHFormOption()
			}
		}
	}
	return nil
}

func (m *tuiModel) activateSSHFormRow() tea.Cmd {
	if m.sshFormReadOnly {
		switch m.sshFormSelected {
		case m.sshFormDeleteRow():
			m.beginSSHDeleteConfirmForName(m.sshFormOriginalName)
		case m.sshFormCancelRow():
			m.resetSSHForm()
			m.snapshot.Status = "SSH profile details closed"
		default:
			m.snapshot.Status = "CONNECTED · READ ONLY · disconnect this SSH profile before editing"
		}
		return nil
	}
	switch m.sshFormSelected {
	case m.sshFormAddOptionRow():
		m.sshForm.Options = append(m.sshForm.Options, "")
		m.sshFormSelected = tuiSSHFormOptionStartRow + len(m.sshForm.Options) - 1
		m.sshFormAddingOption = true
		m.beginSSHFormFieldEdit()
		return nil
	case m.sshFormSaveRow():
		return m.saveSSHForm()
	case m.sshFormDeleteRow():
		m.beginSSHDeleteConfirmForName(m.sshFormOriginalName)
		return nil
	case m.sshFormCancelRow():
		m.resetSSHForm()
		m.snapshot.Status = "SSH profile changes cancelled"
		return nil
	default:
		m.beginSSHFormFieldEdit()
		return nil
	}
}

func (m *tuiModel) deleteSelectedSSHFormOption() tea.Cmd {
	if m.sshFormReadOnly {
		m.snapshot.Status = "CONNECTED · READ ONLY · disconnect this SSH profile before editing"
		return nil
	}
	optionIndex := m.sshFormSelected - tuiSSHFormOptionStartRow
	if optionIndex < 0 || optionIndex >= len(m.sshForm.Options) {
		return nil
	}
	m.sshForm.Options = append(
		m.sshForm.Options[:optionIndex],
		m.sshForm.Options[optionIndex+1:]...,
	)
	if m.sshFormSelected >= m.sshFormRowCount() {
		m.sshFormSelected = m.sshFormRowCount() - 1
	}
	m.snapshot.Status = "SSH option removed from the form; select Save to commit"
	return nil
}

func (m *tuiModel) saveSSHForm() tea.Cmd {
	if m.sshFormReadOnly {
		m.snapshot.Status = "CONNECTED · READ ONLY · disconnect this SSH profile before editing"
		return nil
	}
	profile := m.sshForm
	profile.Name = strings.TrimSpace(profile.Name)
	profile.Username = strings.TrimSpace(profile.Username)
	profile.Host = strings.TrimSpace(profile.Host)
	profile.Jump = strings.TrimSpace(profile.Jump)
	profile.Identity = strings.TrimSpace(profile.Identity)
	profile = normalizeCLISSHProfile(profile)
	if profile.Identity != "" {
		kind, err := inspectCLISSHIdentity(
			profile.Identity,
			profile.IdentityPassphrase,
		)
		if err != nil {
			m.snapshot.Status = "SSH private key invalid: " + err.Error()
			return nil
		}
		if kind == cliSSHIdentityUnencrypted {
			profile.IdentityPassphrase = ""
		}
	}
	if err := validateCLISSHProfile(profile); err != nil {
		m.snapshot.Status = "SSH profile invalid: " + err.Error()
		return nil
	}
	existing := m.sshFormExisting
	originalName := m.sshFormOriginalName
	expectedFingerprint := m.sshFormFingerprint
	m.busy = true
	m.snapshot.Status = "Saving SSH profile " + profile.Name + "..."
	return func() tea.Msg {
		var err error
		action := "add"
		if existing {
			action = "edit"
			err = replaceCLISSHProfile(
				originalName,
				expectedFingerprint,
				profile,
			)
		} else {
			err = addCLISSHProfile(profile)
		}
		status := ""
		if err == nil {
			status = "SSH profile " + profile.Name + " saved"
		}
		return tuiSSHCommandResultMsg{
			action:       action,
			status:       status,
			selectedName: profile.Name,
			err:          err,
		}
	}
}

func (m *tuiModel) handleSSHFormFieldInput(message tea.KeyMsg) tea.Cmd {
	switch message.Type {
	case tea.KeyCtrlC:
		m.resetSSHForm()
		return m.handleKey(tuiKeyInterrupt)
	case tea.KeyEsc:
		m.cancelSSHFormFieldEdit()
		m.snapshot.Status = "SSH field edit cancelled"
	case tea.KeyEnter:
		m.commitSSHFormField()
	case tea.KeyBackspace, tea.KeyCtrlH:
		if m.sshFormSelectAll {
			m.clearSSHFormInput()
		} else if m.sshFormCursor > 0 {
			m.sshFormInput = append(
				m.sshFormInput[:m.sshFormCursor-1],
				m.sshFormInput[m.sshFormCursor:]...,
			)
			m.sshFormCursor--
		}
	case tea.KeyDelete:
		if m.sshFormSelectAll {
			m.clearSSHFormInput()
		} else if m.sshFormCursor < len(m.sshFormInput) {
			m.sshFormInput = append(
				m.sshFormInput[:m.sshFormCursor],
				m.sshFormInput[m.sshFormCursor+1:]...,
			)
		}
	case tea.KeyLeft:
		if m.sshFormSelectAll {
			m.sshFormCursor = 0
			m.sshFormSelectAll = false
		} else if m.sshFormCursor > 0 {
			m.sshFormCursor--
		}
	case tea.KeyRight:
		if m.sshFormSelectAll {
			m.sshFormCursor = len(m.sshFormInput)
			m.sshFormSelectAll = false
		} else if m.sshFormCursor < len(m.sshFormInput) {
			m.sshFormCursor++
		}
	case tea.KeyHome, tea.KeyCtrlA:
		m.sshFormCursor = 0
		m.sshFormSelectAll = false
	case tea.KeyEnd, tea.KeyCtrlE:
		m.sshFormCursor = len(m.sshFormInput)
		m.sshFormSelectAll = false
	case tea.KeyCtrlU:
		m.clearSSHFormInput()
	case tea.KeyRunes:
		limit := 4096
		if m.sshFormSelected == tuiSSHFormNameRow {
			limit = 64
		} else if m.sshFormSelected == tuiSSHFormUsernameRow {
			limit = 128
		} else if m.sshFormSelected == tuiSSHFormHostRow {
			limit = 512
		} else if m.sshFormSelected == tuiSSHFormPortRow {
			limit = 5
		} else if m.sshFormSelected == tuiSSHFormLocalPortRow {
			limit = 5
		}
		if m.sshFormSelectAll {
			m.clearSSHFormInput()
		}
		for _, value := range message.Runes {
			if len(m.sshFormInput) >= limit {
				break
			}
			if m.sshFormSelected == tuiSSHFormPortRow && (value < '0' || value > '9') {
				continue
			}
			if m.sshFormSelected == tuiSSHFormLocalPortRow &&
				!((value >= '0' && value <= '9') ||
					(value >= 'a' && value <= 'z') ||
					(value >= 'A' && value <= 'Z')) {
				continue
			}
			m.sshFormInput = append(m.sshFormInput, 0)
			copy(
				m.sshFormInput[m.sshFormCursor+1:],
				m.sshFormInput[m.sshFormCursor:],
			)
			m.sshFormInput[m.sshFormCursor] = value
			m.sshFormCursor++
		}
	}
	return nil
}

func (m *tuiModel) clearSSHFormInput() {
	m.sshFormInput = nil
	m.sshFormCursor = 0
	m.sshFormSelectAll = false
}

func (m *tuiModel) beginSSHDeleteConfirm() {
	if m.snapshot.SelectedSSH < 0 ||
		m.snapshot.SelectedSSH >= len(m.snapshot.SSHProfiles) {
		m.snapshot.Status = "Select an SSH profile first"
		return
	}
	m.beginSSHDeleteConfirmForName(
		m.snapshot.SSHProfiles[m.snapshot.SelectedSSH].Name,
	)
}

func (m *tuiModel) beginSSHDeleteConfirmForName(name string) {
	m.sshDeleteName = name
	m.sshDeleteConfirmOpen = true
	m.snapshot.Status = "Confirm SSH profile deletion · Enter confirm · Esc cancel"
}

func (m *tuiModel) handleSSHDeleteConfirm(message tea.KeyMsg) tea.Cmd {
	switch message.Type {
	case tea.KeyCtrlC:
		m.sshDeleteConfirmOpen = false
		m.sshDeleteName = ""
		return m.handleKey(tuiKeyInterrupt)
	case tea.KeyEsc:
		m.sshDeleteConfirmOpen = false
		m.sshDeleteName = ""
		m.snapshot.Status = "SSH profile deletion cancelled"
	case tea.KeyEnter:
		name := m.sshDeleteName
		m.sshDeleteConfirmOpen = false
		m.sshDeleteName = ""
		if m.sshFormOpen {
			m.resetSSHForm()
		}
		m.busy = true
		m.snapshot.Status = "Deleting SSH profile " + name + "..."
		return func() tea.Msg {
			err := deleteCLISSHProfile(name)
			status := ""
			if err == nil {
				status = "SSH profile " + name + " deleted"
			}
			return tuiSSHCommandResultMsg{
				action: "delete",
				status: status,
				err:    err,
			}
		}
	case tea.KeyRunes:
		if len(message.Runes) == 1 && message.Runes[0] == 'q' {
			m.sshDeleteConfirmOpen = false
			m.sshDeleteName = ""
			return m.handleKey(tuiKeyQuit)
		}
	}
	return nil
}

func (m *tuiModel) beginProfileDeleteConfirm() {
	if m.snapshot.SelectedRow < 0 ||
		m.snapshot.SelectedRow >= len(m.snapshot.Profiles) {
		m.snapshot.Status = "Select a saved Profile before deleting"
		return
	}
	profile := m.snapshot.Profiles[m.snapshot.SelectedRow]
	if profile.Current {
		m.snapshot.Status = "Cannot delete the active Profile; activate another one first"
		return
	}
	if m.service == nil {
		m.snapshot.Status = "Profile deletion requires the managed Backend"
		return
	}
	m.profileDeleteOpen = true
	m.profileDeletePath = profile.Path
	m.profileDeleteName = profile.Name
	m.profileDeleteKind = "local"
	if profile.SubscriptionURL != "" {
		m.profileDeleteKind = "subscription"
	}
	m.snapshot.Status = "Confirm Profile deletion · Enter confirm · Esc cancel"
}

func (m *tuiModel) resetProfileDeleteConfirm() {
	m.profileDeleteOpen = false
	m.profileDeletePath = ""
	m.profileDeleteName = ""
	m.profileDeleteKind = ""
}

func (m *tuiModel) handleProfileDeleteConfirm(message tea.KeyMsg) tea.Cmd {
	switch message.Type {
	case tea.KeyCtrlC:
		m.resetProfileDeleteConfirm()
		return m.handleKey(tuiKeyInterrupt)
	case tea.KeyEsc:
		m.resetProfileDeleteConfirm()
		m.snapshot.Status = "Profile deletion cancelled"
	case tea.KeyEnter:
		path := m.profileDeletePath
		name := m.profileDeleteName
		selected := m.snapshot.SelectedRow
		service := m.service
		m.resetProfileDeleteConfirm()
		return m.startOperation(func(state *tuiOperationState) {
			if service == nil {
				state.snapshot.Status = "Profile deletion requires the managed Backend"
				return
			}
			if !prepareTUIBackendRevision(state, service) {
				return
			}
			status, err := service.deleteProfile(path, state.backendRevision)
			if err != nil {
				state.snapshot.Status = "Profile deletion failed: " + err.Error()
				return
			}
			applyTUIOperationServiceStatus(state, status)
			refreshTUIProfiles(&state.snapshot, state.paths)
			if len(state.snapshot.Profiles) == 0 {
				state.snapshot.SelectedRow = tuiProfileImportSubscriptionRow
			} else {
				state.snapshot.SelectedRow = clampTUISelection(
					selected,
					len(state.snapshot.Profiles),
				)
			}
			state.snapshot.Status = "Profile deleted: " + name
		})
	case tea.KeyRunes:
		if len(message.Runes) == 1 && message.Runes[0] == 'q' {
			m.resetProfileDeleteConfirm()
			return m.handleKey(tuiKeyQuit)
		}
	}
	return nil
}

func (m *tuiModel) beginInput(mode tuiInputMode) {
	m.inputMode = mode
	m.inputValue = m.inputValue[:0]
	m.inputCursor = 0
	m.inputSelectAll = false
	if mode == tuiInputMixedPort {
		m.inputValue = []rune(strconv.Itoa(m.snapshot.Settings.MixedPort))
		m.inputCursor = len(m.inputValue)
		m.inputSelectAll = true
	} else if mode == tuiInputProfileName {
		name := strings.TrimSuffix(
			filepath.Base(m.renameProfilePath),
			filepath.Ext(m.renameProfilePath),
		)
		m.inputValue = []rune(name)
		m.inputCursor = len(m.inputValue)
		m.inputSelectAll = true
	} else if mode == tuiInputHistorySearch {
		m.inputValue = []rune(m.snapshot.HistoryQuery)
		m.inputCursor = len(m.inputValue)
		m.inputSelectAll = true
	} else if mode == tuiInputConnectionsSearch {
		m.inputValue = []rune(m.snapshot.ConnectionsQuery)
		m.inputCursor = len(m.inputValue)
		m.inputSelectAll = true
	} else if mode == tuiInputLogsSearch {
		m.inputValue = []rune(m.snapshot.LogsQuery)
		m.inputCursor = len(m.inputValue)
		m.inputSelectAll = true
	}
}

func (m *tuiModel) beginModeSelection() {
	m.modeSelectionOpen = true
	m.selectedMode = findTUIString(
		tuiTrafficModes,
		strings.ToLower(m.snapshot.Settings.Mode),
	)
	if m.selectedMode < 0 {
		m.selectedMode = 0
	}
	m.snapshot.Status = "Select an outbound mode"
}

func (m *tuiModel) handleModeSelection(message tea.KeyMsg) tea.Cmd {
	key, ok := tuiKeyFromTea(message)
	if !ok {
		return nil
	}
	switch key {
	case tuiKeyUp:
		m.selectedMode = wrapTUIIndex(
			m.selectedMode,
			-1,
			len(tuiTrafficModes),
		)
	case tuiKeyDown:
		m.selectedMode = wrapTUIIndex(
			m.selectedMode,
			1,
			len(tuiTrafficModes),
		)
	case tuiKeySelect:
		mode := tuiTrafficModes[m.selectedMode]
		m.modeSelectionOpen = false
		return m.changeMode(mode)
	case tuiKeyBack:
		m.modeSelectionOpen = false
		m.snapshot.Status = "Mode selection cancelled"
	case tuiKeyQuit, tuiKeyInterrupt:
		m.modeSelectionOpen = false
		return m.handleKey(key)
	}
	return nil
}

func (m *tuiModel) changeMode(mode string) tea.Cmd {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if strings.EqualFold(mode, m.snapshot.Settings.Mode) {
		m.snapshot.Status = "Mode unchanged: " + mode
		return nil
	}
	if m.service == nil {
		if !m.ownsCore || m.coreRunning {
			m.snapshot.Status = "Mode changes require the managed backend"
			return nil
		}
		if mode == tuiSilentMode {
			m.snapshot.Status = "Silent mode requires the managed backend"
			return nil
		}
		m.stageTUIMode(mode)
		return nil
	}
	service := m.service
	command := m.startOperation(func(state *tuiOperationState) {
		if !prepareTUIBackendRevision(state, service) {
			return
		}
		status, err := service.setMode(mode, state.backendRevision)
		if err != nil {
			state.snapshot.Status = "Mode change failed: " + err.Error()
			return
		}
		applyTUIOperationServiceStatus(state, status)
		if status.Mode == tuiSilentMode {
			if outbound := strings.TrimSpace(status.FLCOutbound); outbound != "" {
				state.snapshot.Status = "Mode silent · flc follows " + outbound + " · pick nodes in Proxies"
			} else {
				state.snapshot.Status = "Mode silent · pick a node in Proxies for flc"
			}
		} else {
			state.snapshot.Status = "Mode changed to " + status.Mode
		}
		state.networkChanged = true
	})
	if command != nil {
		m.snapshot.Status = "Changing mode to " + mode + "..."
	}
	return command
}

func (m *tuiModel) stageTUIMode(mode string) {
	m.snapshot.Settings.Mode = mode
	port := m.snapshot.Settings.MixedPort
	m.pendingMixedPort = &port
	m.stagedSettings = cloneTUISettings(&m.snapshot.Settings)
	m.settingsDirty = true
	m.snapshot.Status = "Mode " + mode +
		" staged; enable System proxy or start Core to apply"
	m.persistStagedTUISettings()
}

func (m *tuiModel) beginProfileRename() {
	if m.snapshot.SelectedRow < 0 {
		m.snapshot.Status = "Select a profile file before renaming"
		return
	}
	if m.snapshot.SelectedRow >= len(m.snapshot.Profiles) {
		m.snapshot.Status = "Selected profile is no longer available"
		return
	}
	profile := m.snapshot.Profiles[m.snapshot.SelectedRow]
	if profile.Current {
		m.snapshot.Status = "Activate another profile before renaming the current one"
		return
	}
	m.renameProfilePath = profile.Path
	m.beginInput(tuiInputProfileName)
}

func (m *tuiModel) updateSelectedProfileSubscription() tea.Cmd {
	if m.snapshot.SelectedRow < 0 {
		m.snapshot.Status = "Select a profile before updating its subscription"
		return nil
	}
	if m.snapshot.SelectedRow >= len(m.snapshot.Profiles) {
		m.snapshot.Status = "Selected profile is no longer available"
		return nil
	}
	profile := m.snapshot.Profiles[m.snapshot.SelectedRow]
	sourceURL, err := loadTUISubscriptionSource(m.paths.homeDir, profile.Path)
	if err != nil {
		m.snapshot.Status = "Subscription refresh unavailable: " + err.Error()
		return nil
	}
	return m.startProfileSubscriptionUpdate(profile.Path, sourceURL)
}

func (m *tuiModel) startProfileSubscriptionUpdate(
	profilePath,
	sourceURL string,
) tea.Cmd {
	if profilePath == "" {
		m.snapshot.Status = "Update failed: selected profile path is empty"
		return nil
	}
	if m.service == nil {
		m.snapshot.Status = "Subscription updates require the managed backend"
		return nil
	}
	return m.startOperation(func(state *tuiOperationState) {
		isActive := filepath.Clean(profilePath) == filepath.Clean(state.paths.configPath)
		previous, err := os.ReadFile(profilePath)
		if err != nil {
			state.snapshot.Status = "Subscription update failed: " + err.Error()
			return
		}
		updated, err := fetchTUISubscription(sourceURL)
		if err != nil {
			state.snapshot.Status = "Subscription update failed: " + err.Error()
			return
		}
		if previousSettings := loadTUIConfiguredSettings(profilePath, true); previousSettings != nil {
			updated, err = applyTUISettingsToConfig(updated, *previousSettings)
			if err != nil {
				state.snapshot.Status = "Subscription update failed: preserve local settings: " +
					err.Error()
				return
			}
		}
		if !prepareTUIBackendRevision(state, m.service) {
			return
		}
		status, err := m.service.putProfile(
			profilePath,
			updated,
			tuiBytesSHA256(previous),
			false,
			&sourceURL,
			state.backendRevision,
		)
		if err != nil {
			state.snapshot.Status = "Subscription update failed: " + err.Error()
			return
		}
		applyTUIOperationServiceStatus(state, status)
		if isActive {
			state.snapshot.Status = "Subscription refreshed and hot-reloaded: " +
				filepath.Base(profilePath)
			syncStoppedTUISettings(state)
			state.networkChanged = true
		} else {
			state.snapshot.Status = "Subscription refreshed: " + filepath.Base(profilePath)
		}
		refreshTUIProfiles(&state.snapshot, state.paths)
		state.snapshot.SelectedRow = findTUIProfile(
			state.snapshot.Profiles,
			profilePath,
		)
		state.profileSelection = profilePath
	})
}

func (m *tuiModel) handleInput(message tea.KeyMsg) tea.Cmd {
	switch message.Type {
	case tea.KeyCtrlC:
		m.resetInput()
		return m.handleKey(tuiKeyInterrupt)
	case tea.KeyEsc:
		m.resetInput()
		m.snapshot.Status = "Input cancelled"
		return nil
	case tea.KeyEnter:
		return m.submitInput()
	case tea.KeyBackspace, tea.KeyCtrlH:
		if m.inputSelectAll {
			m.clearInputSelection()
			return nil
		}
		if m.inputCursor > 0 {
			m.inputValue = append(
				m.inputValue[:m.inputCursor-1],
				m.inputValue[m.inputCursor:]...,
			)
			m.inputCursor--
		}
		return nil
	case tea.KeyDelete:
		if m.inputSelectAll {
			m.clearInputSelection()
			return nil
		}
		if m.inputCursor < len(m.inputValue) {
			m.inputValue = append(
				m.inputValue[:m.inputCursor],
				m.inputValue[m.inputCursor+1:]...,
			)
		}
		return nil
	case tea.KeyLeft:
		if m.inputSelectAll {
			m.inputCursor = 0
			m.inputSelectAll = false
		} else if m.inputCursor > 0 {
			m.inputCursor--
		}
		return nil
	case tea.KeyRight:
		if m.inputSelectAll {
			m.inputCursor = len(m.inputValue)
			m.inputSelectAll = false
		} else if m.inputCursor < len(m.inputValue) {
			m.inputCursor++
		}
		return nil
	case tea.KeyHome, tea.KeyCtrlA:
		m.inputCursor = 0
		m.inputSelectAll = false
		return nil
	case tea.KeyEnd, tea.KeyCtrlE:
		m.inputCursor = len(m.inputValue)
		m.inputSelectAll = false
		return nil
	case tea.KeyCtrlU:
		m.clearInputSelection()
		return nil
	case tea.KeyCtrlW:
		if m.inputSelectAll {
			m.clearInputSelection()
			return nil
		}
		if len(m.inputValue) > 0 {
			start := m.inputCursor
			for start > 0 && m.inputValue[start-1] == ' ' {
				start--
			}
			for start > 0 && m.inputValue[start-1] != ' ' {
				start--
			}
			m.inputValue = append(m.inputValue[:start], m.inputValue[m.inputCursor:]...)
			m.inputCursor = start
		}
		return nil
	case tea.KeyRunes:
		limit := 4096
		if m.inputMode == tuiInputMixedPort {
			limit = 5
		} else if m.inputMode == tuiInputProfileName {
			limit = 128
		}
		if m.inputSelectAll {
			m.clearInputSelection()
		}
		for _, value := range message.Runes {
			if len(m.inputValue) >= limit {
				break
			}
			if m.inputMode != tuiInputMixedPort || value >= '0' && value <= '9' {
				m.inputValue = append(m.inputValue, 0)
				copy(m.inputValue[m.inputCursor+1:], m.inputValue[m.inputCursor:])
				m.inputValue[m.inputCursor] = value
				m.inputCursor++
			}
		}
	}
	return nil
}

func (m *tuiModel) clearInputSelection() {
	m.inputValue = m.inputValue[:0]
	m.inputCursor = 0
	m.inputSelectAll = false
}

func (m *tuiModel) resetInput() {
	m.inputMode = tuiInputNone
	m.clearInputSelection()
	m.renameProfilePath = ""
}

func (m *tuiModel) submitInput() tea.Cmd {
	value := strings.TrimSpace(string(m.inputValue))
	mode := m.inputMode
	renameProfilePath := m.renameProfilePath
	m.resetInput()
	switch mode {
	case tuiInputHistorySearch:
		m.snapshot.HistoryQuery = value
		m.snapshot.SelectedRequest = firstTUIRequestMatch(m.snapshot)
		m.snapshot.HistoryDetailOpen = false
		m.snapshot.Status = "History search updated"
		return nil
	case tuiInputConnectionsSearch:
		m.snapshot.ConnectionsQuery = value
		m.snapshot.SelectedConnection = firstTUIConnectionMatch(m.snapshot)
		m.snapshot.ConnectionsDetailOpen = false
		m.snapshot.Status = "Connections search updated"
		return nil
	case tuiInputLogsSearch:
		m.snapshot.LogsQuery = value
		m.snapshot.SelectedLog = firstTUILogMatch(m.snapshot)
		m.snapshot.LogDetailOpen = false
		m.snapshot.Status = "Log search updated"
		return nil
	case tuiInputMixedPort:
		port, err := strconv.Atoi(value)
		if err != nil || port < 0 || port > 65535 {
			m.snapshot.Status = "Port change failed: Proxy port must be a number from 0 to 65535"
			return nil
		}
		if port == m.snapshot.Settings.MixedPort {
			m.snapshot.Status = "Port unchanged"
			return nil
		}
		if m.service == nil && m.ownsCore && !m.coreRunning {
			m.pendingMixedPort = &port
			m.snapshot.Settings.MixedPort = port
			m.stagedSettings = cloneTUISettings(&m.snapshot.Settings)
			m.settingsDirty = true
			m.snapshot.Status = fmt.Sprintf(
				"Proxy port %d staged; enable System proxy or start Core to apply",
				port,
			)
			m.persistStagedTUISettings()
			return nil
		}
		if m.service == nil {
			m.snapshot.Status = "Changing the proxy port requires the managed backend"
			return nil
		}
		return m.startOperation(func(state *tuiOperationState) {
			settings := state.snapshot.Settings
			settings.MixedPort = port
			commitTUIOperationSettings(state, m.service, m.client, settings)
		})
	case tuiInputSubscription:
		if value == "" {
			m.snapshot.Status = "Profile download cancelled"
			return nil
		}
		if _, err := newTUISubscriptionRequest(value); err != nil {
			m.snapshot.Status = "Add profile failed: subscription URL must use http or https"
			return nil
		}
		if m.service == nil {
			m.snapshot.Status = "Subscription import requires the managed backend"
			return nil
		}
		return m.startOperation(func(state *tuiOperationState) {
			payload, err := fetchTUISubscriptionDetails(value)
			if err != nil {
				state.snapshot.Status = "Add profile failed: " + err.Error()
				return
			}
			if !prepareTUIBackendRevision(state, m.service) {
				return
			}
			path, err := tuiSubscriptionImportPath(state.paths.homeDir, payload)
			if err != nil {
				state.snapshot.Status = "Add profile failed: " + err.Error()
				return
			}
			status, err := m.service.putProfile(
				path,
				payload.Data,
				"",
				true,
				&value,
				state.backendRevision,
			)
			if err != nil {
				state.snapshot.Status = "Add profile failed: " + err.Error()
				return
			}
			state.backendRevision = status.Revision
			path = status.ResultPath
			state.snapshot.Status = "Subscription linked: " + payload.summary() +
				" · U refreshes from the saved URL"
			refreshTUIProfiles(&state.snapshot, state.paths)
			state.snapshot.SelectedRow = findTUIProfile(state.snapshot.Profiles, path)
			state.profileSelection = path
		})
	case tuiInputProfileFile:
		if value == "" {
			m.snapshot.Status = "Local profile import cancelled"
			return nil
		}
		if m.service == nil {
			m.snapshot.Status = "Local profile import requires the managed backend"
			return nil
		}
		payload, name, err := readTUILocalProfileDetails(value)
		if err != nil {
			m.snapshot.Status = "Import local profile failed: " + err.Error()
			appendTUILogEvent("ERROR", m.snapshot.Status)
			return nil
		}
		return m.startOperation(func(state *tuiOperationState) {
			if !prepareTUIBackendRevision(state, m.service) {
				return
			}
			path, err := nextTUIImportedProfilePath(state.paths.homeDir, name)
			if err != nil {
				state.snapshot.Status = "Import local profile failed: " + err.Error()
				return
			}
			status, err := m.service.putProfile(
				path,
				payload.Data,
				"",
				true,
				nil,
				state.backendRevision,
			)
			if err != nil {
				state.snapshot.Status = "Import local profile failed: " + err.Error()
				return
			}
			state.backendRevision = status.Revision
			path = status.ResultPath
			state.snapshot.Status = "Local profile imported: " + filepath.Base(path) +
				" · " + payload.summary()
			refreshTUIProfiles(&state.snapshot, state.paths)
			state.snapshot.SelectedRow = findTUIProfile(state.snapshot.Profiles, path)
			state.profileSelection = path
		})
	case tuiInputProfileName:
		if value == "" {
			m.snapshot.Status = "Profile rename cancelled"
			return nil
		}
		if m.service == nil {
			m.snapshot.Status = "Profile rename requires the managed backend"
			return nil
		}
		return m.startOperation(func(state *tuiOperationState) {
			if !prepareTUIBackendRevision(state, m.service) {
				return
			}
			status, err := m.service.renameProfile(
				renameProfilePath,
				value,
				state.backendRevision,
			)
			if err != nil {
				state.snapshot.Status = "Rename failed: " + err.Error()
				return
			}
			state.backendRevision = status.Revision
			newPath := status.ResultPath
			refreshTUIProfiles(&state.snapshot, state.paths)
			state.snapshot.SelectedRow = findTUIProfile(
				state.snapshot.Profiles,
				newPath,
			)
			state.profileSelection = newPath
			state.snapshot.Status = "Renamed profile to " + filepath.Base(newPath)
		})
	}
	return nil
}

func renameTUIProfile(homeDir, sourcePath, requestedName string) (string, error) {
	sourcePath = filepath.Clean(sourcePath)
	homeDir = filepath.Clean(homeDir)
	if filepath.Dir(sourcePath) != homeDir {
		return "", errors.New("profile must be in the FlClash data directory")
	}
	name := strings.TrimSpace(requestedName)
	if name == "" || name == "." || name == ".." {
		return "", errors.New("profile name cannot be empty")
	}
	if filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
		return "", errors.New("profile name cannot contain a path")
	}
	for _, value := range name {
		if value < 32 || value == 127 {
			return "", errors.New("profile name contains control characters")
		}
	}
	extension := strings.ToLower(filepath.Ext(name))
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	if stem == "" || stem == "." || stem == ".." {
		return "", errors.New("profile name cannot be empty")
	}
	if extension == "" {
		extension = strings.ToLower(filepath.Ext(sourcePath))
		if extension != ".yaml" && extension != ".yml" {
			extension = ".yaml"
		}
		name += extension
	} else if extension != ".yaml" && extension != ".yml" {
		return "", errors.New("profile name must end in .yaml or .yml")
	}
	destinationPath := filepath.Join(homeDir, name)
	if destinationPath == sourcePath {
		return sourcePath, nil
	}
	lease, err := acquireTUIProfileLocks(homeDir, sourcePath, destinationPath)
	if err != nil {
		return "", err
	}
	defer lease.release()
	if _, err := os.Lstat(destinationPath); err == nil {
		return "", fmt.Errorf("%s already exists", name)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.Rename(sourcePath, destinationPath); err != nil {
		return "", err
	}
	if err := renameTUISubscriptionSource(homeDir, sourcePath, destinationPath); err != nil {
		if rollbackErr := os.Rename(destinationPath, sourcePath); rollbackErr != nil {
			return "", fmt.Errorf(
				"save renamed subscription source: %v; file rollback failed: %w",
				err,
				rollbackErr,
			)
		}
		return "", fmt.Errorf("save renamed subscription source: %w", err)
	}
	return destinationPath, nil
}

func applyTUIMixedPort(snapshot *tuiSnapshot, client controllerClient, selectedPort int) bool {
	systemProxyEnabled := snapshot.Settings.SystemProxy
	if err := client.patchConfig(map[string]interface{}{"mixed-port": selectedPort}); err != nil {
		snapshot.Status = "Port change failed: " + err.Error()
		return false
	}
	refreshTUISnapshot(snapshot, client)
	if systemProxyEnabled {
		enableSystemProxy := snapshot.Settings.MixedPort > 0
		if err := setLinuxSystemProxy(snapshot.Settings.MixedPort, enableSystemProxy); err != nil {
			snapshot.Status = "Port changed, but system proxy update failed: " + err.Error()
			return true
		}
		snapshot.Settings.SystemProxy = enableSystemProxy
		if !enableSystemProxy {
			snapshot.Status = "Proxy port disabled; System proxy disabled"
			return true
		}
	}
	snapshot.Status = fmt.Sprintf("Proxy port changed to %d", snapshot.Settings.MixedPort)
	return true
}

func downloadTUIProfile(homeDir, value string) (string, error) {
	payload, err := fetchTUISubscriptionDetails(value)
	if err != nil {
		return "", err
	}
	path, err := tuiSubscriptionImportPath(homeDir, payload)
	if err != nil {
		return "", err
	}
	if err := writeTUIProfileAtomically(path, payload.Data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func readTUILocalProfile(value string) ([]byte, string, error) {
	payload, name, err := readTUILocalProfileDetails(value)
	return payload.Data, name, err
}

func readTUILocalProfileDetails(
	value string,
) (tuiSubscriptionPayload, string, error) {
	path := strings.TrimSpace(value)
	if path == "" {
		return tuiSubscriptionPayload{}, "", errors.New("profile path must not be empty")
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return tuiSubscriptionPayload{}, "", fmt.Errorf("resolve home directory: %w", err)
		}
		if path == "~" {
			path = homeDir
		} else {
			path = filepath.Join(homeDir, strings.TrimPrefix(path, "~/"))
		}
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return tuiSubscriptionPayload{}, "", err
	}
	info, err := os.Lstat(absolutePath)
	if err != nil {
		return tuiSubscriptionPayload{}, "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return tuiSubscriptionPayload{}, "", errors.New("profile must be a regular file, not a symlink")
	}
	name := filepath.Base(absolutePath)
	if info.Size() > tuiSubscriptionMaxBytes {
		return tuiSubscriptionPayload{}, "", fmt.Errorf(
			"profile content exceeds %d MiB",
			tuiSubscriptionMaxBytes>>20,
		)
	}
	data, err := os.ReadFile(absolutePath)
	if err != nil {
		return tuiSubscriptionPayload{}, "", err
	}
	if len(data) == 0 {
		return tuiSubscriptionPayload{}, "", errors.New("profile content must not be empty")
	}
	payload, err := normalizeTUISubscription(data)
	if err != nil {
		return tuiSubscriptionPayload{}, "", errors.New("profile is invalid: " + err.Error())
	}
	return payload, tuiImportedProfileName(name), nil
}

func tuiImportedProfileName(sourceName string) string {
	base := filepath.Base(strings.TrimSpace(sourceName))
	extension := strings.ToLower(filepath.Ext(base))
	if extension == ".yaml" || extension == ".yml" {
		return base
	}
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	if stem == "" || stem == "." || stem == ".." {
		stem = "imported-profile"
	}
	return stem + ".yaml"
}

func nextTUIImportedProfilePath(homeDir, sourceName string) (string, error) {
	extension := strings.ToLower(filepath.Ext(sourceName))
	stem := strings.TrimSuffix(filepath.Base(sourceName), filepath.Ext(sourceName))
	if extension != ".yaml" && extension != ".yml" || stem == "" {
		return "", errors.New("profile file must end in .yaml or .yml")
	}
	if isTUIRuntimeProfileName(sourceName) {
		stem = "imported-" + strings.TrimLeft(stem, ".")
	}
	for suffix := 1; suffix <= 10000; suffix++ {
		name := stem + extension
		if suffix > 1 {
			name = fmt.Sprintf("%s-%d%s", stem, suffix, extension)
		}
		path := filepath.Join(homeDir, name)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			return path, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", errors.New("could not allocate a unique profile name")
}

func fetchTUISubscription(value string) ([]byte, error) {
	payload, err := fetchTUISubscriptionDetails(value)
	return payload.Data, err
}

func fetchTUISubscriptionDetails(
	value string,
) (tuiSubscriptionPayload, error) {
	request, err := newTUISubscriptionRequest(value)
	if err != nil {
		return tuiSubscriptionPayload{}, err
	}
	client := &nethttp.Client{Timeout: 30 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return tuiSubscriptionPayload{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return tuiSubscriptionPayload{}, fmt.Errorf("subscription returned %s", response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, tuiSubscriptionMaxBytes+1))
	if err != nil {
		return tuiSubscriptionPayload{}, err
	}
	if len(data) == 0 {
		return tuiSubscriptionPayload{}, errors.New("subscription response is empty")
	}
	if len(data) > tuiSubscriptionMaxBytes {
		return tuiSubscriptionPayload{}, fmt.Errorf(
			"subscription response exceeds %d MiB",
			tuiSubscriptionMaxBytes>>20,
		)
	}
	payload, err := normalizeTUISubscription(data)
	if err != nil {
		return tuiSubscriptionPayload{}, fmt.Errorf(
			"downloaded subscription is invalid: %w",
			err,
		)
	}
	payload.FileName = tuiNewSubscriptionFileName(
		response.Header.Get("Content-Disposition"),
	)
	return payload, nil
}

func writeTUIProfileAtomically(path string, data []byte, mode os.FileMode) error {
	temp, err := os.CreateTemp(
		filepath.Dir(path),
		"."+filepath.Base(path)+".tmp-*",
	)
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(mode.Perm()); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

type tuiProfileBackup struct {
	data          []byte
	mode          os.FileMode
	updatedSHA256 string
	lock          *tuiProfileLockLease
}

func (b *tuiProfileBackup) release() {
	if b == nil || b.lock == nil {
		return
	}
	b.lock.release()
	b.lock = nil
}

func updateTUISubscriptionProfile(
	homeDir,
	path,
	sourceURL string,
) (tuiProfileBackup, error) {
	if _, err := tuiProfileStateKey(homeDir, path); err != nil {
		return tuiProfileBackup{}, err
	}
	lease, err := acquireTUIProfileLocks(homeDir, path)
	if err != nil {
		return tuiProfileBackup{}, err
	}
	releaseOnError := true
	defer func() {
		if releaseOnError {
			lease.release()
		}
	}()
	info, err := os.Lstat(path)
	if err != nil {
		return tuiProfileBackup{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return tuiProfileBackup{}, errors.New("profile must be a regular file")
	}
	previous, err := os.ReadFile(path)
	if err != nil {
		return tuiProfileBackup{}, err
	}
	previousSettings := loadTUIConfiguredSettings(path, true)
	updated, err := fetchTUISubscription(sourceURL)
	if err != nil {
		return tuiProfileBackup{}, err
	}
	if err := writeTUIProfileAtomically(path, updated, info.Mode()); err != nil {
		return tuiProfileBackup{}, err
	}
	backup := tuiProfileBackup{data: previous, mode: info.Mode(), lock: lease}
	if previousSettings != nil {
		if err := persistTUISettings(path, *previousSettings); err != nil {
			rollbackErr := restoreTUISubscriptionProfile(path, backup)
			if rollbackErr != nil {
				return tuiProfileBackup{}, fmt.Errorf(
					"preserve local settings: %v; profile rollback failed: %w",
					err,
					rollbackErr,
				)
			}
			return tuiProfileBackup{}, fmt.Errorf("preserve local settings: %w", err)
		}
	}
	updatedData, err := os.ReadFile(path)
	if err != nil {
		if rollbackErr := restoreTUISubscriptionProfile(path, backup); rollbackErr != nil {
			return tuiProfileBackup{}, fmt.Errorf(
				"read updated subscription profile: %v; profile rollback failed: %w",
				err,
				rollbackErr,
			)
		}
		return tuiProfileBackup{}, err
	}
	backup.updatedSHA256 = tuiBytesSHA256(updatedData)
	releaseOnError = false
	return backup, nil
}

func restoreTUISubscriptionProfile(path string, backup tuiProfileBackup) error {
	return writeTUIProfileAtomically(path, backup.data, backup.mode)
}

func restoreTUIProfileIfUnchanged(
	homeDir,
	path string,
	backup tuiProfileBackup,
) error {
	lease, err := acquireTUIProfileLocks(homeDir, path)
	if err != nil {
		return err
	}
	defer lease.release()
	actualSHA256, err := tuiFileSHA256(path)
	if err != nil {
		return err
	}
	if backup.updatedSHA256 == "" || actualSHA256 != backup.updatedSHA256 {
		return errors.New("profile changed concurrently")
	}
	return restoreTUISubscriptionProfile(path, backup)
}

func newTUISubscriptionRequest(value string) (*nethttp.Request, error) {
	request, err := nethttp.NewRequest(nethttp.MethodGet, value, nil)
	if err != nil ||
		(request.URL.Scheme != "http" && request.URL.Scheme != "https") {
		return nil, errors.New("subscription URL must use http or https")
	}
	request.Header.Set("User-Agent", tuiSubscriptionUserAgent)
	request.Header.Set(
		"Accept",
		"application/yaml, application/x-yaml, application/json, text/yaml, text/plain, */*",
	)
	return request, nil
}

func tuiKeyFromTea(message tea.KeyMsg) (tuiKey, bool) {
	switch message.String() {
	case "q", "Q":
		return tuiKeyQuit, true
	case "ctrl+c":
		return tuiKeyInterrupt, true
	case "ctrl+n":
		return tuiKeyNotifications, true
	case "/":
		return tuiKeySearch, true
	case "f":
		return tuiKeyFilter, true
	case "r":
		return tuiKeyRefresh, true
	case "R":
		return tuiKeyReload, true
	case "?":
		return tuiKeyHelp, true
	case "tab":
		return tuiKeyFocusNext, true
	case "shift+tab":
		return tuiKeyFocusPrevious, true
	case "up", "w":
		return tuiKeyUp, true
	case "down", "s":
		return tuiKeyDown, true
	case "pgup":
		return tuiKeyPageUp, true
	case "pgdown":
		return tuiKeyPageDown, true
	case "left":
		return tuiKeyLeft, true
	case "right":
		return tuiKeyRight, true
	case "esc":
		return tuiKeyBack, true
	case "[":
		return tuiKeyViewPrevious, true
	case "]":
		return tuiKeyViewNext, true
	case "D":
		return tuiKeyDelayTest, true
	case "A":
		return tuiKeyDelayTestAll, true
	case "enter", " ":
		return tuiKeySelect, true
	case "1":
		return tuiKeyDashboard, true
	case "2":
		return tuiKeySSH, true
	case "3":
		return tuiKeyProxies, true
	case "4":
		return tuiKeyProfiles, true
	case "5":
		return tuiKeyRequests, true
	case "6":
		return tuiKeyConnections, true
	case "7":
		return tuiKeyLogs, true
	case "8":
		return tuiKeyTools, true
	case "9":
		return tuiKeyMaintenance, true
	case "P":
		return tuiKeyProviders, true
	case "x", "X":
		return tuiKeyCloseConnections, true
	case "a":
		return tuiKeyAllowLAN, true
	case "v":
		return tuiKeyIPv6, true
	case "t":
		return tuiKeyTun, true
	case "m":
		return tuiKeyMode, true
	case "i":
		return tuiKeyLogLevel, true
	case "+", "=":
		return tuiKeyPortUp, true
	case "-":
		return tuiKeyPortDown, true
	case "p":
		return tuiKeySetPort, true
	case "S":
		return tuiKeySystemProxy, true
	case "c":
		return tuiKeyCoreToggle, true
	case "e":
		return tuiKeyEdit, true
	case "n":
		return tuiKeyNewProfile, true
	case "f2", "u":
		return tuiKeyRenameProfile, true
	case "U":
		return tuiKeyUpdateProfile, true
	case "d":
		return tuiKeyCloseConnection, true
	case "b":
		return tuiKeyBackup, true
	case "B":
		return tuiKeyRestore, true
	case "g":
		return tuiKeyGeoUpdate, true
	case "z":
		return tuiKeyResetTraffic, true
	default:
		return 0, false
	}
}
