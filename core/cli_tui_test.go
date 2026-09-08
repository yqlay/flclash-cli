//go:build linux && !cgo && cli

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestTUIFormatting(t *testing.T) {
	if got := formatBytes(0); got != "0.0 B" {
		t.Fatalf("formatBytes(0) = %q", got)
	}
	if got := formatBytes(1024 * 1024); got != "1.0 MB" {
		t.Fatalf("formatBytes(1 MiB) = %q", got)
	}
	if got := truncateTUI("abcdef", 4); got != "abc…" {
		t.Fatalf("truncateTUI = %q", got)
	}
	if got := tuiDisplayWidth("节点"); got != 4 {
		t.Fatalf("CJK display width = %d", got)
	}
	if got := tuiDisplayWidth("e\u0301"); got != 1 {
		t.Fatalf("combining display width = %d", got)
	}
	if got := tuiDisplayWidth("🚀"); got != 2 {
		t.Fatalf("emoji display width = %d", got)
	}
	longWord := "/run/user/1000/flclash/a-very-long-session-name"
	wrapped := tuiWrapText(longWord, 12)
	if strings.Join(wrapped, "") != longWord {
		t.Fatalf("wrapped long word lost content: %q", wrapped)
	}
	for _, line := range wrapped {
		if tuiDisplayWidth(line) > 12 {
			t.Fatalf("wrapped line is too wide: %q", line)
		}
	}
}

func TestTUIRenderingFitsTerminalWidth(t *testing.T) {
	paths := cliPaths{configPath: "/tmp/flclash/config.yaml"}
	for _, size := range []struct {
		width  int
		height int
	}{
		{width: 40, height: 8},
		{width: 40, height: 10},
		{width: 44, height: 10},
		{width: 50, height: 12},
		{width: 64, height: 14},
		{width: 72, height: 20},
		{width: 87, height: 21},
		{width: 88, height: 22},
		{width: 80, height: 24},
		{width: 120, height: 30},
	} {
		for page := tuiPageDashboard; page < tuiPageCount; page++ {
			snapshot := populatedTUISnapshot(page)
			var output bytes.Buffer
			drawTUIAtSize(&output, snapshot, paths, "127.0.0.1:9090", true, true, size.width, size.height)
			if strings.HasSuffix(output.String(), "\n") {
				t.Fatalf("page %d at %dx%d ends with a newline", page, size.width, size.height)
			}
			assertTUIUsesCRLF(t, output.String())
			lines := strings.Split(output.String(), "\n")
			if len(lines) != size.height {
				t.Fatalf("page %d at %dx%d has %d lines, want %d", page, size.width, size.height, len(lines), size.height)
			}
			for lineNumber, line := range lines {
				if got := tuiDisplayWidth(stripTUIANSI(line)); got != size.width {
					t.Fatalf("page %d at %dx%d line %d has width %d, want %d: %q", page, size.width, size.height, lineNumber, got, size.width, line)
				}
			}
		}
	}
}

func TestTUIRenderingFitsEveryPositiveTerminalSize(t *testing.T) {
	paths := cliPaths{configPath: "/tmp/flclash/config.yaml"}
	snapshots := make([]tuiSnapshot, 0, int(tuiPageCount))
	for page := tuiPageDashboard; page < tuiPageCount; page++ {
		snapshots = append(snapshots, populatedTUISnapshot(page))
	}
	for width := 1; width <= 160; width++ {
		for height := 1; height <= 60; height++ {
			for page, snapshot := range snapshots {
				output := renderTUIAtSize(
					snapshot,
					paths,
					"private Unix socket",
					true,
					true,
					width,
					height,
				)
				lines := strings.Split(output, "\n")
				if len(lines) != height {
					t.Fatalf(
						"page %d at %dx%d has %d lines, want %d",
						page,
						width,
						height,
						len(lines),
						height,
					)
				}
				for lineNumber, line := range lines {
					if got := tuiDisplayWidth(stripTUIANSI(line)); got != width {
						t.Fatalf(
							"page %d at %dx%d line %d has width %d, want %d",
							page,
							width,
							height,
							lineNumber,
							got,
							width,
						)
					}
				}
			}
		}
	}
}

func TestTUINotificationRenderingFitsEveryPositiveTerminalSize(t *testing.T) {
	paths := cliPaths{configPath: "/tmp/flclash/config.yaml"}
	notifications := []tuiNotification{
		{
			level:     tuiNotificationError,
			title:     "Operation failed",
			message:   strings.Repeat("Long notification 节点 error details ", 20),
			updatedAt: time.Date(2026, 8, 29, 12, 34, 56, 0, time.UTC),
		},
		{
			level:        tuiNotificationSuccess,
			title:        "Operation complete",
			message:      "Previous notification",
			updatedAt:    time.Date(2026, 8, 29, 12, 30, 0, 0, time.UTC),
			acknowledged: true,
		},
	}
	for width := 1; width <= 160; width++ {
		for height := 1; height <= 60; height++ {
			for _, detailsOpen := range []bool{false, true} {
				snapshot := populatedTUISnapshot(tuiPageDashboard)
				snapshot.Notifications = notifications
				snapshot.NotificationDetailOpen = detailsOpen
				snapshot.NotificationScroll = 3
				output := renderTUIAtSize(
					snapshot,
					paths,
					"private Unix socket",
					true,
					true,
					width,
					height,
				)
				lines := strings.Split(output, "\n")
				if len(lines) != height {
					t.Fatalf(
						"notification details=%t at %dx%d has %d lines, want %d",
						detailsOpen,
						width,
						height,
						len(lines),
						height,
					)
				}
				for lineNumber, line := range lines {
					if got := tuiDisplayWidth(stripTUIANSI(line)); got != width {
						t.Fatalf(
							"notification details=%t at %dx%d line %d has width %d, want %d: %q",
							detailsOpen,
							width,
							height,
							lineNumber,
							got,
							width,
							line,
						)
					}
				}
			}
		}
	}
}

func TestTUIProfileDeleteConfirmationOverridesCompactNavigation(t *testing.T) {
	paths := cliPaths{configPath: "/tmp/flclash/config.yaml"}
	for _, size := range []struct {
		width  int
		height int
	}{
		{width: 40, height: 10},
		{width: 64, height: 14},
		{width: 87, height: 17},
		{width: 88, height: 18},
		{width: 120, height: 30},
	} {
		snapshot := populatedTUISnapshot(tuiPageProfiles)
		snapshot.FocusSidebar = true
		snapshot.ProfileDelete = tuiProfileDeleteView{
			Open: true,
			Name: "school.yaml",
			Kind: "subscription",
		}
		output := renderTUIAtSize(
			snapshot,
			paths,
			"private Unix socket",
			true,
			true,
			size.width,
			size.height,
		)
		plain := stripTUIANSI(output)
		if !strings.Contains(plain, "Delete Profile") ||
			!strings.Contains(plain, "Delete school.yaml") {
			t.Fatalf(
				"Profile confirmation was hidden at %dx%d:\n%s",
				size.width,
				size.height,
				plain,
			)
		}
		lines := strings.Split(output, "\n")
		if len(lines) != size.height {
			t.Fatalf(
				"Profile confirmation at %dx%d has %d lines, want %d",
				size.width,
				size.height,
				len(lines),
				size.height,
			)
		}
		for lineNumber, line := range lines {
			if got := tuiDisplayWidth(stripTUIANSI(line)); got != size.width {
				t.Fatalf(
					"Profile confirmation at %dx%d line %d has width %d, want %d",
					size.width,
					size.height,
					lineNumber,
					got,
					size.width,
				)
			}
		}
	}
}

type tuiImmediateQuitModel struct{}

func (tuiImmediateQuitModel) Init() tea.Cmd {
	return tea.Quit
}

func (model tuiImmediateQuitModel) Update(tea.Msg) (tea.Model, tea.Cmd) {
	return model, nil
}

func (tuiImmediateQuitModel) View() string {
	return ""
}

func TestTUIProgramDoesNotCaptureTerminalMouse(t *testing.T) {
	var output bytes.Buffer
	options := append(
		tuiProgramOptions(),
		tea.WithInput(nil),
		tea.WithOutput(&output),
	)
	program := tea.NewProgram(tuiImmediateQuitModel{}, options...)
	if _, err := program.Run(); err != nil {
		t.Fatal(err)
	}

	rendered := output.String()
	if !strings.Contains(rendered, "\x1b[?1049h") {
		t.Fatalf("test did not observe alternate-screen startup: %q", rendered)
	}
	for _, mouseEnableSequence := range []string{
		"\x1b[?1000h",
		"\x1b[?1002h",
		"\x1b[?1003h",
	} {
		if strings.Contains(rendered, mouseEnableSequence) {
			t.Fatalf(
				"TUI enabled terminal mouse capture with %q; native text selection would be blocked",
				mouseEnableSequence,
			)
		}
	}
}

func TestTUICompactDashboardCanScrollEverySection(t *testing.T) {
	model := newTUIModel(
		controllerClient{},
		cliPaths{
			homeDir:    "/tmp/flclash",
			configPath: "/tmp/flclash/config.yaml",
		},
		nil,
		true,
	)
	model.width = 50
	model.height = 12
	model.snapshot = populatedTUISnapshot(tuiPageDashboard)
	model.snapshot.FocusSidebar = false
	model.snapshot.Frontends = []cliProcessOwner{{PID: 101}, {PID: 202}}

	first := stripTUIANSI(model.View())
	if !strings.Contains(first, "Core") ||
		!strings.Contains(first, "Live traffic") ||
		strings.Contains(first, "TUI frontends") {
		t.Fatalf("first compact viewport is wrong:\n%s", first)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	network := stripTUIANSI(model.View())
	if !strings.Contains(network, "Public IP") ||
		!strings.Contains(network, "Rule route") {
		t.Fatalf("PageDown did not reveal network section:\n%s", network)
	}
	viewports := []string{first, network}
	for count := 0; count < 6; count++ {
		_, _ = model.Update(tea.KeyMsg{Type: tea.KeyPgDown})
		viewports = append(viewports, stripTUIANSI(model.View()))
	}
	all := strings.Join(viewports, "\n")
	for _, expected := range []string{
		"Go heap",
		"Network speed",
		"TUI frontends",
		"Config",
	} {
		if !strings.Contains(all, expected) {
			t.Fatalf("compact Dashboard never revealed %q:\n%s", expected, all)
		}
	}
	last := stripTUIANSI(model.View())
	if !strings.Contains(last, "TUI frontends") ||
		!strings.Contains(last, "Config") {
		t.Fatalf("last compact viewport is inaccessible:\n%s", last)
	}

	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyDown})
	if model.snapshot.DashboardScroll != 1 {
		t.Fatalf(
			"dashboard selection was not revealed near the controls: %d",
			model.snapshot.DashboardScroll,
		)
	}
}

func TestTUICompactNavigationTracksSelectedPage(t *testing.T) {
	snapshot := populatedTUISnapshot(tuiPageTools)
	snapshot.FocusSidebar = true
	snapshot.SelectedMenu = int(tuiPageTools)
	output := stripTUIANSI(renderTUIAtSize(
		snapshot,
		cliPaths{},
		"private Unix socket",
		true,
		true,
		44,
		10,
	))
	if !strings.Contains(output, "Navigation") ||
		!strings.Contains(output, "8  Settings") ||
		!strings.Contains(output, "9  Maintenance") {
		t.Fatalf("compact navigation hid selected page:\n%s", output)
	}
}

func TestTUIEscReturnsFromEveryPageToNavigationAtEveryLayout(t *testing.T) {
	sizes := []struct {
		width  int
		height int
	}{
		{width: 40, height: 10},
		{width: 44, height: 10},
		{width: 64, height: 14},
		{width: 87, height: 17},
		{width: 88, height: 18},
		{width: 120, height: 30},
	}
	for _, size := range sizes {
		for page := tuiPageDashboard; page < tuiPageCount; page++ {
			t.Run(fmt.Sprintf("%dx%d/%s", size.width, size.height, tuiPageName(page)), func(t *testing.T) {
				model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
				model.width = size.width
				model.height = size.height
				model.snapshot = populatedTUISnapshot(page)
				model.snapshot.SelectedMenu = int(page)
				model.snapshot.FocusSidebar = false
				model.snapshot.ProxyNodeFocus = false

				_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})

				if !model.snapshot.FocusSidebar {
					t.Fatalf("Esc did not return %s to navigation: %+v", tuiPageName(page), model.snapshot)
				}
				if model.snapshot.SelectedMenu != int(page) {
					t.Fatalf(
						"navigation selection = %d after leaving %s, want %d",
						model.snapshot.SelectedMenu,
						tuiPageName(page),
						page,
					)
				}
				if size.width >= 40 &&
					size.height >= 10 &&
					(size.width < 88 || size.height < 18) {
					output := stripTUIANSI(model.View())
					if !strings.Contains(output, "Navigation") {
						t.Fatalf(
							"navigation is not visible after Esc at %dx%d:\n%s",
							size.width,
							size.height,
							output,
						)
					}
				}
			})
		}
	}
}

func TestTUIEscFollowsProxyNavigationHierarchy(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.width = 44
	model.height = 10
	model.snapshot = populatedTUISnapshot(tuiPageProxies)
	model.snapshot.SelectedMenu = int(tuiPageProxies)
	model.snapshot.FocusSidebar = false
	model.snapshot.ProxyView = tuiProxyViewGroups
	model.snapshot.ProxyNodeFocus = true

	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if model.snapshot.ProxyNodeFocus || model.snapshot.FocusSidebar {
		t.Fatalf("first Esc did not return only to proxy groups: %+v", model.snapshot)
	}

	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if !model.snapshot.FocusSidebar {
		t.Fatalf("second Esc did not return to navigation: %+v", model.snapshot)
	}
	if output := stripTUIANSI(model.View()); !strings.Contains(output, "Navigation") {
		t.Fatalf("compact navigation is not visible after second Esc:\n%s", output)
	}
}

func TestTUIExistingFrontendNoticeIsNonBlockingAndOpensDetails(t *testing.T) {
	model := newTUIModel(
		controllerClient{},
		cliPaths{},
		nil,
		true,
	)
	model.width = 100
	model.height = 30
	model.enqueueNotification(tuiNotification{
		level:   tuiNotificationInfo,
		title:   "Shared backend",
		message: "Attached to shared backend · 1 other TUI frontend: PID 123 /dev/pts/2",
	})
	output := stripTUIANSI(model.View())
	if !strings.Contains(output, "Ctrl+N details") ||
		!strings.Contains(output, "INFO") {
		t.Fatalf("frontend startup notice summary is not visible:\n%s", output)
	}
	_, _ = model.Update(tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune{'2'},
	})
	if model.snapshot.Page != tuiPageSSH || len(model.notifications) != 1 {
		t.Fatalf("notification blocked normal navigation: %+v", model.snapshot)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyCtrlN})
	details := stripTUIANSI(model.View())
	for _, expected := range []string{
		"FlClash  ·  terminal proxy manager",
		"Dashboard",
		"Notifications",
		"Shared backend",
		"PID 123",
	} {
		if !strings.Contains(details, expected) {
			t.Fatalf("framed notification details do not contain %q:\n%s", expected, details)
		}
	}
}

func TestTUINotificationReplacesProgressAndPreservesPage(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageProfiles
	model.snapshot.FocusSidebar = false
	model.enqueueNotification(tuiNotification{
		id:       "operation",
		level:    tuiNotificationInfo,
		message:  "Working...",
		progress: true,
	})
	model.enqueueNotification(tuiNotification{
		id:      "operation",
		level:   tuiNotificationSuccess,
		message: "Configuration saved and hot-reloaded",
	})
	if len(model.notifications) != 1 ||
		model.notifications[0].message != "Configuration saved and hot-reloaded" {
		t.Fatalf("progress notification was not replaced: %+v", model.notifications)
	}
	plain := stripTUIANSI(model.View())
	if !strings.Contains(plain, "Ctrl+N details") ||
		!strings.Contains(plain, "Configuration saved") {
		t.Fatalf("notification footer summary is incomplete:\n%s", plain)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyCtrlN})
	plain = stripTUIANSI(model.View())
	if !strings.Contains(plain, "Operation complete") ||
		!strings.Contains(plain, "Enter confirm · Esc close") ||
		!strings.Contains(plain, "Profiles") {
		t.Fatalf("notification details are incomplete:\n%s", plain)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !model.notifications[0].acknowledged {
		t.Fatal("Enter did not confirm the selected notification")
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if len(model.notifications) != 1 || model.notificationDetailOpen ||
		model.snapshot.Page != tuiPageProfiles ||
		model.snapshot.FocusSidebar {
		t.Fatalf("notification details changed the underlying page: %+v", model.snapshot)
	}
	if strings.Contains(stripTUIANSI(model.View()), "Ctrl+N details") {
		t.Fatal("confirmed notification remained in the footer")
	}
}

func TestTUINotificationHistoryIsBoundedAndKeepsNewestUnread(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	for index := 0; index < tuiNotificationHistoryLimit+5; index++ {
		model.enqueueNotification(tuiNotification{
			level:   tuiNotificationInfo,
			message: fmt.Sprintf("Notice %02d", index),
		})
	}
	if len(model.notifications) != tuiNotificationHistoryLimit ||
		model.notifications[0].message != "Notice 54" ||
		model.notifications[len(model.notifications)-1].message != "Notice 05" {
		t.Fatalf("notification history was not bounded newest-first: %+v", model.notifications)
	}
	model.notifications[0].acknowledged = true
	model.enqueueNotification(tuiNotification{
		level:   tuiNotificationWarning,
		message: "Notice 53",
	})
	if model.notifications[0].message != "Notice 53" ||
		model.notifications[0].acknowledged {
		t.Fatalf("duplicate notification was not refreshed as unread: %+v", model.notifications[0])
	}
}

func TestTUINotificationKeepsCompletedOperationsAndDetailScroll(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.enqueueNotification(tuiNotification{
		id:       "operation",
		level:    tuiNotificationInfo,
		message:  "First operation working",
		progress: true,
	})
	model.enqueueNotification(tuiNotification{
		id:      "operation",
		level:   tuiNotificationSuccess,
		message: "First operation complete",
	})
	if len(model.notifications) != 1 || model.notifications[0].id != "" {
		t.Fatalf("completed operation remained replaceable: %+v", model.notifications)
	}
	model.enqueueNotification(tuiNotification{
		id:       "operation",
		level:    tuiNotificationInfo,
		message:  "Second operation working",
		progress: true,
	})
	model.enqueueNotification(tuiNotification{
		id:      "operation",
		level:   tuiNotificationSuccess,
		message: "Second operation complete",
	})
	if len(model.notifications) != 2 ||
		model.notifications[0].message != "Second operation complete" ||
		model.notifications[1].message != "First operation complete" {
		t.Fatalf("successive operations did not keep separate history: %+v", model.notifications)
	}

	model.notificationDetailOpen = true
	model.notificationSelected = 1
	model.notificationScroll = 7
	model.enqueueNotification(tuiNotification{
		level:   tuiNotificationWarning,
		message: "Unrelated background warning",
	})
	if model.notificationSelected != 2 || model.notificationScroll != 7 {
		t.Fatalf(
			"background notification disturbed selected details: selected=%d scroll=%d",
			model.notificationSelected,
			model.notificationScroll,
		)
	}
}

func TestTUINotificationFooterAdaptsWithoutColorBleed(t *testing.T) {
	snapshot := tuiSnapshot{
		Notifications: []tuiNotification{{
			level:   tuiNotificationError,
			message: "A deliberately long notification message that must be truncated safely",
		}},
	}
	for _, width := range []int{40, 72, 120} {
		line := tuiNotificationFooter(
			snapshot,
			"  ←→ panel  ↑↓ move  Enter apply  q exit",
			width,
		)
		plain := stripTUIANSI(line)
		if !strings.Contains(plain, "ERROR") ||
			!strings.Contains(plain, "Ctrl+N details") {
			t.Fatalf("width %d footer notification is incomplete: %q", width, plain)
		}
		if got := tuiDisplayWidth(plain); got != width {
			t.Fatalf("width %d footer rendered at %d cells: %q", width, got, plain)
		}
		if !strings.HasSuffix(line, tuiReset) {
			t.Fatalf("width %d footer did not reset ANSI color: %q", width, line)
		}
	}
}

func TestTUINotificationDetailsSelectScrollAndRestoreInput(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.width = 70
	model.height = 16
	model.snapshot.Page = tuiPageProfiles
	model.snapshot.FocusSidebar = false
	model.inputMode = tuiInputSubscription
	model.inputValue = []rune("https://example.test/subscription")
	model.enqueueNotification(tuiNotification{
		level:   tuiNotificationWarning,
		message: strings.Repeat("older message section ", 40),
	})
	model.enqueueNotification(tuiNotification{
		level:   tuiNotificationSuccess,
		message: "newest message",
	})

	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyCtrlN})
	if !model.notificationDetailOpen || model.notificationSelected != 0 {
		t.Fatalf("Ctrl+N did not select newest unread notification: %+v", model)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyDown})
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	if model.notificationSelected != 1 || model.notificationScroll == 0 {
		t.Fatalf("notification selection or detail scrolling failed: %+v", model)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if model.notificationDetailOpen || model.inputMode != tuiInputSubscription {
		t.Fatalf("closing details did not restore input state: %+v", model)
	}
	plain := stripTUIANSI(model.View())
	if !strings.Contains(plain, "Import subscription") ||
		!strings.Contains(plain, "example.test") {
		t.Fatalf("input view was not restored after notification details:\n%s", plain)
	}
	key, ok := tuiKeyFromTea(tea.KeyMsg{Type: tea.KeyCtrlN})
	if !ok || key != tuiKeyNotifications {
		t.Fatalf("Ctrl+N key = (%v, %v)", key, ok)
	}
}

func TestTUINotificationLogsRedactSensitiveURLs(t *testing.T) {
	clearTUILogs()
	model := newTUIModel(
		controllerClient{},
		cliPaths{homeDir: "/tmp/private-flclash"},
		nil,
		true,
	)
	model.enqueueNotification(tuiNotification{
		level: tuiNotificationError,
		message: "Add profile failed: https://subscription.example/token " +
			"/tmp/private-flclash/config.yaml",
	})
	logs := cliLogSnapshot()
	if len(logs) == 0 {
		t.Fatal("notification feedback was not written to Logs")
	}
	last := logs[len(logs)-1]
	if strings.Contains(last, "subscription.example") ||
		strings.Contains(last, "/tmp/private-flclash") ||
		!strings.Contains(last, "[redacted-url]") ||
		!strings.Contains(last, "$DATA") {
		t.Fatalf("notification log was not redacted: %q", last)
	}
}

func TestTUIQuitClosesFrontendFromNotificationDetails(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.enqueueNotification(tuiNotification{
		level:   tuiNotificationInfo,
		message: "A notification is open",
	})
	model.toggleNotificationDetails()
	command := model.handleTeaKey(tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune{'q'},
	})
	if command == nil || !model.frontendExitRequested {
		t.Fatal("q did not request frontend exit from notification details")
	}
	if _, ok := command().(tea.QuitMsg); !ok {
		t.Fatal("q did not return Bubble Tea's quit message")
	}
}

func TestTUIStatusDoesNotPolluteFooter(t *testing.T) {
	snapshot := populatedTUISnapshot(tuiPageDashboard)
	snapshot.Status = "This operation failed and must not appear in the footer"
	plain := stripTUIANSI(renderTUIAtSize(
		snapshot,
		cliPaths{},
		"unix:///tmp/core.sock",
		true,
		true,
		120,
		36,
	))
	if strings.Contains(plain, snapshot.Status) {
		t.Fatalf("dynamic status leaked into the Dashboard footer:\n%s", plain)
	}
}

func TestTUIDashboardRouteTestsAreSelectable(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageDashboard
	model.snapshot.FocusSidebar = false
	model.snapshot.SelectedDashboard = tuiDashboardMixedPortRow

	model.moveSelection(1)
	if model.snapshot.SelectedDashboard != tuiDashboardDelayRow {
		t.Fatalf("Dashboard down selected %d, want route delay", model.snapshot.SelectedDashboard)
	}
	if command := model.selectCurrent(); command != nil ||
		!strings.Contains(model.snapshot.Status, "delay test") {
		t.Fatalf("Dashboard Enter did not invoke route delay: %q", model.snapshot.Status)
	}
	model.moveSelection(1)
	if model.snapshot.SelectedDashboard != tuiDashboardSpeedRow {
		t.Fatalf("Dashboard down selected %d, want route speed", model.snapshot.SelectedDashboard)
	}
	if command := model.selectCurrent(); command != nil ||
		!strings.Contains(model.snapshot.Status, "speed test") {
		t.Fatalf("Dashboard Enter did not invoke route speed: %q", model.snapshot.Status)
	}
}

func TestTUIRowStylesDoNotColorPanelBorders(t *testing.T) {
	var output strings.Builder
	tuiRow(&output, "Network", 30, true, tuiCyan)
	row := output.String()
	if !strings.HasPrefix(row, "│"+tuiSelect) ||
		!strings.HasSuffix(row, tuiReset+"│\n") {
		t.Fatalf("row styling polluted its panel borders: %q", row)
	}
}

func TestTUIFrameWriterSkipsUnchangedFrames(t *testing.T) {
	var output bytes.Buffer
	writer := &tuiFrameWriter{writer: &output}
	if _, err := writer.Write([]byte("frame")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("frame")); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "frame" {
		t.Fatalf("duplicate frame output = %q", got)
	}
	writer.invalidate()
	if _, err := writer.Write([]byte("frame")); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "frameframe" {
		t.Fatalf("invalidated frame output = %q", got)
	}
}

func TestBubbleTeaRefreshDoesNotBlockNavigation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/proxies" {
			time.Sleep(200 * time.Millisecond)
			_, _ = io.WriteString(w, `{"proxies":{
				"A":{"type":"Selector","now":"A1","all":["A1"]},
				"B":{"type":"Selector","now":"B1","all":["B1"]}
			}}`)
			return
		}
		http.NotFound(w, request)
	}))
	defer server.Close()

	model := newTUIModel(
		controllerClient{
			options: controllerOptions{address: server.URL},
			client:  server.Client(),
		},
		cliPaths{homeDir: t.TempDir()},
		nil,
		false,
	)
	model.snapshot.Page = tuiPageProxies
	model.snapshot.FocusSidebar = false
	model.snapshot.Groups = []tuiGroup{
		{Name: "A", Nodes: []string{"A1"}},
		{Name: "B", Nodes: []string{"B1"}},
	}
	refresh := model.startRefresh()
	result := make(chan tea.Msg, 1)
	go func() {
		result <- refresh()
	}()

	started := time.Now()
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyDown})
	if command != nil {
		t.Fatal("navigation unexpectedly returned a command")
	}
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("navigation blocked for %s while refresh was running", elapsed)
	}
	if model.snapshot.SelectedGroup != 1 {
		t.Fatalf("selected group = %d, want 1", model.snapshot.SelectedGroup)
	}

	message := <-result
	_, _ = model.Update(message)
	if model.snapshot.SelectedGroup != 1 {
		t.Fatalf("background refresh overwrote the current selection: %d", model.snapshot.SelectedGroup)
	}
}

func TestBubbleTeaViewLeavesTerminalControlToRenderer(t *testing.T) {
	model := newTUIModel(
		controllerClient{options: controllerOptions{address: "127.0.0.1:9090"}},
		cliPaths{configPath: "/tmp/flclash/config.yaml"},
		nil,
		false,
	)
	model.width = 80
	model.height = 24
	view := model.View()
	for _, sequence := range []string{"\x1b[H", "\x1b[2J", "\x1b[?1049h"} {
		if strings.Contains(view, sequence) {
			t.Fatalf("view contains terminal lifecycle sequence %q", sequence)
		}
	}
}

func TestBubbleTeaInputOwnsTypedCharacters(t *testing.T) {
	model := newTUIModel(
		controllerClient{},
		cliPaths{},
		nil,
		false,
	)
	model.beginInput(tuiInputSubscription)
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("https://example.test/q")})
	if command != nil {
		t.Fatal("typing unexpectedly returned a command")
	}
	if got := string(model.inputValue); got != "https://example.test/q" {
		t.Fatalf("input = %q", got)
	}
}

func TestBubbleTeaInputSupportsReplacementAndCursorEditing(t *testing.T) {
	model := newTUIModel(
		controllerClient{},
		cliPaths{},
		nil,
		false,
	)
	model.snapshot.Settings.MixedPort = 7890
	model.beginInput(tuiInputMixedPort)

	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("1")})
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("790")})
	if got := string(model.inputValue); got != "1790" {
		t.Fatalf("typing did not replace the selected port: %q", got)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyLeft})
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("8")})
	if got := string(model.inputValue); got != "1780" {
		t.Fatalf("cursor edit = %q, want 1780", got)
	}
}

func TestBubbleTeaBlocksMutatingActionsWhileBusy(t *testing.T) {
	model := newTUIModel(
		controllerClient{},
		cliPaths{},
		nil,
		true,
	)
	model.snapshot.Page = tuiPageDashboard
	model.snapshot.FocusSidebar = false
	model.snapshot.Settings.TunEnabled = false
	model.busy = true

	_, command := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	if command != nil {
		t.Fatal("busy mutation unexpectedly returned a command")
	}
	if model.snapshot.Settings.TunEnabled {
		t.Fatal("busy mutation changed the staged settings")
	}
	if !strings.Contains(model.snapshot.Status, "Operation in progress") {
		t.Fatalf("busy status = %q", model.snapshot.Status)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})

	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}})
	if model.snapshot.Page != tuiPageProfiles {
		t.Fatalf("navigation was blocked while busy: page %d", model.snapshot.Page)
	}
}

func TestTUIProfilesExposeSubscriptionImportAsSelectableRow(t *testing.T) {
	model := newTUIModel(
		controllerClient{},
		cliPaths{},
		nil,
		false,
	)
	model.snapshot.Page = tuiPageProfiles
	model.snapshot.FocusSidebar = false
	model.snapshot.Profiles = []tuiProfile{
		{Name: "config.yaml", Path: "/tmp/config.yaml"},
	}

	if model.snapshot.SelectedRow != tuiProfileImportSubscriptionRow {
		t.Fatalf("initial profile selection = %d, want import row", model.snapshot.SelectedRow)
	}
	if command := model.selectCurrent(); command != nil {
		t.Fatal("opening the subscription input unexpectedly returned a command")
	}
	if model.inputMode != tuiInputSubscription {
		t.Fatalf("input mode = %d, want subscription input", model.inputMode)
	}

	model.inputMode = tuiInputNone
	model.inputValue = nil
	moveTUIProfile(&model.snapshot, 1)
	if model.snapshot.SelectedRow != tuiProfileImportFileRow {
		t.Fatalf("down from URL import selected row %d, want file import", model.snapshot.SelectedRow)
	}
	if command := model.selectCurrent(); command != nil {
		t.Fatal("opening the local file input unexpectedly returned a command")
	}
	if model.inputMode != tuiInputProfileFile {
		t.Fatalf("input mode = %d, want local file input", model.inputMode)
	}
	model.inputMode = tuiInputNone
	moveTUIProfile(&model.snapshot, 1)
	if model.snapshot.SelectedRow != 0 {
		t.Fatalf("down from import selected row %d, want first profile", model.snapshot.SelectedRow)
	}
	moveTUIProfile(&model.snapshot, -1)
	if model.snapshot.SelectedRow != tuiProfileImportFileRow {
		t.Fatalf("up from first profile selected row %d, want file import", model.snapshot.SelectedRow)
	}
}

func TestTUIProfilesHideManagedRuntimeFiles(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	for _, name := range []string{
		"config.yaml",
		"work.yml",
		tuiSilentRuntimeConfigPrefix + "0123456789abcdef01234567.yaml",
		tuiManagedRuntimeConfigPrefix + "89abcdef0123456789abcdef.yaml",
	} {
		if err := os.WriteFile(
			filepath.Join(directory, name),
			[]byte(defaultTUIConfig),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
	}
	paths := cliPaths{homeDir: directory, configPath: configPath}
	snapshot := tuiSnapshot{SelectedRow: tuiProfileImportSubscriptionRow}
	refreshTUIProfiles(&snapshot, paths)
	if len(snapshot.Profiles) != 2 {
		t.Fatalf("TUI profiles = %+v, want only user profiles", snapshot.Profiles)
	}
	profiles, err := listCLIProfiles(paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("CLI profiles = %+v, want only user profiles", profiles)
	}
	for _, profile := range append(snapshot.Profiles, profiles...) {
		if isTUIRuntimeProfileName(profile.Name) {
			t.Fatalf("runtime profile remained visible: %s", profile.Name)
		}
	}
}

func TestTUILocalProfileImportReadsAndAllocatesSafeName(t *testing.T) {
	sourceDirectory := t.TempDir()
	homeDir := t.TempDir()
	sourcePath := filepath.Join(sourceDirectory, "office.yaml")
	if err := os.WriteFile(sourcePath, []byte(defaultTUIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(homeDir, "office.yaml"),
		[]byte(defaultTUIConfig),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	data, name, err := readTUILocalProfile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if name != "office.yaml" || string(data) != defaultTUIConfig {
		t.Fatalf("local import = %q %q", name, data)
	}
	destination, err := nextTUIImportedProfilePath(homeDir, name)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(destination) != "office-2.yaml" {
		t.Fatalf("collision destination = %s", destination)
	}
	if _, err := os.Stat(sourcePath); err != nil {
		t.Fatalf("reading local profile changed its source: %v", err)
	}
}

func TestTUIProxyPortShowsOneCurrentValue(t *testing.T) {
	snapshot := tuiSnapshot{
		Settings:        tuiSettings{Mode: tuiSilentMode, MixedPort: 7891},
		ActiveProxyPort: 45678,
		FLCEnabled:      true,
		FLCOutbound:     "PROXY",
	}
	if label := tuiProxyPortLabel(snapshot); label != "45678" {
		t.Fatalf("active unified port label = %q", label)
	}
	if label := tuiFLCOutboundLabel(snapshot); label != "PROXY · READY" {
		t.Fatalf("ready FLC label = %q", label)
	}
	snapshot.ActiveProxyPort = 0
	snapshot.FLCEnabled = false
	if label := tuiProxyPortLabel(snapshot); label != "7891" {
		t.Fatalf("stopped unified port label = %q", label)
	}
	if label := tuiFLCOutboundLabel(snapshot); label != "PROXY · WAITING FOR CORE" {
		t.Fatalf("waiting FLC label = %q", label)
	}
	snapshot.Groups = []tuiGroup{{Name: "PROXY", Now: "hk-1", Nodes: []string{"hk-1"}}}
	if label := tuiFLCOutboundLabel(snapshot); label != "PROXY → hk-1 · WAITING FOR CORE" {
		t.Fatalf("FLC label with selected node = %q", label)
	}
}

func TestTUIDashboardDefaultsToCoreRow(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	if model.snapshot.SelectedDashboard != tuiDashboardServiceRow {
		t.Fatalf(
			"default Dashboard row = %d, want Core",
			model.snapshot.SelectedDashboard,
		)
	}
}

func TestTUIDashboardFLCOutboundOpensProxies(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageDashboard
	model.snapshot.FocusSidebar = false
	model.snapshot.FLCOutbound = "PROXY"
	model.snapshot.Groups = []tuiGroup{{
		Name:  "PROXY",
		Now:   "hk-1",
		Nodes: []string{"DIRECT", "hk-1"},
	}}
	model.snapshot.SelectedDashboard = tuiDashboardFLCOutboundRow
	if command := model.selectCurrent(); command != nil {
		t.Fatal("FLC outbound row unexpectedly scheduled a backend mutation")
	}
	if model.snapshot.Page != tuiPageProxies ||
		!model.snapshot.ProxyNodeFocus ||
		model.snapshot.SelectedGroup != 0 ||
		model.snapshot.Groups[model.snapshot.SelectedGroup].Nodes[model.snapshot.SelectedNode] != "hk-1" {
		t.Fatalf("FLC row did not open Proxies on the current node: %+v", model.snapshot)
	}
}

func TestBackendRenamesProfileRequestedByFrontend(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "profile-old.yaml")
	if err := os.WriteFile(sourcePath, []byte(defaultTUIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := newTUIServiceRuntime(
		cliPaths{
			homeDir:    directory,
			configPath: filepath.Join(directory, "config.yaml"),
		},
		defaultCLITestURL,
		filepath.Join(directory, "core.sock"),
		nil,
		nil,
	)
	revision := uint64(1)
	status := runtime.handle(tuiServiceRequest{
		ProtocolVersion:  tuiServiceProtocolVersion,
		RequestID:        "rename-profile",
		ExpectedRevision: &revision,
		Action:           "rename_profile",
		ConfigPath:       sourcePath,
		NewName:          "office",
	})
	destinationPath := filepath.Join(directory, "office.yaml")
	if !status.OK || status.ResultPath != destinationPath || status.Revision != 2 {
		t.Fatalf("rename response = %+v", status)
	}
	if _, err := os.Stat(destinationPath); err != nil {
		t.Fatalf("renamed profile: %v", err)
	}
	if _, err := os.Stat(sourcePath); !os.IsNotExist(err) {
		t.Fatalf("old profile still exists: %v", err)
	}
}

func TestTUIProfileRenameRejectsUnsafeAndDuplicateNames(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.yaml")
	if err := os.WriteFile(sourcePath, []byte(defaultTUIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(directory, "existing.yaml"),
		[]byte(defaultTUIConfig),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"../outside",
		"nested/profile",
		"profile.json",
		"existing.yaml",
	} {
		if _, err := renameTUIProfile(directory, sourcePath, name); err == nil {
			t.Fatalf("unsafe or duplicate name %q was accepted", name)
		}
		if _, err := os.Stat(sourcePath); err != nil {
			t.Fatalf("failed rename removed source for %q: %v", name, err)
		}
	}
}

func TestTUIActiveProfileRenameShowsGuidance(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageProfiles
	model.snapshot.FocusSidebar = false
	model.snapshot.Profiles = []tuiProfile{{
		Name:    "config.yaml",
		Path:    "/tmp/config.yaml",
		Current: true,
	}}
	model.snapshot.SelectedRow = 0

	model.beginProfileRename()
	if model.inputMode != tuiInputNone {
		t.Fatal("active profile opened the rename input")
	}
	if !strings.Contains(model.snapshot.Status, "Activate another profile") {
		t.Fatalf("active profile guidance = %q", model.snapshot.Status)
	}
}

func TestTUIProfileRenameKeyAndHintAreVisible(t *testing.T) {
	key, ok := tuiKeyFromTea(tea.KeyMsg{Type: tea.KeyF2})
	if !ok || key != tuiKeyRenameProfile {
		t.Fatalf("F2 key = (%v, %v)", key, ok)
	}
	updateKey, ok := tuiKeyFromTea(tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune{'U'},
	})
	if !ok || updateKey != tuiKeyUpdateProfile {
		t.Fatalf("U key = (%v, %v)", updateKey, ok)
	}
	deleteKey, ok := tuiKeyFromTea(tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune{'x'},
	})
	if !ok || deleteKey != tuiKeyCloseConnections {
		t.Fatalf("x key = (%v, %v)", deleteKey, ok)
	}
	snapshot := tuiSnapshot{
		Page:         tuiPageProfiles,
		SelectedRow:  0,
		FocusSidebar: false,
		Profiles: []tuiProfile{{
			Name:            "work.yaml",
			Path:            "/tmp/work.yaml",
			SubscriptionURL: "https://example.test/subscription",
		}},
	}
	var output strings.Builder
	drawTUIProfiles(&output, snapshot, 110, 24)
	plain := stripTUIANSI(output.String())
	for _, hint := range []string{
		"U refresh",
		"F2/u rename",
		"F2 rename",
		"x delete",
	} {
		if !strings.Contains(plain, hint) {
			t.Fatalf("profiles view does not contain %q:\n%s", hint, plain)
		}
	}
	snapshot.Profiles[0].Current = true
	output.Reset()
	drawTUIProfiles(&output, snapshot, 110, 24)
	plain = stripTUIANSI(output.String())
	if !strings.Contains(plain, "x locked") {
		t.Fatalf("active Profile does not explain deletion lock:\n%s", plain)
	}
}

func TestTUIQuitKeysUseGracefulShutdownPath(t *testing.T) {
	originalExit := completeCLIExitForTUI
	completeCLIExitForTUI = func(int) error { return nil }
	t.Cleanup(func() { completeCLIExitForTUI = originalExit })
	tests := []struct {
		name              string
		key               tea.KeyMsg
		expected          tuiKey
		stopServiceOnExit bool
	}{
		{
			name:     "q exits current TUI",
			key:      tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}},
			expected: tuiKeyQuit,
		},
		{
			name:              "ctrl+c shuts down managed Backend",
			key:               tea.KeyMsg{Type: tea.KeyCtrlC},
			expected:          tuiKeyInterrupt,
			stopServiceOnExit: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, ok := tuiKeyFromTea(test.key)
			if !ok || key != test.expected {
				t.Fatalf("quit key = (%v, %v)", key, ok)
			}
			model := newTUIModel(controllerClient{}, cliPaths{}, nil, false)
			if test.stopServiceOnExit {
				model.ownsCore = true
				model.service = &tuiServiceClient{}
			}
			command := model.handleTeaKey(test.key)
			if command == nil {
				t.Fatal("quit key did not return a command")
			}
			message := command()
			if test.stopServiceOnExit {
				if _, ok := message.(tuiShutdownResultMsg); !ok {
					t.Fatalf("Ctrl+C command returned %T", message)
				}
			} else if _, ok := message.(tea.QuitMsg); !ok {
				t.Fatal("quit key did not terminate the event loop")
			}
			if model.shutdownRequested != test.stopServiceOnExit {
				t.Fatalf(
					"shutdownRequested = %t, want %t",
					model.shutdownRequested,
					test.stopServiceOnExit,
				)
			}
			if model.frontendExitRequested != !test.stopServiceOnExit {
				t.Fatalf(
					"frontendExitRequested = %t, want %t",
					model.frontendExitRequested,
					!test.stopServiceOnExit,
				)
			}
		})
	}
}

func TestTUIQuitCancelsOnlyFrontendMonitors(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	coreMemoryStopped := false
	trafficStopped := false
	model.stopCoreMemory = func() { coreMemoryStopped = true }
	model.stopTraffic = func() { trafficStopped = true }

	command := model.handleKey(tuiKeyQuit)
	if command == nil {
		t.Fatal("q did not return a quit command")
	}
	if _, ok := command().(tea.QuitMsg); !ok {
		t.Fatal("q did not terminate the TUI event loop")
	}
	if !coreMemoryStopped || !trafficStopped {
		t.Fatalf(
			"q left frontend monitors running: memory=%t traffic=%t",
			coreMemoryStopped,
			trafficStopped,
		)
	}
	if model.shutdownRequested {
		t.Fatal("q requested an owned Core shutdown")
	}
}

func TestTUIInterruptMarksOwnedLocalCoreForShutdown(t *testing.T) {
	originalExit := completeCLIExitForTUI
	completeCLIExitForTUI = func(int) error { return nil }
	t.Cleanup(func() { completeCLIExitForTUI = originalExit })
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	command := model.handleKey(tuiKeyInterrupt)
	if command == nil {
		t.Fatal("Ctrl+C did not return a quit command for an owned local Core")
	}
	if _, ok := command().(tuiShutdownResultMsg); !ok {
		t.Fatal("Ctrl+C did not run complete FlClash shutdown")
	}
	if !model.shutdownRequested || model.frontendExitRequested {
		t.Fatalf(
			"Ctrl+C lifecycle state is wrong: shutdown=%t frontendExit=%t",
			model.shutdownRequested,
			model.frontendExitRequested,
		)
	}
}

func TestTUIInterruptFromInputUsesManagedShutdownPath(t *testing.T) {
	originalExit := completeCLIExitForTUI
	completeCLIExitForTUI = func(int) error { return nil }
	t.Cleanup(func() { completeCLIExitForTUI = originalExit })
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.service = newTUIServiceClientAt(t.TempDir())
	model.beginInput(tuiInputMixedPort)
	command := model.handleInput(tea.KeyMsg{Type: tea.KeyCtrlC})
	if command == nil {
		t.Fatal("Ctrl+C in input mode did not request shutdown")
	}
	if !model.shutdownRequested || model.frontendExitRequested {
		t.Fatalf(
			"Ctrl+C in input mode used the wrong lifecycle: shutdown=%t frontend=%t",
			model.shutdownRequested,
			model.frontendExitRequested,
		)
	}
	if model.inputMode != tuiInputNone {
		t.Fatalf("Ctrl+C left input mode active: %v", model.inputMode)
	}
	if _, ok := command().(tuiShutdownResultMsg); !ok {
		t.Fatal("Ctrl+C in input mode bypassed managed Backend shutdown")
	}
}

func TestTUIInterruptSignalUsesManagedShutdownPath(t *testing.T) {
	originalExit := completeCLIExitForTUI
	completeCLIExitForTUI = func(int) error { return nil }
	t.Cleanup(func() { completeCLIExitForTUI = originalExit })
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.service = newTUIServiceClientAt(t.TempDir())
	_, command := model.Update(tuiInterruptSignalMsg{})
	if command == nil || !model.shutdownRequested {
		t.Fatal("SIGINT did not request managed Backend shutdown")
	}
	if _, ok := command().(tuiShutdownResultMsg); !ok {
		t.Fatal("SIGINT bypassed managed Backend shutdown")
	}
}

func TestTUITerminalExitSignalClosesOnlyCurrentFrontend(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	coreMemoryStopped := false
	trafficStopped := false
	model.stopCoreMemory = func() { coreMemoryStopped = true }
	model.stopTraffic = func() { trafficStopped = true }

	_, command := model.Update(tuiTerminalExitSignalMsg{})
	if command == nil {
		t.Fatal("terminal exit signal did not return a quit command")
	}
	if _, ok := command().(tea.QuitMsg); !ok {
		t.Fatal("terminal exit signal did not quit the TUI event loop")
	}
	if !model.frontendExitRequested || model.shutdownRequested {
		t.Fatalf(
			"terminal exit used wrong lifecycle: frontend=%t shutdown=%t",
			model.frontendExitRequested,
			model.shutdownRequested,
		)
	}
	if !coreMemoryStopped || !trafficStopped {
		t.Fatalf(
			"terminal exit left frontend monitors running: memory=%t traffic=%t",
			coreMemoryStopped,
			trafficStopped,
		)
	}
}

func TestTUITerminalInputReportsEOFOnlyOnce(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()
	if err := writeEnd.Close(); err != nil {
		t.Fatal(err)
	}

	terminalEOF := make(chan struct{}, 2)
	input := newTUITerminalInput(readEnd, terminalEOF)
	buffer := make([]byte, 1)
	for range 2 {
		if _, err := input.Read(buffer); err != io.EOF {
			t.Fatalf("terminal input error = %v, want EOF", err)
		}
	}

	select {
	case <-terminalEOF:
	default:
		t.Fatal("terminal input did not report EOF")
	}
	select {
	case <-terminalEOF:
		t.Fatal("terminal input reported EOF more than once")
	default:
	}
}

func TestTUIParentExitSignalChecksForStartRace(t *testing.T) {
	originalParentPID := tuiParentPID
	originalSetSignal := setTUIParentExitSignal
	t.Cleanup(func() {
		tuiParentPID = originalParentPID
		setTUIParentExitSignal = originalSetSignal
	})

	signalCalls := 0
	setTUIParentExitSignal = func() error {
		signalCalls++
		return nil
	}
	tuiParentPID = func() int { return 42 }
	if err := armTUIParentExitSignal(); err != nil {
		t.Fatalf("arm TUI parent exit signal: %v", err)
	}
	if signalCalls != 1 {
		t.Fatalf("parent exit signal calls = %d, want 1", signalCalls)
	}

	parentCalls := 0
	tuiParentPID = func() int {
		parentCalls++
		if parentCalls == 1 {
			return 42
		}
		return 1
	}
	err := armTUIParentExitSignal()
	if err == nil || !strings.Contains(err.Error(), "parent exited") {
		t.Fatalf("parent exit race error = %v", err)
	}
}

func TestTUIStartupInterruptIsConsumedWithoutBackendResidue(t *testing.T) {
	originalExit := completeCLIExitForTUI
	completeCLIExitForTUI = func(int) error { return nil }
	t.Cleanup(func() { completeCLIExitForTUI = originalExit })
	interrupt := make(chan os.Signal, 1)
	interrupt <- os.Interrupt
	interrupted, err := shutdownTUIServiceOnInterrupt(
		interrupt,
		nil,
		cliPaths{homeDir: t.TempDir()},
	)
	if err != nil || !interrupted {
		t.Fatalf("startup interrupt result = %t, %v", interrupted, err)
	}
	interrupted, err = shutdownTUIServiceOnInterrupt(
		interrupt,
		nil,
		cliPaths{homeDir: t.TempDir()},
	)
	if err != nil || interrupted {
		t.Fatalf("drained startup interrupt result = %t, %v", interrupted, err)
	}
}

func TestTUIProfileRenameUsesVisibleInputPanel(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.width = 80
	model.height = 24
	model.snapshot.Page = tuiPageProfiles
	model.snapshot.FocusSidebar = false
	model.snapshot.Profiles = []tuiProfile{{
		Name: "old-name.yaml",
		Path: "/tmp/old-name.yaml",
	}}
	model.snapshot.SelectedRow = 0
	model.beginProfileRename()

	plain := stripTUIANSI(model.View())
	for _, expected := range []string{
		"Rename profile",
		"old-name█",
		".yaml is added automatically",
		"Enter confirm",
		"Esc cancel",
	} {
		if !strings.Contains(plain, expected) {
			t.Fatalf("rename input panel does not contain %q:\n%s", expected, plain)
		}
	}
}

func TestTUIInputViewportKeepsCursorVisible(t *testing.T) {
	value := []rune("https://example.test/a/very/long/subscription/token")
	output := tuiInputViewport(value, len(value), 20)
	if !strings.Contains(output, "█") {
		t.Fatalf("input viewport lost cursor: %q", output)
	}
	if tuiDisplayWidth(output) > 20 {
		t.Fatalf("input viewport width = %d, want <= 20: %q", tuiDisplayWidth(output), output)
	}
	if !strings.HasPrefix(output, "…") {
		t.Fatalf("long input viewport has no leading ellipsis: %q", output)
	}
}

func TestTUIModeSelectionShowsAllModesBeforeChanging(t *testing.T) {
	if got := strings.Join(tuiTrafficModes, ","); got != "rule,silent,global,direct" {
		t.Fatalf("mode list order = %q", got)
	}
	model := newTUIModel(
		controllerClient{},
		cliPaths{configPath: filepath.Join(t.TempDir(), "missing.yaml")},
		nil,
		true,
	)
	model.width = 100
	model.height = 24
	model.snapshot.Page = tuiPageDashboard
	model.snapshot.FocusSidebar = false
	model.snapshot.SelectedDashboard = tuiDashboardModeRow
	model.snapshot.Settings = tuiSettings{Mode: "rule", MixedPort: 7891}

	if command := model.selectCurrent(); command != nil {
		t.Fatal("opening the mode list unexpectedly started an operation")
	}
	if !model.modeSelectionOpen || model.busy {
		t.Fatalf(
			"mode selection state = open:%t busy:%t",
			model.modeSelectionOpen,
			model.busy,
		)
	}
	if model.snapshot.Settings.Mode != "rule" {
		t.Fatalf("opening the list changed mode to %q", model.snapshot.Settings.Mode)
	}
	plain := stripTUIANSI(model.View())
	for _, expected := range []string{
		"Select outbound mode",
		"rule  (current)",
		"silent",
		"global",
		"direct",
		"Enter confirm",
		"Esc cancel",
	} {
		if !strings.Contains(plain, expected) {
			t.Fatalf("mode list does not contain %q:\n%s", expected, plain)
		}
	}

	_, command := model.Update(tea.KeyMsg{Type: tea.KeyDown})
	if command != nil || model.selectedMode != 1 {
		t.Fatalf(
			"mode list down = selection:%d command:%v",
			model.selectedMode,
			command,
		)
	}
	if model.snapshot.Settings.Mode != "rule" {
		t.Fatalf("moving in the list changed mode to %q", model.snapshot.Settings.Mode)
	}
}

func TestTUIModeSelectionStagesExactChoice(t *testing.T) {
	model := newTUIModel(
		controllerClient{},
		cliPaths{configPath: filepath.Join(t.TempDir(), "missing.yaml")},
		nil,
		true,
	)
	model.snapshot.Page = tuiPageTools
	model.snapshot.FocusSidebar = false
	model.snapshot.Settings = tuiSettings{Mode: "rule", MixedPort: 7891}

	model.beginModeSelection()
	model.selectedMode = findTUIString(tuiTrafficModes, "global")
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if command != nil {
		t.Fatal("staging the selected mode unexpectedly started an operation")
	}
	if model.modeSelectionOpen {
		t.Fatal("mode list remained open after confirmation")
	}
	if model.snapshot.Settings.Mode != "global" || model.stagedSettings == nil ||
		model.stagedSettings.Mode != "global" {
		t.Fatalf(
			"selected mode was not staged exactly: snapshot=%+v staged=%+v",
			model.snapshot.Settings,
			model.stagedSettings,
		)
	}
}

func TestTUIModeSelectionSubmitsExactChoiceAsynchronously(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, tuiServiceSocketFilename)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requests := make(chan tuiServiceRequest, 1)
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		var request tuiServiceRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			serverDone <- decodeErr
			return
		}
		requests <- request
		serverDone <- json.NewEncoder(connection).Encode(tuiServiceStatus{
			ProtocolVersion: tuiServiceProtocolVersion,
			RequestID:       request.RequestID,
			Revision:        8,
			OK:              true,
			Running:         true,
			Mode:            request.Mode,
			ProxyPort:       7891,
		})
	}()

	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.service = newTUIServiceClientAt(directory)
	model.backendRevision = 7
	model.coreRunning = true
	model.snapshot.Page = tuiPageDashboard
	model.snapshot.FocusSidebar = false
	model.snapshot.Settings = tuiSettings{Mode: "rule", MixedPort: 7891}
	model.beginModeSelection()
	model.selectedMode = findTUIString(tuiTrafficModes, "direct")
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if command == nil || !model.busy {
		t.Fatalf("confirmed mode change = command:%v busy:%t", command, model.busy)
	}
	if model.snapshot.Settings.Mode != "rule" ||
		!strings.Contains(model.snapshot.Status, "Changing mode to direct") {
		t.Fatalf("mode changed before Backend result: %+v", model.snapshot)
	}

	_, _ = model.Update(command())
	if model.busy || model.snapshot.Settings.Mode != "direct" ||
		model.backendRevision != 8 {
		t.Fatalf(
			"confirmed mode result = busy:%t mode:%q revision:%d",
			model.busy,
			model.snapshot.Settings.Mode,
			model.backendRevision,
		)
	}
	request := <-requests
	if request.Action != "set_mode" || request.Mode != "direct" ||
		request.ExpectedRevision == nil || *request.ExpectedRevision != 7 {
		t.Fatalf("mode request = %+v", request)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestTUISettingsExposeAllInteractiveRows(t *testing.T) {
	snapshot := tuiSnapshot{
		Page: tuiPageTools,
		Settings: tuiSettings{
			Mode:       "rule",
			MixedPort:  17890,
			AllowLAN:   true,
			LogLevel:   "info",
			TunEnabled: true,
			TunScope:   tuiTunScopeUser,
		},
	}
	var output strings.Builder
	drawTUISettings(&output, snapshot, 80, 24)
	plain := stripTUIANSI(output.String())
	for _, row := range []string{
		"Allow LAN     ON",
		"IPv6          OFF",
		"Unified delay",
		"TCP concurrent",
		"Log level     info",
		"TUN scope     USER",
	} {
		if !strings.Contains(plain, row) {
			t.Fatalf("settings view does not contain %q:\n%s", row, plain)
		}
	}
	for _, daily := range []string{
		"Mode          rule",
		"flc           pick a node in Proxies",
		"Proxy port    17890",
		"Core          STOPPED · Enter to start",
		"System proxy  DISABLED · Enter to enable (starts Core)",
		"TUN           USER ON",
	} {
		if strings.Contains(plain, daily) {
			t.Fatalf("settings still repeats daily control %q:\n%s", daily, plain)
		}
	}
}

func TestTUISettingsServiceRowUsesEnter(t *testing.T) {
	model := newTUIModel(
		controllerClient{},
		cliPaths{},
		nil,
		true,
	)
	model.snapshot.Page = tuiPageDashboard
	model.snapshot.FocusSidebar = false
	model.snapshot.SelectedDashboard = tuiDashboardServiceRow

	command := model.selectCurrent()
	if command == nil {
		t.Fatal("selecting the Dashboard Core row did not return a start operation")
	}
	if !model.busy {
		t.Fatal("selecting the Dashboard Core row did not mark the operation busy")
	}
}

func TestTUISettingsSystemProxyRequiresBackend(t *testing.T) {
	model := newTUIModel(
		controllerClient{},
		cliPaths{},
		nil,
		true,
	)
	model.snapshot.Page = tuiPageDashboard
	model.snapshot.FocusSidebar = false
	model.snapshot.SelectedDashboard = tuiDashboardSystemProxyRow

	if command := model.selectCurrent(); command != nil {
		t.Fatal("system proxy without Backend scheduled a mutation")
	}
	if !strings.Contains(model.snapshot.Status, "managed backend") {
		t.Fatalf("system proxy status = %q", model.snapshot.Status)
	}
}

func TestTUISettingsRunningServiceUnlocksSystemProxy(t *testing.T) {
	snapshot := tuiSnapshot{
		ServiceRunning: true,
		Settings: tuiSettings{
			SystemProxy: false,
		},
	}
	var output strings.Builder
	drawTUIDashboard(
		&output,
		snapshot,
		cliPaths{configPath: "/tmp/config.yaml"},
		80,
		24,
	)
	plain := stripTUIANSI(output.String())
	if !strings.Contains(plain, "Core          RUNNING · Enter to stop") {
		t.Fatalf("running Dashboard has no clear service state:\n%s", plain)
	}
	if !strings.Contains(plain, "System proxy  DISABLED · Enter to enable") {
		t.Fatalf("running Dashboard has no clear system proxy state:\n%s", plain)
	}
	if strings.Contains(plain, "(starts Core)") {
		t.Fatalf("running Dashboard kept automatic-start hint:\n%s", plain)
	}
}

func TestTUISidebarMatchesGraphicalInformationArchitecture(t *testing.T) {
	lines := tuiSidebar(
		tuiSnapshot{
			Page:         tuiPageDashboard,
			SelectedMenu: int(tuiPageDashboard),
			FocusSidebar: true,
		},
		26,
		20,
	)
	plain := stripTUIANSI(strings.Join(lines, "\n"))
	labels := []string{
		"Dashboard",
		"SSH",
		"Proxies",
		"Profiles",
		"History",
		"Connections",
		"Logs",
		"Settings",
		"Maintenance",
	}
	previous := -1
	for _, label := range labels {
		index := strings.Index(plain, label)
		if index < 0 {
			t.Fatalf("sidebar does not contain %q:\n%s", label, plain)
		}
		if index <= previous {
			t.Fatalf("sidebar order is wrong at %q:\n%s", label, plain)
		}
		previous = index
	}
	for _, removed := range []string{"Providers"} {
		if strings.Contains(plain, removed) {
			t.Fatalf("sidebar still exposes standalone %s page:\n%s", removed, plain)
		}
	}
	historySelected := tuiSidebar(
		tuiSnapshot{
			Page:         tuiPageRequests,
			SelectedMenu: int(tuiPageRequests),
			FocusSidebar: true,
		},
		26,
		20,
	)
	if selected := stripTUIANSI(strings.Join(historySelected, "\n")); strings.Contains(selected, "> >  History") {
		t.Fatalf("selected History rendered two cursor chevrons:\n%s", selected)
	}
}

func TestTUISidebarOrderAndNumericShortcutsStayAligned(t *testing.T) {
	pages := []struct {
		digit string
		key   tuiKey
		page  tuiPage
	}{
		{"1", tuiKeyDashboard, tuiPageDashboard},
		{"2", tuiKeySSH, tuiPageSSH},
		{"3", tuiKeyProxies, tuiPageProxies},
		{"4", tuiKeyProfiles, tuiPageProfiles},
		{"5", tuiKeyRequests, tuiPageRequests},
		{"6", tuiKeyConnections, tuiPageConnections},
		{"7", tuiKeyLogs, tuiPageLogs},
		{"8", tuiKeyTools, tuiPageTools},
		{"9", tuiKeyMaintenance, tuiPageMaintenance},
	}
	for index, test := range pages {
		key, ok := tuiKeyFromTea(tea.KeyMsg{
			Type:  tea.KeyRunes,
			Runes: []rune(test.digit),
		})
		if !ok || key != test.key {
			t.Fatalf("%s mapped to (%v, %t), want (%v, true)", test.digit, key, ok, test.key)
		}
		page, ok := tuiPageForKey(key)
		if !ok || page != test.page {
			t.Fatalf("%s opens (%v, %t), want (%v, true)", test.digit, page, ok, test.page)
		}

		snapshot := tuiSnapshot{
			Page:         tuiPageDashboard,
			SelectedMenu: int(tuiPageDashboard),
			FocusSidebar: true,
		}
		for moved := 0; moved < index; moved++ {
			if !handleTUIFocusNavigation(&snapshot, tuiKeyDown) {
				t.Fatalf("sidebar did not move down to position %d", index)
			}
		}
		if snapshot.SelectedMenu != index {
			t.Fatalf("sidebar position = %d, want %d", snapshot.SelectedMenu, index)
		}
		if !handleTUIFocusNavigation(&snapshot, tuiKeySelect) ||
			snapshot.Page != test.page || snapshot.FocusSidebar {
			t.Fatalf("sidebar position %d did not open %s: %+v", index, tuiPageName(test.page), snapshot)
		}
	}
}

func TestSilentNetworkCheckDoesNotCreateListenerWhileCoreStopped(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.coreRunning = false
	model.snapshot.Settings.Mode = tuiSilentMode
	command := model.startNetworkCheck()
	if command == nil {
		t.Fatal("silent stopped-Core check did not return a result command")
	}
	message, ok := command().(tuiNetworkResultMsg)
	if !ok {
		t.Fatalf("network result type = %T", command())
	}
	if message.info.Error != "" || message.info.Route != "SILENT · Core stopped" {
		t.Fatalf("stopped silent network result = %+v", message.info)
	}
}

func TestTUIProxyViewsKeepProvidersInsideProxies(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, false)
	model.snapshot.Page = tuiPageProxies
	model.snapshot.SelectedMenu = int(tuiPageProxies)
	model.snapshot.FocusSidebar = false
	model.snapshot.Providers = []tuiProvider{
		{Name: "one"},
		{Name: "two"},
	}

	_, command := model.Update(tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune{']'},
	})
	if command != nil {
		t.Fatal("switching the proxy view unexpectedly returned a command")
	}
	if model.snapshot.Page != tuiPageProxies ||
		model.snapshot.ProxyView != tuiProxyViewProviders {
		t.Fatalf("provider view escaped Proxies: %+v", model.snapshot)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyDown})
	if model.snapshot.SelectedProvider != 1 {
		t.Fatalf("provider selection = %d, want 1", model.snapshot.SelectedProvider)
	}
	if command := model.selectCurrent(); command == nil {
		t.Fatal("provider Enter did not schedule an update")
	}
}

func TestTUISeparatesSettingsAndMaintenance(t *testing.T) {
	snapshot := tuiSnapshot{
		Page: tuiPageTools,
		Settings: tuiSettings{
			Mode:      "rule",
			MixedPort: 7891,
			LogLevel:  "info",
		},
	}
	var output strings.Builder
	drawTUITools(&output, snapshot, 100, 30)
	plain := stripTUIANSI(output.String())
	for _, expected := range []string{
		"Allow LAN",
		"IPv6",
		"Unified delay",
		"TCP concurrent",
		"Log level     info",
		"TUN scope",
	} {
		if !strings.Contains(plain, expected) {
			t.Fatalf("Settings does not contain %q:\n%s", expected, plain)
		}
	}
	for _, daily := range []string{
		"Mode          rule",
		"flc           pick a node in Proxies",
		"Proxy port    7891",
		"System proxy",
	} {
		if strings.Contains(plain, daily) {
			t.Fatalf("Settings still repeats daily control %q:\n%s", daily, plain)
		}
	}
	output.Reset()
	snapshot.Page = tuiPageMaintenance
	drawTUIMaintenance(&output, snapshot, 100, 30)
	plain = stripTUIANSI(output.String())
	for _, expected := range []string{
		"Edit current YAML",
		"Update Mihomo Geo databases",
		"Reset traffic counters",
		"if stable, do not update lightly",
	} {
		if !strings.Contains(plain, expected) {
			t.Fatalf("Maintenance does not contain %q:\n%s", expected, plain)
		}
	}
}

func TestTUIRequestHistoryTracksLifecycleAndLimit(t *testing.T) {
	start := time.Unix(100, 0)
	connection := tuiConnection{
		ID:      "request-1",
		Host:    "example.com",
		Process: "curl",
		Network: "tcp",
		Chain:   "PROXY",
	}
	history := updateTUIRequestHistory(nil, []tuiConnection{connection}, start)
	if len(history) != 1 || !history[0].Active {
		t.Fatalf("new request was not captured as active: %+v", history)
	}
	connection.Download = 1024
	history = updateTUIRequestHistory(
		history,
		[]tuiConnection{connection},
		start.Add(time.Second),
	)
	if len(history) != 1 || history[0].Download != 1024 {
		t.Fatalf("active request was duplicated or not updated: %+v", history)
	}
	history = updateTUIRequestHistory(
		history,
		nil,
		start.Add(2*time.Second),
	)
	if history[0].Active {
		t.Fatalf("completed request remained active: %+v", history[0])
	}
	history = updateTUIRequestHistory(
		history,
		[]tuiConnection{{Host: "missing-id.example"}},
		start.Add(3*time.Second),
	)
	if len(history) != 1 {
		t.Fatalf("connection without an ID polluted History: %+v", history)
	}

	oversized := make([]tuiRequest, tuiRequestHistoryLimit+20)
	for index := range oversized {
		oversized[index] = tuiRequest{
			tuiConnection: tuiConnection{ID: fmt.Sprintf("id-%d", index)},
			LastSeen:      start.Add(time.Duration(index) * time.Second),
		}
	}
	limited := updateTUIRequestHistory(oversized, nil, start)
	if len(limited) != tuiRequestHistoryLimit {
		t.Fatalf("request history size = %d, want %d", len(limited), tuiRequestHistoryLimit)
	}
}

func TestTUIStoppedCoreClearsActiveConnectionsAndClosesHistory(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Connections = []tuiConnection{{ID: "connection-1"}}
	model.snapshot.SelectedConnection = 0
	model.snapshot.ConnectionsDetailOpen = true
	model.snapshot.Requests = []tuiRequest{{
		tuiConnection: tuiConnection{ID: "request-1"},
		Active:        true,
	}}
	model.coreRunning = false

	model.reconcileStoppedCoreState()

	if len(model.snapshot.Connections) != 0 ||
		model.snapshot.SelectedConnection != -1 ||
		model.snapshot.ConnectionsDetailOpen {
		t.Fatalf("stopped Core left stale Connections: %+v", model.snapshot)
	}
	if len(model.snapshot.Requests) != 1 || model.snapshot.Requests[0].Active {
		t.Fatalf("stopped Core left active History: %+v", model.snapshot.Requests)
	}
}

func TestTUIRefreshDoesNotSelectAnotherConnectionAfterSelectedOneCloses(t *testing.T) {
	current := tuiSnapshot{
		Page:                  tuiPageConnections,
		Connections:           []tuiConnection{{ID: "closed"}},
		SelectedConnection:    0,
		ConnectionsDetailOpen: true,
	}
	refreshed := tuiSnapshot{
		Connections: []tuiConnection{{ID: "still-open"}},
	}
	merged := mergeTUIRefresh(current, refreshed)
	if merged.SelectedConnection != -1 {
		t.Fatalf("closed connection selected replacement row %d", merged.SelectedConnection)
	}
	if merged.ConnectionsDetailOpen {
		t.Fatal("connection detail remained open after its selected entry closed")
	}
}

func TestTUIRefreshClosesStaleHistoryAndLogDetailsAndSelectsNewLogs(t *testing.T) {
	current := tuiSnapshot{
		Page:                  tuiPageLogs,
		Requests:              []tuiRequest{{tuiConnection: tuiConnection{ID: "closed-request"}}},
		SelectedRequest:       0,
		HistoryDetailOpen:     true,
		Logs:                  []string{"old log"},
		SelectedLog:           0,
		LogDetailOpen:         true,
		Connections:           []tuiConnection{{ID: "closed-connection"}},
		SelectedConnection:    0,
		ConnectionsDetailOpen: true,
	}
	refreshed := current
	refreshed.Requests = []tuiRequest{{tuiConnection: tuiConnection{ID: "new-request"}}}
	refreshed.Connections = []tuiConnection{{ID: "new-connection"}}
	refreshed.Logs = []string{"newest log"}

	merged := mergeTUIRefresh(current, refreshed)
	if merged.SelectedConnection != -1 || merged.ConnectionsDetailOpen {
		t.Fatalf("closed connection retained selection/detail: %+v", merged)
	}
	if merged.SelectedRequest != -1 || merged.HistoryDetailOpen {
		t.Fatalf("closed History entry retained selection/detail: %+v", merged)
	}
	if merged.SelectedLog != 0 || merged.LogDetailOpen {
		t.Fatalf("replaced log retained stale detail or did not select new log: %+v", merged)
	}
}

func TestTUIRefreshKeepsSelectedLogByContentAfterReordering(t *testing.T) {
	current := tuiSnapshot{
		Logs:        []string{"older", "selected"},
		SelectedLog: 1,
	}
	refreshed := current
	refreshed.Logs = []string{"selected", "newer"}
	merged := mergeTUIRefresh(current, refreshed)
	if merged.SelectedLog != 0 {
		t.Fatalf("selected log moved to %d instead of following its content", merged.SelectedLog)
	}

	current.SelectedLog = -1
	current.Logs = nil
	refreshed = current
	refreshed.Logs = []string{"first new log"}
	merged = mergeTUIRefresh(current, refreshed)
	if merged.SelectedLog != 0 {
		t.Fatalf("new log was not selected after an empty log state: %+v", merged)
	}
}

func TestTUIRefreshReplacesTransientRefreshErrorsAfterRecovery(t *testing.T) {
	for _, status := range []string{
		"Controller unavailable: dial failed",
		"Invalid controller response: bad JSON",
		"Connections refresh failed: temporary failure",
		"Refresh incomplete · History: temporary failure",
		"SSH profiles unavailable: read config failed",
	} {
		merged := mergeTUIRefresh(
			tuiSnapshot{Status: status},
			tuiSnapshot{Status: "Connected"},
		)
		if merged.Status != "Connected" {
			t.Fatalf("refresh recovery kept stale %q status as %q", status, merged.Status)
		}
	}
}

func TestTUIRefreshClearsStaleTransientStatusBeforeCollectingNewData(t *testing.T) {
	for _, status := range []string{
		"Controller unavailable: dial failed",
		"Invalid controller response: bad JSON",
		"Connections refresh failed: temporary failure",
		"Refresh incomplete · Logs: temporary failure",
		"SSH profiles unavailable: read config failed",
	} {
		snapshot := tuiSnapshot{Status: status}
		clearTUITransientRefreshStatus(&snapshot)
		if snapshot.Status != "Loading..." {
			t.Fatalf("transient refresh status %q was retained as %q", status, snapshot.Status)
		}
	}

	snapshot := tuiSnapshot{Status: "Settings committed"}
	clearTUITransientRefreshStatus(&snapshot)
	if snapshot.Status != "Settings committed" {
		t.Fatalf("action status should remain visible: %q", snapshot.Status)
	}
}

func TestTUIRefreshDoesNotSwitchToAnotherSSHProfileWhenSelectedProfileDisappears(t *testing.T) {
	current := tuiSnapshot{
		SSHProfiles: []tuiSSHProfile{{Name: "gone"}},
		SelectedSSH: 0,
	}
	refreshed := current
	refreshed.SSHProfiles = []tuiSSHProfile{{Name: "other"}}
	merged := mergeTUIRefresh(current, refreshed)
	if merged.SelectedSSH != -1 {
		t.Fatalf("refresh switched disappeared SSH selection to profile %d", merged.SelectedSSH)
	}
}

func TestTUIRefreshDoesNotApplyAnotherProxyWhenSelectionDisappears(t *testing.T) {
	current := tuiSnapshot{
		Groups:         []tuiGroup{{Name: "gone", Nodes: []string{"old-node"}}},
		SelectedGroup:  0,
		SelectedNode:   0,
		ProxyNodeFocus: true,
	}
	refreshed := current
	refreshed.Groups = []tuiGroup{{Name: "other", Nodes: []string{"other-node"}}}
	merged := mergeTUIRefresh(current, refreshed)
	if merged.SelectedGroup != -1 || merged.SelectedNode != -1 || merged.ProxyNodeFocus {
		t.Fatalf("refresh switched a removed proxy group: %+v", merged)
	}

	refreshed = current
	refreshed.Groups = []tuiGroup{{Name: "gone", Nodes: []string{"replacement-node"}}}
	merged = mergeTUIRefresh(current, refreshed)
	if merged.SelectedGroup != 0 || merged.SelectedNode != -1 || merged.ProxyNodeFocus {
		t.Fatalf("refresh retained a removed proxy node as another node: %+v", merged)
	}

	model := &tuiModel{snapshot: tuiSnapshot{
		Page:           tuiPageProxies,
		Groups:         refreshed.Groups,
		SelectedGroup:  0,
		SelectedNode:   -1,
		ProxyNodeFocus: true,
	}}
	if command := model.selectCurrent(); command != nil || model.busy ||
		!strings.Contains(model.snapshot.Status, "Select a proxy node") {
		t.Fatalf("invalid proxy selection started an operation: %+v", model.snapshot)
	}
}

func TestTUIInvalidSelectionsReturnActionableStatus(t *testing.T) {
	state := tuiOperationState{}
	selectTUIServiceProxy(&state, nil, controllerClient{})
	if state.snapshot.Status != "Select a proxy group before applying it" {
		t.Fatalf("managed proxy selection status = %q", state.snapshot.Status)
	}

	snapshot := tuiSnapshot{}
	selectTUIProxy(&snapshot, controllerClient{}, "")
	if snapshot.Status != "Select a proxy group before applying it" {
		t.Fatalf("direct proxy selection status = %q", snapshot.Status)
	}
	updateTUIProvider(&snapshot, controllerClient{})
	if snapshot.Status != "Select a provider before updating it" {
		t.Fatalf("provider selection status = %q", snapshot.Status)
	}

	model := &tuiModel{snapshot: tuiSnapshot{
		Page:        tuiPageProfiles,
		SelectedRow: 0,
	}}
	if command := model.selectCurrent(); command != nil || model.busy ||
		model.snapshot.Status != "Select a profile before activating it" {
		t.Fatalf("invalid profile selection started an operation: %+v", model.snapshot)
	}

	model.snapshot = tuiSnapshot{Page: tuiPageConnections, SelectedConnection: -1}
	if command := model.handleKey(tuiKeyCloseConnection); command != nil ||
		model.snapshot.Status != "Select an active connection before closing it" {
		t.Fatalf("invalid connection close did not explain itself: %+v", model.snapshot)
	}
}

func TestTUIFilteredSelectionClearsAndNavigationRecoversAtEdges(t *testing.T) {
	snapshot := tuiSnapshot{
		Connections: []tuiConnection{{ID: "first"}, {ID: "second"}},
		Requests: []tuiRequest{
			{tuiConnection: tuiConnection{ID: "first"}},
			{tuiConnection: tuiConnection{ID: "second"}},
		},
		Logs: []string{"first", "second"},
	}
	snapshot.ConnectionsQuery = "missing"
	snapshot.HistoryQuery = "missing"
	snapshot.LogsQuery = "missing"
	if firstTUIConnectionMatch(snapshot) != -1 ||
		firstTUIRequestMatch(snapshot) != -1 ||
		firstTUILogMatch(snapshot) != -1 {
		t.Fatal("a no-match filter retained a selectable row")
	}

	snapshot.ConnectionsQuery = ""
	snapshot.HistoryQuery = ""
	snapshot.SelectedConnection = -1
	snapshot.SelectedRequest = -1
	moveTUIConnectionMatch(&snapshot, 1)
	moveTUIRequestMatch(&snapshot, 1)
	if snapshot.SelectedConnection != 0 || snapshot.SelectedRequest != 0 {
		t.Fatalf("down did not recover first match: %+v", snapshot)
	}
	snapshot.SelectedConnection = -1
	snapshot.SelectedRequest = -1
	moveTUIConnectionMatch(&snapshot, -1)
	moveTUIRequestMatch(&snapshot, -1)
	if snapshot.SelectedConnection != 1 || snapshot.SelectedRequest != 1 {
		t.Fatalf("up did not recover last match: %+v", snapshot)
	}
}

func TestTUISearchAndFilterCloseStaleDetails(t *testing.T) {
	model := &tuiModel{
		snapshot: tuiSnapshot{
			Page:                  tuiPageRequests,
			Requests:              []tuiRequest{{tuiConnection: tuiConnection{ID: "active"}, Active: true}},
			SelectedRequest:       0,
			HistoryDetailOpen:     true,
			Connections:           []tuiConnection{{ID: "connection"}},
			SelectedConnection:    0,
			ConnectionsDetailOpen: true,
			Logs:                  []string{"INFO visible"},
			SelectedLog:           0,
			LogDetailOpen:         true,
		},
	}

	model.handleKey(tuiKeyFilter)
	if model.snapshot.HistoryDetailOpen {
		t.Fatal("changing the History filter retained a stale detail")
	}

	model.inputMode = tuiInputConnectionsSearch
	model.inputValue = []rune("missing")
	model.submitInput()
	if model.snapshot.ConnectionsDetailOpen || model.snapshot.SelectedConnection != -1 {
		t.Fatalf("connections search retained stale detail or selection: %+v", model.snapshot)
	}

	model.inputMode = tuiInputLogsSearch
	model.inputValue = []rune("missing")
	model.submitInput()
	if model.snapshot.LogDetailOpen || model.snapshot.SelectedLog != -1 {
		t.Fatalf("log search retained stale detail or selection: %+v", model.snapshot)
	}

	model.snapshot.Page = tuiPageLogs
	model.snapshot.LogDetailOpen = true
	model.handleKey(tuiKeyFilter)
	if model.snapshot.LogDetailOpen {
		t.Fatal("changing the log level filter retained a stale detail")
	}
}

func TestTUILogExportsNeverOverwritePreviousExport(t *testing.T) {
	directory := t.TempDir()
	seen := map[string]bool{}
	for range 10 {
		path, err := exportTUILogs(directory, []string{"retained log"})
		if err != nil {
			t.Fatal(err)
		}
		if seen[path] {
			t.Fatalf("export reused %s", path)
		}
		seen[path] = true
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("export permissions: %v", err)
		}
	}
	for path := range seen {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "retained log\n" {
			t.Fatalf("export lost: %v", err)
		}
	}
}

func TestTUILogExportAndClear(t *testing.T) {
	clearTUILogs()
	sendMessage(Message{
		Type: LogMessage,
		Data: map[string]string{"Payload": "first event"},
	})
	sendMessage(Message{
		Type: LogMessage,
		Data: map[string]string{"Payload": "second event"},
	})
	logs := cliLogSnapshot()
	if len(logs) != 2 {
		t.Fatalf("captured logs = %v, want two entries", logs)
	}

	path, err := exportTUILogs(t.TempDir(), logs)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first event\nsecond event\n" {
		t.Fatalf("exported logs = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("exported log mode = %o, want 600", info.Mode().Perm())
	}

	model := &tuiModel{
		snapshot: tuiSnapshot{
			Page:          tuiPageLogs,
			Logs:          logs,
			SelectedLog:   1,
			LogDetailOpen: true,
		},
	}
	if command := model.handleKey(tuiKeyCloseConnections); command != nil {
		t.Fatal("clearing logs unexpectedly started an asynchronous command")
	}
	if !model.dangerConfirmOpen {
		t.Fatal("clearing logs did not require confirmation")
	}
	if command := model.handleDangerConfirm(tea.KeyMsg{Type: tea.KeyEnter}); command != nil {
		t.Fatal("confirmed local log clear unexpectedly started an asynchronous command")
	}
	if len(model.snapshot.Logs) != 0 || len(cliLogSnapshot()) != 0 {
		t.Fatal("clearing logs left captured entries behind")
	}
	if model.snapshot.SelectedLog != -1 || model.snapshot.LogDetailOpen {
		t.Fatalf("clearing logs retained stale selection/detail: %+v", model.snapshot)
	}
}

func TestCLIApplicationLogRedactsURLsAndDataDirectory(t *testing.T) {
	directory := t.TempDir()
	appendCLIApplicationLog(
		directory,
		"WARN",
		"profile_import",
		"source https://secret.example/token in "+directory,
	)
	data, err := os.ReadFile(filepath.Join(directory, tuiServiceLogFilename))
	if err != nil {
		t.Fatal(err)
	}
	line := string(data)
	if strings.Contains(line, "secret.example") || strings.Contains(line, directory) {
		t.Fatalf("application log leaked sensitive detail: %q", line)
	}
	if !strings.Contains(line, "[redacted-url]") || !strings.Contains(line, "$DATA") {
		t.Fatalf("application log did not mark redaction: %q", line)
	}
	clearTUILogs()
}

func TestTUIPersistentLogsCanBeReadAndCleared(t *testing.T) {
	directory := t.TempDir()
	appendCLIApplicationLog(directory, "INFO", "first", "one")
	appendCLIApplicationLog(directory, "ERROR", "second", "two")
	logs := readTUIPersistentLogs(directory, 10)
	if len(logs) != 2 || !strings.Contains(logs[0], "first") || !strings.Contains(logs[1], "second") {
		t.Fatalf("persistent logs = %v", logs)
	}
	if err := os.WriteFile(filepath.Join(directory, tuiServiceLogFilename)+".1", []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := clearTUIPersistentLogs(directory); err != nil {
		t.Fatal(err)
	}
	if logs := readTUIPersistentLogs(directory, 10); len(logs) != 0 {
		t.Fatalf("cleared persistent logs = %v", logs)
	}
	if _, err := os.Stat(filepath.Join(directory, tuiServiceLogFilename) + ".1"); !os.IsNotExist(err) {
		t.Fatalf("rotated log was not removed: %v", err)
	}
}

func TestTUIEditKeyIsPageScoped(t *testing.T) {
	model := &tuiModel{
		snapshot: tuiSnapshot{Page: tuiPageDashboard},
		paths:    cliPaths{configPath: "/tmp/config.yaml"},
	}
	if command := model.handleKey(tuiKeyEdit); command != nil {
		t.Fatal("Dashboard edit key unexpectedly opened an editor")
	}
	if !strings.Contains(model.snapshot.Status, "Profiles and Maintenance") {
		t.Fatalf("Dashboard edit guidance = %q", model.snapshot.Status)
	}

	model.snapshot.Page = tuiPageProfiles
	model.snapshot.SelectedRow = -1
	if command := model.handleKey(tuiKeyEdit); command != nil {
		t.Fatal("profile import row unexpectedly opened an editor")
	}
	if !strings.Contains(model.snapshot.Status, "Select a profile") {
		t.Fatalf("Profiles edit guidance = %q", model.snapshot.Status)
	}
}

func TestFormatTUIDestination(t *testing.T) {
	for _, test := range []struct {
		host string
		port string
		want string
	}{
		{host: "1.1.1.1", port: "443", want: "1.1.1.1:443"},
		{host: "2001:db8::1", port: "53", want: "[2001:db8::1]:53"},
		{host: "example.com", want: "example.com"},
		{port: "443"},
	} {
		if got := formatTUIDestination(test.host, test.port); got != test.want {
			t.Fatalf(
				"formatTUIDestination(%q, %q) = %q, want %q",
				test.host,
				test.port,
				got,
				test.want,
			)
		}
	}
}

func TestTUIRequestsCanBeClearedWithoutClosingConnections(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, false)
	model.snapshot.Page = tuiPageRequests
	model.snapshot.FocusSidebar = false
	model.snapshot.Requests = []tuiRequest{{
		tuiConnection: tuiConnection{ID: "request-1"},
	}}
	model.snapshot.SelectedRequest = 0
	model.snapshot.HistoryDetailOpen = true
	model.snapshot.Connections = []tuiConnection{{ID: "active-1"}}

	if command := model.handleKey(tuiKeyCloseConnections); command != nil {
		t.Fatal("clearing request history unexpectedly called the controller")
	}
	if !model.dangerConfirmOpen {
		t.Fatal("clearing request history did not require confirmation")
	}
	if command := model.handleDangerConfirm(tea.KeyMsg{Type: tea.KeyEnter}); command != nil {
		t.Fatal("confirmed local History clear unexpectedly called the controller")
	}
	if len(model.snapshot.Requests) != 0 {
		t.Fatalf("request history was not cleared: %+v", model.snapshot.Requests)
	}
	if model.snapshot.SelectedRequest != -1 || model.snapshot.HistoryDetailOpen {
		t.Fatalf("clearing History retained stale selection/detail: %+v", model.snapshot)
	}
	if len(model.snapshot.Connections) != 1 {
		t.Fatal("clearing request history changed active connections")
	}
}

func TestControllerClientTestsSelectedProxyDelay(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/proxies/HK%20Node/delay" &&
			request.URL.Path != "/proxies/HK Node/delay" {
			t.Fatalf("delay path = %q", request.URL.Path)
		}
		if got := request.URL.Query().Get("url"); got != "https://example.test/204?a=1" {
			t.Fatalf("delay test URL = %q", got)
		}
		if got := request.URL.Query().Get("timeout"); got != "5000" {
			t.Fatalf("delay timeout = %q", got)
		}
		_, _ = io.WriteString(w, `{"delay":42}`)
	}))
	defer server.Close()
	client := controllerClient{
		options: controllerOptions{address: server.URL},
		client:  server.Client(),
	}
	delay, err := client.testProxyDelay(
		"HK Node",
		"https://example.test/204?a=1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if delay != 42 {
		t.Fatalf("delay = %d, want 42", delay)
	}
}

func TestControllerClientDelayTestOverridesShortRefreshTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		_ *http.Request,
	) {
		time.Sleep(60 * time.Millisecond)
		_, _ = io.WriteString(w, `{"delay":35}`)
	}))
	defer server.Close()
	httpClient := server.Client()
	httpClient.Timeout = 10 * time.Millisecond
	client := controllerClient{
		options: controllerOptions{address: server.URL},
		client:  httpClient,
	}

	delay, err := client.testProxyDelay("Node", "https://example.test/204")
	if err != nil {
		t.Fatalf("delay test reused the short refresh timeout: %v", err)
	}
	if delay != 35 {
		t.Fatalf("delay = %d, want 35", delay)
	}
}

func TestTUIWholeGroupDelayTestCollectsReachableAndTimeoutNodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		request *http.Request,
	) {
		node := strings.TrimSuffix(
			strings.TrimPrefix(request.URL.Path, "/proxies/"),
			"/delay",
		)
		switch node {
		case "fast":
			_, _ = io.WriteString(w, `{"delay":18}`)
		case "slow":
			_, _ = io.WriteString(w, `{"delay":240}`)
		default:
			http.Error(w, "unreachable", http.StatusGatewayTimeout)
		}
	}))
	defer server.Close()
	client := controllerClient{
		options: controllerOptions{address: server.URL},
		client:  server.Client(),
	}

	delays := testTUIProxyDelays(
		client,
		[]string{"fast", "slow", "dead"},
		"https://example.test/204",
	)
	if delays["fast"].MedianMillis != 18 || delays["fast"].Samples != 5 ||
		delays["slow"].MedianMillis != 240 || delays["dead"].Error == "" {
		t.Fatalf("whole-group delays = %#v", delays)
	}
}

func TestTUIWholeGroupDelayKeyUpdatesVisibleNodeStates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		request *http.Request,
	) {
		if strings.Contains(request.URL.Path, "dead") {
			http.Error(w, "unreachable", http.StatusGatewayTimeout)
			return
		}
		_, _ = io.WriteString(w, `{"delay":27}`)
	}))
	defer server.Close()
	model := newTUIModel(
		controllerClient{
			options: controllerOptions{address: server.URL},
			client:  server.Client(),
		},
		cliPaths{},
		nil,
		false,
	)
	model.snapshot.Page = tuiPageProxies
	model.snapshot.ProxyView = tuiProxyViewGroups
	model.snapshot.FocusSidebar = false
	model.snapshot.Groups = []tuiGroup{{
		Name:   "Proxy",
		Nodes:  []string{"fast", "dead"},
		Delays: map[string]tuiDelayResult{},
	}}

	command := model.handleTeaKey(tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune{'d'},
	})
	if command == nil {
		t.Fatal("d did not test all nodes from proxy-group mode")
	}
	for _, node := range model.snapshot.Groups[0].Nodes {
		if !model.snapshot.Groups[0].Delays[node].Testing {
			t.Fatalf("%s was not marked Testing", node)
		}
	}
	_, _ = model.Update(command())
	if model.snapshot.Groups[0].Delays["fast"].MedianMillis != 27 ||
		model.snapshot.Groups[0].Delays["fast"].Samples != 5 ||
		model.snapshot.Groups[0].Delays["dead"].Error == "" {
		t.Fatalf("visible node delays = %#v", model.snapshot.Groups[0].Delays)
	}
	if !strings.Contains(model.snapshot.Status, "1/2 reachable") {
		t.Fatalf("whole-group status = %q", model.snapshot.Status)
	}
}

func TestTUINetworkDetectionUsesConfiguredMixedPortProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Host != "public-ip.invalid" {
			t.Fatalf("proxy target host = %q", request.URL.Host)
		}
		_, _ = io.WriteString(w, `{"ip":"203.0.113.8","country_code":"SG"}`)
	}))
	defer proxy.Close()
	result := detectTUIPublicIP(
		newTUINetworkHTTPClient(proxy.URL),
		[]string{"http://public-ip.invalid/json"},
	)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if result.IP != "203.0.113.8" || result.Country != "SG" {
		t.Fatalf("public IP result = %+v", result)
	}
}

func TestTUINetworkDetectionAuthenticatesSilentProxy(t *testing.T) {
	authenticated := false
	proxy := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		request *http.Request,
	) {
		authenticated = strings.HasPrefix(
			request.Header.Get("Proxy-Authorization"),
			"Basic ",
		)
		_, _ = io.WriteString(w, `{"ip":"198.51.100.40","country_code":"JP"}`)
	}))
	defer proxy.Close()
	proxyURL := strings.Replace(proxy.URL, "http://", "http://flc:secret@", 1)

	result := detectTUIPublicIP(
		newTUINetworkHTTPClient(proxyURL),
		[]string{"http://public-ip.invalid/json"},
	)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if !authenticated {
		t.Fatal("silent network detection omitted proxy authentication")
	}
}

func TestTUINetworkDetectionUsesActiveFallbackPort(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.coreRunning = true
	model.snapshot.Settings.Mode = "rule"
	model.snapshot.Settings.MixedPort = 7890
	model.snapshot.ActiveProxyPort = 17890

	if port := model.networkCheckProxyPort(); port != 17890 {
		t.Fatalf("network detection port = %d, want active fallback 17890", port)
	}
	if route := model.networkCheckRoute(); route != "proxy:17890" {
		t.Fatalf("network detection route = %q", route)
	}

	model.snapshot.Settings.Mode = tuiSilentMode
	if port := model.networkCheckProxyPort(); port != 0 {
		t.Fatalf("silent network detection exposed private listener %d", port)
	}
	if route := model.networkCheckRoute(); !strings.HasPrefix(route, "silent:") {
		t.Fatalf("silent network detection route = %q", route)
	}
}

func TestTUIPublicIPDetectionAcceptsOriginalFlClashResponseShapes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		request *http.Request,
	) {
		switch request.URL.Path {
		case "/invalid":
			http.Error(w, "failed", http.StatusServiceUnavailable)
		default:
			_, _ = io.WriteString(w, `{"query":"198.51.100.9","countryCode":"US"}`)
		}
	}))
	defer server.Close()

	result := detectTUIPublicIP(
		server.Client(),
		[]string{server.URL + "/invalid", server.URL + "/valid"},
	)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if result.IP != "198.51.100.9" || result.Country != "US" {
		t.Fatalf("public IP result = %+v", result)
	}
}

func TestTUIIntranetIPPrefersPrivateWiFiIPv4(t *testing.T) {
	selected, ok := selectTUIIntranetIP([]tuiLocalIPCandidate{
		{Interface: "eth0", Address: net.ParseIP("2001:db8::8")},
		{Interface: "docker0", Address: net.ParseIP("172.17.0.1")},
		{Interface: "wlp2s0", Address: net.ParseIP("192.168.1.23")},
		{Interface: "eth0", Address: net.ParseIP("198.51.100.4")},
	})
	if !ok {
		t.Fatal("no intranet IP was selected")
	}
	if selected.Interface != "wlp2s0" ||
		selected.Address.String() != "192.168.1.23" {
		t.Fatalf("selected intranet IP = %+v", selected)
	}
}

func TestTUIDashboardRendersPublicAndIntranetIP(t *testing.T) {
	snapshot := populatedTUISnapshot(tuiPageDashboard)
	snapshot.Network = tuiNetworkInfo{
		PublicIP:   "203.0.113.8",
		Country:    "SG",
		IntranetIP: "192.168.1.23 (wlp2s0)",
		Route:      "PROXY 127.0.0.1:7890",
		CheckedAt:  time.Date(2026, 7, 29, 12, 34, 56, 0, time.Local),
	}
	var output strings.Builder
	drawTUIDashboard(
		&output,
		snapshot,
		cliPaths{configPath: "/tmp/config.yaml"},
		100,
		26,
	)
	plain := stripTUIANSI(output.String())
	for _, expected := range []string{
		"Network detection",
		"Public IP",
		"203.0.113.8",
		"[SG]",
		"Intranet IP",
		"192.168.1.23 (wlp2s0)",
		"PROXY 127.0.0.1:7890",
		"n refresh",
	} {
		if !strings.Contains(plain, expected) {
			t.Fatalf("Dashboard does not contain %q:\n%s", expected, plain)
		}
	}
}

func TestTUINetworkCheckDiscardsResultFromOldRoute(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Settings.MixedPort = 7890
	model.coreRunning = true
	model.networkCheckActive = true

	_, command := model.Update(tuiNetworkResultMsg{
		route: "direct",
		info: tuiNetworkInfo{
			PublicIP:  "198.51.100.2",
			Route:     "DIRECT",
			CheckedAt: time.Now(),
		},
	})
	if command == nil {
		t.Fatal("route change did not schedule a fresh network check")
	}
	if !model.networkCheckActive {
		t.Fatal("fresh network check is not marked active")
	}
	if model.snapshot.Network.PublicIP != "" {
		t.Fatal("stale direct-route IP replaced the proxy-route result")
	}
}

func TestTUINetworkCheckHasNoPeriodicCooldown(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Network.CheckedAt = time.Now()

	if command := model.startNetworkCheck(); command == nil {
		t.Fatal("event-triggered network check was suppressed by a cooldown")
	}
}

func TestTUIOperationRefreshesNetworkAfterExitChange(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.coreRunning = true
	model.snapshot.Settings.Mode = "rule"
	model.snapshot.Settings.MixedPort = 7890
	model.snapshot.ActiveProxyPort = 7890

	state := tuiOperationState{
		snapshot:        model.snapshot,
		paths:           model.paths,
		coreRunning:     model.coreRunning,
		backendRevision: model.backendRevision,
		networkChanged:  true,
	}
	_, command := model.Update(tuiOperationResultMsg{state: state})
	if command == nil || !model.networkCheckActive {
		t.Fatal("exit-changing operation did not request a network refresh")
	}
}

func TestTUIMemoryRefreshIntervalIsOneSecond(t *testing.T) {
	if tuiMemoryRefreshInterval < 2*time.Second {
		t.Fatalf("memory refresh interval = %s, want at least 2s", tuiMemoryRefreshInterval)
	}
	if tuiRefreshInterval < 2*time.Second {
		t.Fatalf("TUI tick interval = %s, want at least 2s", tuiRefreshInterval)
	}
	if tuiProgramFPS > 15 || tuiProgramFPS <= 0 {
		t.Fatalf("TUI FPS = %d, want 1..15", tuiProgramFPS)
	}
}

func TestTUIIdleTickSkipsHistoryLogsAndPublicIPOffThosePages(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageDashboard
	_, command := model.Update(tuiTickMsg{})
	if command == nil {
		t.Fatal("Dashboard tick did not reschedule idle work")
	}
	if model.networkCheckActive || model.lastIdleTick.CheckNetwork {
		t.Fatal("tick started a public-IP network check")
	}
	if model.lastIdleTick.FetchHistory || model.lastIdleTick.FetchLogs ||
		model.refreshIncludesHistory || model.refreshIncludesLogs {
		t.Fatalf(
			"Dashboard tick started History/Logs bulk fetch: %+v history=%t logs=%t",
			model.lastIdleTick,
			model.refreshIncludesHistory,
			model.refreshIncludesLogs,
		)
	}
	if !model.lastIdleTick.RefreshSnapshot || !model.lastIdleTick.SampleMemory ||
		model.lastIdleTick.PollSSH {
		t.Fatalf("Dashboard idle plan = %+v", model.lastIdleTick)
	}

	model.refreshInFlight = false
	model.snapshot.Page = tuiPageTools
	_, _ = model.Update(tuiTickMsg{})
	if model.lastIdleTick.RefreshSnapshot || model.lastIdleTick.SampleMemory ||
		model.lastIdleTick.PollSSH || model.lastIdleTick.FetchHistory ||
		model.lastIdleTick.FetchLogs || model.refreshIncludesHistory ||
		model.refreshIncludesLogs || model.networkCheckActive {
		t.Fatalf("Settings tick still did idle bulk work: %+v", model.lastIdleTick)
	}
}

func TestTUILiveMonitorsFollowDashboardPage(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.service = newTUIServiceClientAt(t.TempDir())
	defer model.stopTrafficMonitor()
	defer model.stopCoreMemoryMonitor()
	model.snapshot.Page = tuiPageDashboard
	model.startTrafficMonitor()
	model.startCoreMemoryMonitor()
	if model.stopTraffic == nil || model.stopCoreMemory == nil {
		t.Fatal("Dashboard did not start Core traffic/memory streams")
	}
	if !tuiPageShowsLiveCoreStats(tuiPageDashboard) {
		t.Fatal("Dashboard is not treated as a live traffic/memory page")
	}

	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'8'}})
	if model.snapshot.Page != tuiPageTools {
		t.Fatalf("Settings key opened %s", tuiPageName(model.snapshot.Page))
	}
	if model.stopTraffic != nil || model.stopCoreMemory != nil {
		t.Fatal("Core traffic/memory streams stayed up on Settings")
	}

	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}})
	if model.snapshot.Page != tuiPageProfiles {
		t.Fatalf("Profiles key opened %s", tuiPageName(model.snapshot.Page))
	}
	if model.stopTraffic != nil || model.stopCoreMemory != nil {
		t.Fatal("Core traffic/memory streams started on Profiles")
	}

	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'9'}})
	if model.snapshot.Page != tuiPageMaintenance {
		t.Fatalf("Maintenance key opened %s", tuiPageName(model.snapshot.Page))
	}
	if model.stopTraffic != nil || model.stopCoreMemory != nil {
		t.Fatal("Core traffic/memory streams started on Maintenance")
	}

	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	if model.snapshot.Page != tuiPageDashboard {
		t.Fatalf("Dashboard key opened %s", tuiPageName(model.snapshot.Page))
	}
	if model.stopTraffic == nil || model.stopCoreMemory == nil {
		t.Fatal("entering Dashboard did not resume Core traffic/memory streams")
	}

	model.snapshot.FocusSidebar = false
	model.snapshot.FLCOutbound = "PROXY"
	model.snapshot.Groups = []tuiGroup{{
		Name:  "PROXY",
		Now:   "hk-1",
		Nodes: []string{"DIRECT", "hk-1"},
	}}
	model.snapshot.SelectedDashboard = tuiDashboardFLCOutboundRow
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if model.snapshot.Page != tuiPageProxies {
		t.Fatalf("flc Enter opened %s", tuiPageName(model.snapshot.Page))
	}
	if model.stopTraffic != nil || model.stopCoreMemory != nil {
		t.Fatal("Core traffic/memory streams stayed up after flc Enter opened Proxies")
	}

	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	if model.snapshot.Page != tuiPageDashboard ||
		model.stopTraffic == nil || model.stopCoreMemory == nil {
		t.Fatalf(
			"Dashboard resume after flc = page:%s traffic:%t memory:%t",
			tuiPageName(model.snapshot.Page),
			model.stopTraffic != nil,
			model.stopCoreMemory != nil,
		)
	}

	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'P'}})
	if model.snapshot.Page != tuiPageProxies {
		t.Fatalf("P opened %s", tuiPageName(model.snapshot.Page))
	}
	if model.stopTraffic != nil || model.stopCoreMemory != nil {
		t.Fatal("Core traffic/memory streams stayed up after P opened Proxies")
	}
}

func TestTUIIdleTickFetchesHistoryOnlyOnHistoryPage(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Page = tuiPageRequests
	_, _ = model.Update(tuiTickMsg{})
	if !model.lastIdleTick.FetchHistory || !model.refreshIncludesHistory {
		t.Fatalf("History tick skipped History fetch: %+v", model.lastIdleTick)
	}
	if model.lastIdleTick.FetchLogs || model.refreshIncludesLogs ||
		model.lastIdleTick.CheckNetwork || model.networkCheckActive {
		t.Fatalf("History tick started extra probes: %+v", model.lastIdleTick)
	}

	model.refreshInFlight = false
	model.snapshot.Page = tuiPageLogs
	_, _ = model.Update(tuiTickMsg{})
	if !model.lastIdleTick.FetchLogs || !model.refreshIncludesLogs {
		t.Fatalf("Logs tick skipped Logs fetch: %+v", model.lastIdleTick)
	}
	if model.lastIdleTick.FetchHistory || model.refreshIncludesHistory {
		t.Fatalf("Logs tick started History bulk fetch: %+v", model.lastIdleTick)
	}
}

func TestTUIDashboardOwnsDailyControlsAndSettingsDoesNotRepeatThem(t *testing.T) {
	snapshot := tuiSnapshot{
		Page: tuiPageDashboard,
		Settings: tuiSettings{
			Mode:       "rule",
			MixedPort:  17890,
			TunEnabled: true,
			TunScope:   tuiTunScopeUser,
		},
	}
	var dashboard strings.Builder
	drawTUIDashboard(
		&dashboard,
		snapshot,
		cliPaths{configPath: "/tmp/config.yaml"},
		100,
		26,
	)
	dashboardPlain := stripTUIANSI(dashboard.String())
	for _, row := range []string{
		"Core          STOPPED · Enter to start",
		"Mode          rule",
		"flc           pick a node in Proxies",
		"Proxy port    17890",
		"System proxy",
		"TUN           USER ON",
	} {
		if !strings.Contains(dashboardPlain, row) {
			t.Fatalf("Dashboard does not contain %q:\n%s", row, dashboardPlain)
		}
	}

	snapshot.Page = tuiPageTools
	var settings strings.Builder
	drawTUITools(&settings, snapshot, 100, 30)
	settingsPlain := stripTUIANSI(settings.String())
	for _, daily := range []string{
		"Core          STOPPED · Enter to start",
		"Mode          rule",
		"flc           pick a node in Proxies",
		"Proxy port    17890",
		"System proxy",
		"TUN           USER ON",
	} {
		if strings.Contains(settingsPlain, daily) {
			t.Fatalf("Settings repeats daily control %q:\n%s", daily, settingsPlain)
		}
	}
	for _, row := range []string{
		"Allow LAN",
		"IPv6",
		"Unified delay",
		"Log level",
		"TUN scope",
	} {
		if !strings.Contains(settingsPlain, row) {
			t.Fatalf("Settings does not contain %q:\n%s", row, settingsPlain)
		}
	}
}

func TestTUIParsesLinuxSystemMemoryUsingMemAvailable(t *testing.T) {
	total, available, err := parseTUISystemMemory([]byte(`MemTotal:       8192000 kB
MemFree:        1000000 kB
MemAvailable:   3072000 kB
Buffers:         100000 kB
Cached:          500000 kB
`))
	if err != nil {
		t.Fatal(err)
	}
	if total != 8192000*1024 || available != 3072000*1024 {
		t.Fatalf("memory = total %d available %d", total, available)
	}
}

func TestTUIParsesLinuxSystemMemoryFallback(t *testing.T) {
	total, available, err := parseTUISystemMemory([]byte(`MemTotal: 4096 kB
MemFree: 512 kB
Buffers: 128 kB
Cached: 1024 kB
`))
	if err != nil {
		t.Fatal(err)
	}
	if total != 4096*1024 || available != (512+128+1024)*1024 {
		t.Fatalf("fallback memory = total %d available %d", total, available)
	}
}

func TestTUIReadsProcessRSSFromLinuxStatm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "statm")
	if err := os.WriteFile(path, []byte("100 25 3 2 0 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rss, err := readTUIProcessRSS(path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if rss != 25*4096 {
		t.Fatalf("RSS = %d, want %d", rss, 25*4096)
	}
}

func TestTUILocalMemorySampleIncludesSystemProcessAndGoHeap(t *testing.T) {
	info := sampleTUIMemory(tuiMemoryInfo{}, false)
	if info.SystemTotal == 0 || info.SystemUsed == 0 {
		t.Fatalf("system memory was not sampled: %+v", info)
	}
	if info.ProcessRSS == 0 {
		t.Fatalf("process RSS was not sampled: %+v", info)
	}
	if info.GoHeap == 0 {
		t.Fatalf("Go heap was not sampled: %+v", info)
	}
	if info.ExternalCore {
		t.Fatal("embedded sample was marked as external")
	}
	if info.UpdatedAt.IsZero() {
		t.Fatal("memory sample has no timestamp")
	}
}

func TestTUIMemoryRefreshPreservesNewerExternalCoreSample(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, false)
	newer := time.Now()
	model.memoryRefreshActive = true
	model.snapshot.Memory = tuiMemoryInfo{
		CoreRSS:     222 << 20,
		CoreUpdated: newer,
	}
	_, _ = model.Update(tuiMemoryResultMsg{
		info: tuiMemoryInfo{
			SystemTotal: 8 << 30,
			SystemUsed:  4 << 30,
			ProcessRSS:  20 << 20,
			CoreRSS:     111 << 20,
			CoreUpdated: newer.Add(-time.Second),
			UpdatedAt:   newer,
		},
	})
	if model.memoryRefreshActive {
		t.Fatal("memory refresh remained active after receiving a sample")
	}
	if model.snapshot.Memory.CoreRSS != 222<<20 {
		t.Fatalf("newer external Core RSS was overwritten: %+v", model.snapshot.Memory)
	}
	if model.snapshot.Memory.SystemTotal != 8<<30 {
		t.Fatalf("local memory sample was not applied: %+v", model.snapshot.Memory)
	}
}

func TestTUIExternalCoreMemoryErrorKeepsLastRSS(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, false)
	model.snapshot.Memory.CoreRSS = 256 << 20
	_, command := model.Update(tuiCoreMemoryMsg{
		update: tuiCoreMemoryUpdate{
			Error:     "temporary disconnect",
			UpdatedAt: time.Now(),
		},
	})
	if command != nil {
		t.Fatal("model without a monitor scheduled another monitor read")
	}
	if model.snapshot.Memory.CoreRSS != 256<<20 {
		t.Fatalf("temporary error erased the last Core RSS: %+v", model.snapshot.Memory)
	}
	if model.snapshot.Memory.CoreError != "temporary disconnect" {
		t.Fatalf("Core memory error = %q", model.snapshot.Memory.CoreError)
	}
}

func TestTUIExternalCoreMemoryStreamIgnoresInitialZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/memory" {
			t.Fatalf("memory path = %q", request.URL.Path)
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("test response does not support flushing")
		}
		_, _ = io.WriteString(w, "{\"inuse\":0,\"oslimit\":0}\n")
		flusher.Flush()
		_, _ = io.WriteString(w, "{\"inuse\":98765432,\"oslimit\":0}\n")
		flusher.Flush()
		<-request.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	values := make(chan uint64, 1)
	errors := make(chan error, 1)
	go func() {
		errors <- streamTUICoreMemory(
			ctx,
			controllerClient{
				options: controllerOptions{address: server.URL},
				client:  server.Client(),
			},
			func(value uint64) {
				values <- value
				cancel()
			},
		)
	}()
	select {
	case value := <-values:
		if value != 98765432 {
			t.Fatalf("external Core RSS = %d", value)
		}
	case <-time.After(time.Second):
		t.Fatal("external Core memory stream did not produce a value")
	}
	select {
	case <-errors:
	case <-time.After(time.Second):
		t.Fatal("external Core memory stream did not stop after cancellation")
	}
}

func TestTUITrafficUpdateAppliesLiveAndTotalCounters(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, false)
	_, command := model.Update(tuiTrafficMsg{
		update: tuiTrafficUpdate{
			Traffic: trafficSnapshot{
				Up:        1024,
				Down:      2048,
				UpTotal:   4096,
				DownTotal: 8192,
			},
		},
	})
	if command != nil {
		t.Fatal("model without a traffic monitor scheduled another monitor read")
	}
	if model.snapshot.Traffic.Up != 1024 ||
		model.snapshot.Traffic.Down != 2048 ||
		model.snapshot.TotalTraffic.Up != 4096 ||
		model.snapshot.TotalTraffic.Down != 8192 {
		t.Fatalf("traffic update was not applied: %+v", model.snapshot)
	}
	if len(model.snapshot.TrafficHistory) != 1 ||
		model.snapshot.TrafficHistory[0].Up != 1024 ||
		model.snapshot.TrafficHistory[0].Down != 2048 {
		t.Fatalf("traffic history was not updated: %+v", model.snapshot.TrafficHistory)
	}
}

func TestTUITrafficHistoryKeepsLatestThirtySamples(t *testing.T) {
	history := []trafficSnapshot{}
	for index := 0; index < tuiTrafficHistoryLimit+7; index++ {
		history = appendTUITrafficHistory(history, trafficSnapshot{
			Up:   int64(index),
			Down: int64(index * 2),
		})
	}
	if len(history) != tuiTrafficHistoryLimit {
		t.Fatalf("traffic history length = %d", len(history))
	}
	if history[0].Up != 7 || history[len(history)-1].Up != 36 {
		t.Fatalf("traffic history retained the wrong range: %+v", history)
	}
}

func TestTUITrafficChartOverlaysUploadAndDownload(t *testing.T) {
	history := make([]trafficSnapshot, tuiTrafficHistoryLimit)
	for index := range history {
		history[index] = trafficSnapshot{
			Up:   int64(index * 1024),
			Down: int64((tuiTrafficHistoryLimit - index) * 2048),
		}
	}
	chart := buildTUITrafficChart(history, 32, 4)
	if chart.peak != int64(tuiTrafficHistoryLimit*2048) {
		t.Fatalf("traffic chart peak = %d", chart.peak)
	}
	if len(chart.lines) != 4 {
		t.Fatalf("traffic chart line count = %d", len(chart.lines))
	}
	rendered := strings.Join(chart.lines, "\n")
	if !strings.Contains(rendered, tuiTrafficChartUpload) ||
		!strings.Contains(rendered, tuiTrafficChartDownload) ||
		!strings.Contains(rendered, tuiTrafficChartOverlap) {
		t.Fatalf("traffic chart does not contain both series and overlap: %q", rendered)
	}
	if tuiTrafficChartUpload != "\x1b[38;5;33m" ||
		tuiTrafficChartDownload != tuiGreen ||
		tuiTrafficChartOverlap != tuiCyan ||
		strings.Contains(rendered, "\x1b[97m") {
		t.Fatalf("traffic chart colors are not blue/green/cyan: %q", rendered)
	}
	empty := buildTUITrafficChart(nil, 12, 3)
	if strings.Contains(stripTUIANSI(empty.lines[0]), "·") ||
		strings.Contains(stripTUIANSI(empty.lines[1]), "·") ||
		stripTUIANSI(empty.lines[2]) != strings.Repeat("·", 12) ||
		!strings.Contains(empty.lines[2], tuiTrafficChartBaseline) {
		t.Fatalf("traffic chart baseline is not white dotted: %q", empty.lines)
	}
}

func TestTUITrafficLegendMatchesSeriesColorsAndResetsBorder(t *testing.T) {
	traffic := trafficSnapshot{Up: 1024, Down: 2048}
	legend := formatTUITrafficLegend(traffic, 4096)
	if !strings.Contains(
		legend,
		tuiTrafficChartUpload+"↑ 1.0 KB/s"+tuiReset,
	) || !strings.Contains(
		legend,
		tuiTrafficChartDownload+"↓ 2.0 KB/s"+tuiReset,
	) {
		t.Fatalf("traffic legend does not match series colors: %q", legend)
	}
	example := formatTUITrafficLegend(
		trafficSnapshot{Up: 1021, Down: 18},
		2048,
	)
	if !strings.Contains(
		example,
		tuiTrafficChartUpload+"↑ 1021.0 B/s"+tuiReset,
	) || !strings.Contains(
		example,
		tuiTrafficChartDownload+"↓ 18.0 B/s"+tuiReset,
	) {
		t.Fatalf("live traffic values do not match chart colors: %q", example)
	}

	var output strings.Builder
	tuiTrafficTitle(&output, traffic, 4096, 60)
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[1], tuiReset+"│") {
		t.Fatalf("traffic title color polluted its border: %q", output.String())
	}
}

func TestTUICompactTrafficChartAdaptsToViewportHeight(t *testing.T) {
	for _, test := range []struct {
		height int
		want   int
	}{
		{height: 8, want: 1},
		{height: 10, want: 1},
		{height: 11, want: 2},
		{height: 14, want: 2},
		{height: 15, want: 3},
		{height: 30, want: 3},
	} {
		if got := tuiCompactTrafficChartHeight(test.height); got != test.want {
			t.Fatalf(
				"compact chart height at %d = %d, want %d",
				test.height,
				got,
				test.want,
			)
		}
	}
}

func TestTUIRefreshKeepsNewerTrafficHistory(t *testing.T) {
	current := tuiSnapshot{
		Traffic: trafficSnapshot{Up: 30, Down: 40},
		TrafficHistory: []trafficSnapshot{
			{Up: 10, Down: 20},
			{Up: 30, Down: 40},
		},
		TotalTraffic: trafficSnapshot{Up: 50, Down: 60},
	}
	refreshed := tuiSnapshot{
		Traffic:        trafficSnapshot{Up: 1, Down: 2},
		TrafficHistory: []trafficSnapshot{{Up: 1, Down: 2}},
		TotalTraffic:   trafficSnapshot{Up: 3, Down: 4},
	}
	merged := mergeTUIRefresh(current, refreshed)
	if merged.Traffic != current.Traffic ||
		merged.TotalTraffic != current.TotalTraffic ||
		!slices.Equal(merged.TrafficHistory, current.TrafficHistory) {
		t.Fatalf("refresh restored stale traffic: %+v", merged)
	}
}

func TestTUIRefreshSelectsImportWhenLastProfileDisappears(t *testing.T) {
	current := tuiSnapshot{
		SelectedRow: 0,
		Profiles: []tuiProfile{{
			Name: "deleted.yaml",
			Path: "/tmp/deleted.yaml",
		}},
	}
	merged := mergeTUIRefresh(current, tuiSnapshot{})
	if merged.SelectedRow != tuiProfileImportSubscriptionRow {
		t.Fatalf(
			"empty Profile refresh selected row %d, want subscription import",
			merged.SelectedRow,
		)
	}
	merged = mergeTUIRefresh(current, tuiSnapshot{Profiles: []tuiProfile{{
		Name: "other.yaml",
		Path: "/tmp/other.yaml",
	}}})
	if merged.SelectedRow != tuiProfileImportSubscriptionRow {
		t.Fatalf(
			"Profile refresh selected unrelated profile row %d instead of import",
			merged.SelectedRow,
		)
	}
}

func TestTUITrafficStreamOutlivesControllerRequestTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/traffic" {
			t.Fatalf("traffic path = %q", request.URL.Path)
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("test response does not support flushing")
		}
		select {
		case <-time.After(900 * time.Millisecond):
		case <-request.Context().Done():
			return
		}
		_, _ = io.WriteString(
			w,
			"{\"up\":1024,\"down\":2048,\"upTotal\":4096,\"downTotal\":8192}\n",
		)
		flusher.Flush()
		<-request.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	values := make(chan trafficSnapshot, 1)
	errors := make(chan error, 1)
	baseClient := server.Client()
	go func() {
		errors <- streamTUITraffic(
			ctx,
			controllerClient{
				options: controllerOptions{address: server.URL},
				client: &http.Client{
					Transport: baseClient.Transport,
					Timeout:   750 * time.Millisecond,
				},
			},
			func(value trafficSnapshot) {
				values <- value
				cancel()
			},
		)
	}()
	select {
	case value := <-values:
		if value.Up != 1024 || value.Down != 2048 ||
			value.UpTotal != 4096 || value.DownTotal != 8192 {
			t.Fatalf("traffic stream value = %+v", value)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("traffic stream was stopped by the short controller timeout")
	}
	select {
	case <-errors:
	case <-time.After(time.Second):
		t.Fatal("traffic stream did not stop after cancellation")
	}
}

func TestTUIDashboardRendersEmbeddedAndExternalMemory(t *testing.T) {
	base := populatedTUISnapshot(tuiPageDashboard)
	base.Memory = tuiMemoryInfo{
		SystemTotal: 8 << 30,
		SystemUsed:  4 << 30,
		ProcessRSS:  120 << 20,
		GoHeap:      48 << 20,
		UpdatedAt:   time.Now(),
	}
	var embedded strings.Builder
	drawTUIDashboard(
		&embedded,
		base,
		cliPaths{configPath: "/tmp/config.yaml"},
		100,
		26,
	)
	embeddedPlain := stripTUIANSI(embedded.String())
	for _, expected := range []string{
		"memory refresh 2s",
		"System memory 4.0 GB / 8.0 GB  50.0%",
		"CLI + Mihomo  120.0 MB RSS · shared process",
		"Go heap       48.0 MB",
	} {
		if !strings.Contains(embeddedPlain, expected) {
			t.Fatalf("embedded Dashboard does not contain %q:\n%s", expected, embeddedPlain)
		}
	}

	externalSnapshot := base
	externalSnapshot.ExternalCore = true
	externalSnapshot.Memory.ExternalCore = true
	externalSnapshot.Memory.CoreRSS = 256 << 20
	externalSnapshot.Memory.CoreUpdated = time.Now()
	var external strings.Builder
	drawTUIDashboard(
		&external,
		externalSnapshot,
		cliPaths{configPath: "/tmp/config.yaml"},
		100,
		26,
	)
	externalPlain := stripTUIANSI(external.String())
	for _, expected := range []string{
		"TUI process   120.0 MB",
		"External Core 256.0 MB",
	} {
		if !strings.Contains(externalPlain, expected) {
			t.Fatalf("external Dashboard does not contain %q:\n%s", expected, externalPlain)
		}
	}
}

func TestTUIDashboardRendersAdaptiveLiveTrafficChart(t *testing.T) {
	snapshot := populatedTUISnapshot(tuiPageDashboard)
	for index := 0; index < tuiTrafficHistoryLimit; index++ {
		snapshot.TrafficHistory = append(snapshot.TrafficHistory, trafficSnapshot{
			Up:   int64((index + 1) * 1024),
			Down: int64((tuiTrafficHistoryLimit - index) * 2048),
		})
	}
	snapshot.Traffic = snapshot.TrafficHistory[len(snapshot.TrafficHistory)-1]
	output := renderTUIAtSize(
		snapshot,
		cliPaths{configPath: "/tmp/config.yaml"},
		"private Unix socket",
		true,
		true,
		120,
		40,
	)
	plain := stripTUIANSI(output)
	for _, expected := range []string{
		"Live traffic",
		"30 samples",
		"Traffic total",
	} {
		if !strings.Contains(plain, expected) {
			t.Fatalf("Dashboard traffic chart does not contain %q:\n%s", expected, plain)
		}
	}
	if !strings.Contains(output, tuiTrafficChartUpload+"↑ ") ||
		!strings.Contains(output, tuiTrafficChartDownload+"↓ ") {
		t.Fatalf("Dashboard traffic legend is missing series colors: %q", output)
	}
}

func TestTUIProxiesExposeSelectedAndWholeGroupDelayTests(t *testing.T) {
	snapshot := populatedTUISnapshot(tuiPageProxies)
	snapshot.FocusSidebar = false
	snapshot.SelectedGroup = 0
	snapshot.SelectedNode = 0
	snapshot.Groups = []tuiGroup{{
		Name:  "Proxy",
		Type:  "Selector",
		Now:   "fast",
		Nodes: []string{"fast", "slow", "dead", "new"},
		Delays: map[string]tuiDelayResult{
			"fast": {MedianMillis: 18, Samples: 5},
			"slow": {Testing: true},
			"dead": {Error: "timeout"},
		},
	}}
	var output strings.Builder
	drawTUIProxies(&output, snapshot, 100, 24)
	plain := stripTUIANSI(output.String())
	for _, expected := range []string{
		"↑↓/ws group",
		"d test group",
		"Enter apply",
		"18 ms",
		"Testing...",
		"Timeout · d retry",
		"[d test]",
	} {
		if !strings.Contains(plain, expected) {
			t.Fatalf("Proxies does not contain %q:\n%s", expected, plain)
		}
	}
	key, ok := tuiKeyFromTea(tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune{'A'},
	})
	if !ok || key != tuiKeyDelayTestAll {
		t.Fatalf("A key = (%v, %v)", key, ok)
	}
}

func TestTUIStagesMixedPortUntilCoreStart(t *testing.T) {
	model := newTUIModel(
		controllerClient{},
		cliPaths{configPath: filepath.Join(t.TempDir(), "missing.yaml")},
		nil,
		true,
	)
	model.snapshot.Page = tuiPageDashboard
	model.snapshot.FocusSidebar = false
	model.snapshot.Settings.MixedPort = 7890
	model.inputMode = tuiInputMixedPort
	model.inputValue = []rune("17890")

	command := model.submitInput()
	if command != nil {
		t.Fatal("staging a stopped core port unexpectedly started an asynchronous operation")
	}
	if model.coreRunning {
		t.Fatal("core was marked running while staging a port")
	}
	if model.pendingMixedPort == nil || *model.pendingMixedPort != 17890 {
		t.Fatalf("pending mixed port = %v", model.pendingMixedPort)
	}
	if model.snapshot.Settings.MixedPort != 17890 {
		t.Fatalf("displayed mixed port = %d", model.snapshot.Settings.MixedPort)
	}

	model.refreshSequence = 1
	model.refreshInFlight = true
	_, _ = model.Update(tuiRefreshResultMsg{
		sequence: 1,
		snapshot: tuiSnapshot{
			Status:    "Connected",
			UpdatedAt: time.Now(),
			Settings:  tuiSettings{MixedPort: 0},
		},
	})
	if model.snapshot.Settings.MixedPort != 17890 {
		t.Fatalf("refresh discarded staged mixed port: %d", model.snapshot.Settings.MixedPort)
	}
}

func TestTUIStagesPreStartSettings(t *testing.T) {
	model := newTUIModel(
		controllerClient{},
		cliPaths{configPath: filepath.Join(t.TempDir(), "missing.yaml")},
		nil,
		true,
	)
	model.snapshot.Page = tuiPageTools
	model.snapshot.FocusSidebar = false
	model.snapshot.Settings = tuiSettings{
		Mode:      "rule",
		MixedPort: 17890,
		AllowLAN:  false,
		IPv6:      true,
		LogLevel:  "info",
	}

	for _, key := range []tuiKey{
		tuiKeyAllowLAN,
		tuiKeyIPv6,
		tuiKeyLogLevel,
	} {
		if command := model.handleKey(key); command != nil {
			t.Fatalf("staging key %v unexpectedly returned an operation", key)
		}
	}
	model.snapshot.Page = tuiPageDashboard
	if command := model.handleKey(tuiKeyTun); command != nil {
		t.Fatalf("staging key %v unexpectedly returned an operation", tuiKeyTun)
	}
	if command := model.changeMode("global"); command != nil {
		t.Fatal("staging a selected mode unexpectedly returned an operation")
	}
	if model.coreRunning {
		t.Fatal("staging settings started the core")
	}
	if model.stagedSettings == nil {
		t.Fatal("settings were not staged")
	}
	if !model.stagedSettings.TunEnabled ||
		!model.stagedSettings.AllowLAN ||
		model.stagedSettings.IPv6 ||
		model.stagedSettings.Mode != "global" ||
		model.stagedSettings.LogLevel != "debug" {
		t.Fatalf("unexpected staged settings: %+v", *model.stagedSettings)
	}

	model.refreshSequence = 1
	model.refreshInFlight = true
	_, _ = model.Update(tuiRefreshResultMsg{
		sequence: 1,
		snapshot: tuiSnapshot{
			Status:    "Connected",
			UpdatedAt: time.Now(),
			Settings: tuiSettings{
				Mode:       "direct",
				MixedPort:  0,
				AllowLAN:   false,
				IPv6:       true,
				LogLevel:   "silent",
				TunEnabled: false,
			},
		},
	})
	if model.snapshot.Settings != *model.stagedSettings {
		t.Fatalf("refresh discarded staged settings: %+v", model.snapshot.Settings)
	}
}

func TestTUIDashboardRefreshKeepsSilentTUNAndFLCOverlay(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, tuiServiceSocketFilename)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	actions := make(chan string, 8)
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			var request tuiServiceRequest
			if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
				_ = connection.Close()
				continue
			}
			select {
			case actions <- request.Action:
			default:
			}
			_ = json.NewEncoder(connection).Encode(tuiServiceStatus{
				ProtocolVersion:     tuiServiceProtocolVersion,
				RequestID:           request.RequestID,
				Revision:            3,
				OK:                  true,
				Running:             true,
				Mode:                tuiSilentMode,
				ProxyPort:           17890,
				ConfiguredProxyPort: 17890,
				ActiveProxyPort:     17890,
				TunState:            "off",
				TunScope:            tuiTunScopeSystem,
				FLCEnabled:          true,
				FLCOutbound:         "PROXY",
			})
			_ = connection.Close()
		}
	}()

	controller := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/proxies":
			_, _ = io.WriteString(w, `{"proxies":{"PROXY":{"type":"Selector","now":"hk-1","all":["DIRECT","hk-1"]}}}`)
		case "/connections":
			_, _ = io.WriteString(w, `{"connections":[]}`)
		case "/configs":
			_, _ = io.WriteString(w, `{
				"mode":"rule",
				"mixed-port":17890,
				"allow-lan":false,
				"ipv6":false,
				"unified-delay":true,
				"tcp-concurrent":true,
				"log-level":"info",
				"tun":{"enable":true}
			}`)
		case "/providers/proxies":
			_, _ = io.WriteString(w, `{"providers":{}}`)
		default:
			http.NotFound(w, request)
		}
	}))
	defer controller.Close()

	model := newTUIModel(
		controllerClient{
			options: controllerOptions{address: controller.URL},
			client:  controller.Client(),
		},
		cliPaths{},
		nil,
		true,
	)
	model.service = newTUIServiceClientAt(directory)
	model.coreRunning = true
	model.snapshot.Page = tuiPageDashboard
	model.snapshot.Settings = tuiSettings{
		Mode:       tuiSilentMode,
		MixedPort:  17890,
		TunEnabled: false,
		TunScope:   tuiTunScopeSystem,
	}
	model.snapshot.FLCEnabled = true
	model.snapshot.FLCOutbound = "PROXY"
	model.snapshot.Groups = []tuiGroup{{
		Name:  "PROXY",
		Now:   "hk-1",
		Nodes: []string{"DIRECT", "hk-1"},
	}}

	refresh := model.startRefresh()
	if refresh == nil {
		t.Fatal("Dashboard refresh did not start")
	}
	if model.refreshIncludesHistory || model.refreshIncludesLogs {
		t.Fatalf(
			"Dashboard refresh scheduled History/Logs bulk fetch: history=%t logs=%t",
			model.refreshIncludesHistory,
			model.refreshIncludesLogs,
		)
	}
	_, _ = model.Update(refresh())

	if model.snapshot.Settings.Mode != tuiSilentMode {
		t.Fatalf("Dashboard refresh dropped silent mode: %+v", model.snapshot.Settings)
	}
	if model.snapshot.Settings.TunEnabled ||
		model.snapshot.Settings.TunScope != tuiTunScopeSystem {
		t.Fatalf("Dashboard refresh dropped SYSTEM TUN overlay: %+v", model.snapshot.Settings)
	}
	if label := tuiTUNLabel(model.snapshot); label != "OFF · locked by silent mode" {
		t.Fatalf("TUN label = %q", label)
	}
	if label := tuiFLCOutboundLabel(model.snapshot); !strings.Contains(label, "READY") &&
		!strings.Contains(label, "WAITING FOR CORE") {
		t.Fatalf("flc lost silent suffix: %q", label)
	}
	if !strings.Contains(tuiFLCOutboundLabel(model.snapshot), "PROXY") {
		t.Fatalf("flc outbound was lost: %q", tuiFLCOutboundLabel(model.snapshot))
	}

	select {
	case action := <-actions:
		if action != "status" {
			t.Fatalf("Dashboard refresh called %q, want status", action)
		}
	case <-time.After(time.Second):
		t.Fatal("Dashboard refresh did not call Backend status")
	}
	select {
	case action := <-actions:
		t.Fatalf("Dashboard refresh made extra Backend call %q", action)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestTUIStoppedRefreshKeepsBackendModeAndTunState(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.stagedSettings = &tuiSettings{
		Mode:       "rule",
		MixedPort:  7890,
		TunEnabled: true,
		TunScope:   tuiTunScopeUser,
	}
	model.refreshSequence = 1
	model.refreshInFlight = true
	serviceStatus := &tuiServiceStatus{
		Running:             false,
		Mode:                tuiSilentMode,
		ConfiguredProxyPort: 7890,
		TunState:            "off",
		TunScope:            tuiTunScopeSystem,
	}

	_, _ = model.Update(tuiRefreshResultMsg{
		sequence: 1,
		snapshot: tuiSnapshot{
			Status:   "Connected",
			Settings: tuiSettings{Mode: "rule", TunEnabled: true},
		},
		serviceStatus: serviceStatus,
	})

	if model.snapshot.Settings.Mode != tuiSilentMode ||
		model.snapshot.Settings.TunEnabled ||
		model.snapshot.Settings.TunScope != tuiTunScopeSystem {
		t.Fatalf(
			"staged YAML hid Backend mode/TUN state: %+v",
			model.snapshot.Settings,
		)
	}
	if !strings.Contains(model.snapshot.Status, "start Core") {
		t.Fatalf("stopped Dashboard guidance = %q", model.snapshot.Status)
	}
}

func TestSyncStoppedSettingsSeparatesBackendAndProfileState(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	profileSettings := tuiSettings{
		Mode:       "global",
		MixedPort:  12345,
		LogLevel:   "info",
		TunEnabled: true,
	}
	updated, err := applyTUISettingsToConfig(
		[]byte(defaultTUIConfig),
		profileSettings,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, updated, 0o600); err != nil {
		t.Fatal(err)
	}
	state := tuiOperationState{
		paths: cliPaths{homeDir: directory, configPath: configPath},
		snapshot: tuiSnapshot{Settings: tuiSettings{
			Mode:        tuiSilentMode,
			SystemProxy: false,
			TunEnabled:  false,
			TunScope:    tuiTunScopeSystem,
		}},
	}

	syncStoppedTUISettings(&state)
	if state.stagedSettings == nil ||
		state.stagedSettings.Mode != "global" ||
		!state.stagedSettings.TunEnabled {
		t.Fatalf("profile staged settings = %+v", state.stagedSettings)
	}
	if state.snapshot.Settings.Mode != tuiSilentMode ||
		state.snapshot.Settings.TunEnabled ||
		state.snapshot.Settings.TunScope != tuiTunScopeSystem {
		t.Fatalf("Backend display state was overwritten: %+v", state.snapshot.Settings)
	}
}

func TestTUISilentStopStartDoesNotCommitDisplayMode(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(configPath, []byte(defaultTUIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen(
		"unix",
		filepath.Join(directory, tuiServiceSocketFilename),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requests := make(chan tuiServiceRequest, 2)
	serverDone := make(chan error, 1)
	go func() {
		for index := 0; index < 2; index++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverDone <- acceptErr
				return
			}
			var request tuiServiceRequest
			decodeErr := json.NewDecoder(connection).Decode(&request)
			if decodeErr == nil {
				requests <- request
				decodeErr = json.NewEncoder(connection).Encode(tuiServiceStatus{
					OK:                  true,
					Revision:            uint64(8 + index),
					Running:             index == 1,
					Mode:                tuiSilentMode,
					ConfigPath:          configPath,
					ConfiguredProxyPort: 12345,
					TunState:            "off",
					TunScope:            tuiTunScopeUser,
					FLCEnabled:          index == 1,
					FLCOutbound:         "PROXY",
				})
			}
			_ = connection.Close()
			if decodeErr != nil {
				serverDone <- decodeErr
				return
			}
		}
		serverDone <- nil
	}()

	state := tuiOperationState{
		paths:           cliPaths{homeDir: directory, configPath: configPath},
		coreRunning:     true,
		backendRevision: 7,
		snapshot: tuiSnapshot{Settings: tuiSettings{
			Mode:      tuiSilentMode,
			MixedPort: 12345,
		}},
	}
	service := newTUIServiceClientAt(directory)
	if !stopTUIManagedCore(&state, service) {
		t.Fatalf("silent Core stop failed: %s", state.snapshot.Status)
	}
	if state.stagedSettings == nil || state.stagedSettings.Mode != "rule" ||
		state.settingsDirty || state.snapshot.Settings.Mode != tuiSilentMode {
		t.Fatalf("stopped silent state = %+v", state)
	}
	if !startTUIManagedCore(&state, service) {
		t.Fatalf("silent Core restart failed: %s", state.snapshot.Status)
	}
	first := <-requests
	second := <-requests
	if first.Action != "stop" || second.Action != "start" {
		t.Fatalf("silent restart requests = %q, %q", first.Action, second.Action)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if !state.coreRunning || state.snapshot.Settings.Mode != tuiSilentMode ||
		!state.snapshot.FLCEnabled {
		t.Fatalf("restarted silent state = %+v", state)
	}
}

func TestTUISilentDirtyStagedSettingsRecoverNativeProfileMode(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	profileSettings := tuiSettings{
		Mode:       "global",
		MixedPort:  12345,
		LogLevel:   "info",
		TunEnabled: true,
	}
	updated, err := applyTUISettingsToConfig(
		[]byte(defaultTUIConfig),
		profileSettings,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, updated, 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen(
		"unix",
		filepath.Join(directory, tuiServiceSocketFilename),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requests := make(chan tuiServiceRequest, 3)
	serverDone := make(chan error, 1)
	go func() {
		for index := 0; index < 3; index++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverDone <- acceptErr
				return
			}
			var request tuiServiceRequest
			decodeErr := json.NewDecoder(connection).Decode(&request)
			if decodeErr == nil {
				requests <- request
				decodeErr = json.NewEncoder(connection).Encode(tuiServiceStatus{
					OK:                  true,
					Revision:            uint64(20 + index),
					Running:             index == 2,
					Mode:                tuiSilentMode,
					ConfigPath:          configPath,
					ConfiguredProxyPort: 12346,
					TunState:            "off",
					TunScope:            tuiTunScopeUser,
					FLCEnabled:          index == 2,
					FLCOutbound:         "PROXY",
				})
			}
			_ = connection.Close()
			if decodeErr != nil {
				serverDone <- decodeErr
				return
			}
		}
		serverDone <- nil
	}()

	state := tuiOperationState{
		paths:         cliPaths{homeDir: directory, configPath: configPath},
		settingsDirty: true,
		stagedSettings: &tuiSettings{
			Mode:       tuiSilentMode,
			MixedPort:  12346,
			LogLevel:   "debug",
			TunEnabled: false,
		},
		snapshot: tuiSnapshot{Settings: tuiSettings{
			Mode:      tuiSilentMode,
			MixedPort: 12346,
		}},
	}
	if !startTUIManagedCore(&state, newTUIServiceClientAt(directory)) {
		t.Fatalf("dirty silent Core start failed: %s", state.snapshot.Status)
	}
	statusRequest := <-requests
	applyRequest := <-requests
	startRequest := <-requests
	if statusRequest.Action != "status" || applyRequest.Action != "apply_settings" ||
		startRequest.Action != "start" {
		t.Fatalf(
			"dirty silent start requests = %q, %q, %q",
			statusRequest.Action,
			applyRequest.Action,
			startRequest.Action,
		)
	}
	if applyRequest.Settings == nil ||
		applyRequest.Settings.Mode != "global" ||
		!applyRequest.Settings.TunEnabled ||
		applyRequest.Settings.MixedPort != 12346 ||
		applyRequest.Settings.LogLevel != "debug" {
		t.Fatalf("recovered profile settings = %+v", applyRequest.Settings)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if !state.coreRunning || state.snapshot.Settings.Mode != tuiSilentMode ||
		!state.snapshot.FLCEnabled {
		t.Fatalf("recovered silent state = %+v", state)
	}
}

func TestTUISilentSettingsCommitPreservesNativeModeAndTun(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	profileSettings := tuiSettings{
		Mode:       "global",
		MixedPort:  12345,
		LogLevel:   "info",
		TunEnabled: true,
	}
	updated, err := applyTUISettingsToConfig(
		[]byte(defaultTUIConfig),
		profileSettings,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, updated, 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen(
		"unix",
		filepath.Join(directory, tuiServiceSocketFilename),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requestReceived := make(chan tuiServiceRequest, 1)
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		var request tuiServiceRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			serverDone <- decodeErr
			return
		}
		requestReceived <- request
		serverDone <- json.NewEncoder(connection).Encode(tuiServiceStatus{
			OK:                  true,
			Revision:            12,
			Mode:                tuiSilentMode,
			ConfigPath:          configPath,
			ConfiguredProxyPort: 12346,
			TunState:            "off",
			TunScope:            tuiTunScopeUser,
		})
	}()

	state := tuiOperationState{
		paths:           cliPaths{homeDir: directory, configPath: configPath},
		backendRevision: 11,
		snapshot: tuiSnapshot{Settings: tuiSettings{
			Mode:      tuiSilentMode,
			MixedPort: 12345,
		}},
	}
	desired := state.snapshot.Settings
	desired.MixedPort = 12346
	desired.AllowLAN = true
	coreServer := httptest.NewServer(http.HandlerFunc(func(
		w http.ResponseWriter,
		request *http.Request,
	) {
		if request.URL.Path != "/configs" {
			http.NotFound(w, request)
			return
		}
		_, _ = io.WriteString(w, `{
  "mode": "global",
  "mixed-port": 55555,
  "allow-lan": true,
  "log-level": "info",
  "tun": {"enable": true}
}`)
	}))
	defer coreServer.Close()
	commitTUIOperationSettings(
		&state,
		newTUIServiceClientAt(directory),
		controllerClient{
			options: controllerOptions{address: coreServer.URL},
			client:  coreServer.Client(),
		},
		desired,
	)
	request := <-requestReceived
	if request.Action != "apply_settings" || request.Settings == nil ||
		request.Settings.Mode != "global" ||
		!request.Settings.TunEnabled ||
		request.Settings.MixedPort != 12346 {
		t.Fatalf("profile settings request = %+v", request)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if state.snapshot.Settings.Mode != tuiSilentMode ||
		state.snapshot.Settings.TunEnabled ||
		state.snapshot.Settings.MixedPort != 12346 {
		t.Fatalf("post-commit display state = %+v", state.snapshot.Settings)
	}
}

func TestTUIRunningCoreUsesLiveSettingsInsteadOfStagedYAML(t *testing.T) {
	model := newTUIModel(controllerClient{}, cliPaths{}, nil, true)
	model.snapshot.Settings = tuiSettings{MixedPort: 12345}
	model.stagedSettings = &tuiSettings{MixedPort: 12345}
	stagedPort := 12345
	model.pendingMixedPort = &stagedPort
	model.settingsDirty = true

	model.initializeCoreRuntime(true)
	if model.stagedSettings != nil || model.pendingMixedPort != nil || model.settingsDirty {
		t.Fatalf(
			"running Core retained staged settings: staged=%+v pending=%v dirty=%v",
			model.stagedSettings,
			model.pendingMixedPort,
			model.settingsDirty,
		)
	}

	model.refreshSequence = 1
	model.refreshInFlight = true
	_, _ = model.Update(tuiRefreshResultMsg{
		sequence: 1,
		snapshot: tuiSnapshot{
			Status:    "Connected",
			UpdatedAt: time.Now(),
			Settings:  tuiSettings{MixedPort: 8001},
		},
	})
	if model.snapshot.Settings.MixedPort != 8001 {
		t.Fatalf(
			"Dashboard mixed port = %d, want live Core port 8001",
			model.snapshot.Settings.MixedPort,
		)
	}
}

func TestTUIOperationResultKeepsLiveTrafficUpdates(t *testing.T) {
	current := tuiSnapshot{
		Traffic:        trafficSnapshot{Up: 11, Down: 22},
		TrafficHistory: []trafficSnapshot{{Up: 11, Down: 22}},
		TotalTraffic:   trafficSnapshot{Up: 33, Down: 44},
	}
	staleResult := tuiSnapshot{
		Traffic:        trafficSnapshot{Up: 1, Down: 2},
		TrafficHistory: []trafficSnapshot{{Up: 1, Down: 2}},
		TotalTraffic:   trafficSnapshot{Up: 3, Down: 4},
	}

	merged := mergeTUIOperation(current, staleResult)
	if merged.Traffic != current.Traffic ||
		merged.TotalTraffic != current.TotalTraffic ||
		!slices.Equal(merged.TrafficHistory, current.TrafficHistory) {
		t.Fatalf(
			"operation result restored stale traffic: current=%+v/%+v merged=%+v/%+v",
			current.Traffic,
			current.TotalTraffic,
			merged.Traffic,
			merged.TotalTraffic,
		)
	}
}

func TestBackendImportsSubscriptionWithoutStartingCore(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.UserAgent() != tuiSubscriptionUserAgent {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !strings.Contains(request.Header.Get("Accept"), "application/yaml") {
			http.Error(w, "missing YAML accept header", http.StatusNotAcceptable)
			return
		}
		_, _ = io.WriteString(w, `mixed-port: 17891
mode: rule
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - DIRECT
rules:
  - MATCH,PROXY
`)
	}))
	defer server.Close()

	directory := t.TempDir()
	runtime := newTUIServiceRuntime(
		cliPaths{
			homeDir:    directory,
			configPath: filepath.Join(directory, "config.yaml"),
		},
		defaultCLITestURL,
		filepath.Join(directory, "core.sock"),
		nil,
		nil,
	)
	data, err := fetchTUISubscription(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "profile-imported.yaml")
	revision := uint64(1)
	sourceURL := server.URL
	status := runtime.handle(tuiServiceRequest{
		ProtocolVersion:  tuiServiceProtocolVersion,
		RequestID:        "import-profile",
		ExpectedRevision: &revision,
		Action:           "put_profile",
		ConfigPath:       path,
		ProfileData:      data,
		CreateOnly:       true,
		SubscriptionURL:  &sourceURL,
	})
	if !status.OK {
		t.Fatalf("import response = %+v", status)
	}
	if status.Running {
		t.Fatal("subscription import started the core")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	linkedURL, err := loadTUISubscriptionSource(directory, path)
	if err != nil || linkedURL != server.URL {
		t.Fatalf("subscription source = %q, %v", linkedURL, err)
	}
}

func TestTUIUpdatesSubscriptionAndPreservesLocalSettings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `mixed-port: 9999
mode: rule
allow-lan: false
ipv6: false
unified-delay: true
tcp-concurrent: true
log-level: info
tun:
  enable: false
proxies:
  - name: NEW-NODE
    type: direct
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - NEW-NODE
rules:
  - MATCH,PROXY
`)
	}))
	defer server.Close()

	directory := t.TempDir()
	activePath := filepath.Join(directory, "config.yaml")
	profilePath := filepath.Join(directory, "work.yaml")
	if err := os.WriteFile(activePath, []byte(defaultTUIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	original := `mixed-port: 17890
mode: global
allow-lan: true
ipv6: true
unified-delay: false
tcp-concurrent: false
log-level: debug
tun:
  enable: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - DIRECT
rules:
  - MATCH,PROXY
`
	if err := os.WriteFile(profilePath, []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := rememberTUISubscriptionSource(directory, profilePath, server.URL); err != nil {
		t.Fatal(err)
	}

	runtime := newTUIServiceRuntime(
		cliPaths{homeDir: directory, configPath: activePath},
		defaultCLITestURL,
		filepath.Join(directory, "core.sock"),
		nil,
		nil,
	)
	updated, err := fetchTUISubscription(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	settings := loadTUIConfiguredSettings(profilePath, true)
	if settings == nil {
		t.Fatal("could not read original local settings")
	}
	updated, err = applyTUISettingsToConfig(updated, *settings)
	if err != nil {
		t.Fatal(err)
	}
	revision := uint64(1)
	sourceURL := server.URL
	status := runtime.handle(tuiServiceRequest{
		ProtocolVersion:  tuiServiceProtocolVersion,
		RequestID:        "update-profile",
		ExpectedRevision: &revision,
		Action:           "put_profile",
		ConfigPath:       profilePath,
		ProfileData:      updated,
		ExpectedSHA256:   tuiBytesSHA256([]byte(original)),
		SubscriptionURL:  &sourceURL,
	})
	if !status.OK {
		t.Fatalf("update response = %+v", status)
	}

	data, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	for _, expected := range []string{
		"name: NEW-NODE",
		"mixed-port: 17890",
		"mode: global",
		"allow-lan: true",
		"ipv6: true",
		"unified-delay: false",
		"tcp-concurrent: false",
		"log-level: debug",
		"enable: true",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("updated profile does not contain %q:\n%s", expected, output)
		}
	}
	info, err := os.Stat(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("updated profile mode = %o, want 640", info.Mode().Perm())
	}
	if status.ResultPath != profilePath || status.Revision != 2 {
		t.Fatalf("subscription update status = %+v", status)
	}
}

func TestTUIUnlinkedProfileDoesNotPretendToRefreshSubscription(t *testing.T) {
	directory := t.TempDir()
	activePath := filepath.Join(directory, "config.yaml")
	profilePath := filepath.Join(directory, "legacy.yaml")
	for _, path := range []string{activePath, profilePath} {
		if err := os.WriteFile(path, []byte(defaultTUIConfig), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	model := newTUIModel(
		controllerClient{},
		cliPaths{homeDir: directory, configPath: activePath},
		nil,
		true,
	)
	model.snapshot.Page = tuiPageProfiles
	model.snapshot.FocusSidebar = false
	model.snapshot.Profiles = []tuiProfile{{
		Name: "legacy.yaml",
		Path: profilePath,
	}}
	model.snapshot.SelectedRow = 0

	if command := model.handleKey(tuiKeyUpdateProfile); command != nil {
		t.Fatal("unlinked profile unexpectedly started a subscription refresh")
	}
	if model.inputMode != tuiInputNone {
		t.Fatalf("unlinked profile opened manual URL input: %d", model.inputMode)
	}
	if !strings.Contains(model.snapshot.Status, "not linked to a subscription") {
		t.Fatalf("unlinked profile status = %q", model.snapshot.Status)
	}
}

func TestTUIProfileDeleteValidationAndTransaction(t *testing.T) {
	directory := t.TempDir()
	activePath := filepath.Join(directory, "config.yaml")
	targetPath := filepath.Join(directory, "school.yaml")
	for _, path := range []string{activePath, targetPath} {
		if err := os.WriteFile(path, []byte(defaultTUIConfig), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	model := newTUIModel(
		controllerClient{},
		cliPaths{homeDir: directory, configPath: activePath},
		nil,
		true,
	)
	model.snapshot.Page = tuiPageProfiles
	model.snapshot.FocusSidebar = false
	model.snapshot.SelectedRow = tuiProfileImportSubscriptionRow
	model.beginProfileDeleteConfirm()
	if model.profileDeleteOpen || !strings.Contains(model.snapshot.Status, "saved Profile") {
		t.Fatalf("import row deletion status = %q", model.snapshot.Status)
	}
	model.snapshot.Profiles = []tuiProfile{{
		Name:    "config.yaml",
		Path:    activePath,
		Current: true,
	}}
	model.snapshot.SelectedRow = 0
	model.beginProfileDeleteConfirm()
	if model.profileDeleteOpen || !strings.Contains(model.snapshot.Status, "active Profile") {
		t.Fatalf("active Profile deletion status = %q", model.snapshot.Status)
	}
	model.snapshot.Profiles = []tuiProfile{{
		Name:            "school.yaml",
		Path:            targetPath,
		SubscriptionURL: "https://secret.example/subscription-token",
	}}
	model.beginProfileDeleteConfirm()
	if model.profileDeleteOpen || !strings.Contains(model.snapshot.Status, "managed Backend") {
		t.Fatalf("unmanaged Profile deletion status = %q", model.snapshot.Status)
	}

	socketDirectory := t.TempDir()
	socketPath := filepath.Join(socketDirectory, tuiServiceSocketFilename)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requests := make(chan tuiServiceRequest, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var request tuiServiceRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			return
		}
		requests <- request
		if request.Action == "delete_profile" {
			_ = os.Remove(request.ConfigPath)
		}
		_ = json.NewEncoder(connection).Encode(tuiServiceStatus{
			OK:         true,
			Revision:   2,
			ConfigPath: activePath,
		})
	}()
	model.service = newTUIServiceClientAt(socketDirectory)
	model.backendRevision = 1
	model.beginProfileDeleteConfirm()
	if !model.profileDeleteOpen || model.profileDeleteKind != "subscription" {
		t.Fatalf("Profile confirmation state = %+v", model.snapshot.ProfileDelete)
	}
	confirmation := stripTUIANSI(model.View())
	if !strings.Contains(confirmation, "Delete school.yaml (subscription)?") ||
		strings.Contains(confirmation, "subscription-token") {
		t.Fatalf("unsafe or incomplete Profile confirmation:\n%s", confirmation)
	}
	_, cancelCommand := model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if cancelCommand != nil || model.profileDeleteOpen {
		t.Fatal("Profile deletion confirmation did not cancel in place")
	}
	if _, err := os.Stat(targetPath); err != nil {
		t.Fatalf("cancelled Profile deletion changed the file: %v", err)
	}
	model.beginProfileDeleteConfirm()
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if command == nil || model.profileDeleteOpen {
		t.Fatal("Profile confirmation did not schedule deletion")
	}
	rawMessage := command()
	message, ok := rawMessage.(tuiOperationResultMsg)
	if !ok {
		t.Fatalf("Profile deletion result type = %T", rawMessage)
	}
	_, _ = model.Update(message)
	request := <-requests
	if request.Action != "delete_profile" || request.ConfigPath != targetPath ||
		request.ExpectedRevision == nil || *request.ExpectedRevision != 1 {
		t.Fatalf("Profile deletion request = %+v", request)
	}
	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		t.Fatalf("deleted Profile still exists: %v", err)
	}
	if !strings.Contains(model.snapshot.Status, "Profile deleted: school.yaml") {
		t.Fatalf("Profile deletion status = %q", model.snapshot.Status)
	}
}

func TestTUIActiveSubscriptionUpdateReloadsWithoutStartingListeners(t *testing.T) {
	mixedPort := freeTUITestPort(t)
	controllerPort := freeTUITestPort(t)
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	original := fmt.Appendf(nil, `mixed-port: %d
mode: rule
log-level: silent
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - DIRECT
rules:
  - MATCH,PROXY
`, mixedPort)
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `mixed-port: 9999
mode: global
log-level: info
proxies:
  - name: UPDATED-DIRECT
    type: direct
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - UPDATED-DIRECT
rules:
  - MATCH,PROXY
`)
	}))
	defer server.Close()

	paths := cliPaths{homeDir: directory, configPath: configPath}
	controllerAddress := fmt.Sprintf("127.0.0.1:%d", controllerPort)
	setupParams, err := initializeCore(
		paths,
		"https://www.gstatic.com/generate_204",
		controllerAddress,
		"",
		"",
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		handleShutdown()
	})
	client := controllerClient{
		options: controllerOptions{address: controllerAddress},
		client:  &http.Client{Timeout: time.Second},
	}
	if err := waitForController(client, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := rememberTUISubscriptionSource(directory, configPath, server.URL); err != nil {
		t.Fatal(err)
	}

	model := newTUIModel(client, paths, setupParams, true)
	model.snapshot.Page = tuiPageProfiles
	model.snapshot.FocusSidebar = false
	model.snapshot.Profiles = []tuiProfile{{
		Name:            "config.yaml",
		Path:            configPath,
		Current:         true,
		SubscriptionURL: server.URL,
	}}
	model.snapshot.SelectedRow = 0
	command := model.handleKey(tuiKeyUpdateProfile)
	if command != nil {
		t.Fatal("TUI without a backend scheduled a shared-profile mutation")
	}
	if !strings.Contains(model.snapshot.Status, "managed backend") {
		t.Fatalf("unmanaged update status = %q", model.snapshot.Status)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, original) {
		t.Fatal("unmanaged TUI modified the active profile")
	}
}

func TestTUIBackgroundServiceHotReloadsSubscriptionWithoutStoppingListeners(
	t *testing.T,
) {
	mixedPort := freeTUITestPort(t)
	directory, err := os.MkdirTemp("/tmp", "flclash-service-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(directory)
	})
	previousRuntimeDirectory := cliRuntimeDirectoryOverride
	cliRuntimeDirectoryOverride = directory
	t.Cleanup(func() {
		cliRuntimeDirectoryOverride = previousRuntimeDirectory
	})
	configPath := filepath.Join(directory, "config.yaml")
	original := fmt.Appendf(nil, `mixed-port: %d
mode: rule
log-level: silent
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - DIRECT
rules:
  - MATCH,PROXY
`, mixedPort)
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rememberTUITrafficMode(directory, "rule"); err != nil {
		t.Fatal(err)
	}
	subscription := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprintf(w, `mixed-port: 9999
mode: global
log-level: info
proxies:
  - name: UPDATED-DIRECT
    type: direct
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - UPDATED-DIRECT
rules:
  - MATCH,PROXY
`)
		},
	))
	defer subscription.Close()
	if err := rememberTUISubscriptionSource(
		directory,
		configPath,
		subscription.URL,
	); err != nil {
		t.Fatal(err)
	}

	paths := cliPaths{homeDir: directory, configPath: configPath}
	serviceDone := make(chan error, 1)
	go func() {
		serviceDone <- runTUIService(
			paths,
			"https://www.gstatic.com/generate_204",
			nil,
			false,
		)
	}()
	service := newTUIServiceClient(directory)
	var status tuiServiceStatus
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var err error
		status, err = service.status()
		if err == nil {
			break
		}
		select {
		case serviceErr := <-serviceDone:
			t.Fatalf("background service exited before ready: %v", serviceErr)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !status.OK {
		select {
		case serviceErr := <-serviceDone:
			t.Fatalf("background service did not become ready: %v", serviceErr)
		default:
			t.Fatal("background service did not become ready")
		}
	}
	t.Cleanup(func() {
		_ = service.shutdown()
		select {
		case <-serviceDone:
		case <-time.After(2 * time.Second):
		}
	})
	if status.Running {
		t.Fatal("new background service unexpectedly started listeners")
	}
	stoppedModel := newTUIModel(
		controllerClient{},
		paths,
		nil,
		true,
	)
	stoppedModel.service = service
	stoppedModel.coreRunning = false
	stoppedModel.shutdown()
	stoppedStatus, err := service.status()
	if err != nil || stoppedStatus.Running {
		t.Fatalf(
			"q-style detach stopped an idle shared service: %+v, %v",
			stoppedStatus,
			err,
		)
	}
	status, err = service.start()
	if err != nil {
		t.Fatal(err)
	}
	if !status.Running || !waitForTUITestPort(mixedPort, true, 2*time.Second) {
		t.Fatal("background service did not start the mixed listener")
	}
	client := controllerClient{
		options: controllerOptions{unixSocket: status.CoreSocket},
		client: controllerHTTPClientForOptions(
			controllerOptions{unixSocket: status.CoreSocket},
			time.Second,
		),
	}
	model := newTUIModel(client, paths, nil, true)
	model.service = service
	model.coreRunning = true
	model.shutdown()
	detachedStatus, err := service.status()
	if err != nil || !detachedStatus.Running {
		t.Fatalf("q-style TUI detach stopped the background service: %+v, %v", detachedStatus, err)
	}
	model.snapshot.Page = tuiPageProfiles
	model.snapshot.FocusSidebar = false
	model.snapshot.Profiles = []tuiProfile{{
		Name:            "config.yaml",
		Path:            configPath,
		Current:         true,
		SubscriptionURL: subscription.URL,
	}}
	model.snapshot.SelectedRow = 0
	command := model.handleKey(tuiKeyUpdateProfile)
	if command == nil {
		t.Fatal("linked subscription did not start a refresh")
	}
	_, _ = model.Update(command())
	if model.snapshot.Status !=
		"Subscription refreshed and hot-reloaded: config.yaml" {
		t.Fatalf("refresh status = %q", model.snapshot.Status)
	}
	if !model.coreRunning || !waitForTUITestPort(mixedPort, true, time.Second) {
		t.Fatal("subscription hot-reload stopped the running listener")
	}
	proxyData, err := client.request(http.MethodGet, "/proxies", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(proxyData, []byte("UPDATED-DIRECT")) {
		t.Fatalf("background core did not load refreshed nodes: %s", proxyData)
	}
	beforeEdit, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	temporary, err := os.CreateTemp("", "flclash-editor-test-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	temporaryPath := temporary.Name()
	t.Cleanup(func() { _ = os.Remove(temporaryPath) })
	edited := fmt.Appendf(nil, `mixed-port: %d
mode: rule
log-level: silent
proxies:
  - name: EDITED-DIRECT
    type: direct
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - EDITED-DIRECT
rules:
  - MATCH,PROXY
`, mixedPort)
	if _, err := temporary.Write(edited); err != nil {
		t.Fatal(err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	model.editorPath = configPath
	model.editorTempPath = temporaryPath
	model.editorBackup = tuiProfileBackup{data: beforeEdit, mode: 0o600}
	_, editorCommand := model.Update(tuiEditorResultMsg{})
	if editorCommand == nil {
		t.Fatal("active config edit did not schedule a hot-reload")
	}
	_, _ = model.Update(editorCommand())
	if model.snapshot.Status != "Configuration saved and hot-reloaded" {
		t.Fatalf("editor hot-reload status = %q", model.snapshot.Status)
	}
	proxyData, err = client.request(http.MethodGet, "/proxies", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(proxyData, []byte("EDITED-DIRECT")) {
		t.Fatalf("background core did not hot-reload edited config: %s", proxyData)
	}
	if !waitForTUITestPort(mixedPort, true, time.Second) {
		t.Fatal("configuration edit interrupted the mixed listener")
	}
	model.shutdown()
	if !waitForTUITestPort(mixedPort, true, time.Second) {
		t.Fatal("Ctrl+C-style detach stopped the mixed listener")
	}
	if status, err := service.status(); err != nil || !status.Running {
		t.Fatalf("Ctrl+C-style detach stopped the backend: %+v, %v", status, err)
	}
}

func TestTUISubscriptionUpdateRejectsInvalidResponseWithoutChangingProfile(
	t *testing.T,
) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "this is not a Mihomo configuration")
	}))
	defer server.Close()

	directory := t.TempDir()
	profilePath := filepath.Join(directory, "work.yaml")
	original := []byte(defaultTUIConfig)
	if err := os.WriteFile(profilePath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := updateTUISubscriptionProfile(
		directory,
		profilePath,
		server.URL,
	); err == nil {
		t.Fatal("invalid subscription response was accepted")
	}
	after, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("invalid update changed profile:\n%s", after)
	}
}

func TestTUIProfileRenameMovesSavedSubscriptionSource(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "old.yaml")
	if err := os.WriteFile(sourcePath, []byte(defaultTUIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	const sourceURL = "https://example.test/subscription"
	if err := rememberTUISubscriptionSource(directory, sourcePath, sourceURL); err != nil {
		t.Fatal(err)
	}

	newPath, err := renameTUIProfile(directory, sourcePath, "new.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sources := loadTUISubscriptionSources(directory)
	if sources["old.yaml"] != "" || sources["new.yaml"] != sourceURL {
		t.Fatalf("renamed subscription sources = %+v", sources)
	}
	if filepath.Base(newPath) != "new.yaml" {
		t.Fatalf("renamed path = %q", newPath)
	}
}

func TestTUIInvalidProfileEditNeverTouchesOriginalFile(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	original := []byte(defaultTUIConfig)
	if err := os.WriteFile(configPath, original, 0o640); err != nil {
		t.Fatal(err)
	}
	model := newTUIModel(
		controllerClient{},
		cliPaths{homeDir: directory, configPath: configPath},
		nil,
		true,
	)
	model.editorPath = configPath
	model.editorBackup = tuiProfileBackup{data: original, mode: 0o640}
	temporary, err := os.CreateTemp("", "flclash-invalid-editor-test-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	temporaryPath := temporary.Name()
	if _, err := temporary.Write([]byte("not a mihomo profile")); err != nil {
		t.Fatal(err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	model.editorTempPath = temporaryPath
	_, command := model.Update(tuiEditorResultMsg{})
	if command != nil {
		t.Fatal("invalid edit unexpectedly scheduled a hot-reload")
	}
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatalf("invalid edit was not rolled back:\n%s", restored)
	}
	if !strings.Contains(model.snapshot.Status, "invalid") {
		t.Fatalf("invalid edit status = %q", model.snapshot.Status)
	}
}

func TestTUISubscriptionSourceRejectsProfileOutsideDataDirectory(t *testing.T) {
	directory := t.TempDir()
	outsidePath := filepath.Join(t.TempDir(), "outside.yaml")
	if err := rememberTUISubscriptionSource(
		directory,
		outsidePath,
		"https://example.test/subscription",
	); err == nil {
		t.Fatal("subscription source accepted a profile outside the data directory")
	}
}

func TestPersistTUISettingsUpdatesYAMLWithoutDroppingProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := `# keep this profile comment
mixed-port: 7890
mode: rule
log-level: info
proxies:
  - name: example
    type: direct
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - example
rules:
  - MATCH,PROXY
`
	if err := os.WriteFile(path, []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}
	settings := tuiSettings{
		Mode:          "global",
		MixedPort:     17890,
		AllowLAN:      true,
		IPv6:          false,
		UnifiedDelay:  true,
		TCPConcurrent: true,
		LogLevel:      "debug",
		TunEnabled:    true,
	}
	if err := persistTUISettings(path, settings); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	output := string(data)
	for _, expected := range []string{
		"# keep this profile comment",
		"mixed-port: 17890",
		"mode: global",
		"allow-lan: true",
		"ipv6: false",
		"unified-delay: true",
		"tcp-concurrent: true",
		"log-level: debug",
		"enable: true",
		"name: example",
		"MATCH,PROXY",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("persisted YAML does not contain %q:\n%s", expected, output)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("persisted mode = %o, want 640", got)
	}
}

func TestTUIStateRestoresActiveProfileAndProxySelections(t *testing.T) {
	directory := t.TempDir()
	defaultPath := filepath.Join(directory, "config.yaml")
	activePath := filepath.Join(directory, "work.yaml")
	for _, path := range []string{defaultPath, activePath} {
		if err := os.WriteFile(path, []byte(defaultTUIConfig), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	activePaths := cliPaths{
		homeDir:    directory,
		configPath: activePath,
	}
	if err := rememberTUIActiveProfile(activePaths); err != nil {
		t.Fatal(err)
	}
	if err := rememberTUIProxySelection(directory, "PROXY", "Tokyo"); err != nil {
		t.Fatal(err)
	}
	if err := rememberTUIProxySelection(directory, "AUTO", "Singapore"); err != nil {
		t.Fatal(err)
	}

	restored, err := restoreTUIActiveProfile(cliPaths{
		homeDir:    directory,
		configPath: defaultPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if restored.configPath != activePath {
		t.Fatalf("restored profile = %q, want %q", restored.configPath, activePath)
	}
	selected := loadTUISelectedProxies(directory)
	if selected["PROXY"] != "Tokyo" || selected["AUTO"] != "Singapore" {
		t.Fatalf("restored proxy selections = %+v", selected)
	}
	info, err := os.Stat(filepath.Join(directory, tuiStateFilename))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("saved state mode = %o, want 600", info.Mode().Perm())
	}
}

func TestTUIStateConcurrentUpdatesKeepEveryMutation(t *testing.T) {
	directory := t.TempDir()
	const updates = 32
	var wait sync.WaitGroup
	wait.Add(updates)
	errors := make(chan error, updates)
	for index := 0; index < updates; index++ {
		index := index
		go func() {
			defer wait.Done()
			errors <- rememberTUIProxySelection(
				directory,
				fmt.Sprintf("group-%02d", index),
				fmt.Sprintf("proxy-%02d", index),
			)
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	selected := loadTUISelectedProxies(directory)
	if len(selected) != updates {
		t.Fatalf("saved %d concurrent updates, want %d", len(selected), updates)
	}
	if _, err := os.Stat(filepath.Join(directory, tuiStateLockName)); err != nil {
		t.Fatalf("stable state lock file is missing: %v", err)
	}
}

func TestTUIProfileRollbackDoesNotOverwriteConcurrentChange(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	original := []byte("mode: rule\n")
	edited := []byte("mode: global\n")
	concurrent := []byte("mode: direct\n")
	if err := os.WriteFile(path, concurrent, 0o600); err != nil {
		t.Fatal(err)
	}
	backup := tuiProfileBackup{
		data:          original,
		mode:          0o600,
		updatedSHA256: tuiBytesSHA256(edited),
	}
	if err := restoreTUIProfileIfUnchanged(directory, path, backup); err == nil {
		t.Fatal("concurrent profile change was overwritten")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, concurrent) {
		t.Fatalf("concurrent profile became %q", data)
	}
}

func TestTUIProfileLockSerializesFrontends(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	first, err := acquireTUIProfileLocks(directory, path)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		second, lockErr := acquireTUIProfileLocks(directory, path)
		if lockErr == nil {
			second.release()
		}
		result <- lockErr
	}()
	select {
	case err := <-result:
		first.release()
		t.Fatalf("second frontend bypassed profile lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	first.release()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("second frontend did not acquire released profile lock")
	}
}

func TestTUIStateRejectsInvalidSavedProfileAndRecovers(t *testing.T) {
	directory := t.TempDir()
	defaultPath := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(defaultPath, []byte(defaultTUIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(directory, tuiStateFilename)
	if err := os.WriteFile(
		statePath,
		[]byte(`{"version":1,"active_profile":"../outside.yaml"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	paths := cliPaths{homeDir: directory, configPath: defaultPath}
	restored, err := restoreTUIActiveProfile(paths)
	if err == nil {
		t.Fatal("unsafe saved profile was accepted")
	}
	if restored != paths {
		t.Fatalf("invalid state changed paths: %+v", restored)
	}
	if err := rememberTUIActiveProfile(paths); err != nil {
		t.Fatal(err)
	}
	recovered, err := restoreTUIActiveProfile(paths)
	if err != nil || recovered.configPath != defaultPath {
		t.Fatalf("state did not recover: paths=%+v err=%v", recovered, err)
	}
}

func TestTUIStateUpdateDoesNotOverwriteCorruptState(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, tuiStateFilename)
	corrupt := []byte("not-json\n")
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rememberTUIProxySelection(directory, "PROXY", "Tokyo"); err == nil ||
		!strings.Contains(err.Error(), "load shared state") {
		t.Fatalf("corrupt shared state update error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, corrupt) {
		t.Fatalf("corrupt shared state was overwritten: %q", data)
	}
}

func TestTUIStoppedSettingsStayStagedWithoutBackend(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(configPath, []byte(defaultTUIConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	model := newTUIModel(
		controllerClient{},
		cliPaths{homeDir: directory, configPath: configPath},
		nil,
		true,
	)
	model.snapshot.Page = tuiPageDashboard
	model.snapshot.FocusSidebar = false

	if command := model.handleKey(tuiKeyMode); command != nil {
		t.Fatal("opening the mode list unexpectedly started an asynchronous operation")
	}
	model.selectedMode = findTUIString(tuiTrafficModes, "global")
	if command := model.handleModeSelection(tea.KeyMsg{Type: tea.KeyEnter}); command != nil {
		t.Fatal("stopped mode selection unexpectedly started an asynchronous operation")
	}
	if !model.settingsDirty {
		t.Fatal("uncommitted stopped setting was marked clean")
	}
	if !strings.Contains(model.snapshot.Status, "not saved without Backend") {
		t.Fatalf("Backend boundary missing: %q", model.snapshot.Status)
	}
	reloaded := loadTUIConfiguredSettings(configPath, true)
	if reloaded == nil || reloaded.Mode != "rule" {
		t.Fatalf("frontend changed shared YAML without Backend: %+v", reloaded)
	}
}

func TestMergeTUIRefreshSurfacesControllerErrors(t *testing.T) {
	current := tuiSnapshot{
		Status:    "Settings staged",
		UpdatedAt: time.Now(),
	}
	refreshed := tuiSnapshot{
		Status:    "Controller unavailable: connection refused",
		UpdatedAt: time.Now(),
	}
	merged := mergeTUIRefresh(current, refreshed)
	if merged.Status != refreshed.Status {
		t.Fatalf("controller error was hidden by stale action status: %q", merged.Status)
	}
}

func TestTUIInitializationDefersProxyListener(t *testing.T) {
	mixedPort := freeTUITestPort(t)
	controllerPort := freeTUITestPort(t)
	directory := t.TempDir()
	paths := cliPaths{
		homeDir:    directory,
		configPath: filepath.Join(directory, "config.yaml"),
	}
	configData := fmt.Appendf(nil, `mixed-port: %d
allow-lan: false
mode: rule
log-level: silent
unified-delay: true
tcp-concurrent: true
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - DIRECT
rules:
  - MATCH,PROXY
`, mixedPort)
	if err := os.WriteFile(paths.configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}

	controllerAddress := fmt.Sprintf("127.0.0.1:%d", controllerPort)
	setupParams, err := initializeCore(
		paths,
		"https://www.gstatic.com/generate_204",
		controllerAddress,
		"",
		"",
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		handleShutdown()
	})
	client := controllerClient{
		options: controllerOptions{address: controllerAddress},
		client:  &http.Client{Timeout: time.Second},
	}
	if err := waitForController(client, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if canConnectTUITestPort(mixedPort) {
		t.Fatalf("mixed port %d was occupied before the TUI start action", mixedPort)
	}
	if isRunning {
		t.Fatal("core listener state is running before the TUI start action")
	}
	if !currentConfig.General.UnifiedDelay ||
		!currentConfig.General.TCPConcurrent {
		t.Fatalf(
			"FlClash delay defaults were not applied: %+v",
			currentConfig.General,
		)
	}

	model := newTUIModel(client, paths, setupParams, true)
	model.snapshot.Page = tuiPageDashboard
	model.snapshot.FocusSidebar = false
	initialIPv6 := model.snapshot.Settings.IPv6
	_ = model.handleKey(tuiKeyTun)
	if message := stageTUICoreSettings(*model.stagedSettings); message != "" {
		t.Fatalf("stage TUN setting: %s", message)
	}
	if !currentConfig.General.Tun.Enable {
		t.Fatal("TUN setting was not staged in the core")
	}
	if canConnectTUITestPort(mixedPort) {
		t.Fatalf("staging TUN occupied mixed port %d", mixedPort)
	}
	_ = model.handleKey(tuiKeyTun)
	model.snapshot.Page = tuiPageTools
	_ = model.handleKey(tuiKeyAllowLAN)
	_ = model.handleKey(tuiKeyIPv6)
	_ = model.changeMode("global")
	startCommand := model.handleKey(tuiKeyCoreToggle)
	if startCommand == nil {
		t.Fatal("Core start did not return an operation")
	}
	_, _ = model.Update(startCommand())
	if !model.coreRunning {
		t.Fatalf("Core did not start: %s", model.snapshot.Status)
	}
	if model.snapshot.Settings.SystemProxy || model.systemProxyManaged {
		t.Fatalf("Core start changed system proxy: %+v", model.snapshot.Settings)
	}
	if model.pendingMixedPort != nil {
		t.Fatalf("pending mixed port was not applied: %d", *model.pendingMixedPort)
	}
	if model.stagedSettings != nil {
		t.Fatalf("staged settings were not applied: %+v", *model.stagedSettings)
	}
	if !currentConfig.General.AllowLan ||
		currentConfig.General.IPv6 == initialIPv6 ||
		currentConfig.General.Mode.String() != "global" ||
		!currentConfig.General.UnifiedDelay ||
		!currentConfig.General.TCPConcurrent {
		t.Fatalf("staged core settings were not applied: %+v", currentConfig.General)
	}
	deadline := time.Now().Add(time.Second)
	for !canConnectTUITestPort(mixedPort) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !canConnectTUITestPort(mixedPort) {
		t.Fatalf("mixed port %d did not open after automatic service startup", mixedPort)
	}

	stopCommand := model.handleKey(tuiKeyCoreToggle)
	if stopCommand == nil {
		t.Fatal("service stop did not return an operation")
	}
	_, _ = model.Update(stopCommand())
	deadline = time.Now().Add(time.Second)
	for canConnectTUITestPort(mixedPort) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if model.coreRunning || canConnectTUITestPort(mixedPort) {
		t.Fatalf("service did not stop before rollback test: %s", model.snapshot.Status)
	}

	model.snapshot.Page = tuiPageDashboard
	if command := model.handleKey(tuiKeySystemProxy); command != nil {
		t.Fatal("unmanaged TUI scheduled a system proxy mutation")
	}
	if !strings.Contains(model.snapshot.Status, "managed backend") {
		t.Fatalf("system proxy boundary status = %q", model.snapshot.Status)
	}
}

func TestControllerClientUsesUnixSocketWithoutTCP(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "controller.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/" {
			http.NotFound(w, request)
			return
		}
		_, _ = io.WriteString(w, `{"hello":"unix"}`)
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
	})

	options := controllerOptions{unixSocket: socketPath}
	client := controllerClient{
		options: options,
		client:  controllerHTTPClientForOptions(options, time.Second),
	}
	data, err := client.request(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != `{"hello":"unix"}` {
		t.Fatalf("Unix controller response = %q", got)
	}
}

func freeTUITestPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func canConnectTUITestPort(port int) bool {
	connection, err := net.DialTimeout(
		"tcp4",
		fmt.Sprintf("127.0.0.1:%d", port),
		50*time.Millisecond,
	)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

func waitForTUITestPort(port int, open bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if canConnectTUITestPort(port) == open {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return canConnectTUITestPort(port) == open
}

func TestBubbleTeaProcessesBurstNavigationKeys(t *testing.T) {
	model := newTUIModel(
		controllerClient{},
		cliPaths{},
		nil,
		false,
	)
	_, command := model.Update(tea.KeyMsg{
		Type:  tea.KeyRunes,
		Runes: []rune("sssss"),
	})
	if command != nil {
		t.Fatal("navigation burst unexpectedly returned a command")
	}
	if model.snapshot.SelectedMenu != int(tuiPageConnections) {
		t.Fatalf("selected menu = %d, want connections", model.snapshot.SelectedMenu)
	}
}

func assertTUIUsesCRLF(t *testing.T, output string) {
	t.Helper()
	for index, value := range []byte(output) {
		if value == '\n' && (index == 0 || output[index-1] != '\r') {
			t.Fatalf("TUI frame contains a bare LF at byte %d", index)
		}
	}
}

func populatedTUISnapshot(page tuiPage) tuiSnapshot {
	snapshot := tuiSnapshot{
		Page:      page,
		UpdatedAt: time.Now(),
		Settings: tuiSettings{
			Mode:      "rule",
			MixedPort: 7890,
			LogLevel:  "info",
		},
		Status: "Connected",
	}
	for index := 0; index < 24; index++ {
		nodes := make([]string, 24)
		for nodeIndex := range nodes {
			nodes[nodeIndex] = fmt.Sprintf("node-%02d-%02d", index, nodeIndex)
		}
		snapshot.Groups = append(snapshot.Groups, tuiGroup{
			Name:  fmt.Sprintf("group-%02d", index),
			Type:  "Selector",
			Now:   nodes[18],
			Nodes: nodes,
		})
		snapshot.Connections = append(snapshot.Connections, tuiConnection{
			ID:       fmt.Sprintf("connection-%02d", index),
			Host:     fmt.Sprintf("service-%02d.example.com", index),
			Process:  "example-process",
			Network:  "tcp",
			Chain:    "PROXY",
			Upload:   int64(index * 1024),
			Download: int64(index * 2048),
		})
		snapshot.Requests = append(snapshot.Requests, tuiRequest{
			tuiConnection: tuiConnection{
				ID:       fmt.Sprintf("request-%02d", index),
				Host:     fmt.Sprintf("request-%02d.example.com", index),
				Process:  "example-process",
				Network:  "tcp",
				Chain:    "PROXY",
				Upload:   int64(index * 1024),
				Download: int64(index * 2048),
			},
			LastSeen: time.Now().Add(-time.Duration(index) * time.Second),
			Active:   index%2 == 0,
		})
		snapshot.Profiles = append(snapshot.Profiles, tuiProfile{
			Name: fmt.Sprintf("profile-%02d.yaml", index),
			Path: fmt.Sprintf("/tmp/profile-%02d.yaml", index),
		})
		snapshot.Providers = append(snapshot.Providers, tuiProvider{
			Name:  fmt.Sprintf("provider-%02d", index),
			Type:  "HTTP",
			Count: index,
		})
		snapshot.Logs = append(snapshot.Logs, fmt.Sprintf("log line %02d", index))
	}
	snapshot.SelectedGroup = 18
	snapshot.SelectedNode = 18
	snapshot.SelectedConnection = 18
	snapshot.SelectedRow = 18
	snapshot.SelectedProvider = 18
	return snapshot
}

func stripTUIANSI(value string) string {
	var output strings.Builder
	for index := 0; index < len(value); {
		if value[index] != '\x1b' {
			output.WriteByte(value[index])
			index++
			continue
		}
		index++
		if index < len(value) && value[index] == '[' {
			index++
			for index < len(value) {
				code := value[index]
				index++
				if code >= '@' && code <= '~' {
					break
				}
			}
		}
	}
	return valueWithoutNewline(output.String())
}

func valueWithoutNewline(value string) string {
	return strings.TrimRight(value, "\r\n")
}

func TestTUIGroupAndSelectionMovement(t *testing.T) {
	if !isTUIGroup("Selector") || !isTUIGroup("urltest") || isTUIGroup("Direct") {
		t.Fatal("unexpected proxy group classification")
	}
	snapshot := tuiSnapshot{Groups: []tuiGroup{
		{Name: "A", Nodes: []string{"a", "b"}},
		{Name: "B", Now: "d", Nodes: []string{"c", "d"}},
	}}
	moveTUIGroup(&snapshot, -1)
	if snapshot.SelectedGroup != 1 || snapshot.SelectedNode != 1 {
		t.Fatalf("group movement = (%d, %d)", snapshot.SelectedGroup, snapshot.SelectedNode)
	}
	moveTUINode(&snapshot, 1)
	if snapshot.SelectedNode != 0 {
		t.Fatalf("node movement = %d", snapshot.SelectedNode)
	}
	snapshot.SelectedGroup = 99
	moveTUINode(&snapshot, 1)
	snapshot.SelectedGroup = -99
	moveTUIGroup(&snapshot, -1)
	if snapshot.SelectedGroup != 0 {
		t.Fatalf("out-of-range group movement = %d", snapshot.SelectedGroup)
	}
}

func TestTUIProxyGroupsFollowConfigurationOrder(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	configData := []byte(`proxy-groups:
  - name: Z-LAST-ALPHABETICALLY
    type: select
    proxies: [DIRECT]
  - name: A-FIRST-ALPHABETICALLY
    type: select
    proxies: [DIRECT]
  - name: M-MIDDLE
    type: select
    proxies: [DIRECT]
rules:
  - MATCH,DIRECT
`)
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	order := loadTUIProxyGroupOrder(configPath)
	groups := []tuiGroup{
		{Name: "A-FIRST-ALPHABETICALLY"},
		{Name: "M-MIDDLE"},
		{Name: "Z-LAST-ALPHABETICALLY"},
	}
	orderTUIGroups(groups, order)
	got := []string{groups[0].Name, groups[1].Name, groups[2].Name}
	want := []string{
		"Z-LAST-ALPHABETICALLY",
		"A-FIRST-ALPHABETICALLY",
		"M-MIDDLE",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("proxy group order = %v, want configuration order %v", got, want)
	}
}

func TestTUIVisibleRangeKeepsSelectionOnScreen(t *testing.T) {
	tests := []struct {
		total    int
		selected int
		limit    int
		start    int
		end      int
	}{
		{total: 100, selected: 0, limit: 10, start: 0, end: 10},
		{total: 100, selected: 50, limit: 10, start: 45, end: 55},
		{total: 100, selected: 99, limit: 10, start: 90, end: 100},
		{total: 4, selected: 3, limit: 10, start: 0, end: 4},
	}
	for _, test := range tests {
		start, end := tuiVisibleRange(test.total, test.selected, test.limit)
		if start != test.start || end != test.end {
			t.Fatalf("tuiVisibleRange(%d, %d, %d) = (%d, %d), want (%d, %d)",
				test.total, test.selected, test.limit, start, end, test.start, test.end)
		}
	}
}

func TestWrapTUIIndexNormalizesStaleSelections(t *testing.T) {
	tests := []struct {
		current int
		delta   int
		total   int
		want    int
	}{
		{current: 99, delta: 1, total: 2, want: 0},
		{current: -99, delta: -1, total: 2, want: 0},
		{current: 0, delta: -1, total: 4, want: 3},
		{current: 3, delta: 1, total: 4, want: 0},
	}
	for _, test := range tests {
		if got := wrapTUIIndex(test.current, test.delta, test.total); got != test.want {
			t.Fatalf("wrapTUIIndex(%d, %d, %d) = %d, want %d",
				test.current, test.delta, test.total, got, test.want)
		}
	}
}

func TestReadTUIKeys(t *testing.T) {
	keys := make(chan tuiKey, 8)
	go readTUIKeys(bytes.NewBufferString("rsp\t\x0e\x1b[Z\x1b[1;5Aq"), keys)
	want := []tuiKey{
		tuiKeyRefresh,
		tuiKeyDown,
		tuiKeySetPort,
		tuiKeyFocusNext,
		tuiKeyNotifications,
		tuiKeyFocusPrevious,
		tuiKeyUp,
		tuiKeyQuit,
	}
	for _, expected := range want {
		if got := <-keys; got != expected {
			t.Fatalf("key = %v, want %v", got, expected)
		}
	}
	if _, open := <-keys; open {
		t.Fatal("key channel was not closed after input ended")
	}
}

func TestTUIFocusNavigationMakesSidebarOperable(t *testing.T) {
	snapshot := tuiSnapshot{
		Page:         tuiPageDashboard,
		SelectedMenu: int(tuiPageDashboard),
		FocusSidebar: true,
	}
	if !handleTUIFocusNavigation(&snapshot, tuiKeyDown) {
		t.Fatal("sidebar down key was not handled")
	}
	if snapshot.SelectedMenu != int(tuiPageSSH) || snapshot.Page != tuiPageDashboard {
		t.Fatalf("sidebar movement changed wrong state: %+v", snapshot)
	}
	if !handleTUIFocusNavigation(&snapshot, tuiKeySelect) {
		t.Fatal("sidebar Enter was not handled")
	}
	if snapshot.Page != tuiPageSSH || snapshot.FocusSidebar {
		t.Fatalf("sidebar Enter did not open content: %+v", snapshot)
	}
	if !handleTUIFocusNavigation(&snapshot, tuiKeyLeft) || !snapshot.FocusSidebar {
		t.Fatalf("left did not return to sidebar from SSH: %+v", snapshot)
	}
	if snapshot.SelectedMenu != int(tuiPageSSH) {
		t.Fatalf("sidebar cursor did not follow active page: %+v", snapshot)
	}
	if !handleTUIFocusNavigation(&snapshot, tuiKeySettings) {
		t.Fatal("numeric page shortcut was not handled")
	}
	if snapshot.Page != tuiPageTools || snapshot.FocusSidebar {
		t.Fatalf("numeric page shortcut did not open content: %+v", snapshot)
	}
	if !handleTUIFocusNavigation(&snapshot, tuiKeyLeft) || !snapshot.FocusSidebar {
		t.Fatalf("left did not return to sidebar: %+v", snapshot)
	}
}

func TestTUIFocusNavigationCyclesThroughSSHProfilesAndDashboard(t *testing.T) {
	snapshot := tuiSnapshot{
		Page:         tuiPageSSH,
		SelectedMenu: int(tuiPageSSH),
		FocusSidebar: true,
	}
	if !handleTUIFocusNavigation(&snapshot, tuiKeyFocusNext) ||
		snapshot.FocusSidebar || snapshot.SSHDashboardFocus {
		t.Fatalf("Tab sidebar -> profiles = %+v", snapshot)
	}
	if !handleTUIFocusNavigation(&snapshot, tuiKeyFocusNext) ||
		!snapshot.SSHDashboardFocus {
		t.Fatalf("Tab profiles -> Dashboard = %+v", snapshot)
	}
	if !handleTUIFocusNavigation(&snapshot, tuiKeyFocusNext) ||
		!snapshot.FocusSidebar || snapshot.SSHDashboardFocus {
		t.Fatalf("Tab Dashboard -> sidebar = %+v", snapshot)
	}
	if !handleTUIFocusNavigation(&snapshot, tuiKeyFocusPrevious) ||
		snapshot.FocusSidebar || !snapshot.SSHDashboardFocus {
		t.Fatalf("Shift+Tab sidebar -> Dashboard = %+v", snapshot)
	}
	if !handleTUIFocusNavigation(&snapshot, tuiKeyFocusPrevious) ||
		snapshot.FocusSidebar || snapshot.SSHDashboardFocus {
		t.Fatalf("Shift+Tab Dashboard -> profiles = %+v", snapshot)
	}
	if !handleTUIFocusNavigation(&snapshot, tuiKeyFocusPrevious) ||
		!snapshot.FocusSidebar {
		t.Fatalf("Shift+Tab profiles -> sidebar = %+v", snapshot)
	}
}

func TestPreserveTUIInteractionKeepsSSHSelectionDashboardAndMetrics(t *testing.T) {
	current := tuiSnapshot{
		SSHDashboardFocus: true,
		SelectedSSH:       1,
		SelectedSSHDetail: 3,
		SSHNetwork:        tuiNetworkInfo{PublicIP: "203.0.113.8"},
		SSHTrafficHistory: []trafficSnapshot{{Up: 10, Down: 20}},
		SSHProfiles: []tuiSSHProfile{
			{Name: "first"},
			{Name: "second"},
		},
	}
	updated := tuiSnapshot{
		SSHProfiles: []tuiSSHProfile{
			{Name: "second"},
			{Name: "first"},
		},
	}
	merged := preserveTUIInteraction(current, updated)
	if merged.SelectedSSH != 0 ||
		!merged.SSHDashboardFocus ||
		merged.SelectedSSHDetail != 3 ||
		merged.SSHNetwork.PublicIP != "203.0.113.8" ||
		len(merged.SSHTrafficHistory) != 1 {
		t.Fatalf("SSH interaction was not preserved: %+v", merged)
	}
}

func TestTUIProxyGroupsAndNodesUseArrowOrWSNavigation(t *testing.T) {
	left, ok := tuiKeyFromTea(tea.KeyMsg{Type: tea.KeyLeft})
	if !ok || left != tuiKeyLeft {
		t.Fatalf("left arrow = (%v, %v)", left, ok)
	}
	right, ok := tuiKeyFromTea(tea.KeyMsg{Type: tea.KeyRight})
	if !ok || right != tuiKeyRight {
		t.Fatalf("right arrow = (%v, %v)", right, ok)
	}
	up, ok := tuiKeyFromTea(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'w'}})
	if !ok || up != tuiKeyUp {
		t.Fatalf("w = (%v, %v)", up, ok)
	}
	down, ok := tuiKeyFromTea(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if !ok || down != tuiKeyDown {
		t.Fatalf("s = (%v, %v)", down, ok)
	}
	for _, removed := range []rune{'j', 'k', 'h', 'l'} {
		if key, mapped := tuiKeyFromTea(tea.KeyMsg{
			Type:  tea.KeyRunes,
			Runes: []rune{removed},
		}); mapped {
			t.Fatalf("removed key %q still maps to %v", removed, key)
		}
	}

	model := newTUIModel(controllerClient{}, cliPaths{}, nil, false)
	model.snapshot.Page = tuiPageProxies
	model.snapshot.SelectedMenu = int(tuiPageProxies)
	model.snapshot.FocusSidebar = false
	model.snapshot.Groups = []tuiGroup{
		{Name: "FIRST", Now: "A", Nodes: []string{"A", "B"}},
		{Name: "SECOND", Now: "C", Nodes: []string{"C", "D"}},
	}
	model.snapshot.SelectedNode = 0
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyLeft})
	if !model.snapshot.FocusSidebar || model.snapshot.SelectedNode != 0 {
		t.Fatalf("left arrow changed proxy state instead of focus: %+v", model.snapshot)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRight})
	if model.snapshot.FocusSidebar {
		t.Fatalf("right arrow did not focus content: %+v", model.snapshot)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if model.snapshot.SelectedGroup != 1 || model.snapshot.ProxyNodeFocus {
		t.Fatalf("s did not move the proxy group: %+v", model.snapshot)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !model.snapshot.ProxyNodeFocus {
		t.Fatalf("Enter did not open node selection: %+v", model.snapshot)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if model.snapshot.SelectedNode != 1 {
		t.Fatalf("s did not move the selected node: %+v", model.snapshot)
	}
	_, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if model.snapshot.ProxyNodeFocus {
		t.Fatalf("Esc did not return to proxy groups: %+v", model.snapshot)
	}
}

func TestReadTUIKeysWaitsUntilPreviousKeyIsHandled(t *testing.T) {
	keys := make(chan tuiKey)
	handled := make(chan struct{})
	go readTUIKeysSynchronized(bytes.NewBufferString("1234"), keys, handled)

	want := []tuiKey{
		tuiKeyDashboard,
		tuiKeySSH,
		tuiKeyProxies,
		tuiKeyProfiles,
	}
	for index, expected := range want {
		if got := <-keys; got != expected {
			t.Fatalf("key %d = %v, want %v", index+1, got, expected)
		}
		if index == 0 {
			select {
			case unexpected := <-keys:
				t.Fatalf("read next key before acknowledgement: %v", unexpected)
			case <-time.After(20 * time.Millisecond):
			}
		}
		handled <- struct{}{}
	}
	if _, open := <-keys; open {
		t.Fatal("key channel was not closed after synchronized input ended")
	}
}

func TestReadTUILineDoesNotConsumeFollowingKeys(t *testing.T) {
	input := bytes.NewBufferString("17892\n?q")
	line, err := readTUILine(input)
	if err != nil {
		t.Fatal(err)
	}
	if line != "17892" {
		t.Fatalf("line = %q, want 17892", line)
	}
	remaining, err := io.ReadAll(input)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(remaining); got != "?q" {
		t.Fatalf("remaining input = %q, want ?q", got)
	}
}

func TestSetProxyDoesNotWriteToTerminal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.URL.Path != "/proxies/PROXY" {
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := controllerClient{
		options: controllerOptions{address: server.URL},
		client:  server.Client(),
	}
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStdout := os.Stdout
	os.Stdout = writePipe
	defer func() {
		os.Stdout = originalStdout
	}()

	if err := client.setProxy("PROXY", "DIRECT"); err != nil {
		t.Fatal(err)
	}
	if err := writePipe.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatal(err)
	}
	if len(output) != 0 {
		t.Fatalf("setProxy wrote to terminal: %q", output)
	}
}

func TestRefreshTUISnapshotPreservesSelectionsAndActionStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/proxies":
			_, _ = io.WriteString(w, `{"proxies":{
				"A":{"type":"Selector","now":"A1","all":["A1"]},
				"B":{"type":"Selector","now":"B2","all":["B1","B2"]}
			}}`)
		case "/traffic":
			_, _ = io.WriteString(w, `{"up":1,"down":2,"upTotal":3,"downTotal":4}`+"\n")
		case "/connections":
			_, _ = io.WriteString(w, `{"connections":[
				{"id":"id-1","metadata":{"host":"one","network":"tcp"},"chains":["DIRECT"]},
				{"id":"id-2","metadata":{"destinationIP":"2001:db8::2","destinationPort":"443","network":"tcp"},"chains":["PROXY"]}
			]}`)
		case "/configs":
			_, _ = io.WriteString(w, `{"mode":"rule","mixed-port":17890,"log-level":"info"}`)
		case "/providers/proxies":
			_, _ = io.WriteString(w, `{"providers":{
				"p1":{"name":"p1","type":"Proxy","proxies":[]},
				"p2":{"name":"p2","type":"Proxy","proxies":[]}
			}}`)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()

	snapshot := tuiSnapshot{
		Groups: []tuiGroup{
			{Name: "B", Now: "B2", Nodes: []string{"B1", "B2"}},
		},
		Connections:        []tuiConnection{{ID: "id-2"}},
		Providers:          []tuiProvider{{Name: "p2"}},
		SelectedNode:       0,
		SelectedConnection: 0,
		SelectedProvider:   0,
		Status:             "Switched B to B1",
		UpdatedAt:          time.Now(),
	}
	client := controllerClient{
		options: controllerOptions{address: server.URL},
		client:  server.Client(),
	}
	refreshTUISnapshot(&snapshot, client)

	if snapshot.Groups[snapshot.SelectedGroup].Name != "B" ||
		snapshot.Groups[snapshot.SelectedGroup].Nodes[snapshot.SelectedNode] != "B1" {
		t.Fatalf("proxy selection was not preserved: group=%d node=%d", snapshot.SelectedGroup, snapshot.SelectedNode)
	}
	if snapshot.Connections[snapshot.SelectedConnection].ID != "id-2" {
		t.Fatalf("connection selection = %q", snapshot.Connections[snapshot.SelectedConnection].ID)
	}
	if snapshot.Connections[snapshot.SelectedConnection].Host != "[2001:db8::2]:443" {
		t.Fatalf(
			"connection destination = %q",
			snapshot.Connections[snapshot.SelectedConnection].Host,
		)
	}
	if snapshot.Providers[snapshot.SelectedProvider].Name != "p2" {
		t.Fatalf("provider selection = %q", snapshot.Providers[snapshot.SelectedProvider].Name)
	}
	if snapshot.Status != "Switched B to B1" {
		t.Fatalf("action status was overwritten: %q", snapshot.Status)
	}
	if snapshot.Settings.MixedPort != 17890 {
		t.Fatalf("snapshot values were not refreshed: %+v", snapshot)
	}
}

func TestResolvePathsUsesDirectoryForDefaultConfig(t *testing.T) {
	directory := t.TempDir()
	paths, err := resolvePaths("", directory)
	if err != nil {
		t.Fatal(err)
	}
	wantHome, _ := filepath.Abs(directory)
	wantConfig := filepath.Join(wantHome, "config.yaml")
	if paths.homeDir != wantHome || paths.configPath != wantConfig {
		t.Fatalf("paths = (%q, %q), want (%q, %q)", paths.homeDir, paths.configPath, wantHome, wantConfig)
	}
}

func TestResolvePathsUsesRelativeDirectoryOnce(t *testing.T) {
	directory := filepath.Join("test-data", "instance")
	paths, err := resolvePaths("", directory)
	if err != nil {
		t.Fatal(err)
	}
	wantHome, _ := filepath.Abs(directory)
	wantConfig := filepath.Join(wantHome, "config.yaml")
	if paths.homeDir != wantHome || paths.configPath != wantConfig {
		t.Fatalf("paths = (%q, %q), want (%q, %q)", paths.homeDir, paths.configPath, wantHome, wantConfig)
	}
}

func TestResolvePathsDefaultConfigUsesUserConfigDirectory(t *testing.T) {
	configRoot, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	paths, err := resolvePaths("", "")
	if err != nil {
		t.Fatal(err)
	}
	wantHome, _ := filepath.Abs(filepath.Join(configRoot, "flclash"))
	wantConfig := filepath.Join(wantHome, "config.yaml")
	if paths.homeDir != wantHome || paths.configPath != wantConfig {
		t.Fatalf("paths = (%q, %q), want (%q, %q)", paths.homeDir, paths.configPath, wantHome, wantConfig)
	}
}

func TestEnsureTUIConfigCreatesMinimalConfig(t *testing.T) {
	directory := t.TempDir()
	paths := cliPaths{homeDir: directory, configPath: filepath.Join(directory, "config.yaml")}
	if err := ensureTUIConfig(paths, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(paths.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if message := validateConfigBytes(data); message != "" {
		t.Fatalf("generated config is invalid: %s", message)
	}
	for _, expected := range []string{
		"ipv6: false",
		"unified-delay: true",
		"tcp-concurrent: true",
		"geodata-loader: memconservative",
		"geodata-mode: false",
	} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("generated config does not contain %q:\n%s", expected, data)
		}
	}
	if err := ensureTUIConfig(paths, true); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(paths.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != string(data) {
		t.Fatal("existing config was overwritten")
	}
}

func TestEnsureTUIFlClashDefaultsMigratesOnlyMissingSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	configData := `mixed-port: 7891
mode: rule
ipv6: true
unified-delay: false
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - DIRECT
rules:
  - MATCH,PROXY
`
	if err := os.WriteFile(path, []byte(configData), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureTUIFlClashDefaults(path); err != nil {
		t.Fatal(err)
	}
	settings := loadTUIConfiguredSettings(path, true)
	if settings == nil {
		t.Fatal("migrated settings could not be loaded")
	}
	if !settings.IPv6 {
		t.Fatal("explicit IPv6 setting was overwritten")
	}
	if settings.UnifiedDelay {
		t.Fatal("explicit unified-delay setting was overwritten")
	}
	if !settings.TCPConcurrent {
		t.Fatal("missing tcp-concurrent did not receive FlClash default")
	}
}

func TestRestoreLatestTUIConfigDoesNotOverwriteWithInvalidBackup(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	original := []byte("mixed-port: 17890\n")
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	backupPath := configPath + ".backup-999999999999999999"
	if err := os.WriteFile(backupPath, []byte("mixed-port: [invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := restoreLatestTUIConfig(configPath); err == nil {
		t.Fatal("restore unexpectedly accepted invalid backup")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(original) {
		t.Fatalf("config changed after invalid restore: %q", data)
	}
}
