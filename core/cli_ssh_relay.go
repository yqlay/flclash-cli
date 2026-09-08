//go:build linux && !cgo && cli

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

const cliSSHRelayControlTimeout = 2 * time.Second

type cliSSHRelayStats struct {
	PID          int       `json:"pid"`
	StartedAt    time.Time `json:"started_at"`
	ListenPort   int       `json:"listen_port"`
	UpstreamPort int       `json:"upstream_port"`
	Upload       int64     `json:"upload"`
	Download     int64     `json:"download"`
	Connections  int64     `json:"connections"`
	OK           bool      `json:"ok"`
	Error        string    `json:"error,omitempty"`
}

type cliSSHRelayRequest struct {
	Action string `json:"action"`
}

type cliSSHRelay struct {
	listenPort   int
	upstreamPort int
	controlPath  string
	startedAt    time.Time
	upload       atomic.Int64
	download     atomic.Int64
	connections  atomic.Int64
	shutdown     chan struct{}
	shutdownOnce sync.Once
	listener     net.Listener
	control      net.Listener
}

type cliSSHCountingWriter struct {
	writer  io.Writer
	counter *atomic.Int64
}

func (w cliSSHCountingWriter) Write(data []byte) (int, error) {
	written, err := w.writer.Write(data)
	w.counter.Add(int64(written))
	return written, err
}

func runCLISSHRelayCommand(args []string) error {
	fs := flag.NewFlagSet("_ssh_relay", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	listenPort := fs.Int("listen-port", 0, "public SOCKS5 port")
	upstreamPort := fs.Int("upstream-port", 0, "OpenSSH SOCKS5 port")
	controlPath := fs.String("control", "", "private control socket")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *listenPort < 1 || *listenPort > 65535 ||
		*upstreamPort < 1 || *upstreamPort > 65535 || *listenPort == *upstreamPort {
		return errors.New("invalid SSH relay ports")
	}
	if strings.TrimSpace(*controlPath) == "" || !filepath.IsAbs(*controlPath) {
		return errors.New("invalid SSH relay control socket")
	}
	relay := &cliSSHRelay{
		listenPort:   *listenPort,
		upstreamPort: *upstreamPort,
		controlPath:  filepath.Clean(*controlPath),
		startedAt:    time.Now(),
		shutdown:     make(chan struct{}),
	}
	return relay.run()
}

func (r *cliSSHRelay) run() error {
	publicListener, err := net.Listen(
		"tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(r.listenPort)),
	)
	if err != nil {
		return err
	}
	r.listener = publicListener
	_ = os.Remove(r.controlPath)
	controlListener, err := net.Listen("unix", r.controlPath)
	if err != nil {
		_ = publicListener.Close()
		return err
	}
	r.control = controlListener
	defer os.Remove(r.controlPath)
	defer publicListener.Close()
	defer controlListener.Close()
	if err := os.Chmod(r.controlPath, 0o600); err != nil {
		return err
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	go r.acceptControl()
	go func() {
		select {
		case <-interrupt:
			r.stop()
		case <-r.shutdown:
		}
	}()
	for {
		connection, acceptErr := publicListener.Accept()
		if acceptErr != nil {
			select {
			case <-r.shutdown:
				return nil
			default:
				return acceptErr
			}
		}
		go r.serveSOCKS(connection)
	}
}

func (r *cliSSHRelay) stop() {
	r.shutdownOnce.Do(func() {
		close(r.shutdown)
		if r.listener != nil {
			_ = r.listener.Close()
		}
		if r.control != nil {
			_ = r.control.Close()
		}
	})
}

func (r *cliSSHRelay) acceptControl() {
	for {
		connection, err := r.control.Accept()
		if err != nil {
			return
		}
		go r.serveControl(connection)
	}
}

func (r *cliSSHRelay) serveControl(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(cliSSHRelayControlTimeout))
	var request cliSSHRelayRequest
	if err := json.NewDecoder(bufio.NewReader(connection)).Decode(&request); err != nil {
		_ = json.NewEncoder(connection).Encode(cliSSHRelayStats{Error: err.Error()})
		return
	}
	stats := r.stats()
	switch request.Action {
	case "status":
		_ = json.NewEncoder(connection).Encode(stats)
	case "shutdown":
		_ = json.NewEncoder(connection).Encode(stats)
		r.stop()
	default:
		stats.OK = false
		stats.Error = "unknown relay action"
		_ = json.NewEncoder(connection).Encode(stats)
	}
}

func (r *cliSSHRelay) stats() cliSSHRelayStats {
	return cliSSHRelayStats{
		PID:          os.Getpid(),
		StartedAt:    r.startedAt,
		ListenPort:   r.listenPort,
		UpstreamPort: r.upstreamPort,
		Upload:       r.upload.Load(),
		Download:     r.download.Load(),
		Connections:  r.connections.Load(),
		OK:           true,
	}
}

func (r *cliSSHRelay) serveSOCKS(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	target, err := readCLIInboundSOCKS5(client)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	upstream, err := dialCLISSHRelayUpstream(ctx, r.upstreamPort, target)
	if err != nil {
		writeCLISOCKS5Reply(client, 0x05)
		return
	}
	defer upstream.Close()
	if err := writeCLISOCKS5Reply(client, 0x00); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	r.connections.Add(1)
	defer r.connections.Add(-1)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, _ = io.Copy(cliSSHCountingWriter{writer: upstream, counter: &r.upload}, client)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		defer wait.Done()
		_, _ = io.Copy(cliSSHCountingWriter{writer: client, counter: &r.download}, upstream)
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	wait.Wait()
}

func dialCLISSHRelayUpstream(ctx context.Context, port int, target string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5(
		"tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		nil,
		&net.Dialer{},
	)
	if err != nil {
		return nil, err
	}
	// The context bounds the SOCKS handshake as well as the TCP connection.
	return dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
}

func readCLIInboundSOCKS5(connection net.Conn) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", err
	}
	if header[0] != 5 || header[1] == 0 {
		return "", errors.New("unsupported SOCKS version")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return "", err
	}
	supportsNoAuth := false
	for _, method := range methods {
		if method == 0 {
			supportsNoAuth = true
		}
	}
	if !supportsNoAuth {
		_, _ = connection.Write([]byte{5, 0xff})
		return "", errors.New("SOCKS authentication is unsupported")
	}
	if _, err := connection.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(connection, request); err != nil {
		return "", err
	}
	if request[0] != 5 || request[1] != 1 || request[2] != 0 {
		_ = writeCLISOCKS5Reply(connection, 0x07)
		return "", errors.New("only SOCKS5 CONNECT is supported")
	}
	var host string
	switch request[3] {
	case 1:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(connection, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case 4:
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(connection, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(connection, length); err != nil {
			return "", err
		}
		address := make([]byte, int(length[0]))
		if len(address) == 0 {
			return "", errors.New("empty SOCKS domain")
		}
		if _, err := io.ReadFull(connection, address); err != nil {
			return "", err
		}
		host = string(address)
	default:
		_ = writeCLISOCKS5Reply(connection, 0x08)
		return "", errors.New("unsupported SOCKS address")
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(connection, portBytes); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))), nil
}

func writeCLISOCKS5Reply(connection net.Conn, code byte) error {
	_, err := connection.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func startCLISSHRelay(state *cliSSHTunnelState) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	runtimeDirectory, err := ensureCLISSHRuntimeDirectory()
	if err != nil {
		return err
	}
	socketDirectory, err := ensureCLISSHSocketDirectory(runtimeDirectory)
	if err != nil {
		return err
	}
	digest := fmt.Sprintf("%x", time.Now().UnixNano())
	state.RelayControl = filepath.Join(socketDirectory, "relay-"+digest+".sock")
	command := exec.Command(
		executable,
		"_ssh_relay",
		"--listen-port", strconv.Itoa(state.Port),
		"--upstream-port", strconv.Itoa(state.UpstreamPort),
		"--control", state.RelayControl,
	)
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = nil
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		return err
	}
	state.RelayPID = command.Process.Pid
	_ = command.Process.Release()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stats, statusErr := queryCLISSHRelay(*state, "status")
		if statusErr == nil && stats.OK && stats.PID == state.RelayPID &&
			stats.ListenPort == state.Port && stats.UpstreamPort == state.UpstreamPort {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = stopCLISSHRelay(*state)
	return errors.New("SSH traffic meter did not become ready")
}

func queryCLISSHRelay(state cliSSHTunnelState, action string) (cliSSHRelayStats, error) {
	if state.RelayControl == "" {
		return cliSSHRelayStats{}, errors.New("SSH traffic meter is unavailable")
	}
	connection, err := net.DialTimeout("unix", state.RelayControl, cliSSHRelayControlTimeout)
	if err != nil {
		return cliSSHRelayStats{}, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(cliSSHRelayControlTimeout))
	if err := json.NewEncoder(connection).Encode(cliSSHRelayRequest{Action: action}); err != nil {
		return cliSSHRelayStats{}, err
	}
	var stats cliSSHRelayStats
	if err := json.NewDecoder(bufio.NewReader(connection)).Decode(&stats); err != nil {
		return cliSSHRelayStats{}, err
	}
	if !stats.OK {
		return stats, errors.New(stats.Error)
	}
	return stats, nil
}

func stopCLISSHRelay(state cliSSHTunnelState) error {
	if state.RelayControl == "" {
		return nil
	}
	_, requestErr := queryCLISSHRelay(state, "shutdown")
	deadline := time.Now().Add(time.Second)
	for cliProcessRunning(state.RelayPID) && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	var stopErr error
	if cliProcessRunning(state.RelayPID) && cliSSHRelayProcessMatches(state) {
		if err := syscall.Kill(state.RelayPID, syscall.SIGTERM); err != nil &&
			!errors.Is(err, syscall.ESRCH) {
			stopErr = err
		}
	}
	if err := os.Remove(state.RelayControl); err != nil && !os.IsNotExist(err) {
		stopErr = errors.Join(stopErr, err)
	}
	if requestErr != nil && cliProcessRunning(state.RelayPID) {
		stopErr = errors.Join(stopErr, requestErr)
	}
	return stopErr
}

func cliSSHRelayProcessMatches(state cliSSHTunnelState) bool {
	if state.RelayPID <= 0 || state.RelayControl == "" {
		return false
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(state.RelayPID), "cmdline"))
	if err != nil {
		return false
	}
	arguments := strings.ReplaceAll(string(data), "\x00", " ")
	return strings.Contains(arguments, "_ssh_relay") &&
		strings.Contains(arguments, state.RelayControl)
}

func cliSSHRelayReady(state cliSSHTunnelState) bool {
	stats, err := queryCLISSHRelay(state, "status")
	return err == nil && stats.OK && stats.PID == state.RelayPID &&
		stats.ListenPort == state.Port && stats.UpstreamPort == state.UpstreamPort
}
