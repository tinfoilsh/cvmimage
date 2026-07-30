// Package supervisor owns child creation, wait status collection, service
// restart, and ordered shutdown for Tinfoil PID 1.
package supervisor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	childCgroupRoot     = "/sys/fs/cgroup/tinfoil-pid1"
	cgroupEventsLimit   = 4096
	cgroupPollInterval  = 10 * time.Millisecond
	initialCleanupGrace = 5 * time.Second
)

// Command describes a direct child of PID 1.
type Command struct {
	Name string
	Path string
	Args []string
	Env  []string
	Dir  string
}

// Exit is the wait status collected for a child.
type Exit struct {
	Name   string
	PID    int
	Status syscall.WaitStatus
}

func (e Exit) Err() error {
	identity := fmt.Sprintf("pid %d", e.PID)
	if e.Name != "" {
		identity = fmt.Sprintf("%s (pid %d)", e.Name, e.PID)
	}
	switch {
	case e.Status.Exited() && e.Status.ExitStatus() == 0:
		return nil
	case e.Status.Exited():
		return fmt.Errorf("%s exited with status %d", identity, e.Status.ExitStatus())
	case e.Status.Signaled():
		return fmt.Errorf("%s killed by %s", identity, e.Status.Signal())
	default:
		return fmt.Errorf("%s ended with wait status %#x", identity, uint32(e.Status))
	}
}

type backendProcess interface {
	pid() int
	signal(syscall.Signal) error
	cgroupPopulated() (bool, error)
	killCgroup() error
	removeCgroup() error
	release() error
}

type processBackend interface {
	start(Command, string, startOptions) (backendProcess, error)
	waitNoHang() (int, syscall.WaitStatus, error)
}

type startOptions struct {
	files   []*os.File
	console bool
}

// Process is a child whose status is owned by Manager. Wait may be called by
// multiple observers; all receive the same result.
type Process struct {
	pid   int
	name  string
	child backendProcess
	done  chan struct{}
	exit  Exit
	stop  sync.Mutex
}

func (p *Process) PID() int              { return p.pid }
func (p *Process) Done() <-chan struct{} { return p.done }

func (p *Process) Wait(ctx context.Context) (Exit, error) {
	select {
	case <-p.done:
		return p.exit, nil
	case <-ctx.Done():
		return Exit{}, ctx.Err()
	}
}

func (p *Process) complete(exit Exit) {
	p.exit = exit
	close(p.done)
}

func (p *Process) Signal(sig syscall.Signal) error {
	return p.child.signal(sig)
}

// Stop terminates the process group gracefully, then recursively kills any
// descendants that remain in the process cgroup.
func (p *Process) Stop(termGrace, killGrace time.Duration) error {
	return stopProcesses([]*Process{p}, termGrace, killGrace, realClock{})
}

func (p *Process) cgroupPopulated() (bool, error) {
	return p.child.cgroupPopulated()
}
func (p *Process) killCgroup() error   { return p.child.killCgroup() }
func (p *Process) removeCgroup() error { return p.child.removeCgroup() }

type startResponse struct {
	process *Process
	err     error
}

// Manager is the sole wait4 owner. Every PID 1 child must be started through
// this manager; mixing it with os/exec Wait would race for child statuses.
// Child creation is serialized with reaping, so even a child that exits
// immediately is registered before wait4(-1) can collect it.
type Manager struct {
	backend processBackend
	log     func(string, ...any)
	ops     chan func(map[int]*Process)
	sigchld chan os.Signal
}

// NewManager starts the production Linux child manager.
func NewManager(log func(string, ...any)) *Manager {
	sigchld := make(chan os.Signal, 1)
	signal.Notify(sigchld, syscall.SIGCHLD)
	manager := newManager(&osBackend{cgroupRoot: childCgroupRoot}, sigchld, log)
	return manager
}

func newManager(backend processBackend, sigchld chan os.Signal, log func(string, ...any)) *Manager {
	manager := &Manager{
		backend: backend,
		log:     log,
		ops:     make(chan func(map[int]*Process)),
		sigchld: sigchld,
	}
	go manager.loop()
	return manager
}

func (m *Manager) Start(command Command) (*Process, error) {
	return m.start(command, "", startOptions{})
}

func (m *Manager) start(command Command, scope string, options startOptions) (*Process, error) {
	if command.Name == "" {
		return nil, errors.New("child name is required")
	}
	if !filepath.IsAbs(command.Path) {
		return nil, fmt.Errorf("child path must be absolute: %q", command.Path)
	}
	reply := make(chan startResponse, 1)
	m.ops <- func(children map[int]*Process) {
		child, err := m.backend.start(command, scope, options)
		if err != nil {
			reply <- startResponse{err: err}
			return
		}
		pid := child.pid()
		process := &Process{pid: pid, name: command.Name, child: child, done: make(chan struct{})}
		children[pid] = process
		reply <- startResponse{process: process}
	}
	response := <-reply
	return response.process, response.err
}

func (m *Manager) loop() {
	children := map[int]*Process{}
	m.reapChildren(children)
	for {
		select {
		case operation := <-m.ops:
			operation(children)
		case <-m.sigchld:
			m.reapChildren(children)
		}
	}
}

func (m *Manager) reapChildren(children map[int]*Process) {
	for {
		pid, status, err := m.backend.waitNoHang()
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.ECHILD) || (err == nil && pid == 0) {
			return
		}
		if err != nil {
			m.logf("reaping children: %v", err)
			return
		}
		exit := Exit{PID: pid, Status: status}
		process, owned := children[pid]
		if !owned {
			m.logf("reaped adopted child pid=%d status=%#x", pid, uint32(status))
			continue
		}
		exit.Name = process.name
		delete(children, pid)
		process.complete(exit)
		if err := process.child.release(); err != nil {
			m.logf("releasing child pid=%d: %v", pid, err)
		}
	}
}

func (m *Manager) logf(format string, args ...any) {
	if m.log != nil {
		m.log(format, args...)
	}
}

type osBackend struct {
	cgroupRoot string
	nextCgroup uint64
}

func (b *osBackend) start(command Command, scope string, options startOptions) (backendProcess, error) {
	env := command.Env
	if env == nil {
		env = os.Environ()
	}
	cgroup, cgroupFD, err := b.createCgroup(scope)
	if err != nil {
		return nil, fmt.Errorf("prepare cgroup for %s: %w", command.Name, err)
	}
	defer cgroupFD.Close()
	files := options.files
	if files == nil {
		files = []*os.File{os.Stdin, os.Stdout, os.Stderr}
	}
	system := &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgroupFD.Fd()),
	}
	if options.console {
		system.Setsid = true
		system.Setctty = true
		system.Ctty = 0
	} else {
		system.Setpgid = true
	}
	process, err := os.StartProcess(command.Path, append([]string{command.Path}, command.Args...), &os.ProcAttr{
		Dir:   command.Dir,
		Env:   env,
		Files: files,
		Sys:   system,
	})
	if err != nil {
		_ = cgroup.remove()
		return nil, fmt.Errorf("start %s: %w", command.Name, err)
	}
	return &osChild{process: process, processID: process.Pid, cgroup: cgroup}, nil
}

func (b *osBackend) createCgroup(scope string) (*cgroupScope, *os.File, error) {
	if err := os.Mkdir(b.cgroupRoot, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, nil, err
	}
	if scope != "" {
		if !validScopeName(scope) {
			return nil, nil, fmt.Errorf("invalid service scope %q", scope)
		}
		path := filepath.Join(b.cgroupRoot, "service-"+scope)
		created := false
		if err := os.Mkdir(path, 0700); err == nil {
			created = true
		} else if !errors.Is(err, os.ErrExist) {
			return nil, nil, err
		}
		cgroup, fd, err := openCgroupScope(path, true)
		if err != nil {
			if created {
				_ = os.Remove(path)
			}
			return nil, nil, err
		}
		return cgroup, fd, nil
	}
	for {
		b.nextCgroup++
		path := filepath.Join(b.cgroupRoot, fmt.Sprintf("child-%016x", b.nextCgroup))
		if err := os.Mkdir(path, 0700); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return nil, nil, err
		}
		cgroup, fd, err := openCgroupScope(path, false)
		if err != nil {
			_ = os.Remove(path)
			return nil, nil, err
		}
		return cgroup, fd, nil
	}
}

func openCgroupScope(path string, persistent bool) (*cgroupScope, *os.File, error) {
	cgroup := &cgroupScope{path: path, persistent: persistent}
	populated, err := cgroup.populated()
	if err != nil {
		return nil, nil, err
	}
	if populated {
		return nil, nil, errors.New("cgroup is still populated")
	}
	killFile, err := os.OpenFile(filepath.Join(path, "cgroup.kill"), os.O_WRONLY, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := killFile.Close(); err != nil {
		return nil, nil, err
	}
	fd, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return cgroup, fd, nil
}

func validScopeName(name string) bool {
	for _, character := range name {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return name != "" && name != "." && name != ".."
}

func (*osBackend) waitNoHang() (int, syscall.WaitStatus, error) {
	var status syscall.WaitStatus
	pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
	return pid, status, err
}

type osChild struct {
	process   *os.Process
	processID int
	cgroup    *cgroupScope
}

func (p *osChild) pid() int { return p.processID }
func (p *osChild) signal(sig syscall.Signal) error {
	err := syscall.Kill(-p.processID, sig)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
func (p *osChild) cgroupPopulated() (bool, error) { return p.cgroup.populated() }
func (p *osChild) killCgroup() error              { return p.cgroup.kill() }
func (p *osChild) removeCgroup() error            { return p.cgroup.remove() }
func (p *osChild) release() error                 { return p.process.Release() }

// cgroupScope is persistent for a logical service and ephemeral for a one-shot
// or debug-console process.
type cgroupScope struct {
	path       string
	persistent bool
}

func (c *cgroupScope) populated() (bool, error) {
	data, err := os.ReadFile(filepath.Join(c.path, "cgroup.events"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(data) > cgroupEventsLimit {
		return false, fmt.Errorf("cgroup.events exceeds %d bytes", cgroupEventsLimit)
	}
	for len(data) > 0 {
		end := bytes.IndexByte(data, '\n')
		if end < 0 {
			return false, errors.New("cgroup.events has unterminated line")
		}
		line := data[:end]
		data = data[end+1:]
		switch {
		case bytes.Equal(line, []byte("populated 0")):
			return false, nil
		case bytes.Equal(line, []byte("populated 1")):
			return true, nil
		case bytes.HasPrefix(line, []byte("populated ")):
			return false, fmt.Errorf("invalid cgroup.events populated line %q", line)
		}
	}
	return false, errors.New("cgroup.events lacks populated state")
}

func (c *cgroupScope) kill() error {
	file, err := os.OpenFile(filepath.Join(c.path, "cgroup.kill"), os.O_WRONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString("1")
	return errors.Join(writeErr, file.Close())
}

func (c *cgroupScope) remove() error {
	if c.persistent {
		return nil
	}
	err := os.Remove(c.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// State reports whether a managed service is ready. A required service is
// marked unready before restart delay begins, allowing callers to fail closed.
type State struct {
	Name     string
	Required bool
	Ready    bool
	Err      error
}

// Service is a long-lived child. Ready is called after every start and must
// return only when that instance is usable.
type Service struct {
	Name     string
	Command  Command
	Required bool
	Restart  bool
	Ready    func(context.Context) error
	PIDFile  string
}

type Clock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                             { return time.Now() }
func (realClock) After(delay time.Duration) <-chan time.Time { return time.After(delay) }

// Config controls restart and drain timing.
type Config struct {
	RestartBase time.Duration
	RestartMax  time.Duration
	StableAfter time.Duration
	Clock       Clock
	Observe     func(State)
}

type serviceRecord struct {
	spec    Service
	process *Process
	started time.Time
	delay   time.Duration
	done    chan struct{}
}

// Supervisor restarts services and drains them in dependency order.
type Supervisor struct {
	manager *Manager
	context context.Context
	cancel  context.CancelFunc
	clock   Clock
	base    time.Duration
	max     time.Duration
	stable  time.Duration
	observe func(State)

	mu       sync.Mutex
	draining bool
	services map[string]*serviceRecord
}

func New(parent context.Context, manager *Manager, config Config) *Supervisor {
	if config.RestartBase <= 0 {
		config.RestartBase = 2 * time.Second
	}
	if config.RestartMax <= 0 {
		config.RestartMax = 30 * time.Second
	}
	if config.RestartMax < config.RestartBase {
		config.RestartMax = config.RestartBase
	}
	if config.StableAfter <= 0 {
		config.StableAfter = time.Minute
	}
	if config.Clock == nil {
		config.Clock = realClock{}
	}
	ctx, cancel := context.WithCancel(parent)
	return &Supervisor{
		manager: manager, context: ctx, cancel: cancel, clock: config.Clock,
		base: config.RestartBase, max: config.RestartMax, stable: config.StableAfter,
		observe: config.Observe, services: map[string]*serviceRecord{},
	}
}

func (s *Supervisor) Start(ctx context.Context, service Service) error {
	record := &serviceRecord{
		spec: service, delay: s.base, done: make(chan struct{}),
	}
	s.mu.Lock()
	if s.draining {
		s.mu.Unlock()
		return context.Canceled
	}
	if _, exists := s.services[service.Name]; exists {
		s.mu.Unlock()
		return fmt.Errorf("service %s already registered", service.Name)
	}
	s.services[service.Name] = record
	process, err := s.startLocked(record)
	if err != nil {
		s.retireLocked(record)
	}
	s.mu.Unlock()
	if err != nil {
		s.emit(State{Name: service.Name, Required: service.Required, Err: err})
		return err
	}
	if err := s.ready(ctx, record, process); err != nil {
		cleanupErr := s.stopInitial(record, process)
		readinessErr := fmt.Errorf("%s readiness: %w", service.Name, errors.Join(err, cleanupErr))
		s.emit(State{Name: service.Name, Required: service.Required, Err: readinessErr})
		return readinessErr
	}
	s.emit(State{Name: service.Name, Required: service.Required, Ready: true})
	go func() {
		defer close(record.done)
		s.monitor(record, process)
	}()
	return nil
}
func (s *Supervisor) startLocked(record *serviceRecord) (*Process, error) {
	if s.draining {
		return nil, context.Canceled
	}
	process, err := s.manager.start(record.spec.Command, record.spec.Name, startOptions{})
	if err != nil {
		return nil, err
	}
	if err := writePIDFile(record.spec.PIDFile, process.PID()); err != nil {
		_ = stopProcesses([]*Process{process}, 0, initialCleanupGrace, realClock{})
		_, _ = process.Wait(context.Background())
		return nil, fmt.Errorf("writing %s pid file: %w", record.spec.Name, err)
	}
	record.process = process
	record.started = s.clock.Now()
	return process, nil
}

func (s *Supervisor) stopInitial(record *serviceRecord, process *Process) error {
	var errs []error
	errs = append(errs, stopProcesses([]*Process{process}, 0, initialCleanupGrace, realClock{}))
	if _, err := process.Wait(context.Background()); err != nil {
		errs = append(errs, err)
	}
	removePIDFile(record.spec.PIDFile, process.PID())
	s.mu.Lock()
	s.retireLocked(record)
	s.mu.Unlock()
	return errors.Join(errs...)
}

func (s *Supervisor) retireLocked(record *serviceRecord) {
	if s.services[record.spec.Name] == record {
		delete(s.services, record.spec.Name)
	}
	close(record.done)
}

func (s *Supervisor) ready(ctx context.Context, record *serviceRecord, process *Process) error {
	if record.spec.Ready != nil {
		if err := record.spec.Ready(ctx); err != nil {
			return err
		}
	}
	select {
	case <-process.Done():
		exit, _ := process.Wait(context.Background())
		if err := exit.Err(); err != nil {
			return err
		}
		return fmt.Errorf("%s exited before readiness", record.spec.Name)
	default:
		return nil
	}
}

func (s *Supervisor) monitor(record *serviceRecord, process *Process) {
	for {
		exit, err := process.Wait(context.Background())
		if err != nil {
			return
		}
		removePIDFile(record.spec.PIDFile, process.PID())
		s.mu.Lock()
		draining := s.draining
		runtime := s.clock.Now().Sub(record.started)
		if runtime >= s.stable {
			record.delay = s.base
		}
		s.mu.Unlock()
		var cleanupErr error
		if !draining {
			cleanupErr = stopProcesses([]*Process{process}, 0, initialCleanupGrace, realClock{})
		}
		s.emit(State{Name: record.spec.Name, Required: record.spec.Required, Err: errors.Join(exit.Err(), cleanupErr)})
		if draining || !record.spec.Restart {
			return
		}

		for {
			delay := record.delay
			if s.context.Err() != nil {
				return
			}
			select {
			case <-s.context.Done():
				return
			case <-s.clock.After(delay):
			}

			s.mu.Lock()
			if s.draining || s.context.Err() != nil {
				s.mu.Unlock()
				return
			}
			record.delay = nextDelay(delay, s.max)
			next, startErr := s.startLocked(record)
			s.mu.Unlock()
			if startErr != nil {
				s.emit(State{Name: record.spec.Name, Required: record.spec.Required, Err: startErr})
				continue
			}
			if readyErr := s.ready(s.context, record, next); readyErr != nil {
				s.emit(State{Name: record.spec.Name, Required: record.spec.Required, Err: readyErr})
				cleanupErr := stopProcesses([]*Process{next}, 0, initialCleanupGrace, realClock{})
				_, _ = next.Wait(context.Background())
				removePIDFile(record.spec.PIDFile, next.PID())
				s.mu.Lock()
				if s.clock.Now().Sub(record.started) >= s.stable {
					record.delay = s.base
				}
				s.mu.Unlock()
				if cleanupErr != nil {
					s.emit(State{Name: record.spec.Name, Required: record.spec.Required, Err: cleanupErr})
				}
				continue
			}
			s.emit(State{Name: record.spec.Name, Required: record.spec.Required, Ready: true})
			process = next
			break
		}
	}
}

func writePIDFile(path string, pid int) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".pid-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := fmt.Fprintf(temporary, "%d\n", pid); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func removePIDFile(path string, pid int) {
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(data)) != strconv.Itoa(pid) {
		return
	}
	_ = os.Remove(path)
}

func nextDelay(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func (s *Supervisor) emit(state State) {
	if s.observe != nil {
		s.observe(state)
	}
}

// Drain prevents new starts, then stops each dependency group with TERM and a
// bounded wait before recursively killing each remaining child cgroup.
func (s *Supervisor) Drain(groups [][]string, termGrace, killGrace time.Duration) error {
	s.mu.Lock()
	s.draining = true
	s.cancel()
	s.mu.Unlock()

	var errs []error
	seen := map[string]bool{}
	for _, group := range groups {
		for _, name := range group {
			seen[name] = true
		}
		errs = append(errs, s.drainGroup(group, termGrace, killGrace))
	}
	s.mu.Lock()
	var remaining []string
	for name := range s.services {
		if !seen[name] {
			remaining = append(remaining, name)
		}
	}
	s.mu.Unlock()
	sort.Strings(remaining)
	errs = append(errs, s.drainGroup(remaining, termGrace, killGrace))
	return errors.Join(errs...)
}

func (s *Supervisor) drainGroup(names []string, termGrace, killGrace time.Duration) error {
	s.mu.Lock()
	processes := make([]*Process, 0, len(names))
	for _, name := range names {
		if record := s.services[name]; record != nil && record.process != nil {
			processes = append(processes, record.process)
		}
	}
	s.mu.Unlock()
	return stopProcesses(processes, termGrace, killGrace, s.clock)
}

func stopProcesses(processes []*Process, termGrace, killGrace time.Duration, clock Clock) error {
	if len(processes) == 0 {
		return nil
	}
	locked := append([]*Process(nil), processes...)
	sort.Slice(locked, func(left, right int) bool {
		return locked[left].PID() < locked[right].PID()
	})
	for index, process := range locked {
		if index > 0 && process == locked[index-1] {
			continue
		}
		process.stop.Lock()
		defer process.stop.Unlock()
	}
	var errs []error
	pending, waitErrs := waitCgroups(processes, 0, clock)
	errs = append(errs, waitErrs...)
	for _, process := range pending {
		if err := process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			errs = append(errs, fmt.Errorf("terminate pid %d process group: %w", process.PID(), err))
		}
	}
	pending, waitErrs = waitCgroups(pending, termGrace, clock)
	errs = append(errs, waitErrs...)
	for _, process := range pending {
		if err := process.killCgroup(); err != nil {
			errs = append(errs, fmt.Errorf("kill pid %d cgroup: %w", process.PID(), err))
		}
	}
	pending, waitErrs = waitCgroups(pending, killGrace, clock)
	errs = append(errs, waitErrs...)
	for _, process := range pending {
		errs = append(errs, fmt.Errorf("pid %d cgroup remained populated after cgroup.kill", process.PID()))
	}
	return errors.Join(errs...)
}

func waitCgroups(processes []*Process, grace time.Duration, clock Clock) ([]*Process, []error) {
	pending := make(map[*Process]bool, len(processes))
	check := func() []error {
		var errs []error
		for process := range pending {
			populated, err := process.cgroupPopulated()
			if err != nil {
				errs = append(errs, fmt.Errorf("pid %d cgroup state: %w", process.PID(), err))
				continue
			}
			if populated {
				continue
			}
			if err := process.removeCgroup(); err != nil {
				errs = append(errs, fmt.Errorf("remove pid %d cgroup: %w", process.PID(), err))
			}
			delete(pending, process)
		}
		return errs
	}
	for _, process := range processes {
		pending[process] = true
	}
	errs := check()
	if len(pending) == 0 || grace <= 0 {
		return processSlice(pending), errs
	}

	timeout := clock.After(grace)
	ticker := time.NewTicker(cgroupPollInterval)
	defer ticker.Stop()
	for len(pending) > 0 {
		select {
		case <-timeout:
			return processSlice(pending), errs
		case <-ticker.C:
			errs = append(errs, check()...)
		}
	}
	return nil, errs
}

func processSlice(processes map[*Process]bool) []*Process {
	result := make([]*Process, 0, len(processes))
	for process := range processes {
		result = append(result, process)
	}
	return result
}
