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
	groupAlive() (bool, error)
	cgroupPopulated() (bool, error)
	killCgroup() error
	removeCgroup() error
	release() error
}

type processBackend interface {
	start(Command) (backendProcess, error)
	waitNoHang() (int, syscall.WaitStatus, error)
}

// Process is a child whose status is owned by Manager. Wait may be called by
// multiple observers; all receive the same result.
type Process struct {
	pid   int
	name  string
	child backendProcess
	done  chan struct{}
	exit  Exit
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

// KillCgroup recursively kills every process in this child instance's cgroup.
func (p *Process) KillCgroup() error { return p.child.killCgroup() }

// WaitCgroupEmpty waits for cgroup.events to report populated 0, then removes
// the per-child cgroup directory.
func (p *Process) WaitCgroupEmpty(ctx context.Context) error {
	for {
		populated, err := p.cgroupPopulated()
		if err != nil {
			return err
		}
		if !populated {
			return p.removeCgroup()
		}
		timer := time.NewTimer(cgroupPollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (p *Process) groupAlive() (bool, error) { return p.child.groupAlive() }
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
	if command.Name == "" {
		return nil, errors.New("child name is required")
	}
	if !filepath.IsAbs(command.Path) {
		return nil, fmt.Errorf("child path must be absolute: %q", command.Path)
	}
	reply := make(chan startResponse, 1)
	m.ops <- func(children map[int]*Process) {
		child, err := m.backend.start(command)
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
		populated, err := process.cgroupPopulated()
		if err != nil {
			m.logf("reading child cgroup pid=%d: %v", pid, err)
		} else if !populated {
			if err := process.removeCgroup(); err != nil {
				m.logf("removing child cgroup pid=%d: %v", pid, err)
			}
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

func (b *osBackend) start(command Command) (backendProcess, error) {
	env := command.Env
	if env == nil {
		env = os.Environ()
	}
	cgroup, cgroupFD, err := b.createCgroup()
	if err != nil {
		return nil, fmt.Errorf("prepare cgroup for %s: %w", command.Name, err)
	}
	defer cgroupFD.Close()
	process, err := os.StartProcess(command.Path, append([]string{command.Path}, command.Args...), &os.ProcAttr{
		Dir:   command.Dir,
		Env:   env,
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys: &syscall.SysProcAttr{
			Setpgid:     true,
			UseCgroupFD: true,
			CgroupFD:    int(cgroupFD.Fd()),
		},
	})
	if err != nil {
		_ = os.Remove(cgroup.path)
		return nil, fmt.Errorf("start %s: %w", command.Name, err)
	}
	return &osChild{process: process, processID: process.Pid, cgroup: cgroup}, nil
}

func (b *osBackend) createCgroup() (*processCgroup, *os.File, error) {
	if err := os.Mkdir(b.cgroupRoot, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, nil, err
	}
	for {
		b.nextCgroup++
		path := filepath.Join(b.cgroupRoot, fmt.Sprintf("child-%016x", b.nextCgroup))
		if err := os.Mkdir(path, 0700); errors.Is(err, os.ErrExist) {
			continue
		} else if err != nil {
			return nil, nil, err
		}
		cgroup := &processCgroup{path: path}
		if _, err := cgroup.populated(); err != nil {
			_ = os.Remove(path)
			return nil, nil, err
		}
		killFile, err := os.OpenFile(filepath.Join(path, "cgroup.kill"), os.O_WRONLY, 0)
		if err != nil {
			_ = os.Remove(path)
			return nil, nil, err
		}
		if err := killFile.Close(); err != nil {
			_ = os.Remove(path)
			return nil, nil, err
		}
		fd, err := os.Open(path)
		if err != nil {
			_ = os.Remove(path)
			return nil, nil, err
		}
		return cgroup, fd, nil
	}
}

func (*osBackend) waitNoHang() (int, syscall.WaitStatus, error) {
	var status syscall.WaitStatus
	pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
	return pid, status, err
}

type osChild struct {
	process   *os.Process
	processID int
	cgroup    *processCgroup
}

func (p *osChild) pid() int { return p.processID }
func (p *osChild) signal(sig syscall.Signal) error {
	err := syscall.Kill(-p.processID, sig)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
func (p *osChild) groupAlive() (bool, error) {
	err := syscall.Kill(-p.processID, 0)
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if errors.Is(err, syscall.EPERM) {
		return true, nil
	}
	return err == nil, err
}
func (p *osChild) cgroupPopulated() (bool, error) { return p.cgroup.populated() }
func (p *osChild) killCgroup() error              { return p.cgroup.kill() }
func (p *osChild) removeCgroup() error            { return p.cgroup.remove() }
func (p *osChild) release() error                 { return p.process.Release() }

type processCgroup struct {
	path string
}

func (c *processCgroup) populated() (bool, error) {
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

func (c *processCgroup) kill() error {
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

func (c *processCgroup) remove() error {
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
	groups  map[*Process]struct{}
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
		spec: service, groups: map[*Process]struct{}{},
		delay: s.base, done: make(chan struct{}),
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
	process, err := s.manager.Start(record.spec.Command)
	if err != nil {
		return nil, err
	}
	if err := writePIDFile(record.spec.PIDFile, process.PID()); err != nil {
		_ = process.KillCgroup()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), initialCleanupGrace)
		_ = process.WaitCgroupEmpty(cleanupCtx)
		_, _ = process.Wait(cleanupCtx)
		cancel()
		return nil, fmt.Errorf("writing %s pid file: %w", record.spec.Name, err)
	}
	record.process = process
	record.groups[process] = struct{}{}
	record.started = s.clock.Now()
	return process, nil
}

func (s *Supervisor) stopInitial(record *serviceRecord, process *Process) error {
	var errs []error
	errs = append(errs, s.killCgroups([]*Process{process}, initialCleanupGrace))
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
		if record.process == process {
			record.process = nil
		}
		populated, populatedErr := process.cgroupPopulated()
		if populatedErr == nil && !populated && process.removeCgroup() == nil {
			delete(record.groups, process)
		}
		draining := s.draining
		runtime := s.clock.Now().Sub(record.started)
		if runtime >= s.stable {
			record.delay = s.base
		}
		s.mu.Unlock()
		s.emit(State{Name: record.spec.Name, Required: record.spec.Required, Err: exit.Err()})
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
				cleanupErr := s.killCgroups([]*Process{next}, initialCleanupGrace)
				_, _ = next.Wait(context.Background())
				removePIDFile(record.spec.PIDFile, next.PID())
				s.mu.Lock()
				if record.process == next {
					record.process = nil
				}
				if populated, err := next.cgroupPopulated(); err == nil && !populated && next.removeCgroup() == nil {
					delete(record.groups, next)
				}
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
	seen := map[*Process]bool{}
	for _, name := range names {
		if record := s.services[name]; record != nil {
			for process := range record.groups {
				if !seen[process] {
					seen[process] = true
					processes = append(processes, process)
				}
			}
		}
	}
	s.mu.Unlock()
	if len(processes) == 0 {
		return nil
	}

	var errs []error
	alive := processes[:0]
	for _, process := range processes {
		if err := process.Signal(syscall.SIGTERM); errors.Is(err, os.ErrProcessDone) {
			continue
		} else if err != nil {
			errs = append(errs, err)
		}
		alive = append(alive, process)
	}
	_, waitErrs := waitProcessGroups(alive, s.clock.After(termGrace))
	errs = append(errs, waitErrs...)
	errs = append(errs, s.killCgroups(processes, killGrace))
	return errors.Join(errs...)
}

func (s *Supervisor) killCgroups(processes []*Process, grace time.Duration) error {
	pending := make(map[*Process]bool, len(processes))
	var errs []error
	for _, process := range processes {
		populated, err := process.cgroupPopulated()
		if err != nil {
			errs = append(errs, fmt.Errorf("pid %d cgroup state: %w", process.PID(), err))
			continue
		}
		if !populated {
			if err := process.removeCgroup(); err != nil {
				errs = append(errs, fmt.Errorf("remove pid %d cgroup: %w", process.PID(), err))
			}
			continue
		}
		if err := process.killCgroup(); err != nil {
			errs = append(errs, fmt.Errorf("kill pid %d cgroup: %w", process.PID(), err))
		}
		pending[process] = true
	}
	if len(pending) == 0 {
		return errors.Join(errs...)
	}

	timeout := s.clock.After(grace)
	for len(pending) > 0 {
		for process := range pending {
			populated, err := process.cgroupPopulated()
			if err != nil {
				errs = append(errs, fmt.Errorf("pid %d cgroup state after kill: %w", process.PID(), err))
				delete(pending, process)
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
		if len(pending) == 0 {
			break
		}
		select {
		case <-timeout:
			for process := range pending {
				errs = append(errs, fmt.Errorf("pid %d cgroup remained populated after cgroup.kill", process.PID()))
			}
			return errors.Join(errs...)
		case <-s.clock.After(cgroupPollInterval):
		}
	}
	return errors.Join(errs...)
}

func waitProcessGroups(processes []*Process, timeout <-chan time.Time) ([]*Process, []error) {
	if len(processes) == 0 {
		return nil, nil
	}
	exited := make(chan *Process, len(processes))
	alive := make(map[*Process]bool, len(processes))
	for _, process := range processes {
		alive[process] = true
		go func(process *Process) {
			<-process.Done()
			exited <- process
		}(process)
	}
	for len(alive) > 0 {
		select {
		case process := <-exited:
			groupAlive, err := process.groupAlive()
			if err != nil {
				return processSlice(alive), []error{err}
			}
			if !groupAlive {
				delete(alive, process)
			}
		case <-timeout:
			var errs []error
			for process := range alive {
				groupAlive, err := process.groupAlive()
				if err != nil {
					errs = append(errs, err)
					continue
				}
				if !groupAlive {
					delete(alive, process)
				}
			}
			return processSlice(alive), errs
		}
	}
	return nil, nil
}

func processSlice(processes map[*Process]bool) []*Process {
	result := make([]*Process, 0, len(processes))
	for process := range processes {
		result = append(result, process)
	}
	return result
}
