// Package supervisor owns child creation, wait status collection, service
// restart, and ordered shutdown for Tinfoil PID 1.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
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

func (p *Process) groupAlive() (bool, error) { return p.child.groupAlive() }

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
	manager := newManager(osBackend{}, sigchld, log)
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
	}
}

func (m *Manager) logf(format string, args ...any) {
	if m.log != nil {
		m.log(format, args...)
	}
}

type osBackend struct{}

func (osBackend) start(command Command) (backendProcess, error) {
	env := command.Env
	if env == nil {
		env = os.Environ()
	}
	process, err := os.StartProcess(command.Path, append([]string{command.Path}, command.Args...), &os.ProcAttr{
		Dir:   command.Dir,
		Env:   env,
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys:   &syscall.SysProcAttr{Setpgid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("start %s: %w", command.Name, err)
	}
	return osChild{process: process, processID: process.Pid}, nil
}

func (osBackend) waitNoHang() (int, syscall.WaitStatus, error) {
	var status syscall.WaitStatus
	pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
	return pid, status, err
}

type osChild struct {
	process   *os.Process
	processID int
}

func (p osChild) pid() int { return p.processID }
func (p osChild) signal(sig syscall.Signal) error {
	err := syscall.Kill(-p.processID, sig)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
func (p osChild) groupAlive() (bool, error) {
	err := syscall.Kill(-p.processID, 0)
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if errors.Is(err, syscall.EPERM) {
		return true, nil
	}
	return err == nil, err
}
func (p osChild) release() error { return p.process.Release() }

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
	record.process = process
	record.groups[process] = struct{}{}
	record.started = s.clock.Now()
	return process, nil
}

func (s *Supervisor) stopInitial(record *serviceRecord, process *Process) error {
	var errs []error
	if err := process.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) {
		errs = append(errs, err)
	}
	if _, err := process.Wait(context.Background()); err != nil {
		errs = append(errs, err)
	}
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
		return exit.Err()
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
		s.mu.Lock()
		if record.process == process {
			record.process = nil
		}
		alive, aliveErr := process.groupAlive()
		if aliveErr == nil && !alive {
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
				_ = next.Signal(syscall.SIGKILL)
				_, _ = next.Wait(context.Background())
				s.mu.Lock()
				if record.process == next {
					record.process = nil
				}
				if alive, err := next.groupAlive(); err == nil && !alive {
					delete(record.groups, next)
				}
				if s.clock.Now().Sub(record.started) >= s.stable {
					record.delay = s.base
				}
				s.mu.Unlock()
				continue
			}
			s.emit(State{Name: record.spec.Name, Required: record.spec.Required, Ready: true})
			process = next
			break
		}
	}
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
// bounded wait before escalating remaining members to KILL.
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
	alive, waitErrs := waitProcessGroups(alive, s.clock.After(termGrace))
	errs = append(errs, waitErrs...)
	killed := alive[:0]
	for _, process := range alive {
		if err := process.Signal(syscall.SIGKILL); errors.Is(err, os.ErrProcessDone) {
			continue
		} else if err != nil {
			errs = append(errs, err)
		}
		killed = append(killed, process)
	}
	alive, waitErrs = waitProcessGroups(killed, s.clock.After(killGrace))
	errs = append(errs, waitErrs...)
	for _, process := range alive {
		errs = append(errs, fmt.Errorf("pid %d did not exit after SIGKILL", process.PID()))
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
