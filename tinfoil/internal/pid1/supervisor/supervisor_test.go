package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeWait struct {
	pid    int
	status syscall.WaitStatus
}

type fakeBackend struct {
	mu             sync.Mutex
	nextPID        int
	waits          []fakeWait
	children       map[int]*fakeProcess
	sigchld        chan os.Signal
	started        chan int
	signaled       chan string
	startErrs      []error
	beforeStart    func()
	exitOnTERM     map[string]bool
	groupSurvives  map[string]bool
	cgroupSurvives map[string]bool
	killCgroupErr  map[string]error
	removeErr      map[string]error
	externalCgroup bool
}

type fakeProcess struct {
	backend       *fakeBackend
	id            int
	pgid          int
	name          string
	exited        bool
	groupRunning  bool
	cgroupRunning bool
}

func newFakeBackend(sigchld chan os.Signal) *fakeBackend {
	return &fakeBackend{
		nextPID: 100, children: map[int]*fakeProcess{}, sigchld: sigchld,
		started: make(chan int, 32), signaled: make(chan string, 32),
		exitOnTERM: map[string]bool{}, groupSurvives: map[string]bool{},
		cgroupSurvives: map[string]bool{},
		killCgroupErr:  map[string]error{},
		removeErr:      map[string]error{},
	}
}

func (b *fakeBackend) start(command Command) (backendProcess, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.beforeStart != nil {
		b.beforeStart()
	}
	if len(b.startErrs) > 0 {
		err := b.startErrs[0]
		b.startErrs = b.startErrs[1:]
		return nil, err
	}
	b.nextPID++
	child := &fakeProcess{
		backend: b, id: b.nextPID, pgid: b.nextPID, name: command.Name,
		groupRunning: true, cgroupRunning: true,
	}
	b.children[child.id] = child
	b.started <- child.id
	return child, nil
}

func (b *fakeBackend) waitNoHang() (int, syscall.WaitStatus, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.waits) == 0 {
		return 0, 0, nil
	}
	wait := b.waits[0]
	b.waits = b.waits[1:]
	return wait.pid, wait.status, nil
}

func (b *fakeBackend) cgroupPopulated() (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.externalCgroup {
		return true, nil
	}
	for _, child := range b.children {
		if child.cgroupRunning {
			return true, nil
		}
	}
	return false, nil
}

func (b *fakeBackend) killCgroup() error {
	b.signaled <- "root:cgroup.kill"
	b.mu.Lock()
	b.externalCgroup = false
	b.mu.Unlock()
	return nil
}

func (b *fakeBackend) exit(pid int, status syscall.WaitStatus) {
	b.mu.Lock()
	if child := b.children[pid]; child != nil {
		child.exited = true
		if !b.groupSurvives[child.name] {
			child.groupRunning = false
		}
		if !b.groupSurvives[child.name] && !b.cgroupSurvives[child.name] {
			child.cgroupRunning = false
		}
	}
	b.waits = append(b.waits, fakeWait{pid: pid, status: status})
	b.mu.Unlock()
	b.sigchld <- syscall.SIGCHLD
}

func (p *fakeProcess) pid() int { return p.id }
func (p *fakeProcess) release() error {
	p.id = -1
	return p.backend.removeErr[p.name]
}
func (p *fakeProcess) signal(signal syscall.Signal) error {
	p.backend.signaled <- fmt.Sprintf("%s:%s", p.name, signal)
	p.backend.mu.Lock()
	exited := p.exited
	groupAlive := p.groupRunning
	exitOnTERM := p.backend.exitOnTERM[p.name]
	if signal == syscall.SIGKILL {
		p.groupRunning = false
	}
	p.backend.mu.Unlock()
	if !groupAlive {
		return os.ErrProcessDone
	}
	if !exited && (signal == syscall.SIGKILL || (signal == syscall.SIGTERM && exitOnTERM)) {
		p.backend.exit(p.pgid, syscall.WaitStatus(uint32(signal)&0x7f))
	}
	return nil
}

func (p *fakeProcess) groupAlive() (bool, error) {
	p.backend.mu.Lock()
	defer p.backend.mu.Unlock()
	return p.groupRunning, nil
}

func (p *fakeProcess) cgroupPopulated() (bool, error) {
	p.backend.mu.Lock()
	defer p.backend.mu.Unlock()
	return p.cgroupRunning, nil
}

func (p *fakeProcess) killCgroup() error {
	p.backend.signaled <- fmt.Sprintf("%s:cgroup.kill", p.name)
	p.backend.mu.Lock()
	if err := p.backend.killCgroupErr[p.name]; err != nil {
		p.backend.mu.Unlock()
		return err
	}
	exited := p.exited
	p.groupRunning = false
	p.cgroupRunning = false
	p.backend.mu.Unlock()
	if !exited {
		p.backend.exit(p.pgid, syscall.WaitStatus(uint32(syscall.SIGKILL)&0x7f))
	}
	return nil
}

func TestManagerOwnsDirectWaitsAndReapsOrphans(t *testing.T) {
	sigchld := make(chan os.Signal, 8)
	backend := newFakeBackend(sigchld)
	var logsMu sync.Mutex
	var logs []string
	manager := newManager(backend, sigchld, func(format string, args ...any) {
		logsMu.Lock()
		logs = append(logs, fmt.Sprintf(format, args...))
		logsMu.Unlock()
	})

	managed, err := manager.Start(Command{Name: "managed", Path: "/managed"})
	if err != nil {
		t.Fatal(err)
	}
	oneShot, err := manager.Start(Command{Name: "one-shot", Path: "/one-shot"})
	if err != nil {
		t.Fatal(err)
	}
	backend.exit(999, 0)
	backend.exit(oneShot.PID(), syscall.WaitStatus(3<<8))
	backend.exit(managed.PID(), 0)

	managedExit, err := managed.Wait(context.Background())
	if err != nil || managedExit.Err() != nil {
		t.Fatalf("managed wait = (%+v, %v)", managedExit, err)
	}
	oneShotExit, err := oneShot.Wait(context.Background())
	if err != nil || oneShotExit.Status.ExitStatus() != 3 {
		t.Fatalf("one-shot wait = (%+v, %v)", oneShotExit, err)
	}
	if oneShotExit.Name != "one-shot" {
		t.Fatalf("one-shot exit name = %q", oneShotExit.Name)
	}
	if got := oneShotExit.Err().Error(); !strings.Contains(got, "one-shot (pid ") {
		t.Fatalf("one-shot error lacks command identity: %q", got)
	}
	if oneShot.PID() != oneShotExit.PID {
		t.Fatalf("released one-shot pid = %d, want %d", oneShot.PID(), oneShotExit.PID)
	}
	logsMu.Lock()
	defer logsMu.Unlock()
	if got := strings.Join(logs, "\n"); !strings.Contains(got, "reaped adopted child pid=999") {
		t.Fatalf("orphan was not reported:\n%s", got)
	}
}

func TestManagerRejectsUnboundedCommands(t *testing.T) {
	sigchld := make(chan os.Signal, 1)
	manager := newManager(newFakeBackend(sigchld), sigchld, nil)
	for _, command := range []Command{
		{Path: "/usr/bin/service"},
		{Name: "service", Path: "service"},
	} {
		if _, err := manager.Start(command); err == nil {
			t.Fatalf("Start accepted command %#v", command)
		}
	}
}

func TestInitialStartFailureRetiresRegistrationAndPermitsRetry(t *testing.T) {
	sigchld := make(chan os.Signal, 4)
	backend := newFakeBackend(sigchld)
	backend.startErrs = []error{errors.New("start failed")}
	manager := newManager(backend, sigchld, nil)
	supervisor := New(context.Background(), manager, Config{})
	var failedRecord *serviceRecord
	backend.beforeStart = func() {
		failedRecord = supervisor.services["service"]
	}
	service := Service{Name: "service", Command: Command{Name: "service", Path: "/service"}}

	if err := supervisor.Start(context.Background(), service); err == nil {
		t.Fatal("initial start succeeded")
	}
	if failedRecord == nil {
		t.Fatal("failed registration was not captured")
	}
	select {
	case <-failedRecord.done:
	default:
		t.Fatal("failed registration done channel was not closed")
	}
	supervisor.mu.Lock()
	_, registered := supervisor.services[service.Name]
	supervisor.mu.Unlock()
	if registered {
		t.Fatal("failed service remained registered")
	}
	backend.beforeStart = nil
	if err := supervisor.Start(context.Background(), service); err != nil {
		t.Fatalf("retry start: %v", err)
	}
	_ = receive(t, backend.started)
}

func TestInitialReadinessFailureKillsCgroupWaitsAndPermitsRetry(t *testing.T) {
	sigchld := make(chan os.Signal, 8)
	backend := newFakeBackend(sigchld)
	backend.groupSurvives["service"] = true
	manager := newManager(backend, sigchld, nil)
	supervisor := New(context.Background(), manager, Config{})
	var failedRecord *serviceRecord
	readyCalls := 0
	service := Service{
		Name: "service", Command: Command{Name: "service", Path: "/service"},
		Ready: func(context.Context) error {
			readyCalls++
			if readyCalls > 1 {
				return nil
			}
			pid := receive(t, backend.started)
			supervisor.mu.Lock()
			failedRecord = supervisor.services["service"]
			supervisor.mu.Unlock()
			backend.exit(pid, 0)
			return errors.New("not ready")
		},
	}

	if err := supervisor.Start(context.Background(), service); err == nil {
		t.Fatal("readiness failure was ignored")
	}
	if got := receive(t, backend.signaled); got != "service:cgroup.kill" {
		t.Fatalf("cleanup signal = %q, want service:cgroup.kill", got)
	}
	if failedRecord == nil {
		t.Fatal("failed readiness record was not captured")
	}
	select {
	case <-failedRecord.done:
	default:
		t.Fatal("failed readiness done channel was not closed")
	}
	supervisor.mu.Lock()
	_, registered := supervisor.services[service.Name]
	supervisor.mu.Unlock()
	if registered {
		t.Fatal("readiness-failed service remained registered")
	}
	if err := supervisor.Start(context.Background(), service); err != nil {
		t.Fatalf("retry start: %v", err)
	}
	_ = receive(t, backend.started)
}

func TestInitialReadinessFailureFallsBackWhenCgroupKillFails(t *testing.T) {
	sigchld := make(chan os.Signal, 8)
	backend := newFakeBackend(sigchld)
	backend.killCgroupErr["service"] = errors.New("cgroup kill denied")
	manager := newManager(backend, sigchld, nil)
	supervisor := New(context.Background(), manager, Config{})
	service := Service{
		Name: "service", Command: Command{Name: "service", Path: "/service"},
		Ready: func(context.Context) error { return errors.New("not ready") },
	}

	err := supervisor.Start(context.Background(), service)
	if err == nil || !strings.Contains(err.Error(), "cgroup kill denied") {
		t.Fatalf("Start() = %v, want cgroup cleanup error", err)
	}
	if got := receive(t, backend.signaled); got != "service:cgroup.kill" {
		t.Fatalf("cleanup signal = %q, want service:cgroup.kill", got)
	}
	if got := receive(t, backend.signaled); got != "service:killed" {
		t.Fatalf("fallback signal = %q, want service:killed", got)
	}
}

func TestRestartMaximumIsNeverBelowBase(t *testing.T) {
	for _, test := range []struct {
		name    string
		base    time.Duration
		maximum time.Duration
	}{
		{name: "default below large base", base: time.Minute, maximum: 0},
		{name: "explicit below base", base: 5 * time.Second, maximum: time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			supervisor := New(context.Background(), nil, Config{
				RestartBase: test.base,
				RestartMax:  test.maximum,
			})
			if supervisor.max != test.base {
				t.Fatalf("restart max = %s, want %s", supervisor.max, test.base)
			}
		})
	}
}

type fakeTimer struct {
	delay time.Duration
	fire  chan time.Time
}

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers chan fakeTimer
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1, 0), timers: make(chan fakeTimer, 32)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(delay time.Duration) <-chan time.Time {
	timer := fakeTimer{delay: delay, fire: make(chan time.Time, 1)}
	c.timers <- timer
	return timer.fire
}

func (c *fakeClock) fire(t *testing.T, want time.Duration) {
	t.Helper()
	timer := receive(t, c.timers)
	if timer.delay != want {
		t.Fatalf("timer delay = %s, want %s", timer.delay, want)
	}
	c.mu.Lock()
	c.now = c.now.Add(timer.delay)
	now := c.now
	c.mu.Unlock()
	timer.fire <- now
}

func (c *fakeClock) elapse(delay time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delay)
	c.mu.Unlock()
}

func receive[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for test event")
		var zero T
		return zero
	}
}

func waitForServiceProcess(t *testing.T, supervisor *Supervisor, name string, pid int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		supervisor.mu.Lock()
		record := supervisor.services[name]
		ready := record != nil && record.process != nil && record.process.PID() == pid
		supervisor.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("service %q did not publish pid %d", name, pid)
}

func TestRestartBackoffCapsAndResetsOnlyAfterStableRun(t *testing.T) {
	sigchld := make(chan os.Signal, 16)
	backend := newFakeBackend(sigchld)
	manager := newManager(backend, sigchld, nil)
	clock := newFakeClock()
	parent, cancel := context.WithCancel(context.Background())
	supervisor := New(parent, manager, Config{
		RestartBase: time.Second, RestartMax: 4 * time.Second,
		StableAfter: 10 * time.Second, Clock: clock,
	})
	if err := supervisor.Start(context.Background(), Service{
		Name: "required", Required: true, Restart: true,
		Command: Command{Name: "required", Path: "/required"},
	}); err != nil {
		t.Fatal(err)
	}
	pid := receive(t, backend.started)
	waitForServiceProcess(t, supervisor, "required", pid)

	for _, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second} {
		backend.exit(pid, syscall.WaitStatus(1<<8))
		clock.fire(t, delay)
		pid = receive(t, backend.started)
		waitForServiceProcess(t, supervisor, "required", pid)
	}

	clock.elapse(10 * time.Second)
	backend.exit(pid, syscall.WaitStatus(1<<8))
	clock.fire(t, time.Second)
	pid = receive(t, backend.started)
	supervisor.mu.Lock()
	done := supervisor.services["required"].done
	supervisor.mu.Unlock()
	cancel()
	backend.exit(pid, syscall.WaitStatus(1<<8))
	receive(t, done)
	select {
	case pid := <-backend.started:
		t.Fatalf("required service restarted after cancellation as pid %d", pid)
	default:
	}
}

func TestDrainOrdersGroupsAndEscalatesTermToKill(t *testing.T) {
	sigchld := make(chan os.Signal, 16)
	backend := newFakeBackend(sigchld)
	backend.exitOnTERM["shim"] = true
	backend.exitOnTERM["dockerd"] = true
	backend.exitOnTERM["containerd"] = true
	backend.externalCgroup = true
	manager := newManager(backend, sigchld, nil)
	clock := newFakeClock()
	supervisor := New(context.Background(), manager, Config{Clock: clock})
	for _, name := range []string{"egress", "shim", "dockerd", "containerd"} {
		if err := supervisor.Start(context.Background(), Service{
			Name: name, Restart: true, Command: Command{Name: name, Path: "/" + name},
		}); err != nil {
			t.Fatal(err)
		}
		_ = receive(t, backend.started)
	}

	result := make(chan error, 1)
	go func() {
		result <- supervisor.Drain(
			[][]string{{"egress", "shim"}, {"dockerd"}, {"containerd"}},
			time.Second, 2*time.Second,
		)
	}()

	got := []string{
		receive(t, backend.signaled),
		receive(t, backend.signaled),
	}
	clock.fire(t, time.Second)
	got = append(got, receive(t, backend.signaled))
	got = append(got, receive(t, backend.signaled))
	got = append(got, receive(t, backend.signaled))
	got = append(got, receive(t, backend.signaled))
	if err := receive(t, result); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"egress:terminated", "shim:terminated", "egress:cgroup.kill",
		"dockerd:terminated", "containerd:terminated", "root:cgroup.kill",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("signals = %v, want %v", got, want)
	}
	select {
	case pid := <-backend.started:
		t.Fatalf("service resurrected during drain as pid %d", pid)
	default:
	}
}

func TestDrainKillsSetsidDescendantAfterDirectChildExit(t *testing.T) {
	sigchld := make(chan os.Signal, 8)
	backend := newFakeBackend(sigchld)
	backend.exitOnTERM["service"] = true
	backend.cgroupSurvives["service"] = true
	backend.removeErr["service"] = syscall.ENOTEMPTY
	manager := newManager(backend, sigchld, nil)
	clock := newFakeClock()
	supervisor := New(context.Background(), manager, Config{Clock: clock})
	if err := supervisor.Start(context.Background(), Service{
		Name: "service", Command: Command{Name: "service", Path: "/service"},
	}); err != nil {
		t.Fatal(err)
	}
	_ = receive(t, backend.started)
	supervisor.mu.Lock()
	process := supervisor.services["service"].process
	supervisor.mu.Unlock()

	result := make(chan error, 1)
	go func() {
		result <- supervisor.Drain([][]string{{"service"}}, time.Second, 2*time.Second)
	}()
	if got := receive(t, backend.signaled); got != "service:terminated" {
		t.Fatalf("TERM signal = %q", got)
	}
	receive(t, process.Done())
	clock.fire(t, time.Second)
	if got := receive(t, backend.signaled); got != "service:cgroup.kill" {
		t.Fatalf("cgroup kill = %q", got)
	}
	if err := receive(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestProcessCgroupReadsFixedPopulatedEvent(t *testing.T) {
	directory := t.TempDir()
	events := filepath.Join(directory, "cgroup.events")
	cgroup := &processCgroup{path: directory}
	for contents, want := range map[string]bool{"populated 0\n": false, "populated 1\n": true} {
		if err := os.WriteFile(events, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := cgroup.populated(); err != nil || got != want {
			t.Fatalf("events %q: populated=%v error=%v", contents, got, err)
		}
	}
	if err := os.WriteFile(events, []byte("populated 2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := cgroup.populated(); err == nil {
		t.Fatal("invalid populated value succeeded")
	}
}

func TestProcessCgroupMissingControlsFailClosed(t *testing.T) {
	cgroup := &processCgroup{path: filepath.Join(t.TempDir(), "missing")}
	if _, err := cgroup.populated(); err == nil {
		t.Fatal("missing cgroup.events succeeded")
	}
	if err := cgroup.kill(); err == nil {
		t.Fatal("missing cgroup.kill succeeded")
	}
}

func TestOSChildReleaseRejectsPopulatedCgroup(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "cgroup.events"), []byte("populated 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	child := &osChild{process: process, processID: os.Getpid(), cgroup: &processCgroup{path: directory}}
	if err := child.release(); err == nil {
		t.Fatal("populated cgroup release succeeded")
	}
}

func TestOSChildWithoutCgroupIsExplicitlyUnpopulated(t *testing.T) {
	child := &osChild{}
	populated, err := child.cgroupPopulated()
	if err != nil {
		t.Fatal(err)
	}
	if populated {
		t.Fatal("child without cgroup reported populated")
	}
	if err := child.killCgroup(); err != nil {
		t.Fatalf("killCgroup() = %v", err)
	}
}

func TestDrainKillsOrphanedDescendant(t *testing.T) {
	sigchld := make(chan os.Signal, 8)
	backend := newFakeBackend(sigchld)
	backend.cgroupSurvives["service"] = true
	manager := newManager(backend, sigchld, nil)
	supervisor := New(context.Background(), manager, Config{Clock: newFakeClock()})
	if err := supervisor.Start(context.Background(), Service{
		Name: "service", Command: Command{Name: "service", Path: "/service"},
	}); err != nil {
		t.Fatal(err)
	}
	pid := receive(t, backend.started)
	supervisor.mu.Lock()
	process := supervisor.services["service"].process
	supervisor.mu.Unlock()
	backend.exit(pid, 0)
	receive(t, process.Done())

	if err := supervisor.Drain([][]string{{"service"}}, time.Second, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, backend.signaled); got != "service:terminated" {
		t.Fatalf("TERM signal = %q", got)
	}
	if got := receive(t, backend.signaled); got != "service:cgroup.kill" {
		t.Fatalf("orphan cleanup = %q", got)
	}
}
