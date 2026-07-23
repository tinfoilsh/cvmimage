//go:build tinfoil_debug_image && linux && amd64

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// StartConsole starts one debug-image child as a new session with console as
// its controlling terminal. The manager remains the sole wait4 owner.
func (m *Manager) StartConsole(command Command, console *os.File) (*Process, error) {
	if command.Name == "" {
		return nil, errors.New("child name is required")
	}
	if !filepath.IsAbs(command.Path) {
		return nil, fmt.Errorf("child path must be absolute: %q", command.Path)
	}
	if console == nil {
		return nil, errors.New("console is required")
	}

	reply := make(chan startResponse, 1)
	m.ops <- func(children map[int]*Process) {
		environment := command.Env
		if environment == nil {
			environment = os.Environ()
		}
		process, err := os.StartProcess(
			command.Path,
			append([]string{command.Path}, command.Args...),
			&os.ProcAttr{
				Dir:   command.Dir,
				Env:   environment,
				Files: []*os.File{console, console, console},
				Sys: &syscall.SysProcAttr{
					Setsid:  true,
					Setctty: true,
					Ctty:    0,
				},
			},
		)
		if err != nil {
			reply <- startResponse{err: fmt.Errorf("start %s: %w", command.Name, err)}
			return
		}
		child := osChild{process: process}
		managed := &Process{child: child, done: make(chan struct{})}
		children[process.Pid] = managed
		reply <- startResponse{process: managed}
	}
	response := <-reply
	return response.process, response.err
}

// StopConsole terminates the complete console process group with bounded
// escalation, including background descendants left after the shell exits.
func (p *Process) StopConsole(termGrace, killGrace time.Duration) error {
	var errs []error
	if err := p.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		errs = append(errs, err)
	}
	alive, waitErrs := waitProcessGroups([]*Process{p}, time.After(termGrace))
	errs = append(errs, waitErrs...)
	for _, process := range alive {
		if err := process.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) {
			errs = append(errs, err)
		}
	}
	alive, waitErrs = waitProcessGroups(alive, time.After(killGrace))
	errs = append(errs, waitErrs...)
	for _, process := range alive {
		errs = append(errs, fmt.Errorf("debug console process group %d survived SIGKILL", process.PID()))
	}
	return errors.Join(errs...)
}
