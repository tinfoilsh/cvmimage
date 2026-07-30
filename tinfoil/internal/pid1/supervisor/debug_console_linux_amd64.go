//go:build tinfoil_debug_image && linux && amd64

package supervisor

import (
	"errors"
	"os"
	"time"
)

// StartConsole starts one debug-image child as a new session with console as
// its controlling terminal. The manager remains the sole wait4 owner.
func (m *Manager) StartConsole(command Command, console *os.File) (*Process, error) {
	if console == nil {
		return nil, errors.New("console is required")
	}
	return m.start(command, "", startOptions{
		files:   []*os.File{console, console, console},
		console: true,
	})
}

// StopConsole terminates the complete console process group with bounded
// escalation, including background descendants left after the shell exits.
func (p *Process) StopConsole(termGrace, killGrace time.Duration) error {
	return p.Stop(termGrace, killGrace)
}
