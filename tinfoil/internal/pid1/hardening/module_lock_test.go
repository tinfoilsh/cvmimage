package hardening

import (
	"errors"
	"slices"
	"testing"
)

func TestLockKernelModules(t *testing.T) {
	kernel := &fakeModuleLockKernel{readback: []byte("1\n")}
	if err := lockKernelModules(kernel); err != nil {
		t.Fatal(err)
	}
	wantCalls := []string{"write:1\n", "read-modules-disabled"}
	if !slices.Equal(kernel.calls, wantCalls) {
		t.Fatalf("calls = %q, want %q", kernel.calls, wantCalls)
	}
}

func TestLockKernelModulesRejectsUnverifiedState(t *testing.T) {
	kernel := &fakeModuleLockKernel{readback: []byte("0\n")}
	err := lockKernelModules(kernel)
	if err == nil || !slices.Equal(kernel.calls, []string{"write:1\n", "read-modules-disabled"}) {
		t.Fatalf("lockKernelModules = %v, calls = %v", err, kernel.calls)
	}
}

func TestLockKernelModulesRejectsShortWrite(t *testing.T) {
	kernel := &fakeModuleLockKernel{writeCount: 1, readback: []byte("1\n")}
	err := lockKernelModules(kernel)
	if err == nil || !slices.Equal(kernel.calls, []string{"write:1\n"}) {
		t.Fatalf("lockKernelModules = %v, calls = %v", err, kernel.calls)
	}
}

func TestLockKernelModulesFailsClosedOnFileErrors(t *testing.T) {
	for _, failCall := range []string{"write:1\n", "read-modules-disabled"} {
		t.Run(failCall, func(t *testing.T) {
			kernel := &fakeModuleLockKernel{readback: []byte("1\n"), failCall: failCall}
			if err := lockKernelModules(kernel); err == nil {
				t.Fatal("lockKernelModules succeeded")
			}
		})
	}
}

type fakeModuleLockKernel struct {
	calls      []string
	readback   []byte
	writeCount int
	failCall   string
}

func (k *fakeModuleLockKernel) record(call string) error {
	k.calls = append(k.calls, call)
	if call == k.failCall {
		return errors.New("injected failure")
	}
	return nil
}

func (k *fakeModuleLockKernel) writeModulesDisabled(value []byte) (int, error) {
	if err := k.record("write:" + string(value)); err != nil {
		return 0, err
	}
	if k.writeCount != 0 {
		return k.writeCount, nil
	}
	return len(value), nil
}

func (k *fakeModuleLockKernel) readModulesDisabled() ([]byte, error) {
	if err := k.record("read-modules-disabled"); err != nil {
		return nil, err
	}
	return k.readback, nil
}
