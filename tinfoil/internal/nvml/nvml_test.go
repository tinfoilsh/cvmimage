package nvml

import (
	"fmt"
	"sync"
	"testing"
)

// TestInitFailsClosedWithoutLibrary exercises the dlopen path. On hosts
// without the NVIDIA library, Init must report ERROR_LIBRARY_NOT_FOUND
// instead of crashing; on GPU hosts a successful Init is paired with
// Shutdown.
func TestInitFailsClosedWithoutLibrary(t *testing.T) {
	result := Init()
	switch result {
	case SUCCESS:
		if shutdown := Shutdown(); shutdown != SUCCESS {
			t.Fatalf("Shutdown after successful Init: %s", ErrorString(shutdown))
		}
	case ERROR_LIBRARY_NOT_FOUND:
		t.Logf("NVML library not present: %s", ErrorString(result))
	default:
		t.Fatalf("Init: unexpected result %d (%s)", result, ErrorString(result))
	}
}

// TestUninitializedCallsFailClosed verifies entry points refuse to run
// before the library is loaded rather than dereferencing a nil entry point.
func TestUninitializedCallsFailClosed(t *testing.T) {
	if _, result := current(); result == SUCCESS {
		t.Skip("library already loaded on this host")
	}
	if _, result := DeviceGetCount(); result != ERROR_UNINITIALIZED {
		t.Fatalf("DeviceGetCount before load: got %d", result)
	}
	if result := Shutdown(); result != ERROR_UNINITIALIZED {
		t.Fatalf("Shutdown before load: got %d", result)
	}
	if result := SystemSetConfComputeGpusReadyState(CC_ACCEPTING_CLIENT_REQUESTS_FALSE); result != ERROR_UNINITIALIZED {
		t.Fatalf("SystemSetConfComputeGpusReadyState before load: got %d", result)
	}
}

// TestConcurrentInitAndCalls drives Init concurrently with other entry
// points so the race detector validates the snapshot publication. Results
// are not asserted because they depend on whether the library is present.
func TestConcurrentInitAndCalls(t *testing.T) {
	exerciseConcurrentCalls(t, false)
}

func exerciseConcurrentCalls(t *testing.T, requireSuccess bool) {
	t.Helper()
	var group sync.WaitGroup
	failures := make(chan error, 8)
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for i := 0; i < 100; i++ {
				if result := Init(); result != SUCCESS {
					if requireSuccess {
						failures <- fmt.Errorf("Init: %s", ErrorString(result))
					}
					return
				}
				_, countResult := DeviceGetCount()
				shutdownResult := Shutdown()
				if requireSuccess && (countResult != SUCCESS || shutdownResult != SUCCESS) {
					failures <- fmt.Errorf("DeviceGetCount: %s; Shutdown: %s",
						ErrorString(countResult), ErrorString(shutdownResult))
					return
				}
			}
		}()
	}
	group.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
}

func TestNegativeDeviceIndexFailsClosed(t *testing.T) {
	if _, result := DeviceGetHandleByIndex(-1); result != ERROR_INVALID_ARGUMENT {
		t.Fatalf("DeviceGetHandleByIndex(-1): %s", ErrorString(result))
	}
}

func TestNilAttestationReportFailsClosed(t *testing.T) {
	if result := (Device{}).GetConfComputeGpuAttestationReport(nil); result != ERROR_INVALID_ARGUMENT {
		t.Fatalf("GetConfComputeGpuAttestationReport(nil): %s", ErrorString(result))
	}
}

func TestErrorStringCoversUnknownCodes(t *testing.T) {
	if message := ErrorString(ERROR_LIBRARY_NOT_FOUND); message == "" {
		t.Fatal("ErrorString returned empty message")
	}
	if message := ErrorString(Return(12345)); message != "unknown NVML return code 12345" {
		t.Fatalf("ErrorString for unknown code: %q", message)
	}
}
