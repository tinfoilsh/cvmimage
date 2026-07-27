package nvml

import "testing"

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
	if loaded() {
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

func TestErrorStringCoversUnknownCodes(t *testing.T) {
	if message := ErrorString(ERROR_LIBRARY_NOT_FOUND); message == "" {
		t.Fatal("ErrorString returned empty message")
	}
	if message := ErrorString(Return(12345)); message != "unknown NVML return code 12345" {
		t.Fatalf("ErrorString for unknown code: %q", message)
	}
}
