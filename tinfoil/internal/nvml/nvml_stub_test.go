package nvml

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// stubSource is a fake libnvidia-ml.so.1 implementing every symbol this
// binding resolves, with fixed answers the driven test asserts on. The
// report call echoes the caller nonce into the report body, so a layout
// mismatch between the Go structs and the C structs corrupts the echo and
// fails the test. The memory call rejects a wrong versioned-struct header.
const stubSource = `
#include <stdint.h>
#include <string.h>

typedef int nvmlReturn_t;
typedef struct nvmlDevice_st* nvmlDevice_t;

#define NVML_SUCCESS 0
#define NVML_ERROR_INVALID_ARGUMENT 2
#define NVML_ERROR_ARGUMENT_VERSION_MISMATCH 25

typedef struct nvmlUtilization_st {
	unsigned int gpu;
	unsigned int memory;
} nvmlUtilization_t;

typedef struct nvmlMemory_v2_st {
	unsigned int version;
	unsigned long long total;
	unsigned long long reserved;
	unsigned long long free;
	unsigned long long used;
} nvmlMemory_v2_t;

typedef struct nvmlConfComputeGpuCertificate_st {
	unsigned int certChainSize;
	unsigned int attestationCertChainSize;
	unsigned char certChain[0x1000];
	unsigned char attestationCertChain[0x1400];
} nvmlConfComputeGpuCertificate_t;

typedef struct nvmlConfComputeGpuAttestationReport_st {
	unsigned int isCecAttestationReportPresent;
	unsigned int attestationReportSize;
	unsigned int cecAttestationReportSize;
	unsigned char nonce[0x20];
	unsigned char attestationReport[0x2000];
	unsigned char cecAttestationReport[0x1000];
} nvmlConfComputeGpuAttestationReport_t;

static int checkDevice(nvmlDevice_t device) {
	return (uintptr_t)device == 0x1001;
}

nvmlReturn_t nvmlInit_v2(void) { return NVML_SUCCESS; }
nvmlReturn_t nvmlShutdown(void) { return NVML_SUCCESS; }

nvmlReturn_t nvmlDeviceGetCount_v2(unsigned int *count) {
	*count = 2;
	return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetHandleByIndex_v2(unsigned int index, nvmlDevice_t *device) {
	if (index > 2) return NVML_ERROR_INVALID_ARGUMENT;
	*device = (nvmlDevice_t)(uintptr_t)(0x1000 + index);
	return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetArchitecture(nvmlDevice_t device, unsigned int *architecture) {
	if (!checkDevice(device)) return NVML_ERROR_INVALID_ARGUMENT;
	*architecture = 9;
	return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetName(nvmlDevice_t device, char *name, unsigned int length) {
	if (length < sizeof("STUB-GPU-1")) return NVML_ERROR_INVALID_ARGUMENT;
	if ((uintptr_t)device == 0x1000) {
		memset(name, 'X', length);
		return NVML_SUCCESS;
	}
	if (!checkDevice(device)) return NVML_ERROR_INVALID_ARGUMENT;
	memcpy(name, "STUB-GPU-1", sizeof("STUB-GPU-1"));
	return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetMemoryInfo_v2(nvmlDevice_t device, nvmlMemory_v2_t *memory) {
	if (!checkDevice(device)) return NVML_ERROR_INVALID_ARGUMENT;
	if (memory->version != (unsigned int)(sizeof(nvmlMemory_v2_t) | (2U << 24)))
		return NVML_ERROR_ARGUMENT_VERSION_MISMATCH;
	memory->total = 4096;
	memory->reserved = 8;
	memory->free = 3064;
	memory->used = 1024;
	return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetUtilizationRates(nvmlDevice_t device, nvmlUtilization_t *utilization) {
	if (!checkDevice(device)) return NVML_ERROR_INVALID_ARGUMENT;
	utilization->gpu = 37;
	utilization->memory = 11;
	return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetConfComputeGpuAttestationReport(
		nvmlDevice_t device, nvmlConfComputeGpuAttestationReport_t *report) {
	if (!checkDevice(device)) return NVML_ERROR_INVALID_ARGUMENT;
	if (report->nonce[0] == 0xFF) {
		report->attestationReportSize = sizeof(report->attestationReport) + 1;
		report->cecAttestationReportSize = sizeof(report->cecAttestationReport) + 1;
		return NVML_SUCCESS;
	}
	report->isCecAttestationReportPresent = 1;
	report->attestationReportSize = 64;
	memcpy(report->attestationReport, report->nonce, sizeof(report->nonce));
	memset(report->attestationReport + sizeof(report->nonce), 0xA5, 32);
	report->cecAttestationReportSize = 16;
	memset(report->cecAttestationReport, 0x5A, 16);
	return NVML_SUCCESS;
}

nvmlReturn_t nvmlDeviceGetConfComputeGpuCertificate(
		nvmlDevice_t device, nvmlConfComputeGpuCertificate_t *certificate) {
	if ((uintptr_t)device == 0x1002) {
		certificate->certChainSize = sizeof(certificate->certChain) + 1;
		certificate->attestationCertChainSize = sizeof(certificate->attestationCertChain) + 1;
		return NVML_SUCCESS;
	}
	if (!checkDevice(device)) return NVML_ERROR_INVALID_ARGUMENT;
	certificate->certChainSize = 8;
	memset(certificate->certChain, 0xC1, 8);
	certificate->attestationCertChainSize = 12;
	memset(certificate->attestationCertChain, 0xC2, 12);
	return NVML_SUCCESS;
}

nvmlReturn_t nvmlSystemSetConfComputeGpusReadyState(unsigned int state) {
	return state == 1 ? NVML_SUCCESS : NVML_ERROR_INVALID_ARGUMENT;
}
`

const (
	stubEnvironment = "TINFOIL_NVML_STUB"
	stubLibraryName = "libnvidia-ml.so.1"
)

// TestStubLibrary compiles the stub library and re-runs this test binary
// against its explicit path in a child process.
func TestStubLibrary(t *testing.T) {
	if os.Getenv(stubEnvironment) != "" {
		t.Skip("already running against the stub")
	}
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skipf("no C compiler available: %v", err)
	}

	directory := t.TempDir()
	source := filepath.Join(directory, "stub.c")
	if err := os.WriteFile(source, []byte(stubSource), 0o644); err != nil {
		t.Fatal(err)
	}
	stubLibrary := filepath.Join(directory, stubLibraryName)
	compile := exec.Command(compiler, "-shared", "-fPIC", "-o", stubLibrary, source)
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compiling stub: %v\n%s", err, output)
	}

	child := exec.Command(os.Args[0], "-test.run=TestStubDriven$", "-test.v")
	child.Env = append(os.Environ(), stubEnvironment+"="+stubLibrary)
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("stub-driven test failed: %v\n%s", err, output)
	}
	// A run pattern matching nothing also exits zero; require the pass line.
	if !bytes.Contains(output, []byte("--- PASS: TestStubDriven")) {
		t.Fatalf("stub-driven test did not run:\n%s", output)
	}
}

// TestStubDriven exercises every entry point against the stub library:
// dlopen/dlsym resolution, the C call helpers, argument passing, the
// versioned-struct header, and the layout of every struct crossing the C
// boundary (via the nonce echo, sizes, and fill patterns).
func TestStubDriven(t *testing.T) {
	stubLibrary := os.Getenv(stubEnvironment)
	if stubLibrary == "" {
		t.Skip("only run by TestStubLibrary against the stub library")
	}
	if _, result := loadPath(stubLibrary); result != SUCCESS {
		t.Fatalf("loadPath: %s", ErrorString(result))
	}

	if result := Init(); result != SUCCESS {
		t.Fatalf("Init: %s", ErrorString(result))
	}
	defer Shutdown()

	count, result := DeviceGetCount()
	if result != SUCCESS || count != 2 {
		t.Fatalf("DeviceGetCount: %d, %s", count, ErrorString(result))
	}

	device, result := DeviceGetHandleByIndex(1)
	if result != SUCCESS {
		t.Fatalf("DeviceGetHandleByIndex: %s", ErrorString(result))
	}

	name, result := DeviceGetName(device)
	if result != SUCCESS || name != "STUB-GPU-1" {
		t.Fatalf("DeviceGetName: %q, %s", name, ErrorString(result))
	}
	unterminatedDevice, result := DeviceGetHandleByIndex(0)
	if result != SUCCESS {
		t.Fatalf("DeviceGetHandleByIndex(0): %s", ErrorString(result))
	}
	unterminatedName, result := DeviceGetName(unterminatedDevice)
	if result != SUCCESS || unterminatedName != string(bytes.Repeat([]byte{'X'}, 96)) {
		t.Fatalf("unterminated DeviceGetName: %q, %s", unterminatedName, ErrorString(result))
	}

	architecture, result := device.GetArchitecture()
	if result != SUCCESS || architecture != DEVICE_ARCH_HOPPER {
		t.Fatalf("GetArchitecture: %d, %s", architecture, ErrorString(result))
	}

	memory, result := DeviceGetMemoryInfo_v2(device)
	if result != SUCCESS {
		t.Fatalf("DeviceGetMemoryInfo_v2: %s", ErrorString(result))
	}
	// The stub rejects a wrong versioned-struct header, so SUCCESS already
	// proves the header; the value check pins sizeof(nvmlMemory_v2_t) == 40.
	if memory.Version != 2<<24|40 {
		t.Fatalf("memory version: %#x", memory.Version)
	}
	if memory.Total != 4096 || memory.Reserved != 8 || memory.Free != 3064 || memory.Used != 1024 {
		t.Fatalf("memory values: %+v", memory)
	}

	utilization, result := DeviceGetUtilizationRates(device)
	if result != SUCCESS || utilization.Gpu != 37 || utilization.Memory != 11 {
		t.Fatalf("DeviceGetUtilizationRates: %+v, %s", utilization, ErrorString(result))
	}

	var report ConfComputeGpuAttestationReport
	for i := range report.Nonce {
		report.Nonce[i] = byte(i)
	}
	nonce := report.Nonce
	if result := device.GetConfComputeGpuAttestationReport(&report); result != SUCCESS {
		t.Fatalf("GetConfComputeGpuAttestationReport: %s", ErrorString(result))
	}
	if report.IsCecAttestationReportPresent != 1 {
		t.Fatalf("cec present: %d", report.IsCecAttestationReportPresent)
	}
	if report.AttestationReportSize != 64 || report.CecAttestationReportSize != 16 {
		t.Fatalf("report sizes: %d, %d",
			report.AttestationReportSize, report.CecAttestationReportSize)
	}
	if !bytes.Equal(report.AttestationReport[:32], nonce[:]) {
		t.Fatalf("nonce echo mismatch: %x", report.AttestationReport[:32])
	}
	if !bytes.Equal(report.AttestationReport[32:64], bytes.Repeat([]byte{0xA5}, 32)) {
		t.Fatalf("report body mismatch: %x", report.AttestationReport[32:64])
	}
	if !bytes.Equal(report.CecAttestationReport[:16], bytes.Repeat([]byte{0x5A}, 16)) {
		t.Fatalf("cec report mismatch: %x", report.CecAttestationReport[:16])
	}
	var oversizedReport ConfComputeGpuAttestationReport
	oversizedReport.Nonce[0] = 0xFF
	if result := device.GetConfComputeGpuAttestationReport(&oversizedReport); result != ERROR_INSUFFICIENT_SIZE {
		t.Fatalf("oversized report: %s", ErrorString(result))
	}

	certificate, result := device.GetConfComputeGpuCertificate()
	if result != SUCCESS {
		t.Fatalf("GetConfComputeGpuCertificate: %s", ErrorString(result))
	}
	if certificate.CertChainSize != 8 || certificate.AttestationCertChainSize != 12 {
		t.Fatalf("certificate sizes: %d, %d",
			certificate.CertChainSize, certificate.AttestationCertChainSize)
	}
	if !bytes.Equal(certificate.CertChain[:8], bytes.Repeat([]byte{0xC1}, 8)) {
		t.Fatalf("cert chain mismatch: %x", certificate.CertChain[:8])
	}
	if !bytes.Equal(certificate.AttestationCertChain[:12], bytes.Repeat([]byte{0xC2}, 12)) {
		t.Fatalf("attestation cert chain mismatch: %x", certificate.AttestationCertChain[:12])
	}
	oversizedDevice, result := DeviceGetHandleByIndex(2)
	if result != SUCCESS {
		t.Fatalf("DeviceGetHandleByIndex(2): %s", ErrorString(result))
	}
	if _, result := oversizedDevice.GetConfComputeGpuCertificate(); result != ERROR_INSUFFICIENT_SIZE {
		t.Fatalf("oversized certificate: %s", ErrorString(result))
	}

	if result := SystemSetConfComputeGpusReadyState(CC_ACCEPTING_CLIENT_REQUESTS_TRUE); result != SUCCESS {
		t.Fatalf("SystemSetConfComputeGpusReadyState(true): %s", ErrorString(result))
	}
	if result := SystemSetConfComputeGpusReadyState(CC_ACCEPTING_CLIENT_REQUESTS_FALSE); result != ERROR_INVALID_ARGUMENT {
		t.Fatalf("SystemSetConfComputeGpusReadyState(false): %s", ErrorString(result))
	}
	exerciseConcurrentCalls(t, true)
}
