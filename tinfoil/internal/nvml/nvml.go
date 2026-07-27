// Package nvml is a minimal NVML binding covering exactly the calls this
// repository makes. The measured NVIDIA library is opened with dlopen and
// every entry point is resolved with dlsym at Init, so the runtime binaries
// carry no undefined NVML symbols and link with full RELRO (BIND_NOW). On
// CPU-only guests Init fails closed with ERROR_LIBRARY_NOT_FOUND instead of
// the process failing at exec.
//
// The ABI below is transcribed from the NVML header shipped with go-nvml
// v0.13.0-1, matching the pinned 595-series driver.
package nvml

/*
#include <dlfcn.h>
#include <stdlib.h>

typedef int nvmlReturn_t;
typedef struct nvmlDevice_st* nvmlDevice_t;

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

#define NVML_STRUCT_VERSION(data, ver) \
	(unsigned int)(sizeof(nvml ## data ## _v ## ver ## _t) | (ver << 24U))
#define nvmlMemory_v2 NVML_STRUCT_VERSION(Memory, 2)

#define NVML_GPU_CERT_CHAIN_SIZE 0x1000
#define NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE 0x1400
#define NVML_CC_GPU_CEC_NONCE_SIZE 0x20
#define NVML_CC_GPU_ATTESTATION_REPORT_SIZE 0x2000
#define NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE 0x1000

typedef struct nvmlConfComputeGpuCertificate_st {
	unsigned int certChainSize;
	unsigned int attestationCertChainSize;
	unsigned char certChain[NVML_GPU_CERT_CHAIN_SIZE];
	unsigned char attestationCertChain[NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE];
} nvmlConfComputeGpuCertificate_t;

typedef struct nvmlConfComputeGpuAttestationReport_st {
	unsigned int isCecAttestationReportPresent;
	unsigned int attestationReportSize;
	unsigned int cecAttestationReportSize;
	unsigned char nonce[NVML_CC_GPU_CEC_NONCE_SIZE];
	unsigned char attestationReport[NVML_CC_GPU_ATTESTATION_REPORT_SIZE];
	unsigned char cecAttestationReport[NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE];
} nvmlConfComputeGpuAttestationReport_t;

// cgo cannot call C function pointers, so each resolved entry point is
// invoked through a static helper of the exact prototype.
static nvmlReturn_t tinfoilNvmlCall(void *fn) {
	return ((nvmlReturn_t (*)(void))fn)();
}
static nvmlReturn_t tinfoilNvmlGetUint(void *fn, unsigned int *value) {
	return ((nvmlReturn_t (*)(unsigned int *))fn)(value);
}
static nvmlReturn_t tinfoilNvmlSetUint(void *fn, unsigned int value) {
	return ((nvmlReturn_t (*)(unsigned int))fn)(value);
}
static nvmlReturn_t tinfoilNvmlDeviceByIndex(void *fn, unsigned int index, nvmlDevice_t *device) {
	return ((nvmlReturn_t (*)(unsigned int, nvmlDevice_t *))fn)(index, device);
}
static nvmlReturn_t tinfoilNvmlDeviceGetUint(void *fn, nvmlDevice_t device, unsigned int *value) {
	return ((nvmlReturn_t (*)(nvmlDevice_t, unsigned int *))fn)(device, value);
}
static nvmlReturn_t tinfoilNvmlDeviceGetName(void *fn, nvmlDevice_t device, char *name, unsigned int length) {
	return ((nvmlReturn_t (*)(nvmlDevice_t, char *, unsigned int))fn)(device, name, length);
}
static nvmlReturn_t tinfoilNvmlDeviceGetMemory(void *fn, nvmlDevice_t device, nvmlMemory_v2_t *memory) {
	memory->version = nvmlMemory_v2;
	return ((nvmlReturn_t (*)(nvmlDevice_t, nvmlMemory_v2_t *))fn)(device, memory);
}
static nvmlReturn_t tinfoilNvmlDeviceGetUtilization(void *fn, nvmlDevice_t device, nvmlUtilization_t *utilization) {
	return ((nvmlReturn_t (*)(nvmlDevice_t, nvmlUtilization_t *))fn)(device, utilization);
}
static nvmlReturn_t tinfoilNvmlDeviceGetReport(void *fn, nvmlDevice_t device, nvmlConfComputeGpuAttestationReport_t *report) {
	return ((nvmlReturn_t (*)(nvmlDevice_t, nvmlConfComputeGpuAttestationReport_t *))fn)(device, report);
}
static nvmlReturn_t tinfoilNvmlDeviceGetCertificate(void *fn, nvmlDevice_t device, nvmlConfComputeGpuCertificate_t *certificate) {
	return ((nvmlReturn_t (*)(nvmlDevice_t, nvmlConfComputeGpuCertificate_t *))fn)(device, certificate);
}
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// Return mirrors nvmlReturn_t.
type Return int32

const (
	SUCCESS                         Return = 0
	ERROR_UNINITIALIZED             Return = 1
	ERROR_INVALID_ARGUMENT          Return = 2
	ERROR_NOT_SUPPORTED             Return = 3
	ERROR_NO_PERMISSION             Return = 4
	ERROR_NOT_FOUND                 Return = 6
	ERROR_INSUFFICIENT_SIZE         Return = 7
	ERROR_DRIVER_NOT_LOADED         Return = 9
	ERROR_TIMEOUT                   Return = 10
	ERROR_LIBRARY_NOT_FOUND         Return = 12
	ERROR_FUNCTION_NOT_FOUND        Return = 13
	ERROR_GPU_IS_LOST               Return = 15
	ERROR_RESET_REQUIRED            Return = 16
	ERROR_OPERATING_SYSTEM          Return = 17
	ERROR_LIB_RM_VERSION_MISMATCH   Return = 18
	ERROR_IN_USE                    Return = 19
	ERROR_MEMORY                    Return = 20
	ERROR_NO_DATA                   Return = 21
	ERROR_INSUFFICIENT_RESOURCES    Return = 23
	ERROR_ARGUMENT_VERSION_MISMATCH Return = 25
	ERROR_NOT_READY                 Return = 27
	ERROR_GPU_NOT_FOUND             Return = 28
	ERROR_INVALID_STATE             Return = 29
	ERROR_UNKNOWN                   Return = 999
)

var returnStrings = map[Return]string{
	SUCCESS:                         "the operation was successful",
	ERROR_UNINITIALIZED:             "NVML was not first initialized with nvmlInit()",
	ERROR_INVALID_ARGUMENT:          "a supplied argument is invalid",
	ERROR_NOT_SUPPORTED:             "the requested operation is not available on target device",
	ERROR_NO_PERMISSION:             "the current user does not have permission for operation",
	ERROR_NOT_FOUND:                 "a query to find an object was unsuccessful",
	ERROR_INSUFFICIENT_SIZE:         "an input argument is not large enough",
	ERROR_DRIVER_NOT_LOADED:         "the NVIDIA driver is not loaded",
	ERROR_TIMEOUT:                   "user provided timeout passed",
	ERROR_LIBRARY_NOT_FOUND:         "the NVML shared library could not be found or loaded",
	ERROR_FUNCTION_NOT_FOUND:        "local version of NVML does not implement this function",
	ERROR_GPU_IS_LOST:               "the GPU has fallen off the bus or has otherwise become inaccessible",
	ERROR_RESET_REQUIRED:            "the GPU requires a reset before it can be used again",
	ERROR_OPERATING_SYSTEM:          "the GPU control device has been blocked by the operating system",
	ERROR_LIB_RM_VERSION_MISMATCH:   "RM detects a driver/library version mismatch",
	ERROR_IN_USE:                    "the GPU is currently in use",
	ERROR_MEMORY:                    "insufficient memory",
	ERROR_NO_DATA:                   "no data",
	ERROR_INSUFFICIENT_RESOURCES:    "ran out of critical resources, other than memory",
	ERROR_ARGUMENT_VERSION_MISMATCH: "the provided version is invalid or unsupported",
	ERROR_NOT_READY:                 "the system is not ready for the request",
	ERROR_GPU_NOT_FOUND:             "no GPUs were found",
	ERROR_INVALID_STATE:             "resource not in correct state to perform requested operation",
	ERROR_UNKNOWN:                   "an internal driver error occurred",
}

// ErrorString describes a Return without calling into the driver, so it is
// usable when the library itself failed to load.
func ErrorString(result Return) string {
	if message, ok := returnStrings[result]; ok {
		return message
	}
	return fmt.Sprintf("unknown NVML return code %d", int32(result))
}

// DeviceArchitecture mirrors nvmlDeviceArchitecture_t.
type DeviceArchitecture uint32

const (
	DEVICE_ARCH_HOPPER    DeviceArchitecture = 9
	DEVICE_ARCH_BLACKWELL DeviceArchitecture = 10
)

const (
	CC_ACCEPTING_CLIENT_REQUESTS_FALSE = 0
	CC_ACCEPTING_CLIENT_REQUESTS_TRUE  = 1
)

// Device is an opaque NVML device handle.
type Device struct {
	handle C.nvmlDevice_t
}

// Utilization mirrors nvmlUtilization_t.
type Utilization struct {
	Gpu    uint32
	Memory uint32
}

// Memory_v2 mirrors nvmlMemory_v2_t.
type Memory_v2 struct {
	Version  uint32
	Total    uint64
	Reserved uint64
	Free     uint64
	Used     uint64
}

// ConfComputeGpuAttestationReport mirrors nvmlConfComputeGpuAttestationReport_t.
// Nonce is the caller-supplied input; the remaining fields are outputs.
type ConfComputeGpuAttestationReport struct {
	IsCecAttestationReportPresent uint32
	AttestationReportSize         uint32
	CecAttestationReportSize      uint32
	Nonce                         [32]byte
	AttestationReport             [8192]byte
	CecAttestationReport          [4096]byte
}

// ConfComputeGpuCertificate mirrors nvmlConfComputeGpuCertificate_t.
type ConfComputeGpuCertificate struct {
	CertChainSize            uint32
	AttestationCertChainSize uint32
	CertChain                [4096]byte
	AttestationCertChain     [5120]byte
}

const libraryName = "libnvidia-ml.so.1"

// entryPoints holds every resolved NVML entry point. A value is only ever
// published complete and is never mutated afterwards, so callers work from
// an immutable snapshot.
type entryPoints struct {
	init                                     unsafe.Pointer
	shutdown                                 unsafe.Pointer
	deviceGetCount                           unsafe.Pointer
	deviceGetHandleByIndex                   unsafe.Pointer
	deviceGetArchitecture                    unsafe.Pointer
	deviceGetName                            unsafe.Pointer
	deviceGetMemoryInfo                      unsafe.Pointer
	deviceGetUtilizationRates                unsafe.Pointer
	deviceGetConfComputeGpuAttestationReport unsafe.Pointer
	deviceGetConfComputeGpuCertificate       unsafe.Pointer
	systemSetConfComputeGpusReadyState       unsafe.Pointer
}

// library publishes the resolved entry points under one mutex. Loading is
// retryable because Init is polled while the driver comes up; a failed
// attempt publishes nothing. NVML itself reference-counts Init/Shutdown.
var library struct {
	sync.Mutex
	resolved *entryPoints
}

// load resolves the library and every entry point, publishing the snapshot
// on first success and returning the cached snapshot afterwards.
func load() (*entryPoints, Return) {
	library.Lock()
	defer library.Unlock()
	if library.resolved != nil {
		return library.resolved, SUCCESS
	}

	name := C.CString(libraryName)
	defer C.free(unsafe.Pointer(name))
	handle := C.dlopen(name, C.RTLD_NOW|C.RTLD_LOCAL)
	if handle == nil {
		return nil, ERROR_LIBRARY_NOT_FOUND
	}

	resolved := &entryPoints{}
	symbols := []struct {
		name   string
		target *unsafe.Pointer
	}{
		{"nvmlInit_v2", &resolved.init},
		{"nvmlShutdown", &resolved.shutdown},
		{"nvmlDeviceGetCount_v2", &resolved.deviceGetCount},
		{"nvmlDeviceGetHandleByIndex_v2", &resolved.deviceGetHandleByIndex},
		{"nvmlDeviceGetArchitecture", &resolved.deviceGetArchitecture},
		{"nvmlDeviceGetName", &resolved.deviceGetName},
		{"nvmlDeviceGetMemoryInfo_v2", &resolved.deviceGetMemoryInfo},
		{"nvmlDeviceGetUtilizationRates", &resolved.deviceGetUtilizationRates},
		{"nvmlDeviceGetConfComputeGpuAttestationReport", &resolved.deviceGetConfComputeGpuAttestationReport},
		{"nvmlDeviceGetConfComputeGpuCertificate", &resolved.deviceGetConfComputeGpuCertificate},
		{"nvmlSystemSetConfComputeGpusReadyState", &resolved.systemSetConfComputeGpusReadyState},
	}
	for _, symbol := range symbols {
		name := C.CString(symbol.name)
		address := C.dlsym(handle, name)
		C.free(unsafe.Pointer(name))
		if address == nil {
			C.dlclose(handle)
			return nil, ERROR_FUNCTION_NOT_FOUND
		}
		*symbol.target = address
	}
	library.resolved = resolved
	return resolved, SUCCESS
}

// current returns the published snapshot without attempting to load.
func current() (*entryPoints, Return) {
	library.Lock()
	defer library.Unlock()
	if library.resolved == nil {
		return nil, ERROR_UNINITIALIZED
	}
	return library.resolved, SUCCESS
}

// Init loads the measured NVML library and initializes it.
func Init() Return {
	entry, result := load()
	if result != SUCCESS {
		return result
	}
	return Return(C.tinfoilNvmlCall(entry.init))
}

// Shutdown releases one NVML initialization reference.
func Shutdown() Return {
	entry, result := current()
	if result != SUCCESS {
		return result
	}
	return Return(C.tinfoilNvmlCall(entry.shutdown))
}

// DeviceGetCount reports the number of NVML-visible GPUs.
func DeviceGetCount() (int, Return) {
	entry, result := current()
	if result != SUCCESS {
		return 0, result
	}
	var count C.uint
	result = Return(C.tinfoilNvmlGetUint(entry.deviceGetCount, &count))
	return int(count), result
}

// DeviceGetHandleByIndex resolves one GPU handle.
func DeviceGetHandleByIndex(index int) (Device, Return) {
	entry, result := current()
	if result != SUCCESS {
		return Device{}, result
	}
	var device Device
	result = Return(C.tinfoilNvmlDeviceByIndex(
		entry.deviceGetHandleByIndex, C.uint(index), &device.handle))
	return device, result
}

// DeviceGetName reports the product name of a GPU.
func DeviceGetName(device Device) (string, Return) {
	entry, result := current()
	if result != SUCCESS {
		return "", result
	}
	var name [96]C.char
	result = Return(C.tinfoilNvmlDeviceGetName(
		entry.deviceGetName, device.handle, &name[0], C.uint(len(name))))
	if result != SUCCESS {
		return "", result
	}
	return C.GoString(&name[0]), result
}

// DeviceGetMemoryInfo_v2 reports versioned device memory information.
func DeviceGetMemoryInfo_v2(device Device) (Memory_v2, Return) {
	entry, result := current()
	if result != SUCCESS {
		return Memory_v2{}, result
	}
	var memory C.nvmlMemory_v2_t
	result = Return(C.tinfoilNvmlDeviceGetMemory(
		entry.deviceGetMemoryInfo, device.handle, &memory))
	return Memory_v2{
		Version:  uint32(memory.version),
		Total:    uint64(memory.total),
		Reserved: uint64(memory.reserved),
		Free:     uint64(memory.free),
		Used:     uint64(memory.used),
	}, result
}

// DeviceGetUtilizationRates reports GPU and memory utilization.
func DeviceGetUtilizationRates(device Device) (Utilization, Return) {
	entry, result := current()
	if result != SUCCESS {
		return Utilization{}, result
	}
	var utilization C.nvmlUtilization_t
	result = Return(C.tinfoilNvmlDeviceGetUtilization(
		entry.deviceGetUtilizationRates, device.handle, &utilization))
	return Utilization{
		Gpu:    uint32(utilization.gpu),
		Memory: uint32(utilization.memory),
	}, result
}

// SystemSetConfComputeGpusReadyState marks the GPUs ready (or not) for
// confidential-compute client work.
func SystemSetConfComputeGpusReadyState(state uint32) Return {
	entry, result := current()
	if result != SUCCESS {
		return result
	}
	return Return(C.tinfoilNvmlSetUint(
		entry.systemSetConfComputeGpusReadyState, C.uint(state)))
}

// GetArchitecture reports the device architecture.
func (device Device) GetArchitecture() (DeviceArchitecture, Return) {
	entry, result := current()
	if result != SUCCESS {
		return 0, result
	}
	var architecture C.uint
	result = Return(C.tinfoilNvmlDeviceGetUint(
		entry.deviceGetArchitecture, device.handle, &architecture))
	return DeviceArchitecture(architecture), result
}

// GetConfComputeGpuAttestationReport fills report with a hardware-signed
// attestation report over report.Nonce.
func (device Device) GetConfComputeGpuAttestationReport(report *ConfComputeGpuAttestationReport) Return {
	entry, result := current()
	if result != SUCCESS {
		return result
	}
	var native C.nvmlConfComputeGpuAttestationReport_t
	for i, value := range report.Nonce {
		native.nonce[i] = C.uchar(value)
	}
	result = Return(C.tinfoilNvmlDeviceGetReport(
		entry.deviceGetConfComputeGpuAttestationReport, device.handle, &native))
	if result != SUCCESS {
		return result
	}
	report.IsCecAttestationReportPresent = uint32(native.isCecAttestationReportPresent)
	report.AttestationReportSize = uint32(native.attestationReportSize)
	report.CecAttestationReportSize = uint32(native.cecAttestationReportSize)
	report.AttestationReport = *(*[8192]byte)(unsafe.Pointer(&native.attestationReport))
	report.CecAttestationReport = *(*[4096]byte)(unsafe.Pointer(&native.cecAttestationReport))
	return result
}

// GetConfComputeGpuCertificate reports the GPU certificate chains.
func (device Device) GetConfComputeGpuCertificate() (ConfComputeGpuCertificate, Return) {
	entry, result := current()
	if result != SUCCESS {
		return ConfComputeGpuCertificate{}, result
	}
	var native C.nvmlConfComputeGpuCertificate_t
	result = Return(C.tinfoilNvmlDeviceGetCertificate(
		entry.deviceGetConfComputeGpuCertificate, device.handle, &native))
	if result != SUCCESS {
		return ConfComputeGpuCertificate{}, result
	}
	return ConfComputeGpuCertificate{
		CertChainSize:            uint32(native.certChainSize),
		AttestationCertChainSize: uint32(native.attestationCertChainSize),
		CertChain:                *(*[4096]byte)(unsafe.Pointer(&native.certChain)),
		AttestationCertChain:     *(*[5120]byte)(unsafe.Pointer(&native.attestationCertChain)),
	}, result
}

// Library exposes the package entry points as methods for callers that
// depend on a fake-able interface.
type Library struct{}

// New returns the production NVML library binding.
func New() Library {
	return Library{}
}

// Init implements the readiness-probe interface.
func (Library) Init() Return { return Init() }

// DeviceGetCount implements the readiness-probe interface.
func (Library) DeviceGetCount() (int, Return) { return DeviceGetCount() }

// Shutdown implements the readiness-probe interface.
func (Library) Shutdown() Return { return Shutdown() }
