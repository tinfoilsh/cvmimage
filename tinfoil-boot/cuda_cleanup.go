package main

/*
#cgo LDFLAGS: -ldl

#include <dlfcn.h>
#include <stdlib.h>

typedef int CUresult;
typedef int CUdevice;
typedef void* CUcontext;

#define CUDA_SUCCESS 0

typedef CUresult (*fn_cuInit)(unsigned int);
typedef CUresult (*fn_cuDeviceGetCount)(int *);
typedef CUresult (*fn_cuDeviceGet)(CUdevice *, int);
typedef CUresult (*fn_cuCtxCreate)(CUcontext *, unsigned int, CUdevice);
typedef CUresult (*fn_cuCtxDestroy)(CUcontext);
typedef CUresult (*fn_cuCtxSetCurrent)(CUcontext);
typedef CUresult (*fn_cuCtxSynchronize)(void);
typedef CUresult (*fn_cuCtxEnablePeerAccess)(CUcontext, unsigned int);
typedef CUresult (*fn_cuCtxDisablePeerAccess)(CUcontext);
typedef CUresult (*fn_cuDeviceCanAccessPeer)(int *, CUdevice, CUdevice);
typedef CUresult (*fn_cuDevicePrimaryCtxReset)(CUdevice);

static struct {
	void *lib;
	fn_cuInit                  cuInit;
	fn_cuDeviceGetCount        cuDeviceGetCount;
	fn_cuDeviceGet             cuDeviceGet;
	fn_cuCtxCreate             cuCtxCreate;
	fn_cuCtxDestroy            cuCtxDestroy;
	fn_cuCtxSetCurrent         cuCtxSetCurrent;
	fn_cuCtxSynchronize        cuCtxSynchronize;
	fn_cuCtxEnablePeerAccess   cuCtxEnablePeerAccess;
	fn_cuCtxDisablePeerAccess  cuCtxDisablePeerAccess;
	fn_cuDeviceCanAccessPeer   cuDeviceCanAccessPeer;
	fn_cuDevicePrimaryCtxReset cuDevicePrimaryCtxReset;
} cu;

static int cu_load(void) {
	cu.lib = dlopen("libcuda.so.1", RTLD_NOW);
	if (!cu.lib) return -1;

	cu.cuInit                  = (fn_cuInit)dlsym(cu.lib, "cuInit");
	cu.cuDeviceGetCount        = (fn_cuDeviceGetCount)dlsym(cu.lib, "cuDeviceGetCount");
	cu.cuDeviceGet             = (fn_cuDeviceGet)dlsym(cu.lib, "cuDeviceGet");
	cu.cuCtxCreate             = (fn_cuCtxCreate)dlsym(cu.lib, "cuCtxCreate_v2");
	cu.cuCtxDestroy            = (fn_cuCtxDestroy)dlsym(cu.lib, "cuCtxDestroy_v2");
	cu.cuCtxSetCurrent         = (fn_cuCtxSetCurrent)dlsym(cu.lib, "cuCtxSetCurrent");
	cu.cuCtxSynchronize        = (fn_cuCtxSynchronize)dlsym(cu.lib, "cuCtxSynchronize");
	cu.cuCtxEnablePeerAccess   = (fn_cuCtxEnablePeerAccess)dlsym(cu.lib, "cuCtxEnablePeerAccess");
	cu.cuCtxDisablePeerAccess  = (fn_cuCtxDisablePeerAccess)dlsym(cu.lib, "cuCtxDisablePeerAccess");
	cu.cuDeviceCanAccessPeer   = (fn_cuDeviceCanAccessPeer)dlsym(cu.lib, "cuDeviceCanAccessPeer");
	cu.cuDevicePrimaryCtxReset = (fn_cuDevicePrimaryCtxReset)dlsym(cu.lib, "cuDevicePrimaryCtxReset_v2");

	if (!cu.cuInit || !cu.cuDeviceGetCount || !cu.cuDeviceGet ||
	    !cu.cuCtxCreate || !cu.cuCtxDestroy || !cu.cuCtxSetCurrent ||
	    !cu.cuCtxSynchronize || !cu.cuCtxEnablePeerAccess ||
	    !cu.cuCtxDisablePeerAccess || !cu.cuDeviceCanAccessPeer ||
	    !cu.cuDevicePrimaryCtxReset) {
		dlclose(cu.lib);
		cu.lib = NULL;
		return -2;
	}
	return 0;
}

static void cu_unload(void) {
	if (cu.lib) {
		dlclose(cu.lib);
		cu.lib = NULL;
	}
}

static int cu_init(void)              { return cu.cuInit(0); }
static int cu_device_count(void)      { int n = 0; cu.cuDeviceGetCount(&n); return n; }
static int cu_device_get(int i)       { CUdevice d = 0; cu.cuDeviceGet(&d, i); return d; }

static CUcontext cu_ctx_create(CUdevice dev) {
	CUcontext ctx = NULL;
	cu.cuCtxCreate(&ctx, 0, dev);
	return ctx;
}

static int cu_ctx_destroy(CUcontext ctx)            { return cu.cuCtxDestroy(ctx); }
static int cu_ctx_set_current(CUcontext ctx)        { return cu.cuCtxSetCurrent(ctx); }
static int cu_ctx_synchronize(void)                 { return cu.cuCtxSynchronize(); }
static int cu_ctx_enable_peer(CUcontext peer)       { return cu.cuCtxEnablePeerAccess(peer, 0); }
static int cu_ctx_disable_peer(CUcontext peer)      { return cu.cuCtxDisablePeerAccess(peer); }
static int cu_primary_ctx_reset(CUdevice dev)       { return cu.cuDevicePrimaryCtxReset(dev); }

static int cu_can_access_peer(CUdevice from, CUdevice to) {
	int ok = 0;
	cu.cuDeviceCanAccessPeer(&ok, from, to);
	return ok;
}
*/
import "C"

import (
	"log"
	"time"
)

type gpuCtx struct {
	dev   C.CUdevice
	ctx   C.CUcontext
	valid bool
}

// drainNVLinkState opens CUDA contexts on every GPU, cycles peer access
// enable/disable to force a clean teardown of NVLink mappings, then resets
// all primary contexts. This should leave the NVSwitch fabric in a quiescent
// state before the nvidia modules are unloaded.
func drainNVLinkState() {
	log.Println("Draining NVLink state via CUDA driver API...")
	start := time.Now()

	if rc := C.cu_load(); rc != 0 {
		log.Printf("CUDA cleanup: libcuda.so.1 not available (rc=%d), skipping", rc)
		return
	}
	defer C.cu_unload()

	if rc := C.cu_init(); rc != C.CUDA_SUCCESS {
		log.Printf("CUDA cleanup: cuInit failed (rc=%d), skipping", rc)
		return
	}

	count := int(C.cu_device_count())
	if count == 0 {
		log.Println("CUDA cleanup: no devices found")
		return
	}
	log.Printf("CUDA cleanup: found %d devices", count)

	gpus := make([]gpuCtx, count)
	for i := 0; i < count; i++ {
		gpus[i].dev = C.CUdevice(C.cu_device_get(C.int(i)))
		gpus[i].ctx = C.cu_ctx_create(gpus[i].dev)
		gpus[i].valid = gpus[i].ctx != nil
		if !gpus[i].valid {
			log.Printf("CUDA cleanup: cuCtxCreate(%d) failed", i)
		}
	}

	enabled := 0
	for i := 0; i < count; i++ {
		if !gpus[i].valid {
			continue
		}
		C.cu_ctx_set_current(gpus[i].ctx)
		for j := 0; j < count; j++ {
			if i == j || !gpus[j].valid {
				continue
			}
			if C.cu_can_access_peer(gpus[i].dev, gpus[j].dev) != 0 {
				if C.cu_ctx_enable_peer(gpus[j].ctx) == C.CUDA_SUCCESS {
					enabled++
				}
			}
		}
	}
	log.Printf("CUDA cleanup: enabled %d peer access links", enabled)

	for i := 0; i < count; i++ {
		if !gpus[i].valid {
			continue
		}
		C.cu_ctx_set_current(gpus[i].ctx)
		C.cu_ctx_synchronize()
	}

	disabled := 0
	for i := 0; i < count; i++ {
		if !gpus[i].valid {
			continue
		}
		C.cu_ctx_set_current(gpus[i].ctx)
		for j := 0; j < count; j++ {
			if i == j || !gpus[j].valid {
				continue
			}
			if C.cu_ctx_disable_peer(gpus[j].ctx) == C.CUDA_SUCCESS {
				disabled++
			}
		}
	}
	log.Printf("CUDA cleanup: disabled %d peer access links", disabled)

	for i := 0; i < count; i++ {
		if !gpus[i].valid {
			continue
		}
		C.cu_ctx_set_current(gpus[i].ctx)
		C.cu_ctx_synchronize()
	}

	for i := 0; i < count; i++ {
		if gpus[i].valid {
			C.cu_ctx_destroy(gpus[i].ctx)
		}
		C.cu_primary_ctx_reset(gpus[i].dev)
	}

	log.Printf("NVLink drain complete in %v (enabled=%d, disabled=%d)",
		time.Since(start).Round(time.Millisecond), enabled, disabled)
}
