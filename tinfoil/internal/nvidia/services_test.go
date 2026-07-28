package nvidia

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tinfoil/internal/nvml"
)

type nvmlProbe struct {
	initResult     nvml.Return
	count          int
	countResult    nvml.Return
	shutdownResult nvml.Return
}

type fakeNVML struct {
	mu        sync.Mutex
	probes    []nvmlProbe
	current   nvmlProbe
	attempts  int
	shutdowns int
}

func (f *fakeNVML) Init() nvml.Return {
	f.mu.Lock()
	defer f.mu.Unlock()
	index := f.attempts
	if index >= len(f.probes) {
		index = len(f.probes) - 1
	}
	f.current = f.probes[index]
	f.attempts++
	return f.current.initResult
}

func (f *fakeNVML) DeviceGetCount() (int, nvml.Return) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current.count, f.current.countResult
}

func (f *fakeNVML) Shutdown() nvml.Return {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shutdowns++
	return f.current.shutdownResult
}

func testServices(t *testing.T, api nvmlAPI) *Services {
	t.Helper()
	root := t.TempDir()
	services := newServices(api)
	services.paths = servicePaths{
		persistencedRun:  filepath.Join(root, "run", "nvidia-persistenced"),
		persistencedPID:  filepath.Join(root, "run", "nvidia-persistenced", "nvidia-persistenced.pid"),
		persistencedSock: filepath.Join(root, "run", "nvidia-persistenced", "socket"),
		fabricRun:        filepath.Join(root, "run", "nvidia-fabricmanager"),
		fabricPID:        filepath.Join(root, "run", "nvidia-fabricmanager", "nv-fabricmanager.pid"),
		fabricSock:       filepath.Join(root, "run", "nvidia-fabricmanager", "socket"),
		cdiSpec:          filepath.Join(root, "run", "cdi", "nvidia.yaml"),
	}
	services.persistUID = os.Getuid()
	services.persistGID = os.Getgid()
	services.readyWait = 100 * time.Millisecond
	services.pollInterval = time.Millisecond
	return services
}

func writeServiceFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func listenUnix(t *testing.T, path string) net.Listener {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func TestNewServicesUsesMeasuredPersistencedIdentity(t *testing.T) {
	services := NewServices()
	if services.persistUID != 143 || services.persistGID != 143 {
		t.Fatalf("persistenced identity = %d:%d, want 143:143", services.persistUID, services.persistGID)
	}
	if services.nvml == nil {
		t.Fatal("NewServices did not configure NVML")
	}
}

func TestPreparePersistencedRuntime(t *testing.T) {
	services := testServices(t, nil)
	if err := os.MkdirAll(services.paths.persistencedRun, 0700); err != nil {
		t.Fatal(err)
	}
	writeServiceFile(t, services.paths.persistencedPID, "stale\n")
	listenUnix(t, services.paths.persistencedSock)

	if err := services.PreparePersistencedRuntime(); err != nil {
		t.Fatalf("PreparePersistencedRuntime: %v", err)
	}
	info, err := os.Stat(services.paths.persistencedRun)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("runtime mode = %#o, want 0755", info.Mode().Perm())
	}
	for _, path := range []string{services.paths.persistencedPID, services.paths.persistencedSock} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale path %s remains: %v", path, err)
		}
	}
}

func TestPreparePersistencedRuntimeRejectsUnexpectedStaleType(t *testing.T) {
	services := testServices(t, nil)
	if err := os.MkdirAll(services.paths.persistencedPID, 0755); err != nil {
		t.Fatal(err)
	}
	if err := services.PreparePersistencedRuntime(); err == nil {
		t.Fatal("PreparePersistencedRuntime accepted directory PID path")
	}
	if info, err := os.Stat(services.paths.persistencedPID); err != nil || !info.IsDir() {
		t.Fatalf("unexpected PID path changed: %v, %v", info, err)
	}
}

func TestPrepareFabricManagerRuntimeCreatesDirectory(t *testing.T) {
	services := testServices(t, nil)

	if err := services.PrepareFabricManagerRuntime(); err != nil {
		t.Fatalf("PrepareFabricManagerRuntime: %v", err)
	}
	info, err := os.Stat(services.paths.fabricRun)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0755 {
		t.Fatalf("runtime mode = %v, want directory 0755", info.Mode())
	}
}

func TestPrepareFabricManagerRuntimeRemovesStaleState(t *testing.T) {
	services := testServices(t, nil)
	if err := os.MkdirAll(services.paths.fabricRun, 0700); err != nil {
		t.Fatal(err)
	}
	writeServiceFile(t, services.paths.fabricPID, "stale\n")
	listenUnix(t, services.paths.fabricSock)

	if err := services.PrepareFabricManagerRuntime(); err != nil {
		t.Fatalf("PrepareFabricManagerRuntime: %v", err)
	}
	info, err := os.Stat(services.paths.fabricRun)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("runtime mode = %#o, want 0755", info.Mode().Perm())
	}
	for _, path := range []string{services.paths.fabricPID, services.paths.fabricSock} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale path %s remains: %v", path, err)
		}
	}
}

func TestPrepareFabricManagerRuntimeRejectsUnexpectedTypes(t *testing.T) {
	t.Run("PID directory", func(t *testing.T) {
		services := testServices(t, nil)
		if err := os.MkdirAll(services.paths.fabricPID, 0755); err != nil {
			t.Fatal(err)
		}
		if err := services.PrepareFabricManagerRuntime(); err == nil {
			t.Fatal("PrepareFabricManagerRuntime accepted directory PID path")
		}
		if info, err := os.Lstat(services.paths.fabricPID); err != nil || !info.IsDir() {
			t.Fatalf("unexpected PID path changed: %v, %v", info, err)
		}
	})

	t.Run("socket symlink", func(t *testing.T) {
		services := testServices(t, nil)
		target := filepath.Join(filepath.Dir(services.paths.fabricRun), "socket-target")
		writeServiceFile(t, target, "preserve\n")
		if err := os.MkdirAll(services.paths.fabricRun, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, services.paths.fabricSock); err != nil {
			t.Fatal(err)
		}
		if err := services.PrepareFabricManagerRuntime(); err == nil {
			t.Fatal("PrepareFabricManagerRuntime accepted socket symlink")
		}
		contents, err := os.ReadFile(target)
		if err != nil || string(contents) != "preserve\n" {
			t.Fatalf("symlink target changed to %q: %v", contents, err)
		}
		if info, err := os.Lstat(services.paths.fabricSock); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("socket symlink changed: %v, %v", info, err)
		}
	})

	t.Run("runtime symlink", func(t *testing.T) {
		services := testServices(t, nil)
		target := filepath.Join(filepath.Dir(services.paths.fabricRun), "fabric-target")
		if err := os.MkdirAll(target, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, services.paths.fabricRun); err != nil {
			t.Fatal(err)
		}
		if err := services.PrepareFabricManagerRuntime(); err == nil {
			t.Fatal("PrepareFabricManagerRuntime accepted runtime symlink")
		}
		if info, err := os.Lstat(services.paths.fabricRun); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("runtime symlink changed: %v, %v", info, err)
		}
	})
}

func TestWaitForPersistencedRequiresUnixSocket(t *testing.T) {
	services := testServices(t, nil)
	writeServiceFile(t, services.paths.persistencedPID, strconv.Itoa(os.Getpid())+"\n")
	writeServiceFile(t, services.paths.persistencedSock, "not a socket")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := services.WaitForPersistenced(ctx); err == nil {
		t.Fatal("WaitForPersistenced accepted regular file")
	}
	if err := os.Remove(services.paths.persistencedSock); err != nil {
		t.Fatal(err)
	}
	listenUnix(t, services.paths.persistencedSock)
	if err := services.WaitForPersistenced(context.Background()); err != nil {
		t.Fatalf("WaitForPersistenced: %v", err)
	}
}

func TestWaitForFabricManagerRequiresPIDAndSocket(t *testing.T) {
	services := testServices(t, nil)
	writeServiceFile(t, services.paths.fabricPID, "")
	listenUnix(t, services.paths.fabricSock)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := services.WaitForFabricManager(ctx); err == nil {
		t.Fatal("WaitForFabricManager accepted empty PID file")
	}

	writeServiceFile(t, services.paths.fabricPID, strconv.Itoa(os.Getpid())+"\n")
	if err := services.WaitForFabricManager(context.Background()); err != nil {
		t.Fatalf("WaitForFabricManager: %v", err)
	}
}

func TestWaitForFabricManagerRejectsPIDLinksAndOversize(t *testing.T) {
	services := testServices(t, nil)
	writeServiceFile(t, services.paths.fabricPID+".target", strconv.Itoa(os.Getpid())+"\n")
	if err := os.Symlink(services.paths.fabricPID+".target", services.paths.fabricPID); err != nil {
		t.Fatal(err)
	}
	listenUnix(t, services.paths.fabricSock)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := services.WaitForFabricManager(ctx); err == nil {
		t.Fatal("WaitForFabricManager followed PID symlink")
	}
	if err := os.Remove(services.paths.fabricPID); err != nil {
		t.Fatal(err)
	}
	writeServiceFile(t, services.paths.fabricPID, strings.Repeat("1", maxPIDFileSize+1))
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := services.WaitForFabricManager(ctx); err == nil {
		t.Fatal("WaitForFabricManager accepted oversized PID file")
	}
}

func TestWaitForNVMLPollsExactCountAndShutsDown(t *testing.T) {
	api := &fakeNVML{probes: []nvmlProbe{
		{initResult: nvml.ERROR_UNINITIALIZED},
		{initResult: nvml.SUCCESS, count: 7, countResult: nvml.SUCCESS, shutdownResult: nvml.SUCCESS},
		{initResult: nvml.SUCCESS, count: 8, countResult: nvml.SUCCESS, shutdownResult: nvml.SUCCESS},
	}}
	services := testServices(t, api)
	if err := services.WaitForNVML(context.Background(), 8); err != nil {
		t.Fatalf("WaitForNVML: %v", err)
	}
	if api.attempts != 3 || api.shutdowns != 2 {
		t.Fatalf("NVML attempts/shutdowns = %d/%d, want 3/2", api.attempts, api.shutdowns)
	}
}

func TestWaitForNVMLShutsDownAfterCountFailure(t *testing.T) {
	api := &fakeNVML{probes: []nvmlProbe{
		{initResult: nvml.SUCCESS, countResult: nvml.ERROR_UNKNOWN, shutdownResult: nvml.SUCCESS},
		{initResult: nvml.SUCCESS, count: 1, countResult: nvml.SUCCESS, shutdownResult: nvml.SUCCESS},
	}}
	services := testServices(t, api)
	if err := services.WaitForNVML(context.Background(), 1); err != nil {
		t.Fatalf("WaitForNVML: %v", err)
	}
	if api.shutdowns != 2 {
		t.Fatalf("Shutdown calls = %d, want 2", api.shutdowns)
	}
}

func TestWaitForNVMLRejectsInvalidExpectedCount(t *testing.T) {
	services := testServices(t, nil)
	for _, count := range []int{-1, 0} {
		if err := services.WaitForNVML(context.Background(), count); err == nil {
			t.Fatalf("WaitForNVML accepted invalid expected count %d", count)
		}
	}
}

func TestCreateAndPublishCDIAtomically(t *testing.T) {
	services := testServices(t, nil)
	writeServiceFile(t, services.paths.cdiSpec, "old\n")
	temporary, err := services.CreateCDITemporary()
	if err != nil {
		t.Fatalf("CreateCDITemporary: %v", err)
	}
	if filepath.Dir(temporary) != filepath.Dir(services.paths.cdiSpec) {
		t.Fatalf("temporary directory = %s", filepath.Dir(temporary))
	}
	if filepath.Ext(temporary) != ".yaml" || filepath.Base(temporary)[0] != '.' || temporary == services.paths.cdiSpec {
		t.Fatalf("temporary path = %s, want hidden distinct YAML file", temporary)
	}
	if err := os.WriteFile(temporary, []byte("new\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := services.PublishCDI(temporary); err != nil {
		t.Fatalf("PublishCDI: %v", err)
	}
	contents, err := os.ReadFile(services.paths.cdiSpec)
	if err != nil || string(contents) != "new\n" {
		t.Fatalf("published CDI = %q, %v", contents, err)
	}
	if _, err := os.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary still exists: %v", err)
	}
}

func TestPublishCDIPreservesOldFileOnValidationFailure(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *Services) string
	}{
		{
			name: "empty",
			setup: func(t *testing.T, services *Services) string {
				path, err := services.CreateCDITemporary()
				if err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
		{
			name: "different directory",
			setup: func(t *testing.T, _ *Services) string {
				path := filepath.Join(t.TempDir(), "nvidia.yaml")
				writeServiceFile(t, path, "new\n")
				return path
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, services *Services) string {
				target := filepath.Join(filepath.Dir(services.paths.cdiSpec), "target")
				writeServiceFile(t, target, "new\n")
				path := filepath.Join(filepath.Dir(services.paths.cdiSpec), ".nvidia.yaml.link")
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
				return path
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			services := testServices(t, nil)
			writeServiceFile(t, services.paths.cdiSpec, "old\n")
			temporary := test.setup(t, services)
			if err := services.PublishCDI(temporary); err == nil {
				t.Fatal("PublishCDI accepted invalid temporary file")
			}
			contents, err := os.ReadFile(services.paths.cdiSpec)
			if err != nil || string(contents) != "old\n" {
				t.Fatalf("old CDI changed to %q: %v", contents, err)
			}
		})
	}
}
