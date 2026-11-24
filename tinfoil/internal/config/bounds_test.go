package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// nested returns a JSON object whose one member holds arrays nested to depth,
// counting the object itself.
func nested(depth int) []byte {
	return []byte(`{"value":` + strings.Repeat("[", depth-1) + strings.Repeat("]", depth-1) + "}")
}

// counted returns a JSON object of exactly values values: itself, one member
// name, the array under it and the array's numbers.
func counted(values int) []byte {
	return []byte(`{"value":[` + strings.TrimSuffix(strings.Repeat("0,", values-3), ",") + "]}")
}

func TestJSONStructureLimits(t *testing.T) {
	for name, test := range map[string]struct {
		data     []byte
		accepted bool
	}{
		"largest size":           {append([]byte(`{"value":"`), append(bytes.Repeat([]byte("x"), maxConfigFileBytes-len(`{"value":""}`)), `"}`...)...), true},
		"oversized":              {append([]byte(`{"value":"`), append(bytes.Repeat([]byte("x"), maxConfigFileBytes-len(`{"value":""}`)+1), `"}`...)...), false},
		"deepest nesting":        {nested(maxJSONDepth), true},
		"too deep":               {nested(maxJSONDepth + 1), false},
		"most values":            {counted(maxJSONValues), true},
		"too many values":        {counted(maxJSONValues + 1), false},
		"text full of structure": {[]byte(`{"value":"` + strings.Repeat("[{,:}]", maxJSONValues) + `"}`), true},
		"not an object":          {[]byte(`["value"]`), false},
		"unterminated":           {[]byte(`{"value":[`), false},
		"not JSON":               {[]byte("value: [x]\n"), false},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateJSONStructure(test.data)
			if test.accepted && err != nil {
				t.Fatalf("validateJSONStructure rejected %s: %v", name, err)
			}
			if !test.accepted && err == nil {
				t.Fatalf("validateJSONStructure accepted %s", name)
			}
		})
	}
}

// Both documents the package reads are held to the structure limits before
// they are decoded.
func TestDecodersEnforceStructureLimits(t *testing.T) {
	tooDeep := `{"operator":` + string(nested(maxJSONDepth)) + "}"
	tooMany := `{"operator":` + string(counted(maxJSONValues)) + "}"
	oversized := `{"operator":"` + strings.Repeat("x", maxConfigFileBytes) + `"}`
	for name, data := range map[string]string{"too deep": tooDeep, "too many values": tooMany, "oversized": oversized} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeExternal([]byte(data)); err == nil {
				t.Fatalf("DecodeExternal accepted %s input", name)
			}
			settings := `{"upstream-port":8080,` + data[1:]
			if _, err := Decode([]byte(settings)); err == nil || strings.Contains(err.Error(), "unknown") {
				t.Fatalf("Decode did not hold %s input to the structure limits: %v", name, err)
			}
		})
	}
	if _, err := DecodeExternal([]byte(`{"operator":` + string(nested(maxJSONDepth-1)) + "}")); err != nil {
		t.Fatalf("DecodeExternal rejected operator data within the limits: %v", err)
	}
}

func TestSameConfigFileVersionIncludesChangeTime(t *testing.T) {
	initial := unix.Stat_t{
		Size: 4,
		Mtim: unix.Timespec{Sec: 10, Nsec: 20},
		Ctim: unix.Timespec{Sec: 30, Nsec: 40},
	}
	final := initial
	if !sameConfigFileVersion(&initial, &final) {
		t.Fatal("sameConfigFileVersion rejected identical metadata")
	}
	final.Ctim.Nsec++
	if sameConfigFileVersion(&initial, &final) {
		t.Fatal("sameConfigFileVersion ignored a change-time update")
	}
}

func TestDecodeExternalRejectsUnsafeMapsAndValues(t *testing.T) {
	tooMany := make(map[string]string, maxExternalEntries+1)
	for index := range maxExternalEntries + 1 {
		tooMany["KEY_"+string(rune(index+1))] = "value"
	}
	for name, config := range map[string]ExternalConfig{
		"env count":    {Env: tooMany},
		"env key":      {Env: map[string]string{"BAD-KEY": "value"}},
		"secret value": {Secrets: map[string]string{"KEY": strings.Repeat("x", maxExternalValueBytes+1)}},
		"metadata":     {Metadata: Metadata{Domain: strings.Repeat("x", maxMetadataFieldBytes+1)}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := config.validateBounds(); err == nil {
				t.Fatalf("validateBounds accepted %s", name)
			}
		})
	}
}

func TestLoadRejectsSymlinkAndOversizedFiles(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid.json")
	if err := os.WriteFile(valid, []byte(`{"upstream-port":8080}`), 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink.json")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigFile(symlink); err == nil {
		t.Fatal("readConfigFile accepted symlink")
	}
	parent := filepath.Join(directory, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	parentFile := filepath.Join(parent, "config.json")
	if err := os.WriteFile(parentFile, []byte(`{"upstream-port":8080}`), 0600); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(directory, "parent-link")
	if err := os.Symlink(parent, parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigFile(filepath.Join(parentLink, "config.json")); err == nil {
		t.Fatal("readConfigFile accepted symlinked parent")
	}
	oversized := filepath.Join(directory, "oversized.json")
	if err := os.WriteFile(oversized, []byte(strings.Repeat("x", maxConfigFileBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigFile(oversized); err == nil {
		t.Fatal("readConfigFile accepted oversized file")
	}
}

func TestReadConfigFileRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readConfigFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("readConfigFile accepted FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("readConfigFile blocked opening FIFO")
	}
}
