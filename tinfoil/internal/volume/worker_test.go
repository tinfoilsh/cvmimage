package volume

import "testing"

func TestWorkerRequiresExplicitSupportedFormat(t *testing.T) {
	for _, version := range []byte{0, 3, 255} {
		packet := append([]byte{version, opUnlock}, make([]byte, 64)...)
		w := new(volume)
		status, err := w.handle(t.Context(), packet)
		if status != statusRejected || err == nil {
			t.Fatalf("format %d = %q, %v; want rejected", version, status, err)
		}
	}
}
