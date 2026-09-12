package volume

import (
	"errors"
	"fmt"
	"os"
)

const rtmr3Path = "/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384"

// extendSeal marks this boot with what the caller sealed it to. The write is
// the extend -- hardware replaces the register with the hash of its old value
// and these bytes -- so a marked boot cannot be returned to an unmarked one
// without a reboot. Where the guest has no such register there is nothing to
// extend and nothing in the attestation to read it from, which is why the mark
// is a client-side check against the report rather than this program's word.
func extendSeal(digest []byte) error {
	file, err := os.OpenFile(rtmr3Path, os.O_WRONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("opening the seal register: %w", err)
	}
	if _, err := file.Write(digest); err != nil {
		file.Close()
		return fmt.Errorf("extending the seal register: %w", err)
	}
	return file.Close()
}
