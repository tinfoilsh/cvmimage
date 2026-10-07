package tinfoilconfig

import (
	"fmt"
	"math"
	"math/big"
	"strings"
)

// MinVolumeSize is the smallest volume a config may declare: dm-integrity and
// ext4 need room for their own metadata before any file fits.
const MinVolumeSize = 64 << 20

// sizeUnits maps a unit suffix to its multiplier. Bare letters follow the
// docker convention already used by tmpfs (binary), "KB"/"MB"/... are decimal
// and "KiB"/"MiB"/... binary.
var sizeUnits = map[string]int64{
	"b":   1,
	"k":   1 << 10,
	"kib": 1 << 10,
	"kb":  1_000,
	"m":   1 << 20,
	"mib": 1 << 20,
	"mb":  1_000_000,
	"g":   1 << 30,
	"gib": 1 << 30,
	"gb":  1_000_000_000,
	"t":   1 << 40,
	"tib": 1 << 40,
	"tb":  1_000_000_000_000,
}

// ParseSize converts a size such as "30GiB", "16TB", "1.5T" or "512m" to
// bytes. The unit is required, the number may carry a decimal fraction, and
// the result must be a whole multiple of 512 bytes of at least MinVolumeSize.
func ParseSize(text string) (int64, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0, fmt.Errorf("size is empty")
	}
	split := len(trimmed)
	for split > 0 {
		c := trimmed[split-1]
		if (c >= '0' && c <= '9') || c == '.' {
			break
		}
		split--
	}
	number, unit := trimmed[:split], strings.ToLower(strings.TrimSpace(trimmed[split:]))
	if number == "" {
		return 0, fmt.Errorf("size %q has no number", text)
	}
	if unit == "" {
		return 0, fmt.Errorf("size %q needs a unit such as GiB or TB", text)
	}
	multiplier, ok := sizeUnits[unit]
	if !ok {
		return 0, fmt.Errorf("size %q has unknown unit %q (use B, KB, MB, GB, TB or KiB, MiB, GiB, TiB)", text, unit)
	}
	value, ok := new(big.Rat).SetString(number)
	if !ok || value.Sign() <= 0 {
		return 0, fmt.Errorf("size %q must be a positive number with a unit", text)
	}
	bytes := new(big.Rat).Mul(value, new(big.Rat).SetInt64(multiplier))
	if !bytes.IsInt() {
		return 0, fmt.Errorf("size %q is not a whole number of bytes", text)
	}
	if !bytes.Num().IsInt64() || bytes.Num().Int64() > math.MaxInt64/2 {
		return 0, fmt.Errorf("size %q is too large", text)
	}
	result := bytes.Num().Int64()
	if result%512 != 0 {
		return 0, fmt.Errorf("size %q must be a multiple of 512 bytes", text)
	}
	if result < MinVolumeSize {
		return 0, fmt.Errorf("size %q is below the minimum of 64MiB", text)
	}
	return result, nil
}
