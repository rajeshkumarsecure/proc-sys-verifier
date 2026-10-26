// preflight.go — runtime checks that must pass before loading LSM
// programs. Phase 4 surfaces these as clear, actionable errors at
// `psv watch` startup so operators get a one-liner fix instead of a
// cryptic verifier complaint.

package watch

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrBPFLSMNotEnabled is returned by NewSBMount (and slice 22's
// NewFileOpen) when the running kernel doesn't have `bpf` in its
// active LSM list. The error message points at the helper script
// that fixes it.
var ErrBPFLSMNotEnabled = errors.New(
	"bpf is not in the kernel's active LSM list; " +
		"run `sudo scripts/enable-bpf-lsm.sh` and reboot " +
		"(see scripts/README.md for caveats); " +
		"verify with `cat /sys/kernel/security/lsm`")

// checkBPFLSMEnabled returns nil iff /sys/kernel/security/lsm
// contains `bpf` as a comma-delimited token. Returns
// ErrBPFLSMNotEnabled otherwise, or a wrapped read error if the file
// is unreadable (which is itself a sign that the kernel is missing
// CONFIG_SECURITY=y or similar).
func checkBPFLSMEnabled() error {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return fmt.Errorf("read /sys/kernel/security/lsm: %w (kernel missing CONFIG_SECURITY?)", err)
	}
	// File contents are a comma-separated list with no trailing
	// newline on most kernels; strip whitespace defensively.
	list := strings.TrimSpace(string(data))
	for _, tok := range strings.Split(list, ",") {
		if tok == "bpf" {
			return nil
		}
	}
	return ErrBPFLSMNotEnabled
}
