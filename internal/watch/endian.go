// endian.go — small helpers to keep hello.go readable. binary.NativeEndian
// landed in Go 1.21; we use the same byte-order regardless of the
// machine because cilium/ebpf already selects the right .bpf.o per
// platform.

package watch

import (
	"bytes"
	"encoding/binary"
)

var nativeEndian = binary.NativeEndian

func byteReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
