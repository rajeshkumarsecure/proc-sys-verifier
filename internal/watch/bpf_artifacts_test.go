package watch

import (
	"bytes"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

func TestBPFArtifacts(t *testing.T) {
	for _, name := range []string{
		"hello_bpfel.o", "hello_bpfeb.o",
		"sbmount_bpfel.o", "sbmount_bpfeb.o",
		"fileopen_bpfel.o", "fileopen_bpfeb.o",
	} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			for _, privatePrefix := range []string{"/home/", "/root/"} {
				if bytes.Contains(data, []byte(privatePrefix)) {
					t.Errorf("object embeds a private build path starting with %s", privatePrefix)
				}
			}
			spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if len(spec.Programs) == 0 {
				t.Fatal("object has no BPF programs")
			}
			for program, ps := range spec.Programs {
				if ps.License != "Dual MIT/GPL" {
					t.Errorf("%s license = %q, want Dual MIT/GPL", program, ps.License)
				}
			}
		})
	}
}
