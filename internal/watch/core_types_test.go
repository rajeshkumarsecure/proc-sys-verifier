package watch

import (
	"bytes"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func TestFileOpenPartialTypesRelocate(t *testing.T) {
	for _, target := range []struct {
		name       string
		modeOffset uint32
		pathOffset uint32
		nested     bool
		missing    string
	}{
		{"shifted", 136, 64, false, ""},
		{"reordered", 32, 160, false, ""},
		{"anonymous-member", 32, 80, true, ""},
		{"missing-mode", 136, 64, false, "f_mode"},
		{"missing-path", 136, 64, false, "f_path"},
	} {
		for _, endian := range []string{"bpfel", "bpfeb"} {
			t.Run(target.name+"/"+endian, func(t *testing.T) {
				spec, err := ebpf.LoadCollectionSpec("fileopen_" + endian + ".o")
				if err != nil {
					t.Fatal(err)
				}
				var localFile *btf.Struct
				if err := spec.Types.TypeByName("file", &localFile); err != nil {
					t.Fatal(err)
				}
				if len(localFile.Members) != 2 ||
					localFile.Members[0].Name != "f_path" ||
					localFile.Members[1].Name != "f_mode" {
					t.Fatalf("expected only the two partial file interface members, got %v", localFile.Members)
				}

				u32 := &btf.Int{Name: "unsigned int", Size: 4}
				path := &btf.Struct{
					Name: "path",
					Size: 16,
					Members: []btf.Member{
						{Name: "mnt", Type: &btf.Pointer{Target: &btf.Fwd{Name: "vfsmount", Kind: btf.FwdStruct}}},
						{Name: "dentry", Type: &btf.Pointer{Target: &btf.Fwd{Name: "dentry", Kind: btf.FwdStruct}}, Offset: 64},
					},
				}
				base := uint32(0)
				if target.nested {
					base = 16
				}
				var members []btf.Member
				if target.missing != "f_mode" {
					members = append(members, btf.Member{
						Name: "f_mode", Type: u32, Offset: btf.Bits((target.modeOffset - base) * 8),
					})
				}
				if target.missing != "f_path" {
					members = append(members, btf.Member{
						Name: "f_path", Type: path, Offset: btf.Bits((target.pathOffset - base) * 8),
					})
				}
				slices.SortFunc(members, func(a, b btf.Member) int {
					return int(a.Offset) - int(b.Offset)
				})
				file := &btf.Struct{Name: "file", Size: 256, Members: members}
				if target.nested {
					file.Members = []btf.Member{{
						Type: &btf.Struct{Size: 224, Members: members}, Offset: btf.Bits(base * 8),
					}}
				}
				builder, err := btf.NewBuilder([]btf.Type{file}, nil)
				if err != nil {
					t.Fatal(err)
				}
				data, err := builder.Marshal(nil, &btf.MarshalOptions{Order: spec.ByteOrder})
				if err != nil {
					t.Fatal(err)
				}
				kernel, err := btf.LoadSpecFromReader(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				program := spec.Programs["psv_file_open"]
				if program == nil {
					t.Fatal("missing file-open program")
				}
				var relos []*btf.CORERelocation
				var indices []int
				for i := range program.Instructions {
					if relo := btf.CORERelocationMetadata(&program.Instructions[i]); relo != nil {
						relos = append(relos, relo)
						indices = append(indices, i)
					}
				}
				if len(relos) != 2 {
					t.Fatalf("want exactly two file-field relocations, got %d", len(relos))
				}
				fixups, err := btf.CORERelocate(relos, []*btf.Spec{kernel}, spec.ByteOrder, spec.Types.TypeID)
				if err != nil {
					if target.missing != "" {
						return
					}
					t.Fatal(err)
				}
				var offsets []uint32
				poisoned := false
				for i, index := range indices {
					ins := &program.Instructions[index]
					if err := fixups[i].Apply(ins); err != nil {
						t.Fatal(err)
					}
					if ins.Constant == btf.COREBadRelocationSentinel {
						poisoned = true
						continue
					}
					switch ins.OpCode.Class() {
					case asm.LdXClass, asm.StClass, asm.StXClass:
						offsets = append(offsets, uint32(ins.Offset))
					default:
						offsets = append(offsets, uint32(ins.Constant))
					}
				}
				if target.missing != "" {
					if !poisoned {
						t.Fatal("a missing required kernel field must not produce a valid program")
					}
					return
				}
				if poisoned {
					t.Fatal("valid target layout produced a poisoned relocation")
				}
				slices.Sort(offsets)
				want := []uint32{target.modeOffset, target.pathOffset}
				slices.Sort(want)
				if !slices.Equal(offsets, want) {
					t.Fatalf("relocated byte offsets = %v, want %v", offsets, want)
				}
			})
		}
	}
}

func TestBPFMapInterfaceConstants(t *testing.T) {
	for _, endian := range []string{"bpfel", "bpfeb"} {
		t.Run(endian, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpec("fileopen_" + endian + ".o")
			if err != nil {
				t.Fatal(err)
			}
			for name, want := range map[string]ebpf.MapType{
				"watched_cgroups":       ebpf.Hash,
				"intended_sets":         ebpf.ArrayOfMaps,
				"intended_set_template": ebpf.LPMTrie,
				"events":                ebpf.RingBuf,
			} {
				got := spec.Maps[name]
				if got == nil || got.Type != want {
					t.Errorf("map %s = %v, want type %s", name, got, want)
				}
			}
			trie := spec.Maps["intended_set_template"]
			if trie == nil {
				t.Fatal("missing LPM trie template")
			}
			if flags := trie.Flags; flags != 1 {
				t.Errorf("LPM no-preallocation flags = %d, want 1", flags)
			}
		})
	}
}
