package observe

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

// MountInfo is one entry from /proc/<pid>/mountinfo. See proc(5):
//
//	36 35 98:0 /mnt1 /mnt/parent rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//	(1)(2)(3)   (4)   (5)        (6)        (7)      (8) (9)  (10)    (11)
//
// Fields (7) is zero or more optional "tag" or "tag:value" tokens, terminated
// by a literal " - ".
type MountInfo struct {
	MountID    int      `json:"mount_id"`
	ParentID   int      `json:"parent_id"`
	DevMajor   int      `json:"dev_major"`
	DevMinor   int      `json:"dev_minor"`
	Root       string   `json:"root"`
	MountPoint string   `json:"mount_point"`
	VFSOptions []string `json:"vfs_options"`
	Optional   []string `json:"optional,omitempty"`
	FSType     string   `json:"fs_type"`
	Source     string   `json:"source"`
	SuperOpts  []string `json:"super_options"`
}

// ReadOnly reports whether this mount has the 'ro' VFS option.
func (m MountInfo) ReadOnly() bool {
	for _, o := range m.VFSOptions {
		if o == "ro" {
			return true
		}
	}
	return false
}

// ReadMountInfo reads and parses a /proc/<pid>/mountinfo file.
func ReadMountInfo(path string) ([]MountInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseMountInfo(f)
}

// ParseMountInfo parses the contents of a /proc/<pid>/mountinfo file.
func ParseMountInfo(r io.Reader) ([]MountInfo, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var out []MountInfo
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		m, err := parseMountInfoLine(line)
		if err != nil {
			return nil, fmt.Errorf("mountinfo parse: %w", err)
		}
		out = append(out, m)
	}
	return out, scanner.Err()
}

func parseMountInfoLine(line string) (MountInfo, error) {
	sepIdx := strings.Index(line, " - ")
	if sepIdx < 0 {
		return MountInfo{}, fmt.Errorf("missing %q separator in: %q", " - ", line)
	}
	pre := strings.Fields(line[:sepIdx])
	post := strings.Fields(line[sepIdx+3:])
	if len(pre) < 6 {
		return MountInfo{}, fmt.Errorf("too few pre-separator fields: %q", line)
	}
	if len(post) < 3 {
		return MountInfo{}, fmt.Errorf("too few post-separator fields: %q", line)
	}

	mid, err := strconv.Atoi(pre[0])
	if err != nil {
		return MountInfo{}, fmt.Errorf("mount id: %w", err)
	}
	pid, err := strconv.Atoi(pre[1])
	if err != nil {
		return MountInfo{}, fmt.Errorf("parent id: %w", err)
	}
	devs := strings.SplitN(pre[2], ":", 2)
	if len(devs) != 2 {
		return MountInfo{}, fmt.Errorf("bad dev %q", pre[2])
	}
	maj, err := strconv.Atoi(devs[0])
	if err != nil {
		return MountInfo{}, fmt.Errorf("dev major: %w", err)
	}
	min, err := strconv.Atoi(devs[1])
	if err != nil {
		return MountInfo{}, fmt.Errorf("dev minor: %w", err)
	}

	return MountInfo{
		MountID:    mid,
		ParentID:   pid,
		DevMajor:   maj,
		DevMinor:   min,
		Root:       unescapeOctal(pre[3]),
		MountPoint: unescapeOctal(pre[4]),
		VFSOptions: strings.Split(pre[5], ","),
		Optional:   append([]string(nil), pre[6:]...),
		FSType:     post[0],
		Source:     unescapeOctal(post[1]),
		SuperOpts:  strings.Split(post[2], ","),
	}, nil
}

// unescapeOctal decodes the three-digit octal escapes the kernel uses for
// space (\040), tab (\011), newline (\012), and backslash (\134) in paths.
func unescapeOctal(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mountIndex answers "which mount contains this path?" via longest-prefix
// match on MountPoint. It does not handle bind mounts of subtrees from
// different filesystems — for that we would need to consult Root too.
type mountIndex struct {
	sorted []MountInfo
}

func indexMounts(mounts []MountInfo) *mountIndex {
	dup := append([]MountInfo(nil), mounts...)
	sort.SliceStable(dup, func(i, j int) bool {
		return len(dup[i].MountPoint) > len(dup[j].MountPoint)
	})
	return &mountIndex{sorted: dup}
}

// containing returns the most-specific mount whose mount point contains path,
// or nil if no mount matches (which would be surprising — '/' should always
// match if mountinfo is well-formed).
func (idx *mountIndex) containing(path string) *MountInfo {
	for i := range idx.sorted {
		mp := idx.sorted[i].MountPoint
		if mp == "/" || mp == path || strings.HasPrefix(path, mp+"/") {
			return &idx.sorted[i]
		}
	}
	return nil
}
