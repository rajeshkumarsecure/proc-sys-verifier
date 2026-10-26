/* SPDX-License-Identifier: MIT OR GPL-2.0-only */
#ifndef PSV_TYPES_H
#define PSV_TYPES_H

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef unsigned int fmode_t;

/* Linux BPF UAPI numeric identifiers, not kernel implementation code. */
enum {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_RINGBUF = 27,
};

#define BPF_F_NO_PREALLOC 1U

struct vfsmount;
struct dentry;

/* Partial interfaces: CO-RE resolves field offsets from the target kernel BTF. */
struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
    const struct path f_path;
    fmode_t f_mode;
} __attribute__((preserve_access_index));

#endif
