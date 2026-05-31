// Minimal CO-RE-compatible kernel type definitions used by socket_track.c.
//
// We DON'T need a full vmlinux.h dump — clang+libbpf will rewrite the byte
// offsets at load time against the running kernel's BTF, thanks to the
// preserve_access_index attribute. The struct layouts here only need to
// reference the fields we actually read; the kernel may have any number of
// other fields before, between, or after.
//
// If a future version of tir reads more fields, append to these structs
// rather than reordering existing ones.

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

// Kernel integer aliases (provided by <linux/types.h>, but vmlinux.h is
// usually self-contained — duplicating them here is harmless and lets the
// file be parsed without external includes).
#ifndef _LINUX_TYPES_H
typedef signed char __s8;
typedef unsigned char __u8;
typedef short __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u16 __le16;
typedef __u32 __le32;
#endif

#define __preserve __attribute__((preserve_access_index))

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__u16 u6_addr16[8];
		__u32 u6_addr32[4];
	} in6_u;
} __preserve;

struct sock_common {
	__u32 skc_daddr;          // IPv4 dst
	__u32 skc_rcv_saddr;      // IPv4 src
	__u16 skc_dport;          // dst port (network byte order)
	__u16 skc_num;            // src port (host byte order)
	__u16 skc_family;         // AF_INET / AF_INET6
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} __preserve;

struct sock {
	struct sock_common __sk_common;
} __preserve;

// pt_regs layout per architecture. libbpf's PT_REGS_* macros dereference
// register fields by name (ax on x86, regs[] on arm64), so the fields must
// exist on the target arch.
//
// Only amd64 is checked in for now; an arm64 contributor can extend this
// file and regenerate the BPF object on their host.
#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};
#else
#error "Define struct pt_regs for this target architecture"
#endif

#endif /* __VMLINUX_H__ */
