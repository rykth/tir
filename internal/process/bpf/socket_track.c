// socket_track.c — emit (PID, comm, 5-tuple) events on TCP connect/accept.
//
// Hooks:
//   - kprobe:tcp_v4_connect / tcp_v6_connect  (entry: stash sock by tid)
//   - kretprobe:tcp_v4_connect / tcp_v6_connect (success: read sock fields, emit)
//   - kretprobe:inet_csk_accept (returns newsk → emit)
//
// Field reads use CO-RE relocations (BPF_CORE_READ_INTO), so the offsets
// resolve against the running kernel's BTF at load time. Layout in vmlinux.h
// just has to *list* the fields, not place them correctly.

// clang-format off
// System UAPI headers come first: they define kernel type aliases (__wsum,
// __sum16) and BPF enum constants (BPF_MAP_TYPE_RINGBUF, BPF_ANY, ...) that
// libbpf's bpf_helper_defs.h and our map declarations reference.
#include <linux/types.h>
#include <linux/bpf.h>

// vmlinux.h carries the kernel struct subset we read with CO-RE.
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
// clang-format on

#define AF_INET 2
#define AF_INET6 10
#define TASK_COMM_LEN 16

enum event_type {
	EVT_TCP_CONNECT = 1,
	EVT_TCP_ACCEPT = 2,
};

// Ring buffer event laid out for direct copying by the Go side. Field order
// and packing matter — see internal/process/ebpf_linux.go.
struct event {
	__u8 event_type;
	__u8 family;       // AF_INET or AF_INET6
	__u16 _pad;
	__u32 pid;
	__u32 saddr4;      // IPv4 src (network byte order, big-endian)
	__u32 daddr4;      // IPv4 dst (network byte order)
	__u8 saddr6[16];   // IPv6 src
	__u8 daddr6[16];   // IPv6 dst
	__u16 sport;       // host byte order
	__u16 dport;       // host byte order (we ntohs in BPF before emit)
	char comm[TASK_COMM_LEN];
};

// Ring buffer for events. 256 KiB is plenty: events are small and Go drains
// continuously.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18);
} events SEC(".maps");

// Per-thread temporary map: stash the sock* on kprobe entry so the retprobe
// can read its post-connect state. Keyed by pid_tgid so concurrent connects
// from different threads don't collide.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct sock *);
} active_socks SEC(".maps");

static __always_inline void fill_v4(struct event *e, struct sock *sk)
{
	BPF_CORE_READ_INTO(&e->saddr4, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&e->daddr4, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&e->sport, sk, __sk_common.skc_num);
	__u16 dport_be;
	BPF_CORE_READ_INTO(&dport_be, sk, __sk_common.skc_dport);
	e->dport = bpf_ntohs(dport_be);
}

static __always_inline void fill_v6(struct event *e, struct sock *sk)
{
	BPF_CORE_READ_INTO(&e->saddr6, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	BPF_CORE_READ_INTO(&e->daddr6, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	BPF_CORE_READ_INTO(&e->sport, sk, __sk_common.skc_num);
	__u16 dport_be;
	BPF_CORE_READ_INTO(&dport_be, sk, __sk_common.skc_dport);
	e->dport = bpf_ntohs(dport_be);
}

static __always_inline void emit(__u8 type, struct sock *sk)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	__builtin_memset(e, 0, sizeof(*e));
	e->event_type = type;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	__u16 family = 0;
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
	e->family = (__u8)family;

	if (family == AF_INET)
		fill_v4(e, sk);
	else if (family == AF_INET6)
		fill_v6(e, sk);

	bpf_ringbuf_submit(e, 0);
}

// tcp_v4_connect: entry has the sock; stash it so the retprobe can read
// post-connect state.
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock *sk)
{
	__u64 tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&active_socks, &tid, &sk, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe_tcp_v4_connect, int ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct sock **skp = bpf_map_lookup_elem(&active_socks, &tid);
	if (skp && ret == 0)
		emit(EVT_TCP_CONNECT, *skp);
	bpf_map_delete_elem(&active_socks, &tid);
	return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kprobe_tcp_v6_connect, struct sock *sk)
{
	__u64 tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&active_socks, &tid, &sk, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(kretprobe_tcp_v6_connect, int ret)
{
	__u64 tid = bpf_get_current_pid_tgid();
	struct sock **skp = bpf_map_lookup_elem(&active_socks, &tid);
	if (skp && ret == 0)
		emit(EVT_TCP_CONNECT, *skp);
	bpf_map_delete_elem(&active_socks, &tid);
	return 0;
}

// inet_csk_accept returns the *new* server-side sock. We only care about
// successful returns (non-NULL).
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe_inet_csk_accept, struct sock *newsk)
{
	if (!newsk)
		return 0;
	emit(EVT_TCP_ACCEPT, newsk);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
