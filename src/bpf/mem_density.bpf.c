// SPDX-License-Identifier: Apache-2.0
/*
 * K3 memory-density eBPF programs.
 *
 * The board kernel has no BTF (CONFIG_DEBUG_INFO_BTF is unset and
 * /sys/kernel/btf/vmlinux is absent), so every program is an ordinary
 * tracepoint program that reads the trace-entry fields at fixed offsets. The
 * offsets below are the ones the kernel publishes in
 * /sys/kernel/tracing/events/<group>/<name>/format; the loader re-verifies each
 * offset before it attaches a program and refuses to attach on a mismatch.
 *
 * Raw tracepoints are not usable for the kmem events here: the sizes the tool
 * needs (bytes_req, bytes_alloc, page order) are fields the kernel computes
 * into the trace entry, not arguments passed to the tracepoint.
 */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_TRACKED_PIDS 4096
#define ALLOC_BUCKETS 40
#define ORDER_BUCKETS 12
#define MAX_SITES 8192

struct pid_key {
	__u32 pid;
};

struct pid_stats {
	__u64 alloc_ops;
	__u64 alloc_bytes;
	__u64 free_ops;
	__u64 fault_reads;
	__u64 fault_writes;
	__u64 page_alloc_ops;
	__u64 page_alloc_pages;
	__u64 page_free_ops;
	__u64 reclaim_events;
	__u64 read_ops;
	__u64 write_ops;
	__u64 read_bytes;
	__u64 write_bytes;
	char comm[16];
};

/* Trace-entry layouts (offsets from the tracepoint format files). */
struct alloc_ctx {          /* kmem:kmalloc */
	__u64 common;
	__u64 call_site;    /*  8 */
	__u64 ptr;          /* 16 */
	__u64 bytes_req;    /* 24 */
	__u64 bytes_alloc;  /* 32 */
};

struct cache_alloc_ctx {    /* kmem:kmem_cache_alloc */
	__u64 common;
	__u64 call_site;    /*  8 */
	__u64 ptr;          /* 16 */
	__u32 name;         /* 24, __data_loc */
	__u32 pad;
	__u64 bytes_req;    /* 32 */
	__u64 bytes_alloc;  /* 40 */
};

struct free_ctx {           /* kmem:kfree, kmem:kmem_cache_free */
	__u64 common;
	__u64 call_site;    /*  8 */
	__u64 ptr;          /* 16 */
};

struct page_ctx {           /* kmem:mm_page_alloc, kmem:mm_page_free */
	__u64 common;
	__u64 pfn;          /*  8 */
	__u32 order;        /* 16 */
	__u32 pad;
	__u64 gfp_flags;    /* 24 */
	__u32 migratetype;  /* 32 */
};

struct fault_ctx {          /* exceptions:page_fault_user|kernel */
	__u64 common;
	__u64 address;      /*  8 */
	__u64 ip;           /* 16 */
	__u64 error_code;   /* 24 */
};

struct common_ctx {         /* events that are only counted */
	__u64 common;
};

struct sys_enter_ctx {      /* syscalls:sys_enter_read|write */
	__u64 common;
	__s64 syscall_nr;   /*  8 */
	__u64 fd;           /* 16 */
	__u64 buf;          /* 24 */
	__u64 count;        /* 32 */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_TRACKED_PIDS);
	__type(key, struct pid_key);
	__type(value, struct pid_stats);
} pid_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, ALLOC_BUCKETS);
	__type(key, __u32);
	__type(value, __u64);
} alloc_width SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, ORDER_BUCKETS);
	__type(key, __u32);
	__type(value, __u64);
} page_order SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, MAX_SITES);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, 127 * sizeof(__u64));
} alloc_sites SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_SITES);
	__type(key, __u32);
	__type(value, __u64);
} site_ops SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u64);
} totals SEC(".maps");

enum total_slot {
	TOTAL_ALLOC_OPS = 0,
	TOTAL_ALLOC_BYTES,
	TOTAL_FREE_OPS,
	TOTAL_FAULT_READS,
	TOTAL_FAULT_WRITES,
	TOTAL_PAGE_ALLOC_OPS,
	TOTAL_PAGE_ALLOC_PAGES,
	TOTAL_PAGE_FREE_OPS,
	TOTAL_RECLAIM_DIRECT,
	TOTAL_RECLAIM_KSWAPD,
	TOTAL_READ_OPS,
	TOTAL_WRITE_OPS,
	TOTAL_READ_BYTES,
	TOTAL_WRITE_BYTES,
	TOTAL_KMEM_CACHE_ALLOC_OPS,
	TOTAL_KMEM_CACHE_FREE_OPS,
};

static __always_inline void total_add(enum total_slot slot, __u64 value)
{
	__u32 index = slot;
	__u64 *counter = bpf_map_lookup_elem(&totals, &index);

	if (counter)
		__sync_fetch_and_add(counter, value);
}

static __always_inline struct pid_stats *stats_for_current(void)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pid_key key = { .pid = (__u32)(pid_tgid >> 32) };
	struct pid_stats zero = {};
	struct pid_stats *stats;

	stats = bpf_map_lookup_elem(&pid_stats, &key);
	if (stats)
		return stats;
	if (bpf_map_update_elem(&pid_stats, &key, &zero, BPF_NOEXIST) != 0)
		return bpf_map_lookup_elem(&pid_stats, &key);
	stats = bpf_map_lookup_elem(&pid_stats, &key);
	if (stats)
		bpf_get_current_comm(&stats->comm, sizeof(stats->comm));
	return stats;
}

static __always_inline void width_bucket(__u64 bytes)
{
	__u32 bucket = 0;
	__u64 value = bytes;
	__u64 *counter;

	while (value > 1 && bucket < ALLOC_BUCKETS - 1) {
		value >>= 1;
		bucket += 1;
	}
	counter = bpf_map_lookup_elem(&alloc_width, &bucket);
	if (counter)
		__sync_fetch_and_add(counter, 1);
}

static __always_inline void record_allocation(void *ctx, int is_cache, __u64 bytes_alloc)
{
	struct pid_stats *stats = stats_for_current();
	long stack_id = bpf_get_stackid(ctx, &alloc_sites, BPF_F_FAST_STACK_CMP);
	__u32 key;
	__u64 *site;

	if (stats) {
		stats->alloc_ops += 1;
		stats->alloc_bytes += bytes_alloc;
	}
	total_add(TOTAL_ALLOC_OPS, 1);
	total_add(TOTAL_ALLOC_BYTES, bytes_alloc);
	if (is_cache)
		total_add(TOTAL_KMEM_CACHE_ALLOC_OPS, 1);
	width_bucket(bytes_alloc);

	if (stack_id < 0)
		return;
	key = (__u32)stack_id;
	site = bpf_map_lookup_elem(&site_ops, &key);
	if (site) {
		__sync_fetch_and_add(site, 1);
	} else {
		__u64 one = 1;

		bpf_map_update_elem(&site_ops, &key, &one, BPF_NOEXIST);
	}
}

static __always_inline void record_free(int is_cache)
{
	struct pid_stats *stats = stats_for_current();

	if (stats)
		stats->free_ops += 1;
	total_add(TOTAL_FREE_OPS, 1);
	if (is_cache)
		total_add(TOTAL_KMEM_CACHE_FREE_OPS, 1);
}

static __always_inline void record_fault(__u64 error_code)
{
	struct pid_stats *stats = stats_for_current();
	int is_write = (error_code & 0x2) != 0;

	if (stats) {
		if (is_write)
			stats->fault_writes += 1;
		else
			stats->fault_reads += 1;
	}
	if (is_write)
		total_add(TOTAL_FAULT_WRITES, 1);
	else
		total_add(TOTAL_FAULT_READS, 1);
}

static __always_inline void record_reclaim(enum total_slot slot)
{
	struct pid_stats *stats = stats_for_current();

	if (stats)
		stats->reclaim_events += 1;
	total_add(slot, 1);
}

SEC("tp/kmem/kmalloc")
int kmalloc_enter(struct alloc_ctx *ctx)
{
	record_allocation(ctx, 0, ctx->bytes_alloc);
	return 0;
}

SEC("tp/kmem/kmem_cache_alloc")
int kmem_cache_alloc_enter(struct cache_alloc_ctx *ctx)
{
	record_allocation(ctx, 1, ctx->bytes_alloc);
	return 0;
}

SEC("tp/kmem/kfree")
int kfree_enter(struct free_ctx *ctx)
{
	record_free(0);
	return 0;
}

SEC("tp/kmem/kmem_cache_free")
int kmem_cache_free_enter(struct free_ctx *ctx)
{
	record_free(1);
	return 0;
}

SEC("tp/kmem/mm_page_alloc")
int page_alloc_enter(struct page_ctx *ctx)
{
	struct pid_stats *stats = stats_for_current();
	__u32 order = ctx->order;
	__u32 bucket = order < ORDER_BUCKETS ? order : ORDER_BUCKETS - 1;
	__u64 pages = 1ULL << (order < 31 ? order : 30);
	__u64 *counter = bpf_map_lookup_elem(&page_order, &bucket);

	if (counter)
		__sync_fetch_and_add(counter, 1);
	if (stats) {
		stats->page_alloc_ops += 1;
		stats->page_alloc_pages += pages;
	}
	total_add(TOTAL_PAGE_ALLOC_OPS, 1);
	total_add(TOTAL_PAGE_ALLOC_PAGES, pages);
	return 0;
}

SEC("tp/kmem/mm_page_free")
int page_free_enter(struct page_ctx *ctx)
{
	struct pid_stats *stats = stats_for_current();

	if (stats)
		stats->page_free_ops += 1;
	total_add(TOTAL_PAGE_FREE_OPS, 1);
	return 0;
}

SEC("tp/exceptions/page_fault_user")
int page_fault_user(struct fault_ctx *ctx)
{
	record_fault(ctx->error_code);
	return 0;
}

SEC("tp/exceptions/page_fault_kernel")
int page_fault_kernel(struct fault_ctx *ctx)
{
	record_fault(ctx->error_code);
	return 0;
}

SEC("tp/vmscan/mm_vmscan_direct_reclaim_begin")
int direct_reclaim_begin(struct common_ctx *ctx)
{
	record_reclaim(TOTAL_RECLAIM_DIRECT);
	return 0;
}

SEC("tp/vmscan/mm_vmscan_kswapd_wake")
int kswapd_wake(struct common_ctx *ctx)
{
	record_reclaim(TOTAL_RECLAIM_KSWAPD);
	return 0;
}

SEC("tp/syscalls/sys_enter_read")
int sys_enter_read_tp(struct sys_enter_ctx *ctx)
{
	struct pid_stats *stats = stats_for_current();
	__u64 count = ctx->count;

	if (stats) {
		stats->read_ops += 1;
		stats->read_bytes += count;
	}
	total_add(TOTAL_READ_OPS, 1);
	total_add(TOTAL_READ_BYTES, count);
	return 0;
}

SEC("tp/syscalls/sys_enter_write")
int sys_enter_write_tp(struct sys_enter_ctx *ctx)
{
	struct pid_stats *stats = stats_for_current();
	__u64 count = ctx->count;

	if (stats) {
		stats->write_ops += 1;
		stats->write_bytes += count;
	}
	total_add(TOTAL_WRITE_OPS, 1);
	total_add(TOTAL_WRITE_BYTES, count);
	return 0;
}

/* The kernel only lets GPL-declared programs call bpf_get_stackid, which the
 * locating view needs. The repository itself stays under Apache-2.0; this
 * string is the licence declaration the BPF verifier reads. */
char LICENSE[] SEC("license") = "GPL";
