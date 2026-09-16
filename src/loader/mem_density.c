// SPDX-License-Identifier: Apache-2.0
/*
 * K3 memory-density loader.
 *
 * Loads the raw-tracepoint eBPF programs, reads their maps and reports the
 * three densities plus the locating views:
 *
 *   rate density   allocations, frees, page allocations/frees, page faults
 *                  (read and write), reclaim events, read/write syscalls per
 *                  second and their requested bytes per second
 *   width density  allocation-size and page-order histograms
 *   space/depth    page-fault frequency and reclaim pressure per second
 *   locating       top processes by allocation/fault activity and the top
 *                  kernel stacks that request memory
 *
 * The loader is cross-built for the board and links the board's own libbpf; it
 * needs no BTF because every program uses raw tracepoints.
 */
#include <bpf/bpf.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MAX_ATTACH_FDS 256

static int attach_fds[MAX_ATTACH_FDS];
static int attach_fd_count;

static int perf_event_open_wrapper(struct perf_event_attr *attr, int cpu)
{
	return (int)syscall(__NR_perf_event_open, attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
}

static int read_tracepoint_id(const char *group, const char *name)
{
	char path[256];
	FILE *file;
	int id = -1;

	snprintf(path, sizeof(path), "/sys/kernel/tracing/events/%s/%s/id", group, name);
	file = fopen(path, "r");
	if (!file)
		return -1;
	if (fscanf(file, "%d", &id) != 1)
		id = -1;
	fclose(file);
	return id;
}

/* Verify one field offset in the tracepoint format description; the compiled
 * programs read the entry at fixed offsets, so a mismatch must fail closed. */
static int verify_tracepoint_field(const char *group, const char *name,
				   const char *field, int expected_offset)
{
	char path[256], line[512];
	FILE *file;
	int found = 0;

	snprintf(path, sizeof(path), "/sys/kernel/tracing/events/%s/%s/format", group, name);
	file = fopen(path, "r");
	if (!file)
		return -1;
	while (fgets(line, sizeof(line), file)) {
		char *field_pos = strstr(line, "field:");
		char *offset_pos = strstr(line, "offset:");
		char *semicolon = strchr(line, ';');

		if (field_pos && offset_pos && semicolon && semicolon > field_pos) {
			char declared[128];
			size_t length = (size_t)(semicolon - (field_pos + 6));
			const char *declared_name;
			char *space;
			int offset = atoi(offset_pos + 7);

			if (length >= sizeof(declared))
				length = sizeof(declared) - 1;
			memcpy(declared, field_pos + 6, length);
			declared[length] = '\0';
			space = strrchr(declared, ' ');
			declared_name = space ? space + 1 : declared;
			if (strcmp(declared_name, field) == 0) {
				found = offset == expected_offset ? 1 : -2;
				break;
			}
		}
	}
	fclose(file);
	return found;
}

static int online_cpus(int *cpus, int max_cpus)
{
	char text[256];
	FILE *file = fopen("/sys/devices/system/cpu/online", "r");
	int count = 0;

	if (!file)
		return 0;
	if (!fgets(text, sizeof(text), file)) {
		fclose(file);
		return 0;
	}
	fclose(file);
	char *cursor = text;

	while (*cursor && count < max_cpus) {
		int first = 0, last = 0;

		if (sscanf(cursor, "%d-%d", &first, &last) == 2) {
			for (int cpu = first; cpu <= last && count < max_cpus; cpu++)
				cpus[count++] = cpu;
		} else if (sscanf(cursor, "%d", &first) == 1) {
			cpus[count++] = first;
		}
		cursor = strchr(cursor, ',');
		if (!cursor)
			break;
		cursor++;
	}
	return count;
}

static int attach_tracepoint(struct bpf_program *program, const char *group,
			     const char *name)
{
	int cpus[64];
	int cpu_count = online_cpus(cpus, 64);
	int id = read_tracepoint_id(group, name);
	int attached_here = 0;

	if (id < 0) {
		fprintf(stderr, "warning: tracepoint %s:%s has no id\n", group, name);
		return 0;
	}
	if (cpu_count == 0) {
		cpus[0] = 0;
		cpu_count = 1;
	}
	for (int index = 0; index < cpu_count; index++) {
		struct perf_event_attr attr;

		memset(&attr, 0, sizeof(attr));
		attr.type = PERF_TYPE_TRACEPOINT;
		attr.size = sizeof(attr);
		attr.config = (__u64)id;
		attr.sample_period = 1;
		attr.wakeup_events = 1;
		int fd = perf_event_open_wrapper(&attr, cpus[index]);

		if (fd < 0)
			continue;
		if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, bpf_program__fd(program)) != 0) {
			close(fd);
			continue;
		}
		if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
			close(fd);
			continue;
		}
		if (attach_fd_count < MAX_ATTACH_FDS)
			attach_fds[attach_fd_count++] = fd;
		attached_here++;
	}
	if (attached_here == 0)
		fprintf(stderr, "warning: cannot attach tracepoint %s:%s\n", group, name);
	return attached_here;
}

static int libbpf_log(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

#define MAX_TRACKED_PIDS 4096
#define ALLOC_BUCKETS 40
#define ORDER_BUCKETS 12
#define MAX_SITES 8192
#define STACK_DEPTH 127
#define MAX_SYMBOLS 200000

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
	TOTAL_SLOTS
};

static const char *total_names[TOTAL_SLOTS] = {
	[TOTAL_ALLOC_OPS] = "alloc_ops",
	[TOTAL_ALLOC_BYTES] = "alloc_bytes",
	[TOTAL_FREE_OPS] = "free_ops",
	[TOTAL_FAULT_READS] = "fault_reads",
	[TOTAL_FAULT_WRITES] = "fault_writes",
	[TOTAL_PAGE_ALLOC_OPS] = "page_alloc_ops",
	[TOTAL_PAGE_ALLOC_PAGES] = "page_alloc_pages",
	[TOTAL_PAGE_FREE_OPS] = "page_free_ops",
	[TOTAL_RECLAIM_DIRECT] = "reclaim_direct",
	[TOTAL_RECLAIM_KSWAPD] = "reclaim_kswapd",
	[TOTAL_READ_OPS] = "read_ops",
	[TOTAL_WRITE_OPS] = "write_ops",
	[TOTAL_READ_BYTES] = "read_bytes",
	[TOTAL_WRITE_BYTES] = "write_bytes",
	[TOTAL_KMEM_CACHE_ALLOC_OPS] = "kmem_cache_alloc_ops",
	[TOTAL_KMEM_CACHE_FREE_OPS] = "kmem_cache_free_ops",
};

struct layout_expectation {
	const char *section;      /* tp/<group>/<name> */
	const char *field;
	int offset;
};

/* Every program reads trace-entry fields at fixed offsets, so the offsets each
 * program assumes are verified against the tracepoint format description
 * before the program is attached. A mismatch means the kernel changed the
 * tracepoint and the program must not run. Tracepoints without an entry here
 * are pure event counters and do not read any field. */
static const struct layout_expectation expected_layouts[] = {
	{ "tp/kmem/kmalloc", "bytes_alloc", 32 },
	{ "tp/kmem/kmem_cache_alloc", "bytes_alloc", 40 },
	{ "tp/kmem/mm_page_alloc", "order", 16 },
	{ "tp/exceptions/page_fault_user", "error_code", 24 },
	{ "tp/exceptions/page_fault_kernel", "error_code", 24 },
	{ "tp/syscalls/sys_enter_read", "fd", 16 },
	{ "tp/syscalls/sys_enter_read", "count", 32 },
	{ "tp/syscalls/sys_enter_write", "fd", 16 },
	{ "tp/syscalls/sys_enter_write", "count", 32 },
};

static int verify_layout(const char *section, const char *group, const char *event)
{
	for (size_t index = 0; index < sizeof(expected_layouts) / sizeof(expected_layouts[0]);
	     index++) {
		const struct layout_expectation *expectation = &expected_layouts[index];

		if (strcmp(expectation->section, section) != 0)
			continue;
		if (verify_tracepoint_field(group, event, expectation->field,
					    expectation->offset) != 1) {
			fprintf(stderr,
				"warning: %s/%s no longer has %s at offset %d; refusing to attach\n",
				group, event, expectation->field, expectation->offset);
			return -1;
		}
	}
	return 0;
}

struct symbol {
	__u64 address;
	char name[128];
};

static struct symbol *symbols;
static size_t symbol_count;

static int load_symbols(void)
{
	FILE *file = fopen("/proc/kallsyms", "r");
	char line[512];

	if (!file)
		return -1;
	symbols = calloc(MAX_SYMBOLS, sizeof(*symbols));
	if (!symbols) {
		fclose(file);
		return -1;
	}
	while (fgets(line, sizeof(line), file) && symbol_count < MAX_SYMBOLS) {
		unsigned long long address;
		char type;
		char name[128];

		if (sscanf(line, "%llx %c %127s", &address, &type, name) != 3)
			continue;
		if (address == 0)
			continue;
		symbols[symbol_count].address = address;
		snprintf(symbols[symbol_count].name, sizeof(symbols[0].name), "%s", name);
		symbol_count++;
	}
	fclose(file);
	return 0;
}

static const char *symbol_for(__u64 address)
{
	size_t low = 0, high = symbol_count;

	while (low < high) {
		size_t mid = (low + high) / 2;

		if (symbols[mid].address <= address)
			low = mid + 1;
		else
			high = mid;
	}
	if (low == 0)
		return "?";
	return symbols[low - 1].name;
}

static int read_totals(int map_fd, __u64 *values)
{
	for (__u32 slot = 0; slot < TOTAL_SLOTS; slot++) {
		__u64 value = 0;

		if (bpf_map_lookup_elem(map_fd, &slot, &value) != 0)
			return -1;
		values[slot] = value;
	}
	return 0;
}

static int read_array(int map_fd, __u64 *values, int count)
{
	for (int index = 0; index < count; index++) {
		__u32 key = index;
		__u64 value = 0;

		if (bpf_map_lookup_elem(map_fd, &key, &value) != 0)
			return -1;
		values[index] = value;
	}
	return 0;
}

struct pid_row {
	__u32 pid;
	struct pid_stats stats;
};

static int collect_pids(int map_fd, struct pid_row **rows, size_t *row_count)
{
	struct pid_key key = { 0 }, next_key;
	size_t capacity = 256, count = 0;
	struct pid_row *out = calloc(capacity, sizeof(*out));
	int has_next = 0;

	if (!out)
		return -1;
	while (bpf_map_get_next_key(map_fd, count ? &key : NULL, &next_key) == 0) {
		struct pid_stats stats;

		if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
			if (count == capacity) {
				capacity *= 2;
				struct pid_row *grown = realloc(out, capacity * sizeof(*out));

				if (!grown) {
					free(out);
					return -1;
				}
				out = grown;
			}
			out[count].pid = next_key.pid;
			out[count].stats = stats;
			count++;
		}
		key = next_key;
		has_next = 1;
	}
	(void)has_next;
	*rows = out;
	*row_count = count;
	return 0;
}

static int collect_sites(int ops_fd, int stack_fd, __u32 **ids, __u64 **counts, size_t *count)
{
	__u32 key = 0, next_key;
	size_t capacity = 256, found = 0;
	__u32 *out_ids = calloc(capacity, sizeof(__u32));
	__u64 *out_counts = calloc(capacity, sizeof(__u64));
	int first = 1;

	if (!out_ids || !out_counts) {
		free(out_ids);
		free(out_counts);
		return -1;
	}
	while (bpf_map_get_next_key(ops_fd, first ? NULL : &key, &next_key) == 0) {
		__u64 value = 0;

		first = 0;
		if (bpf_map_lookup_elem(ops_fd, &next_key, &value) == 0 && value > 0) {
			if (found == capacity) {
				capacity *= 2;
				__u32 *grown_ids = realloc(out_ids, capacity * sizeof(__u32));

				if (!grown_ids) {
					free(out_ids);
					free(out_counts);
					return -1;
				}
				out_ids = grown_ids;
				__u64 *grown_counts = realloc(out_counts, capacity * sizeof(__u64));

				if (!grown_counts) {
					free(out_ids);
					free(out_counts);
					return -1;
				}
				out_counts = grown_counts;
			}
			out_ids[found] = next_key;
			out_counts[found] = value;
			found++;
		}
		key = next_key;
	}
	(void)stack_fd;
	*ids = out_ids;
	*counts = out_counts;
	*count = found;
	return 0;
}

static void print_stack(int stack_fd, __u32 id)
{
	__u64 frames[STACK_DEPTH];
	int levels;

	memset(frames, 0, sizeof(frames));
	if (bpf_map_lookup_elem(stack_fd, &id, frames) != 0) {
		printf("      <unavailable>\n");
		return;
	}
	levels = 0;
	for (int index = 0; index < STACK_DEPTH && frames[index]; index++)
		levels++;
	for (int index = 0; index < levels && index < 6; index++)
		printf("      %s+0x%llx\n", symbol_for(frames[index]),
		       (unsigned long long)(frames[index] - (frames[index] & ~0xfffULL)) & 0xfff);
	if (levels > 6)
		printf("      ... %d more frames\n", levels - 6);
}

static int compare_rows(const void *a, const void *b)
{
	const struct pid_row *left = a;
	const struct pid_row *right = b;
	__u64 left_total = left->stats.alloc_ops + left->stats.fault_reads + left->stats.fault_writes;
	__u64 right_total = right->stats.alloc_ops + right->stats.fault_reads + right->stats.fault_writes;

	if (left_total < right_total)
		return 1;
	if (left_total > right_total)
		return -1;
	return 0;
}

static int compare_sites(const void *a, const void *b)
{
	const struct {
		__u32 id;
		__u64 count;
	} *left = a, *right = b;

	if (left->count < right->count)
		return 1;
	if (left->count > right->count)
		return -1;
	return 0;
}

int main(int argc, char **argv)
{
	const char *object_path = "/usr/local/lib/k3-mem-density/mem_density.bpf.o";
	const char *json_path = NULL;
	int seconds = 10, interval = 1, top = 5, check_only = 0;
	struct bpf_object *object = NULL;
	struct bpf_program *program;
	int attached = 0, failed = 0;
	__u64 *previous = NULL, *current = NULL;
	FILE *json = NULL;
	int exit_code = 0;

	for (int index = 1; index < argc; index++) {
		if (strcmp(argv[index], "--object") == 0 && index + 1 < argc)
			object_path = argv[++index];
		else if (strcmp(argv[index], "--seconds") == 0 && index + 1 < argc)
			seconds = atoi(argv[++index]);
		else if (strcmp(argv[index], "--interval") == 0 && index + 1 < argc)
			interval = atoi(argv[++index]);
		else if (strcmp(argv[index], "--top") == 0 && index + 1 < argc)
			top = atoi(argv[++index]);
		else if (strcmp(argv[index], "--json") == 0 && index + 1 < argc)
			json_path = argv[++index];
		else if (strcmp(argv[index], "--check") == 0)
			check_only = 1, seconds = 1, interval = 1;
		else {
			fprintf(stderr, "usage: %s [--object PATH] [--seconds N] [--interval S] "
					"[--top N] [--json PATH] [--check]\n", argv[0]);
			return 2;
		}
	}
	if (interval < 1)
		interval = 1;

	libbpf_set_print(libbpf_log);
	object = bpf_object__open_file(object_path, NULL);
	if (!object || libbpf_get_error(object)) {
		fprintf(stderr, "cannot open BPF object %s\n", object_path);
		return 1;
	}
	if (bpf_object__load(object) != 0) {
		fprintf(stderr, "cannot load BPF object: %s\n", strerror(errno));
		bpf_object__close(object);
		return 1;
	}

	bpf_object__for_each_program(program, object) {
		const char *section = bpf_program__section_name(program);
		char spec[128];
		char *slash;
		const char *group;
		const char *event;

		if (!section || strncmp(section, "tp/", 3) != 0) {
			fprintf(stderr, "warning: skipping program %s with unexpected section %s\n",
				bpf_program__name(program), section ? section : "(none)");
			failed++;
			continue;
		}
		snprintf(spec, sizeof(spec), "%s", section + 3);
		slash = strchr(spec, '/');
		if (!slash) {
			fprintf(stderr, "warning: malformed tracepoint section %s\n", section);
			failed++;
			continue;
		}
		*slash = '\0';
		group = spec;
		event = slash + 1;
		if (verify_layout(section, group, event) != 0) {
			failed++;
			continue;
		}
		if (attach_tracepoint(program, group, event) > 0)
			attached++;
		else
			failed++;
	}
	if (attached == 0) {
		fprintf(stderr, "no eBPF program could be attached\n");
		bpf_object__close(object);
		return 1;
	}

	struct bpf_map *totals_map = bpf_object__find_map_by_name(object, "totals");
	struct bpf_map *width_map = bpf_object__find_map_by_name(object, "alloc_width");
	struct bpf_map *order_map = bpf_object__find_map_by_name(object, "page_order");
	struct bpf_map *pids_map = bpf_object__find_map_by_name(object, "pid_stats");
	struct bpf_map *sites_map = bpf_object__find_map_by_name(object, "site_ops");
	struct bpf_map *stacks_map = bpf_object__find_map_by_name(object, "alloc_sites");

	if (!totals_map || !width_map || !order_map || !pids_map) {
		fprintf(stderr, "BPF object is missing expected maps\n");
		bpf_object__close(object);
		return 1;
	}
	load_symbols();
	previous = calloc(TOTAL_SLOTS, sizeof(__u64));
	current = calloc(TOTAL_SLOTS, sizeof(__u64));
	read_totals(bpf_map__fd(totals_map), previous);

	if (json_path) {
		json = fopen(json_path, "w");
		if (!json)
			fprintf(stderr, "warning: cannot write %s\n", json_path);
	}
	if (json)
		fprintf(json, "{\"kind\":\"k3-mem-density\",\"interval_seconds\":%d,"
			      "\"samples\":[", interval);

	printf("k3-mem-density: attached %d eBPF programs (%d unavailable)\n", attached, failed);
	int samples = 0;
	struct timespec start, stamp;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (int elapsed = 0; elapsed < seconds; elapsed += interval) {
		sleep(interval);
		if (read_totals(bpf_map__fd(totals_map), current) != 0)
			break;
		samples++;
		clock_gettime(CLOCK_MONOTONIC, &stamp);
		double seconds_elapsed = (stamp.tv_sec - start.tv_sec) +
					 (stamp.tv_nsec - start.tv_nsec) / 1e9;

		__u64 rate[TOTAL_SLOTS];
		for (int slot = 0; slot < TOTAL_SLOTS; slot++)
			rate[slot] = current[slot] - previous[slot];
		if (json) {
			fprintf(json, "%s{\"t_seconds\":%.3f", samples > 1 ? "," : "",
				seconds_elapsed);
			for (int slot = 0; slot < TOTAL_SLOTS; slot++)
				fprintf(json, ",\"%s\":%llu", total_names[slot],
					(unsigned long long)rate[slot]);
			fprintf(json, "}");
		}
		printf("[%5.1fs] rate: alloc=%.0f/s (%.0f KiB/s) free=%.0f/s "
		       "pgalloc=%.0f/s (%.0f pg/s) faults=%.0f/s (r%.0f/w%.0f) "
		       "reclaim=%.0f/s (direct %.0f + kswapd %.0f) "
		       "rw_syscall=%.0f/%.0f/s\n",
		       seconds_elapsed,
		       (double)rate[TOTAL_ALLOC_OPS] / interval,
		       (double)rate[TOTAL_ALLOC_BYTES] / interval / 1024.0,
		       (double)rate[TOTAL_FREE_OPS] / interval,
		       (double)rate[TOTAL_PAGE_ALLOC_OPS] / interval,
		       (double)rate[TOTAL_PAGE_ALLOC_PAGES] / interval,
		       (double)(rate[TOTAL_FAULT_READS] + rate[TOTAL_FAULT_WRITES]) / interval,
		       (double)rate[TOTAL_FAULT_READS] / interval,
		       (double)rate[TOTAL_FAULT_WRITES] / interval,
		       (double)(rate[TOTAL_RECLAIM_DIRECT] + rate[TOTAL_RECLAIM_KSWAPD]) / interval,
		       (double)rate[TOTAL_RECLAIM_DIRECT] / interval,
		       (double)rate[TOTAL_RECLAIM_KSWAPD] / interval,
		       (double)rate[TOTAL_READ_OPS] / interval,
		       (double)rate[TOTAL_WRITE_OPS] / interval);
		fflush(stdout);
		memcpy(previous, current, sizeof(__u64) * TOTAL_SLOTS);
	}
	if (json)
		fprintf(json, "]}");

	__u64 width[ALLOC_BUCKETS] = { 0 }, orders[ORDER_BUCKETS] = { 0 };
	read_array(bpf_map__fd(width_map), width, ALLOC_BUCKETS);
	read_array(bpf_map__fd(order_map), orders, ORDER_BUCKETS);

	__u64 total_allocs = 0;
	for (int index = 0; index < ALLOC_BUCKETS; index++)
		total_allocs += width[index];
	printf("\nwidth density: allocation size distribution (log2 buckets)\n");
	for (int index = 0; index < ALLOC_BUCKETS; index++) {
		if (!width[index])
			continue;
		__u64 low = index == 0 ? 0 : (1ULL << (index - 1));
		__u64 high = 1ULL << index;

		printf("  %6llu .. %6llu B : %10llu ops (%5.1f%%)\n",
		       (unsigned long long)low, (unsigned long long)high,
		       (unsigned long long)width[index],
		       total_allocs ? 100.0 * width[index] / total_allocs : 0.0);
	}
	__u64 total_pages = 0;
	for (int index = 0; index < ORDER_BUCKETS; index++)
		total_pages += orders[index];
	printf("width density: page-allocation order distribution\n");
	for (int index = 0; index < ORDER_BUCKETS; index++) {
		if (!orders[index])
			continue;
		printf("  order %2d : %10llu ops (%5.1f%%)  %llu pages\n", index,
		       (unsigned long long)orders[index],
		       total_pages ? 100.0 * orders[index] / total_pages : 0.0,
		       (unsigned long long)(orders[index] * (1ULL << index)));
	}

	struct pid_row *rows = NULL;
	size_t row_count = 0;
	if (collect_pids(bpf_map__fd(pids_map), &rows, &row_count) == 0) {
		qsort(rows, row_count, sizeof(*rows), compare_rows);
		printf("\nlocating: top processes by allocation and fault activity\n");
		for (size_t index = 0; index < row_count && (int)index < top; index++)
			printf("  pid %-7u %-16s alloc=%llu (%.1f MiB) free=%llu "
			       "faults=%llu(r)/%llu(w) pages=%llu reclaim=%llu\n",
			       rows[index].pid, rows[index].stats.comm,
			       (unsigned long long)rows[index].stats.alloc_ops,
			       rows[index].stats.alloc_bytes / 1048576.0,
			       (unsigned long long)rows[index].stats.free_ops,
			       (unsigned long long)rows[index].stats.fault_reads,
			       (unsigned long long)rows[index].stats.fault_writes,
			       (unsigned long long)rows[index].stats.page_alloc_pages,
			       (unsigned long long)rows[index].stats.reclaim_events);
		free(rows);
	}

	if (sites_map && stacks_map) {
		__u32 *ids = NULL;
		__u64 *counts = NULL;
		size_t site_count = 0;

		if (collect_sites(bpf_map__fd(sites_map), bpf_map__fd(stacks_map),
				  &ids, &counts, &site_count) == 0) {
			struct {
				__u32 id;
				__u64 count;
			} *sites = calloc(site_count ? site_count : 1, sizeof(*sites));

			for (size_t index = 0; index < site_count; index++) {
				sites[index].id = ids[index];
				sites[index].count = counts[index];
			}
			qsort(sites, site_count, sizeof(*sites), compare_sites);
			printf("\nlocating: top kernel stacks requesting memory\n");
			for (size_t index = 0; index < site_count && (int)index < top; index++) {
				printf("  %llu allocations, stack id %u\n",
				       (unsigned long long)sites[index].count, sites[index].id);
				print_stack(bpf_map__fd(stacks_map), sites[index].id);
			}
			free(sites);
			free(ids);
			free(counts);
		}
	}

	__u64 totals_now[TOTAL_SLOTS] = { 0 };
	read_totals(bpf_map__fd(totals_map), totals_now);
	int moved = 0;
	for (int slot = 0; slot < TOTAL_SLOTS; slot++)
		if (totals_now[slot] != 0)
			moved++;

	if (json) {
		fprintf(json, ",\"summary\":{");
		for (int slot = 0; slot < TOTAL_SLOTS; slot++)
			fprintf(json, "%s\"%s\":%llu", slot ? "," : "", total_names[slot],
				(unsigned long long)totals_now[slot]);
		fprintf(json, "},\"attached_programs\":%d,\"unavailable_programs\":%d,"
			      "\"samples\":%d,\"counters_moved\":%d}\n",
			attached, failed, samples, moved);
		fclose(json);
	}
	if (check_only) {
		printf("\ncheck: %d/%d programs attached, %d counter families moved\n",
		       attached, attached + failed, moved);
		exit_code = (attached > 0 && moved > 0) ? 0 : 1;
	}

	bpf_object__close(object);
	free(previous);
	free(current);
	free(symbols);
	return exit_code;
}
