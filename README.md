[中文](README.zh-CN.md)

# K3 memory density probe

Kernel-eBPF tooling that measures **memory usage density** on the SpacemiT K3
Pico ITX and points at the code responsible for it. It is meant to run next to
an AI or benchmark workload on the X100 cores (0-7) and answer "how dense is
this program's memory behaviour, and where does it come from".

It reports three densities plus the locating views:

| density | measured as | probe |
|---|---|---|
| rate | allocation, free, page-allocation, page-free, page-fault (read and write), reclaim and read/write syscall operations per second | `kmem:kmalloc`, `kmem:kmem_cache_alloc`, `kmem:kfree`, `kmem:kmem_cache_free`, `kmem:mm_page_alloc`, `kmem:mm_page_free`, `exceptions:page_fault_user`, `exceptions:page_fault_kernel`, `vmscan:mm_vmscan_direct_reclaim_begin`, `vmscan:mm_vmscan_kswapd_wake`, `syscalls:sys_enter_read`, `syscalls:sys_enter_write` |
| width | histogram of allocation sizes and page-allocation orders | `bytes_alloc` of the kmalloc events, `order` of `mm_page_alloc` |
| space and depth | page-fault frequency split into read and write faults, plus direct-reclaim and kswapd pressure per second | `error_code` of the fault events, vmscan events |
| locating | top processes by allocation and fault activity, and the top kernel stacks that request memory | per-pid aggregation and `bpf_get_stackid` |
| allocation-layer bottlenecks | lock contention rate, zone-locked page allocations, fragmentation fallbacks and per-CPU page-list churn, with the most contended lock and the top contention stacks | `lock:contention_begin`, `lock:contention_end`, `kmem:mm_page_alloc_zone_locked`, `kmem:mm_page_alloc_extfrag`, `kmem:mm_page_free_batched`, `kmem:mm_page_pcpu_drain` |
| hardware saturation | IPC, L1D load miss ratio, MPKI and the beyond-L1 traffic estimate the LLC and memory system actually see, with a utilisation figure against a calibrated peak | the SoC PMU (`cycles`, `instructions`, `L1-dcache-*`) |

## Software bottleneck view versus hardware saturation view

The two halves answer different questions and are reported separately:

- **allocation-layer bottlenecks** are the software signals: SLUB per-cache lock
  contention (`lock:contention_begin`, with the contended lock address and the
  stack that fights for it), the buddy allocator zone-lock path
  (`kmem:mm_page_alloc_zone_locked`), buddy fragmentation fallbacks
  (`kmem:mm_page_alloc_extfrag`, reported as alloc order to fallback order) and
  per-CPU page-list churn (`mm_page_free_batched`, `mm_page_pcpu_drain`).
- **hardware saturation** is the memory-system signal: beyond-L1 traffic, which
  is what the LLC and the memory controller see, derived from the L1D load and
  store miss counters times the 64 B cache line, together with MPKI and IPC.
  Calibrate the peak once with `--probe-bandwidth` and the report becomes a bus
  utilisation percentage.

This SoC exposes **no LLC and no memory-controller counters** (`LLC-*` and
`dTLB-*` are not provided by the PMU, and the `rvtrace` PMU only encodes
trace), so LLC-miss density and DDR saturation cannot be read directly. The
beyond-L1 traffic estimate is the closest observable quantity and is always
labelled as an estimate, never presented as a raw counter.

## A100 (AI cluster) coverage and build parameters

Cores 8-15 are the SpacemiT A100 AI cluster. Measured on the updated K3 board:

- Linux cannot schedule ordinary tasks there (`taskset -c 8` and
  `sched_setaffinity` fail with `EINVAL`), and `/proc/stat` reports zero user
  and system time on cpu8-15 even while the AI runtime is initialising.
- The hardware counters do move: system-wide `perf` on cpu8-15 shows cycles,
  instructions and L1D activity, so the probe takes its A100 view from
  per-CPU system-wide PMU counting and labels it as AI-runtime cores.
- The vendor AI runtime confirms the split itself: `llama-bench` reports
  `cpu_mask: ff00`, `aicpu_id_offset: 8`, `use_ime2: 1` and TCM blocks, i.e.
  its operators run on cores 8-15.
- Code that targets A100 must ask the compiler for it: both the workspace GCC
  and clang-23 accept `-mcpu=spacemit-a100`, which selects the A100 scheduling
  model and the vector ISA (clang also reports `__riscv_v`). Compiling A100
  kernels without that parameter produces X100/generic code.

## How it works on this board

The probe is a set of tracepoint programs. Two objects are built from the same
accounting:

- `mem_density_core.bpf.o` is CO-RE: it takes the trace-entry structs from the
  running kernel's own BTF (`/sys/kernel/btf/vmlinux`, generated into a
  `vmlinux.h` by `hardware/k3-monitor/scripts/run.sh btf-pull`) and reads the
  fields through `bpf_core_read`, so no offset is compiled in. Load it with
  `--core`.
- `mem_density.bpf.o` is the offset form: it reads the trace-entry fields at
  fixed offsets taken from `/sys/kernel/tracing/events/<group>/<name>/format`,
  and the loader verifies every offset it depends on and refuses to attach on a
  mismatch. It is the fallback for a kernel without BTF.

Two tracepoints stay on validated offsets even in the CO-RE object, and that is
a measurement rather than a shortcut: this kernel's BTF carries no
`trace_event_raw_page_fault_user/_kernel` (only the `btf_trace_*` prototypes)
and ships `mm_vmscan_direct_reclaim_begin` as a `*_template` type, so those
fields have no type information to resolve against.

Raw tracepoints are not usable here: the sizes this tool needs are fields the
kernel computes into the trace entry, not tracepoint arguments.

The eBPF programs are compiled on the host with `clang-23 -target bpf`; the
loader is cross-compiled with the workspace SpacemiT toolchain and links the
board's own `libbpf`. Nothing has to be installed on the board.

## Attachment, coverage and measurement notes

Measured on the board rather than assumed, because each of these changes what a
number means:

- **One attach covers every CPU.** A tracepoint program is stored in the
  tracepoint's own program array (`perf_event_attach_bpf_prog()` ->
  `bpf_prog_array_copy()`, which keeps the array on `event->tp_event`), not in
  the perf event. Attaching the same program to a second CPU's perf event
  returns `EEXIST`, which is a duplicate, not a failure. Verified: with the
  workload pinned to cpu 5 and the program attached through cpu 0's event only,
  the collector counted 71,265 allocations and 63,838 faults against the
  kernel's own perf counters at 71,436 and 64,212 (-0.2 % and -0.6 %).
- **perf cannot count the same tracepoint at the same time.** While a BPF
  program is attached, `trace_call_bpf()` consumes the event and
  `perf_trace_run_bpf_submit()` skips the perf ring-buffer path, so
  `perf stat -e kmem:kmalloc` reports exactly 0 for that tracepoint. Ground
  truth has to be measured in a separate window.
- **Two collectors can share one window.** `--align-at EPOCH` holds the
  measurement start until a common wall-clock second, and both the per-tick
  series and the summary are taken between that instant and the last sample, so
  `summary == sum(ticks)` and an A/B comparison no longer measures attach-time
  skew.
- **Repeatability limit.** Two runs of the *same* object over one aligned
  window agreed exactly on `kmem_cache_alloc`/`free`, `mm_page_alloc`/`free`,
  page faults and `read_bytes` (0.00 %), within 0.1 % on allocation bytes, and
  differed by up to 1.2 % on total allocation count. The whole residual sits in
  the rare `kmalloc`/`kfree` family (about 7 % of events), where two runs of one
  object differed by 16.9 % in one run - so that family carries no better than
  a few-percent resolution, and a CO-RE-versus-offsets difference of the same
  size (16.3 %) is that noise, not a port defect.

## Build, run, verify

```sh
hardware/k3-mem-density/scripts/build.sh
hardware/k3-mem-density/scripts/run.sh --check
hardware/k3-mem-density/scripts/run.sh --probe-bandwidth --seconds 3
hardware/k3-mem-density/scripts/run.sh --seconds 30 --workload \
  --evidence /root/k3-evidence/k3-mem-density/<run-id>
```

`--check` loads and attaches every program and fails if no counter moves.
`--workload` also runs the bundled synthetic allocator so the four densities are
exercised on demand. `--evidence` copies the raw report outside every Git
repository. Board access uses the workspace record `<workspace>/.ssh-k3`, which
must be mode `0600` and is never printed.

`--probe-bandwidth` measures the achievable streaming bandwidth of the board so
the saturation figure has a reference; `--peak-mib-s` supplies a known peak
instead, and `--pid` restricts the hardware view to one process.

## Installed service

`systemd/k3-mem-density.service` keeps a 10 s-cadence series in
`/run/k3-mem-density/latest.json` for long AI runs.

## Measured on the K3 Pico ITX (2026-09-16)

| metric | observed |
|---|---|
| allocation rate | 9-12 k ops/s (7 MB/s) at the desktop's idle level |
| page-allocation rate | about 296 k pages/s, 99.9 % order 0 |
| page faults | about 7.1 k/s, split about 1.95 k read / 5.1 k write |
| reclaim | 0 in steady state, 16-18 events/s during the allocation storm |
| widest bucket | 256-512 B (47.6 % of allocations) |
| top allocator | the synthetic workload, 28.7 MiB in 52 k allocations |
| lock contention | 425 begins in 14 s (30/s) during the threaded allocation workload |
| zone-locked page allocations | 913 k in 14 s (65 k/s), the buddy zone-lock path |
| fragmentation fallbacks | 42, seen as order 0 falling back to order 4, 6 and 7 |
| beyond-L1 traffic | 136-157 MiB/s at 0.8-1.1 % L1D load miss, MPKI 0.15-0.30, i.e. 0.9-1.4 % of the calibrated peak |
| streaming peak | 17771 MiB/s with 8 X100 threads, 10347 MiB/s with one thread (read+write) |

## Limitations

- Memory read/write operations are not directly observable; the tool reports
  page-fault read/write density and read/write syscall density instead.
- Large allocations bypass `kmalloc` (they go straight to the page allocator),
  which is exactly what the page-order histogram shows.
- Reclaim pressure is only visible when the board is actually under pressure;
  an idle board reports zero, which is correct rather than missing.
- LLC misses and DDR saturation have no counters on this SoC; the beyond-L1
  traffic estimate is a lower bound of memory-system traffic, because prefetch
  and hardware-initiated traffic are not counted.

## Workspace integration

This repository lives at `hardware/k3-mem-density` and carries its own Git
history. It is not listed in the workspace manifest yet, because the manifest
resolves `k3-mem-density.git` from the shared remote and the first push still
needs human approval. Once the remote repository exists, add this entry to
`default.xml`:

```xml
<project name="k3-mem-density.git" path="hardware/k3-mem-density" />
```
