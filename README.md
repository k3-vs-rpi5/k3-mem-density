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

## How it works on this board

The K3 kernel has no BTF (`CONFIG_DEBUG_INFO_BTF` unset, no
`/sys/kernel/btf/vmlinux`) and bpftrace refuses to parse tracepoint arguments
without it, so the probe is a set of ordinary tracepoint programs that read the
trace-entry fields at fixed offsets taken from
`/sys/kernel/tracing/events/<group>/<name>/format`. Before attaching anything,
the loader verifies every offset it depends on and refuses to attach on a
mismatch; that is also why the raw-tracepoint form is not used: the sizes this
tool needs are fields the kernel computes into the entry, not tracepoint
arguments.

The eBPF programs are compiled on the host with `clang-23 -target bpf`; the
loader is cross-compiled with the workspace SpacemiT toolchain and links the
board's own `libbpf`. Nothing has to be installed on the board.

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
| beyond-L1 traffic | 136-138 MiB/s at 1.0 % L1D load miss and MPKI 0.26-0.30 |
| single-core streaming peak | 10151 MiB/s of read+write traffic |

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
