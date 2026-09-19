[English](README.md)

# K3 内存密度探针

基于内核 eBPF 的测量工具，用于在 SpacemiT K3 Pico ITX 上度量**内存使用密度**，
并定位产生这些行为的代码。它适合与 AI 或评测负载一起运行在 X100 核心（0-7）上，
回答“这个程序的内存行为密度有多高、来源在哪里”。

工具输出三种密度以及定位视图：

| 密度 | 度量方式 | 探针 |
|---|---|---|
| 速率 | 每秒分配、释放、页分配、页释放、缺页（读/写）、回收以及读写系统调用次数 | `kmem:kmalloc`、`kmem:kmem_cache_alloc`、`kmem:kfree`、`kmem:kmem_cache_free`、`kmem:mm_page_alloc`、`kmem:mm_page_free`、`exceptions:page_fault_user`、`exceptions:page_fault_kernel`、`vmscan:mm_vmscan_direct_reclaim_begin`、`vmscan:mm_vmscan_kswapd_wake`、`syscalls:sys_enter_read`、`syscalls:sys_enter_write` |
| 宽度 | 分配大小直方图与页分配 order 直方图 | kmalloc 事件的 `bytes_alloc`、`mm_page_alloc` 的 `order` |
| 空间与深度 | 缺页频率（读写分开）以及每秒直接回收与 kswapd 压力 | 缺页事件的 `error_code`、vmscan 事件 |
| 定位 | 按进程的分配与缺页排名，以及申请内存最多的内核栈 | 按 pid 聚合与 `bpf_get_stackid` |
| 分配层瓶颈 | 锁竞争速率、持 zone 锁的页分配、碎片回退、每 CPU 页链表抖动，含最热竞争锁与竞争栈 | `lock:contention_begin`、`lock:contention_end`、`kmem:mm_page_alloc_zone_locked`、`kmem:mm_page_alloc_extfrag`、`kmem:mm_page_free_batched`、`kmem:mm_page_pcpu_drain` |
| 硬件饱和 | IPC、L1D 读缺失率、MPKI，以及 LLC 与内存系统实际看到的“越过 L1”流量估算，并可对照标定峰值给出利用率 | SoC PMU（`cycles`、`instructions`、`L1-dcache-*`） |

## 软件瓶颈视图与硬件饱和视图

两部分回答不同问题，因此分开报告：

- **分配层瓶颈**是软件侧信号：SLUB 每缓存锁竞争（`lock:contention_begin`，含竞争锁
  地址与争夺它的调用栈）、伙伴系统的 zone 锁路径
  （`kmem:mm_page_alloc_zone_locked`）、伙伴系统碎片回退
  （`kmem:mm_page_alloc_extfrag`，报告为分配 order → 回退 order），以及每 CPU 页
  链表抖动（`mm_page_free_batched`、`mm_page_pcpu_drain`）。
- **硬件饱和**是内存系统侧信号：越过 L1 的流量，也就是 LLC 与内存控制器看到的
  流量，由 L1D 读/写缺失计数乘以 64 B 缓存行估算，同时给出 MPKI 与 IPC。用
  `--probe-bandwidth` 标定一次峰值后，报告会给出总线利用率百分比。

本 SoC **没有 LLC 计数器，也没有内存控制器计数器**（PMU 不提供 `LLC-*` 与
`dTLB-*`，`rvtrace` PMU 只用于 trace 编码），因此 LLC 缺失密度与 DDR 饱和度无法
直接读取。越过 L1 的流量估算是当前可观测的最近似量，且始终标注为估算值，绝不冒
充为原始计数器。

## A100（AI 簇）覆盖范围与编译参数

8–15 号核是进迭时空的 A100 AI 簇。在更新后的 K3 板上实测：

- Linux 无法把普通任务调度到这些核上（`taskset -c 8` 与 `sched_setaffinity`
  返回 `EINVAL`），而且即使 AI 运行时正在初始化，`/proc/stat` 中 cpu8-15 的
  user 与 system 时间仍为 0。
- 但硬件计数器会动：对 cpu8-15 做系统级 `perf` 能看到 cycles、instructions 与
  L1D 活动，因此探针的 A100 视图来自按 CPU 的系统级 PMU 计数，并标注为
  AI 运行时核心。
- 厂商 AI 运行时自己也印证了这个分工：`llama-bench` 输出
  `cpu_mask: ff00`、`aicpu_id_offset: 8`、`use_ime2: 1` 与 TCM 块信息，即其算子
  运行在 8–15 号核上。
- 面向 A100 的代码必须让编译器显式指定：工作区 GCC 与 clang-23 都接受
  `-mcpu=spacemit-a100`，它会选择 A100 调度模型与向量 ISA（clang 还会定义
  `__riscv_v`）。不带该参数编译只会得到 X100/通用代码。

## 在本板上的实现方式

探针是一组 tracepoint 程序，由同一套计量逻辑编译出两个对象：

- `mem_density_core.bpf.o` 是 CO-RE 版本：从运行中的内核自身 BTF
  （`/sys/kernel/btf/vmlinux`，由 `hardware/k3-monitor/scripts/run.sh btf-pull`
  生成 `vmlinux.h`）取 trace 条目结构，通过 `bpf_core_read` 读取字段，因此不
  编译任何偏移。用 `--core` 加载。
- `mem_density.bpf.o` 是偏移版本：按
  `/sys/kernel/tracing/events/<group>/<name>/format` 中公布的固定偏移读取 trace
  条目字段，加载器在挂载前逐一校验它依赖的每个偏移，不一致就拒绝挂载，是没有
  BTF 的内核上的后备方案。

即使 CO-RE 对象里也有两个 tracepoint 保留偏移校验，这是实测结论而非取巧：本内核
BTF 中没有 `trace_event_raw_page_fault_user/_kernel`（只有 `btf_trace_*` 原型），
`mm_vmscan_direct_reclaim_begin` 以 `*_template` 类型发布，这些字段没有可用于
CO-RE 解析的类型信息。

这里也不能使用 raw tracepoint：本工具需要的尺寸是内核计算进条目的字段，而不是
tracepoint 的参数。

eBPF 程序在主机上用 `clang-23 -target bpf` 编译；加载器用工作区 spacemit 工具链
交叉编译，并链接板卡自带的 `libbpf`。板卡上无需安装任何东西。

## 挂载、覆盖范围与测量说明

以下均为板上实测而非推断，因为它们都改变数字的含义：

- **一次挂载即覆盖全部 CPU。** tracepoint 程序存放在 tracepoint 自己的程序数组
  里（`perf_event_attach_bpf_prog()` -> `bpf_prog_array_copy()`，数组挂在
  `event->tp_event` 上），而不是存在于 perf event 中。把同一程序再挂到另一个
  CPU 的 perf event 会返回 `EEXIST`，那是重复而不是失败。实测：把负载绑到 cpu 5，
  程序只通过 cpu 0 的 event 挂载，收集器计得 71,265 次分配与 63,838 次缺页，
  内核自身 perf 计数器为 71,436 与 64,212（-0.2 % 与 -0.6 %）。
- **perf 无法在同一时刻统计同一 tracepoint。** 只要挂了 BPF 程序，
  `trace_call_bpf()` 就会吃掉该事件，`perf_trace_run_bpf_submit()` 跳过 perf
  ring-buffer 路径，于是 `perf stat -e kmem:kmalloc` 对该 tracepoint 报 0。
  因此基准值必须在另一个时间窗内单独测量。
- **两个收集器可以共用同一个时间窗。** `--align-at EPOCH` 让测量起点对齐到同一
  个墙上时钟秒，逐 tick 序列与汇总都取自该时刻到最后一个采样点，于是
  `summary == sum(ticks)`，A/B 比较不再测到挂载耗时差。
- **重复性上限。** 同一对象的两次运行在同一对齐窗口内：`kmem_cache_alloc`/`free`、
  `mm_page_alloc`/`free`、缺页与 `read_bytes` 完全一致（0.00 %），分配字节数
  相差不超过 0.1 %，分配总次数最多相差 1.2 %。全部残差集中在占比约 7 % 的
  `kmalloc`/`kfree` 家族——同一对象两次运行在该家族上就能相差 16.9 %——因此该
  家族的分辨率只有百分之几，与此同量级的 CO-RE 与偏移版本差异（16.3 %）属于该
  噪声，而不是移植缺陷。

## 构建、运行、验证

```sh
hardware/k3-mem-density/scripts/build.sh
hardware/k3-mem-density/scripts/run.sh --check
hardware/k3-mem-density/scripts/run.sh --probe-bandwidth --seconds 3
hardware/k3-mem-density/scripts/run.sh --seconds 30 --workload \
  --evidence /root/k3-evidence/k3-mem-density/<run-id>
```

`--check` 会加载并挂载全部程序，若没有任何计数器变化则失败。`--workload` 会同时
运行自带的合成分配负载，按需触发四种密度。`--evidence` 会把原始报告复制到所有
Git 仓库之外。板卡访问使用工作区记录 `<workspace>/.ssh-k3`，该文件必须是
`0600`，且绝不打印其内容。

`--probe-bandwidth` 测量板卡可达到的流式带宽，为饱和率提供参照；`--peak-mib-s`
可用已知峰值代替；`--pid` 把硬件视图限制在某一个进程上。

## 常驻服务

`systemd/k3-mem-density.service` 以 10 秒间隔把序列写入
`/run/k3-mem-density/latest.json`，便于长时间 AI 运行期间观察。

## K3 Pico ITX 实测（2026-09-16）

| 指标 | 实测 |
|---|---|
| 分配速率 | 桌面空闲水平下 9–12 k 次/秒（7 MB/s） |
| 页分配速率 | 约 296 k 页/秒，99.9 % 为 order 0 |
| 缺页 | 约 7.1 k/秒，约 1.95 k 读 / 5.1 k 写 |
| 回收 | 稳态为 0，分配风暴期间 16–18 次/秒 |
| 最宽区间 | 256–512 B（占分配次数 47.6 %） |
| 最大分配者 | 合成负载，52 k 次分配共 28.7 MiB |
| 锁竞争 | 线程化分配负载下 14 秒内 425 次开始（30 次/秒） |
| 持 zone 锁的页分配 | 14 秒内 913 k 次（65 k 次/秒），即伙伴系统 zone 锁路径 |
| 碎片回退 | 42 次，表现为 order 0 回退到 order 4、6、7 |
| 越过 L1 流量 | 136–157 MiB/s，L1D 读缺失 0.8–1.1 %、MPKI 0.15–0.30，即标定峰值的 0.9–1.4 % |
| 流式峰值 | 8 个 X100 线程 17771 MiB/s，单线程 10347 MiB/s（读+写） |

## 限制

- 内存读写操作本身不可直接观测；工具改为报告缺页的读/写密度与读写系统调用密度。
- 大块分配会绕过 `kmalloc`（直接走页分配器），这正是页 order 直方图所显示的。
- 回收压力只在板卡真正有压力时可见；空闲板卡报告为 0 是正确结果，而不是缺失。
- 本 SoC 没有 LLC 与 DDR 饱和度计数器；越过 L1 的流量估算是内存系统流量的下限，
  因为预取与硬件发起的流量未计入。

## 工作区集成

本仓库位于 `hardware/k3-mem-density`，自带 Git 历史。它目前还没有登记到工作区
manifest 中，因为 manifest 会从共享远端解析 `k3-mem-density.git`，而首次 push
仍需人工批准。远端仓库就绪后，把下面这行加入 `default.xml`：

```xml
<project name="k3-mem-density.git" path="hardware/k3-mem-density" />
```
