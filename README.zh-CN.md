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

## 在本板上的实现方式

K3 内核没有 BTF（未开启 `CONFIG_DEBUG_INFO_BTF`，也没有
`/sys/kernel/btf/vmlinux`），而 bpftrace 在没有 BTF 时拒绝解析 tracepoint
参数，因此探针由一组普通 tracepoint 程序构成，按
`/sys/kernel/tracing/events/<group>/<name>/format` 中公布的固定偏移读取 trace
条目字段。加载器在挂载前会逐一校验它依赖的每个偏移，不一致就拒绝挂载；这也是
不使用 raw tracepoint 的原因：本工具需要的尺寸是内核计算进条目的字段，而不是
tracepoint 的参数。

eBPF 程序在主机上用 `clang-23 -target bpf` 编译；加载器用工作区 spacemit 工具链
交叉编译，并链接板卡自带的 `libbpf`。板卡上无需安装任何东西。

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
| 越过 L1 流量 | 136–138 MiB/s，L1D 读缺失 1.0 %、MPKI 0.26–0.30 |
| 单核流式峰值 | 读+写合计 10151 MiB/s |

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
