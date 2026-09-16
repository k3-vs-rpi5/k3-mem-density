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
hardware/k3-mem-density/scripts/run.sh --seconds 30 --workload \
  --evidence /root/k3-evidence/k3-mem-density/<run-id>
```

`--check` 会加载并挂载全部程序，若没有任何计数器变化则失败。`--workload` 会同时
运行自带的合成分配负载，按需触发四种密度。`--evidence` 会把原始报告复制到所有
Git 仓库之外。板卡访问使用工作区记录 `<workspace>/.ssh-k3`，该文件必须是
`0600`，且绝不打印其内容。

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

## 限制

- 内存读写操作本身不可直接观测；工具改为报告缺页的读/写密度与读写系统调用密度。
- 大块分配会绕过 `kmalloc`（直接走页分配器），这正是页 order 直方图所显示的。
- 回收压力只在板卡真正有压力时可见；空闲板卡报告为 0 是正确结果，而不是缺失。
