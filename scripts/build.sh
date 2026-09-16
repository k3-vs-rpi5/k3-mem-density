#!/bin/sh
# Cross-build the memory-density loader, its eBPF object and the workload.
#
# Everything is built on the host: the eBPF programs with clang (BPF target)
# and the riscv64 binaries with the workspace SpacemiT toolchain, linked against
# the board's own libbpf. No device side effects.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
WORKSPACE=$(CDPATH='' cd -- "$ROOT/../.." && pwd)
CLANG=${K3_MEM_CLANG:-clang-23}
TOOLCHAIN=${K3_MEM_TOOLCHAIN:-$WORKSPACE/spacemit-toolchain-linux-glibc-x86_64-v1.2.2}
LIBBPF_DIR=${K3_MEM_LIBBPF_DIR:-$WORKSPACE/.local/k3-tools/riscv64/lib}
INCLUDE_DIR=${K3_MEM_INCLUDE_DIR:-$WORKSPACE/.local/k3-tools/include}
OUT=${K3_MEM_OUT:-$WORKSPACE/.local/k3-mem-density/build}

command -v "$CLANG" >/dev/null 2>&1 || {
    echo "missing BPF compiler: $CLANG" >&2
    exit 1
}
[ -x "$TOOLCHAIN/bin/riscv64-unknown-linux-gnu-gcc" ] || {
    echo "missing workspace cross toolchain: $TOOLCHAIN" >&2
    exit 1
}
[ -e "$LIBBPF_DIR/libbpf.so" ] || {
    echo "missing the board libbpf used for cross-linking: $LIBBPF_DIR/libbpf.so" >&2
    echo "copy it from the board: /usr/lib/riscv64-linux-gnu/libbpf.so.1.6.3" >&2
    exit 1
}

mkdir -p "$OUT"

"$CLANG" -target bpf -O2 -g -Wall \
    -I"$INCLUDE_DIR" \
    -I/usr/include -I/usr/include/x86_64-linux-gnu \
    -c "$ROOT/src/bpf/mem_density.bpf.c" -o "$OUT/mem_density.bpf.o"

"$TOOLCHAIN/bin/riscv64-unknown-linux-gnu-gcc" -O2 -Wall -Wextra \
    -I"$INCLUDE_DIR" --sysroot="$TOOLCHAIN/sysroot" \
    -L"$LIBBPF_DIR" -o "$OUT/mem_density" "$ROOT/src/loader/mem_density.c" \
    -lbpf -lelf -lz -lzstd \
    -Wl,-rpath-link="$LIBBPF_DIR" -Wl,-rpath,/usr/lib/riscv64-linux-gnu

"$TOOLCHAIN/bin/riscv64-unknown-linux-gnu-gcc" -O2 -Wall -pthread \
    --sysroot="$TOOLCHAIN/sysroot" \
    -o "$OUT/alloc_stress" "$ROOT/src/workload/alloc_stress.c"

sh -n "$ROOT/scripts/run.sh"

echo "cli: $("$CLANG" --version | head -1)"
echo "toolchain: $("$TOOLCHAIN/bin/riscv64-unknown-linux-gnu-gcc" --version | head -1)"
echo "artifacts:"
sha256sum "$OUT/mem_density.bpf.o" "$OUT/mem_density" "$OUT/alloc_stress"
