#!/bin/sh
# Deliver the memory-density probe to the K3 board and collect its report.
#
#   run.sh                    30 s window, no extra workload
#   run.sh --seconds N        bounded window
#   run.sh --workload         also run the bundled allocation workload
#   run.sh --check            load-only smoke test, non-zero on failure
#   run.sh --core             load the CO-RE object (needs the board's BTF)
#   run.sh --align-at EPOCH   hold the window until a common wall-clock second
#   run.sh --evidence DIR     also copy the raw report into DIR (outside Git)
#
# The board credentials come from the workspace record <workspace>/.ssh-k3 and
# are never printed.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
WORKSPACE=$(CDPATH='' cd -- "$ROOT/../.." && pwd)
CREDENTIALS=${K3_MEM_CREDENTIALS:-"$WORKSPACE/.ssh-k3"}
BUILD=${K3_MEM_OUT:-$WORKSPACE/.local/k3-mem-density/build}
STAGE=/tmp/k3-mem-density

SECONDS_WINDOW=30
WORKLOAD=0
CHECK=0
CORE=0
EVIDENCE=
EXTRA=
while [ $# -gt 0 ]; do
    case "$1" in
        --seconds) SECONDS_WINDOW=$2; shift 2 ;;
        --workload) WORKLOAD=1; shift ;;
        --check) CHECK=1; shift ;;
        --core) CORE=1; shift ;;
        --align-at) EXTRA="$EXTRA --align-at $2"; shift 2 ;;
        --evidence) EVIDENCE=$2; shift 2 ;;
        --probe-bandwidth) EXTRA="$EXTRA --probe-bandwidth"; shift ;;
        --peak-mib-s) EXTRA="$EXTRA --peak-mib-s $2"; shift 2 ;;
        --pid) EXTRA="$EXTRA --pid $2"; shift 2 ;;
        *) echo "usage: $0 [--seconds N] [--workload] [--check] [--core]" >&2
           echo "          [--align-at EPOCH] [--probe-bandwidth] [--peak-mib-s N]" >&2
           echo "          [--pid PID] [--evidence DIR]" >&2
           exit 2 ;;
    esac
done

for artifact in mem_density mem_density.bpf.o alloc_stress; do
    [ -f "$BUILD/$artifact" ] || {
        echo "missing artifact $BUILD/$artifact; run scripts/build.sh" >&2
        exit 1
    }
done
OBJECT=mem_density.bpf.o
if [ "$CORE" = 1 ]; then
    [ -f "$BUILD/mem_density_core.bpf.o" ] || {
        echo "missing artifact $BUILD/mem_density_core.bpf.o; build first (needs" >&2
        echo "the board's BTF: hardware/k3-monitor/scripts/run.sh btf-pull)" >&2
        exit 1
    }
    OBJECT=mem_density_core.bpf.o
    EXTRA="$EXTRA --core"
fi
command -v sshpass >/dev/null 2>&1 || { echo "sshpass is required" >&2; exit 1; }

[ -r "$CREDENTIALS" ] || { echo "cannot read credentials: $CREDENTIALS" >&2; exit 1; }
mode=$(stat -c '%a' "$CREDENTIALS")
[ "$mode" = "600" ] || { echo "credentials must be mode 0600 (found $mode)" >&2; exit 1; }

host=; user=; secret=
while read -r host_field user_field secret_field _rest; do
    host=$host_field; user=$user_field; secret=$secret_field; break
done < "$CREDENTIALS"
if [ -z "$host" ] || [ -z "$user" ] || [ -z "$secret" ]; then
    echo "credentials record must contain: host account secret" >&2
    exit 1
fi

SSHPASS=$secret
export SSHPASS
# A board whose address changed is reached without editing the credential
# record: export K3_BOARD_HOST=<address> for this invocation.
[ -n "${K3_BOARD_HOST:-}" ] && host=$K3_BOARD_HOST
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$WORKSPACE/.local/known_hosts \
-o ConnectTimeout=20 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password,publickey"
DEST="$user@$host"

# shellcheck disable=SC2086
remote() { sshpass -e ssh $SSH_OPTS "$DEST" "$@"; }

remote "mkdir -p $STAGE"
# shellcheck disable=SC2086
sshpass -e scp -q $SSH_OPTS \
    "$BUILD/mem_density" "$BUILD/mem_density.bpf.o" "$BUILD/alloc_stress" \
    "$DEST:$STAGE/"
if [ "$CORE" = 1 ]; then
    sshpass -e scp -q $SSH_OPTS "$BUILD/mem_density_core.bpf.o" "$DEST:$STAGE/"
fi

if [ "$CHECK" = 1 ]; then
    if remote "cd $STAGE && ./mem_density --object ./$OBJECT --check $EXTRA"; then
        exit 0
    fi
    exit 1
fi

RUN="cd $STAGE && ./mem_density --object ./$OBJECT --seconds $SECONDS_WINDOW --json report.json $EXTRA"
if [ "$WORKLOAD" = 1 ]; then
    # several concurrent allocators so SLUB/zone contention and fragmentation
    # show up instead of a single thread's private fast path
    RUN="cd $STAGE && (./alloc_stress $((SECONDS_WINDOW - 1)) 256 6 &) && $RUN"
fi
remote "$RUN" | tee "$BUILD/report.txt"
sshpass -e scp -q $SSH_OPTS "$DEST:$STAGE/report.json" "$BUILD/report.json" || true

if [ -n "$EVIDENCE" ]; then
    mkdir -p "$EVIDENCE"
    cp "$BUILD/report.txt" "$BUILD/report.json" "$EVIDENCE/"
    sha256sum "$EVIDENCE"/* > "$EVIDENCE/SHA256SUMS"
    echo "evidence written to $EVIDENCE"
fi
