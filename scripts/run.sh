#!/bin/sh
# Deliver the memory-density probe to the K3 board and collect its report.
#
#   run.sh                    30 s window, no extra workload
#   run.sh --seconds N        bounded window
#   run.sh --workload         also run the bundled allocation workload
#   run.sh --check            load-only smoke test, non-zero on failure
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
EVIDENCE=
while [ $# -gt 0 ]; do
    case "$1" in
        --seconds) SECONDS_WINDOW=$2; shift 2 ;;
        --workload) WORKLOAD=1; shift ;;
        --check) CHECK=1; shift ;;
        --evidence) EVIDENCE=$2; shift 2 ;;
        *) echo "usage: $0 [--seconds N] [--workload] [--check] [--evidence DIR]" >&2
           exit 2 ;;
    esac
done

for artifact in mem_density mem_density.bpf.o alloc_stress; do
    [ -f "$BUILD/$artifact" ] || {
        echo "missing artifact $BUILD/$artifact; run scripts/build.sh" >&2
        exit 1
    }
done
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

if [ "$CHECK" = 1 ]; then
    if remote "cd $STAGE && ./mem_density --object ./mem_density.bpf.o --check"; then
        exit 0
    fi
    exit 1
fi

RUN="cd $STAGE && ./mem_density --object ./mem_density.bpf.o --seconds $SECONDS_WINDOW --json report.json"
if [ "$WORKLOAD" = 1 ]; then
    RUN="cd $STAGE && (./alloc_stress $((SECONDS_WINDOW - 1)) 128 &) && $RUN"
fi
remote "$RUN" | tee "$BUILD/report.txt"
sshpass -e scp -q $SSH_OPTS "$DEST:$STAGE/report.json" "$BUILD/report.json" || true

if [ -n "$EVIDENCE" ]; then
    mkdir -p "$EVIDENCE"
    cp "$BUILD/report.txt" "$BUILD/report.json" "$EVIDENCE/"
    sha256sum "$EVIDENCE"/* > "$EVIDENCE/SHA256SUMS"
    echo "evidence written to $EVIDENCE"
fi
