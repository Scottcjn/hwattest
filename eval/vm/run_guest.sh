#!/bin/bash
# Boot a local throwaway QEMU guest, run eval/collect.py inside it, copy the
# JSONL back, power the guest off. No root needed (KVM via the kvm group).
#
# Usage: eval/vm/run_guest.sh MODE RUNS OUT.jsonl [LOAD_PROCS]
#   MODE: kvm          KVM, -cpu host (stock VM, all the usual tells)
#         kvm_hidden   KVM, -cpu host,-hypervisor,kvm=off + SMBIOS spoofed to an OEM
#                      (the "VM-hiding" adversary)
#         tcg          pure emulation (TCG), -cpu max
#         tcg_hardened TCG, SMBIOS + CPU model string spoofed
#
# Needs: qemu-system-x86_64, sshpass, a cloud image with python3 >= 3.9 whose
# cloud-init seed sets user "ubuntu" / password "hwfp" (BASE_IMG / SEED_ISO).
set -euo pipefail
MODE="$1"; RUNS="$2"; OUT="$3"; LOAD="${4:-0}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
BASE_IMG="${BASE_IMG:-/home/scott/hwfp-bench/tcg-lab/amd64.img}"
SEED_ISO="${SEED_ISO:-/home/scott/hwfp-bench/tcg-lab/seed.iso}"
WORK="$HERE/work/$MODE"
PORT="${PORT:-22$((RANDOM % 90 + 10))}"
mkdir -p "$WORK"
rm -f "$WORK"/overlay.qcow2 "$WORK"/qemu.pid

qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_IMG" "$WORK/overlay.qcow2"
cp "$SEED_ISO" "$WORK/seed.iso"

COMMON=(-M q35 -m 2048 -smp 2
  -drive "file=$WORK/overlay.qcow2,format=qcow2,if=virtio"
  -drive "file=$WORK/seed.iso,format=raw,if=virtio,readonly=on"
  -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:22" -device virtio-net-pci,netdev=n0
  -display none -serial "file:$WORK/serial.log" -daemonize -pidfile "$WORK/qemu.pid")
SPOOF=(-smbios "type=0,vendor=Dell Inc.,version=2.15.0"
  -smbios "type=1,manufacturer=Dell Inc.,product=PowerEdge R730,serial=HWA0001")
case "$MODE" in
  kvm)          ACCEL=(-accel kvm -cpu host); SUB=kvm; LABEL=vm ;;
  kvm_hidden)   ACCEL=(-accel kvm -cpu host,-hypervisor,kvm=off "${SPOOF[@]}"); SUB=kvm_hidden; LABEL=vm ;;
  tcg)          ACCEL=(-accel tcg -cpu max); SUB=tcg; LABEL=emulator ;;
  tcg_hardened) ACCEL=(-accel tcg -cpu "max,model-id=Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz" "${SPOOF[@]}"); SUB=tcg_hardened; LABEL=emulator ;;
  *) echo "unknown mode $MODE"; exit 2 ;;
esac

cleanup() {
  if [ -f "$WORK/qemu.pid" ]; then kill "$(cat "$WORK/qemu.pid")" 2>/dev/null || true; fi
  rm -f "$WORK/overlay.qcow2" "$WORK/seed.iso"
}
trap cleanup EXIT

qemu-system-x86_64 "${COMMON[@]}" "${ACCEL[@]}"
SSHO=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
      -o PreferredAuthentications=password -o PubkeyAuthentication=no)
SSH=(sshpass -p hwfp ssh "${SSHO[@]}" -p "$PORT" ubuntu@127.0.0.1)
SCP=(sshpass -p hwfp scp "${SSHO[@]}" -P "$PORT")

echo "[$MODE] booting (pid $(cat "$WORK/qemu.pid")), ssh :$PORT" >&2
for i in $(seq 1 160); do
  if "${SSH[@]}" -o ConnectTimeout=5 'echo GUEST-UP' 2>/dev/null | grep -q GUEST-UP; then break; fi
  [ "$i" = 160 ] && { echo "timeout waiting for guest" >&2; exit 1; }
  sleep 10
done
"${SSH[@]}" 'python3 --version; nproc' >&2

tar -C "$REPO" -czf "$WORK/src.tgz" src eval/collect.py
"${SCP[@]}" "$WORK/src.tgz" ubuntu@127.0.0.1:hwattest.tgz
"${SSH[@]}" "rm -rf hwa && mkdir hwa && tar -C hwa -xzf hwattest.tgz && \
  python3 hwa/eval/collect.py --label $LABEL --sublabel $SUB --host-alias victus-guest \
  --runs $RUNS --load $LOAD --out hwa/out.jsonl"
"${SCP[@]}" ubuntu@127.0.0.1:hwa/out.jsonl "$WORK/out.jsonl"
cat "$WORK/out.jsonl" >> "$OUT"
"${SSH[@]}" 'sudo poweroff' 2>/dev/null || true
sleep 3
echo "[$MODE] appended $(wc -l < "$WORK/out.jsonl") records to $OUT" >&2
