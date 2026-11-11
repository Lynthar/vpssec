#!/usr/bin/env bats
# kernel.unused_protocols_*: which of dccp/sctp/rds/tipc modprobe would still load,
# and for those already loaded, that a blacklist waits for a reboot and who uses them.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/kernel.sh"
    i18n_load en_US
    state_init
    KERNEL_MODPROBE_DIRS=("$BATS_TEST_TMPDIR/modprobe.d")
    KERNEL_PROC_DIR="$BATS_TEST_TMPDIR/proc"
    mkdir -p "${KERNEL_MODPROBE_DIRS[0]}" "$KERNEL_PROC_DIR"
    : > "$KERNEL_PROC_DIR/modules"
}

_desc() {
    jq -r '.[] | select(.id == "kernel.unused_protocols_unblocked") | .desc' "$VPSSEC_STATE/checks.json"
}

# sctp loaded, as /proc/modules showed it on Debian 13 (6.12) with two listeners.
_sctp_loaded() {
    echo 'sctp 528384 6 - Live 0xffffffffc0d72000' > "$KERNEL_PROC_DIR/modules"
}

# Process $1 named $2, holding fd $3 -> $4.
_proc() {
    mkdir -p "$KERNEL_PROC_DIR/$1/fd"
    echo "$2" > "$KERNEL_PROC_DIR/$1/comm"
    ln -s "$4" "$KERNEL_PROC_DIR/$1/fd/$3"
}

@test "unused protocols: unloaded and unblacklisted ones are named as they are" {
    _kernel_audit_unused_protocols >/dev/null
    [ "$(_desc)" = "Unblacklisted: dccp; sctp; rds; tipc" ]
}

@test "unused protocols: a blacklisted or install-disabled one is not listed" {
    printf 'blacklist dccp\ninstall sctp /bin/false\n' > "${KERNEL_MODPROBE_DIRS[0]}/rare.conf"
    _kernel_audit_unused_protocols >/dev/null
    [ "$(_desc)" = "Unblacklisted: rds; tipc" ]
}

@test "unused protocols: a loaded one says a blacklist waits for a reboot" {
    # Each network namespace holds two references: rmmod fails while it is up.
    _sctp_loaded
    mkdir -p "$KERNEL_PROC_DIR/net/sctp"
    head -1 "$(_vpssec_repo_root)/tests/fixtures/sctp-eps-debian13.txt" > "$KERNEL_PROC_DIR/net/sctp/eps"
    _kernel_audit_unused_protocols >/dev/null
    [ "$(_desc)" = "Unblacklisted: dccp; sctp (loaded: a blacklist takes effect only after a reboot); rds; tipc" ]
}

@test "unused protocols: one in use names the processes holding its sockets" {
    # Real eps of an SCTP stream and an SCTP seqpacket listener; a TCP socket and
    # /dev/null elsewhere are not theirs.
    _sctp_loaded
    mkdir -p "$KERNEL_PROC_DIR/net/sctp"
    cp "$(_vpssec_repo_root)/tests/fixtures/sctp-eps-debian13.txt" "$KERNEL_PROC_DIR/net/sctp/eps"
    _proc 324577 turnserver 3 'socket:[3706426]'
    _proc 324578 python3 3 'socket:[3709414]'
    _proc 1 systemd 0 /dev/null
    ln -s 'socket:[37064260]' "$KERNEL_PROC_DIR/1/fd/7"
    _kernel_audit_unused_protocols >/dev/null
    [ "$(_desc)" = "Unblacklisted: dccp; sctp (in use by python3, turnserver: blacklisting it stops them after the next reboot); rds; tipc" ]
}

@test "unused protocols: every one blacklisted passes" {
    printf 'install %s /bin/false\n' dccp sctp rds tipc > "${KERNEL_MODPROBE_DIRS[0]}/rare.conf"
    _kernel_audit_unused_protocols >/dev/null
    jq -e '.[] | select(.id == "kernel.unused_protocols_blocked" and .status == "passed")' \
        "$VPSSEC_STATE/checks.json" >/dev/null
}
