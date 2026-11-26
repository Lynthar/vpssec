#!/usr/bin/env bats
# Which public listeners are SSH. A process name is no evidence: any local user
# can set one (`sshd` included), and ss does not escape the quotes around it.
# The ports sshd listens on are what ssh.sh approved, so those are the exemption.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/networking.sh"
    SSH_CONFIG="$BATS_TEST_TMPDIR/sshd_config"
    SSH_DROPIN_DIR="$BATS_TEST_TMPDIR/sshd_config.d"
    printf 'Port 2222\n' > "$SSH_CONFIG"
    _vpssec_stub_sshd_merging
    # get_ssh_ports asks systemd before sshd: with no stub the host's own
    # ssh.socket answers, and the CI runner's is active on 22.
    _vpssec_stub systemctl 3
}

# `ss -tulnpH` lines, as ss prints them, one argument each.
_ss_says() {
    printf '%s\n' "$@" > "$BATS_TEST_TMPDIR/ss.out"
    _vpssec_stub_script ss <<SH
cat "$BATS_TEST_TMPDIR/ss.out"
SH
}

_net_findings() {
    jq -r '[.[] | "\(.id): \(.desc // "")"] | join("\n")' "$VPSSEC_STATE/checks.json"
}

@test "listeners: a process named sshd on another port is not exempt" {
    _ss_says 'tcp   LISTEN 0      128          0.0.0.0:31337      0.0.0.0:*    users:(("sshd",pid=4243,fd=3))'
    _net_audit_listeners
    [[ "$(_net_findings)" == *"networking.public_listeners_present:"*"tcp/31337 (sshd)"* ]]
}

@test "listeners: a quote inside a process name does not cut the name short" {
    _ss_says 'tcp   LISTEN 0      511          0.0.0.0:6379       0.0.0.0:*    users:(("sshd"x",pid=4242,fd=6))'
    _net_audit_listeners
    [[ "$(_net_findings)" == *"networking.exposed_dangerous_ports:"*'tcp/6379 (sshd"x)'* ]]
}

@test "listeners: the port sshd listens on is SSH, whoever holds the socket" {
    # Ubuntu's socket activation: systemd, not sshd, owns the listener.
    _ss_says \
        'tcp   LISTEN 0      4096         0.0.0.0:2222       0.0.0.0:*    users:(("systemd",pid=1,fd=50))' \
        'tcp   LISTEN 0      4096            [::]:2222          [::]:*    users:(("systemd",pid=1,fd=51))'
    _net_audit_listeners
    [ "$(_net_findings)" = "networking.listeners_ok: " ]
}

@test "listeners: the SSH port on the host's public address is SSH too" {
    _ss_says 'tcp   LISTEN 0      4096    203.0.113.10:2222       0.0.0.0:*    users:(("systemd",pid=1,fd=50))'
    _net_audit_listeners
    [ "$(_net_findings)" = "networking.listeners_ok: " ]
}

@test "listeners: a UDP listener on the SSH port is not SSH" {
    _ss_says 'udp   UNCONN 0      0            0.0.0.0:2222       0.0.0.0:*    users:(("python3",pid=900,fd=3))'
    _net_audit_listeners
    [[ "$(_net_findings)" == *"udp/2222 (python3)"* ]]
}

# ---- unconnected UDP on the ephemeral range (zoro: sing-box's outbound sockets) ------

_ephemeral_range_is() { _vpssec_stub sysctl 0 "$(printf '%s\t%s' "$1" "$2")"; }

_zoro_udp() {
    _ss_says \
        'udp   UNCONN 0      0            0.0.0.0:11923      0.0.0.0:*    users:(("sing-box",pid=700,fd=9))' \
        'udp   UNCONN 0      0            0.0.0.0:52391      0.0.0.0:*    users:(("sing-box",pid=700,fd=12))' \
        'udp   UNCONN 0      0            0.0.0.0:34181      0.0.0.0:*'
}

_desc_of() { jq -r --arg id "$1" '.[] | select(.id == $id) | .desc' "$VPSSEC_STATE/checks.json"; }

@test "listeners: UDP on an ephemeral port is listed apart and unscored, the inbound stays medium" {
    _ephemeral_range_is 32768 60999
    _zoro_udp
    _net_audit_listeners
    [ "$(_desc_of networking.public_listeners_present)" = "Listening on a wildcard or public address (whether the host firewall lets it through is not checked here): udp/11923 (sing-box)" ]
    local note; note=$(_desc_of networking.udp_ephemeral_sockets)
    [[ "$note" == *"(32768-60999): udp/52391 (sing-box) udp/34181."* ]]
    [ "${CHECK_SCORE_CATEGORY[networking.udp_ephemeral_sockets]}" = "info" ]
}

@test "listeners: only TCP, or a port outside the range, is a listener whatever its number" {
    _ephemeral_range_is 32768 60999
    _ss_says \
        'tcp   LISTEN 0      4096         0.0.0.0:40000      0.0.0.0:*    users:(("xray",pid=812,fd=7))' \
        'udp   UNCONN 0      0            0.0.0.0:61000      0.0.0.0:*    users:(("wg",pid=0,fd=0))'
    _net_audit_listeners
    [[ "$(_desc_of networking.public_listeners_present)" == *"tcp/40000 (xray) udp/61000 (wg)" ]]
    [ -z "$(_desc_of networking.udp_ephemeral_sockets)" ]
}

@test "listeners: an unreadable ephemeral range keeps every UDP socket a listener" {
    _vpssec_stub sysctl 1
    _zoro_udp
    _net_audit_listeners
    [[ "$(_desc_of networking.public_listeners_present)" == *"udp/11923 (sing-box) udp/52391 (sing-box) udp/34181" ]]
    [ -z "$(_desc_of networking.udp_ephemeral_sockets)" ]
}

@test "listeners: ephemeral UDP alone still passes the listener check" {
    _ephemeral_range_is 32768 60999
    _ss_says 'udp   UNCONN 0      0            0.0.0.0:52391      0.0.0.0:*    users:(("sing-box",pid=700,fd=12))'
    _net_audit_listeners
    [ "$(jq -r '[.[] | "\(.id) \(.status)"] | join(",")' "$VPSSEC_STATE/checks.json")" = "networking.udp_ephemeral_sockets failed,networking.listeners_ok passed" ]
}
