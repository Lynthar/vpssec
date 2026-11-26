#!/usr/bin/env bats
# What the fail2ban audit says about the SSH jail. A jail that is loaded but
# cannot ban still reports "Currently banned: N", so "loaded" alone is no pass.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/fail2ban.sh"
    _f2b_service_active() { return 0; }
    _f2b_ssh_jail_enabled() { return 0; }
    _f2b_get_maxretry() { echo 3; }
}

_checks() { jq -r '[.[] | "\(.id) \(.status) \(.fix_id)"] | join(",")' "$VPSSEC_STATE/checks.json"; }

@test "audit: a jail that bans passes as enabled" {
    _f2b_ssh_jail_bans() { return 0; }
    _f2b_audit_ssh_jail
    [ "$(_checks)" = "fail2ban.ssh_jail_enabled passed " ]
}

@test "audit: a jail that bans no one is a finding, with the fix that repairs it" {
    # Left by a reload across a banaction rename (no action), or by an iptables
    # action on an nftables-only host — vpssec's own fix produced both.
    _f2b_ssh_jail_bans() { return 1; }
    _f2b_audit_ssh_jail
    [ "$(_checks)" = "fail2ban.ssh_jail_not_banning failed fail2ban.configure_ssh_jail" ]
    [ "${CHECK_SCORE_CATEGORY[fail2ban.ssh_jail_not_banning]}" = "recommended" ]
}

_desc() { jq -r '.[] | select(.id == "fail2ban.ssh_jail_not_banning") | .desc' "$VPSSEC_STATE/checks.json"; }

@test "audit: the finding names the one reason the jail does not ban" {
    _f2b_ssh_jail_bans() { return 1; }
    _f2b_audit_ssh_jail
    [ "$(_desc)" = "The sshd jail runs, but it has no ban action (a banaction renamed or removed leaves it so). Its banned count is bookkeeping: a banned address still reaches sshd." ]

    state_init
    _f2b_ssh_jail_bans() { F2B_GAP=$'iptables-multiport\tiptables'; return 2; }
    _f2b_audit_ssh_jail
    [[ "$(_desc)" == "The sshd jail runs, but its action iptables-multiport needs iptables, which this host does not have. Its"* ]]

    state_init
    get_ssh_ports() { printf '22\n35387\n'; }
    _f2b_ssh_jail_bans() { F2B_GAP=$'nftables\tnft\tssh'; return 3; }
    _f2b_audit_ssh_jail
    [[ "$(_desc)" == "The sshd jail runs, but its action nftables blocks only port ssh, and sshd listens on 22,35387. Its"* ]]
}

# ---- a host SSH takes no password on (DMIT LA: both paths off) ---------------

# fail2ban absent, ssh.sh loaded as the engine's earlier ssh pass leaves it, sshd -T
# answering from $1 written as sshd_config.
_absent_under_sshd() {
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ssh.sh"
    declare -gA VPSSEC_MODULE_LOADED=([ssh]=1)
    SSH_CONFIG="$BATS_TEST_TMPDIR/sshd_config"
    SSH_DROPIN_DIR="$BATS_TEST_TMPDIR/sshd_config.d"
    printf '%b' "$1" > "$SSH_CONFIG"
    _vpssec_stub_sshd_merging
    _f2b_installed() { return 1; }
    fail2ban_audit >/dev/null
}

_scored() { checks_with_scoring | jq -r '[.[] | "\(.id) \(.scored)"] | join(",")'; }

@test "audit: with no SSH password, fail2ban findings are listed, fix offered, none scored" {
    _absent_under_sshd 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n'
    [ "$(_checks)" = "fail2ban.ssh_key_only passed ,fail2ban.not_installed failed fail2ban.install" ]
    [ "$(_scored)" = "fail2ban.ssh_key_only false,fail2ban.not_installed false" ]
}

@test "audit: a password SSH takes, either way in, keeps fail2ban scored" {
    _absent_under_sshd 'PasswordAuthentication yes\nKbdInteractiveAuthentication no\n'
    [ "$(_scored)" = "fail2ban.not_installed true" ]

    state_init
    # keyboard-interactive through PAM asks pam_unix for the password.
    _absent_under_sshd 'PasswordAuthentication no\nKbdInteractiveAuthentication yes\nUsePAM yes\n'
    [ "$(_scored)" = "fail2ban.not_installed true" ]
}

@test "audit: a Match block that may let a password in keeps fail2ban scored" {
    local d
    for d in PasswordAuthentication KbdInteractiveAuthentication AuthenticationMethods; do
        state_init
        _absent_under_sshd "PasswordAuthentication no\nKbdInteractiveAuthentication no\nMatch Address 10.0.0.0/8\n    $d yes\n"
        [ "$(_scored)" = "fail2ban.not_installed true" ] || { echo "$d" >&2; return 1; }
    done
}

@test "audit: sshd that cannot report its config is not taken as key-only" {
    _absent_under_sshd 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n'
    state_init
    _vpssec_stub sshd 255
    fail2ban_audit >/dev/null
    [ "$(_scored)" = "fail2ban.not_installed true" ]
}
