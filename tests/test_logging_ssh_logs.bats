#!/usr/bin/env bats
# Failed SSH logins, counted from sshd's own journal lines. Two fixtures are
# OpenSSH 10.0 on Debian 13 driven over loopback (key-only, password); the
# third is real brute-force traffic, addresses moved into 203.0.113.0/24.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    source "$(_vpssec_repo_root)/modules/logging.sh"
}

# journalctl answers with the named fixtures, in order.
_journal_is() {
    local f files=()
    for f in "$@"; do
        files+=("$(_vpssec_repo_root)/tests/fixtures/journal-sshd-$f-debian13.txt")
    done
    _vpssec_stub_script journalctl <<<"cat $(printf '%q ' "${files[@]}")"
}

@test "logging: a key-only host's turned-away connections are attempts" {
    # Unknown user, user outside AllowUsers, wrong key, MaxAuthTries of wrong
    # keys, IPv6, a user name carrying a fake address; the accepted key is not.
    _journal_is keyonly
    [ "$(_logging_get_failed_logins)" = "6 6" ]
}

@test "logging: a rejected password counts once, not again for its pam_unix lines" {
    # 1 + 3 + 6 + 1 (a key got in after it) + 2 from the first source again;
    # the port scan never reached authentication.
    _journal_is password
    [ "$(_logging_get_failed_logins)" = "13 4" ]
}

@test "logging: bots that close, reset or disconnect mid-auth are attempts" {
    _journal_is bots
    [ "$(_logging_get_failed_logins)" = "18 9" ]
}

@test "logging: past the threshold the finding names attempts and sources" {
    _journal_is keyonly password bots
    _logging_audit_ssh_logs
    run jq -r '.[] | "\(.id) \(.status) \(.title)"' "$VPSSEC_STATE/checks.json"
    [ "$status" -eq 0 ]
    [ "$output" = "logging.ssh_some_failures failed $(i18n 'logging.ssh_logs_moderate' 'count=37' 'sources=19')" ]
}
