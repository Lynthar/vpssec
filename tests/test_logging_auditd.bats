#!/usr/bin/env bats
# The auditd audit. A kernel booted with audit=0 or audit=off makes systemd skip
# auditd.service, so a fix that enables or installs it would "succeed" and change nothing.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/logging.sh"
    LOGGING_PROC_CMDLINE="$BATS_TEST_TMPDIR/cmdline"
    AUDIT_RULES_D="$BATS_TEST_TMPDIR/rules.d"
}

_cmdline() { printf '%s\n' "$1" > "$LOGGING_PROC_CMDLINE"; }

# auditd installed and stopped: is-active answers 3, as systemctl does.
_auditd_installed_stopped() {
    _vpssec_stub auditd
    _vpssec_stub auditctl
    _vpssec_stub systemctl 3
}

# Field $1 of every check emitted, one per line.
_emitted() {
    jq -r --arg f "$1" '.[] | .[$f]' "$STATE_CHECKS_FILE"
}

@test "auditd: audit=0 on the kernel command line offers no fix and names the parameter" {
    _auditd_installed_stopped
    _cmdline 'BOOT_IMAGE=/vmlinuz-6.12 root=LABEL=ROOTPART ro console=tty0 net.ifnames=0 audit=0'

    _logging_audit_auditd
    [ "$(_emitted id)" = logging.auditd_inactive ]
    [ -z "$(_emitted fix_id)" ]
    [[ "$(_emitted title)" == *"audit=0"* ]]
    [[ "$(_emitted desc)" == *"audit=0"* ]]
}

@test "auditd: audit=off counts too, and an uninstalled auditd is not offered for install" {
    _vpssec_absent_command auditd
    _vpssec_stub systemctl 3
    _cmdline 'ro quiet audit=off'

    _logging_audit_auditd
    [ "$(_emitted id)" = logging.auditd_inactive ]
    [ -z "$(_emitted fix_id)" ]
    [[ "$(_emitted desc)" == *"audit=off"* ]]
}

@test "auditd: only the whole words audit=0 and audit=off count, as systemd matches them" {
    # The unit's condition compares whole words: audit=1, a prefix or an
    # unrelated parameter ending in audit=0 leave auditd startable.
    _auditd_installed_stopped
    _cmdline 'ro audit=1 noaudit=0 audit=0x audit_backlog_limit=8192'

    _logging_audit_auditd
    [ "$(_emitted id)" = logging.auditd_inactive ]
    [ "$(_emitted fix_id)" = logging.enable_auditd ]
}

@test "auditd: an unreadable kernel command line is not read as audit=0" {
    _auditd_installed_stopped
    LOGGING_PROC_CMDLINE="$BATS_TEST_TMPDIR/absent"

    run _logging_audit_auditd
    [ "$status" -eq 0 ]
    [ -z "$output" ]
    [ "$(_emitted fix_id)" = logging.enable_auditd ]
}

@test "auditd: audit=0 is decided before systemctl is asked, so no rules check follows" {
    # The kernel records nothing then, whatever the unit reports.
    _vpssec_stub auditd
    _vpssec_stub auditctl
    _vpssec_stub systemctl 0
    _cmdline 'audit=0'

    _logging_audit_auditd
    [ "$(_emitted id)" = logging.auditd_inactive ]
}

# auditd running, its rules.d holding $1, and auditctl -l answering $2 (exit 1 when empty).
_auditd_running_with() {
    _vpssec_stub auditd
    _vpssec_stub systemctl 0
    mkdir -p "$AUDIT_RULES_D"
    printf '%b' "$1" > "$AUDIT_RULES_D/audit.rules"
    if [[ -n "$2" ]]; then _vpssec_stub auditctl 0 "$2"; else _vpssec_stub auditctl 1; fi
    _cmdline 'quiet'
}

@test "auditd: the distro's own audit.rules, control lines only, is no rules" {
    # Debian and RHEL ship it with the auditd package: -D, -b, -f and the like.
    _auditd_running_with '## First rule - delete all\n-D\n-b 8192\n-f 1\n--backlog_wait_time 60000\n' 'No rules'
    _logging_audit_auditd
    [ "$(_emitted id)" = logging.auditd_no_rules ]
    [ "$(_emitted fix_id)" = logging.setup_audit_rules ]

    # The same files with an auditctl that cannot answer: they alone say none.
    state_init
    _auditd_running_with '-D\n-b 8192\n-f 1\n' ''
    _logging_audit_auditd
    [ "$(_emitted id)" = logging.auditd_no_rules ]
}

@test "auditd: a watch or a syscall rule in rules.d, loaded, is rules" {
    _auditd_running_with '-D\n-w /etc/passwd -p wa -k identity\n' '-w /etc/passwd -p wa -k identity'
    _logging_audit_auditd
    [ "$(_emitted id)" = logging.auditd_configured ]

    state_init
    _auditd_running_with '-a always,exit -F arch=b64 -S execve -k exec\n' '-a always,exit -F arch=b64 -S execve -F key=exec'
    _logging_audit_auditd
    [ "$(_emitted id)" = logging.auditd_configured ]
}

@test "auditd: while it runs, an empty kernel set is no rules whatever the files say" {
    # rules.d kept a rule after a rollback deleted vpssec's file and a reboot.
    _auditd_running_with '-w /srv -p wa -k srv\n' 'No rules'
    _logging_audit_auditd
    [ "$(_emitted id)" = logging.auditd_no_rules ]
}

@test "auditd: an auditctl that cannot answer leaves the files to decide" {
    _auditd_running_with '-w /srv -p wa -k srv\n' ''
    _logging_audit_auditd
    [ "$(_emitted id)" = logging.auditd_configured ]
}
