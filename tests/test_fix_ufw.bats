#!/usr/bin/env bats
# Coverage for the ufw fixes. ufw.enable and ufw.set_default_deny can cut the
# operator's session, so ORDER is the contract — open every sshd port first,
# abort if that fails — and every ordering assertion compares call-log positions.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/ufw.sh"

    export TMPDIR="$BATS_TEST_TMPDIR"

    # get_current_ssh_ip reads these first and falls back to `who am i`.
    # Unset plus a silent `who` gives "operator IP unknown" as the default;
    # individual tests opt into a known IP.
    unset SSH_CONNECTION SSH_CLIENT
    _vpssec_stub who

    ufw_state="$BATS_TEST_TMPDIR/ufw-state"
    ufw_policy="$BATS_TEST_TMPDIR/ufw-policy"
    # ufw's own rule store, which is what the coverage predicate reads.
    UFW_USER_RULES="$BATS_TEST_TMPDIR/user.rules"
    UFW_USER6_RULES="$BATS_TEST_TMPDIR/user6.rules"
    # What `ufw show added` prints: real ufw 0.36.2's answer for no rules, unless a
    # test seeds the store and this together from one recording.
    ufw_shown="$BATS_TEST_TMPDIR/ufw-shown"
    cp "$(_vpssec_repo_root)/tests/fixtures/ufw-show-added-none-debian12.txt" "$ufw_shown"

    # get_ssh_ports asks systemd before sshd: with no stub the host's own
    # ssh.socket answers, and the CI runner's is active on 22.
    _vpssec_stub systemctl 3
    _sshd_ports 22
    _ufw_working

    # ufw.enable holds harden_network's keys in ufw's sysctl file through
    # kernel.sh, which the engine loads; test_fix_kernel.bats covers that helper.
    declare -gA VPSSEC_MODULE_LOADED=([kernel]=1 [networking]=1)
    _kernel_ufw_align_persisted() { echo "ufw-sysctl-align" >> "$VPSSEC_STUB_LOG"; }

    # ufw.enable names the public listeners it will cut off, through networking.sh.
    # No listener and no defaults file unless a test sets them: the CI runner has both.
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/networking.sh"
    _vpssec_stub ss
    DISTRO_UFW_DEFAULTS="$BATS_TEST_TMPDIR/default-ufw"
}

# ---- stubs ----------------------------------------------------------

# `sshd -T` reporting the given ports as real sshd prints them: a port line
# each, and the listenaddress lines it always adds, which get_ssh_ports reads.
_sshd_ports() {
    local p
    {
        printf 'port %s\n' "$@"
        for p; do printf 'listenaddress [::]:%s\nlistenaddress 0.0.0.0:%s\n' "$p" "$p"; done
    } > "$BATS_TEST_TMPDIR/sshd-ports"
    _vpssec_stub_script sshd <<SH
[[ "\$*" == *-T* ]] && cat "$BATS_TEST_TMPDIR/sshd-ports"
exit 0
SH
}

# `sshd -T` the way real sshd prints `ListenAddress host:port`: the port line
# still says the default, only the listenaddress lines carry the real port.
_sshd_listening_on() {
    { printf 'port 22\n'; printf 'listenaddress %s\n' "$@"; } > "$BATS_TEST_TMPDIR/sshd-ports"
}

# ssh.socket as systemd reports it: `is-active` exits $1, `show -p Listen
# --value` prints the rest as Listen lines. No sshd.socket is installed.
_ssh_socket() {
    local rc="$1"; shift
    printf '%s (Stream)\n' "$@" > "$BATS_TEST_TMPDIR/socket-listen"
    _vpssec_stub_script systemctl <<SH
case "\$*" in
    "is-active --quiet ssh.socket") exit $rc ;;
    "is-active --quiet "*) exit 4 ;;
    "show -p Listen --value ssh.socket") cat "$BATS_TEST_TMPDIR/socket-listen" ;;
esac
exit 0
SH
}

# Seed ufw's rule store with one tuple, in the format ufw writes.
_tuple() {
    printf '### tuple ### %s\n' "$*" >> "$UFW_USER_RULES"
}

# A ufw that remembers: `allow`/`limit` append the tuple ufw would write,
# `delete` removes it, `default` records the policy. $1: a port whose `allow`
# fails; $2: a subcommand refused outright.
_ufw_working() {
    local failing_port="${1:-}" refused="${2:-}"
    : > "$UFW_USER_RULES"
    printf 'inactive\n' > "$ufw_state"
    printf 'allow\n' > "$ufw_policy"
    _vpssec_stub_script ufw <<SH
rules="$UFW_USER_RULES"
state="$ufw_state"
policy="$ufw_policy"
shown="$ufw_shown"
fail_port="$failing_port"
[[ -n "$refused" && "\$1" == "$refused" ]] && exit 1
case "\$1" in
    allow|limit)
        act="\$1"; shift
        if [[ "\$1" == from ]]; then
            echo "### tuple ### \$act any any 0.0.0.0/0 any \$2 in" >> "\$rules"
        else
            [[ -n "\$fail_port" && "\$1" == "\$fail_port"* ]] && exit 1
            echo "### tuple ### \$act tcp \${1%/*} 0.0.0.0/0 any 0.0.0.0/0 in" >> "\$rules"
        fi
        ;;
    delete)
        if [[ "\$3" == from ]]; then
            sed -i "/ any \$4 in\\\$/d" "\$rules"
        else
            sed -i "/^### tuple ### \$2 tcp \${3%/*} 0.0.0.0\\/0 any 0.0.0.0\\/0 in\\\$/d" "\$rules"
        fi
        ;;
    enable)  printf 'active\n' > "\$state" ;;
    status)
        printf 'Status: %s\n' "\$(cat "\$state")"
        # Real ufw prints nothing more while inactive, verbose or not.
        if [[ "\${2:-}" == verbose && "\$(cat "\$state")" == active ]]; then
            printf 'Logging: on (low)\nDefault: %s (incoming), allow (outgoing), disabled (routed)\n' "\$(cat "\$policy")"
        fi
        ;;
    show)    cat "\$shown" ;;
    default) [[ "\$3" == incoming ]] && printf '%s\n' "\$2" > "\$policy" ;;
esac
exit 0
SH
}

# set_default_deny is offered only while ufw is active: an inactive ufw prints
# no policy to read or restore.
_ufw_active() { printf 'active\n' > "$ufw_state"; }

# ufw refuses the operation named by $1 (enable / default), everything else
# behaves as _ufw_working.
_ufw_refuses() {
    _ufw_working "" "$1"
}

# `ss -tulnpH` lines, as ss prints them, one argument each.
_ss_says() {
    printf '%s\n' "$@" > "$BATS_TEST_TMPDIR/ss.out"
    _vpssec_stub_script ss <<SH
cat "$BATS_TEST_TMPDIR/ss.out"
SH
}

# Pretend the operator is connected from this address.
_operator_at() { export SSH_CONNECTION="$1 54321 10.0.0.1 22"; }

# 1-based position of the first logged call matching the regex; empty when
# it never ran. Comparing two of these is how ordering is asserted.
_call_at() {
    grep -nE "$1" "$VPSSEC_STUB_LOG" 2>/dev/null | head -1 | cut -d: -f1
}

# ==============================================================================
# ufw.enable — the fix that can strand the operator
# ==============================================================================

@test "enable: every sshd port is opened before the firewall comes up" {
    _sshd_ports 22 2222
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 0 ]

    local first_port second_port enable_at
    first_port=$(_call_at '^ufw allow 22/tcp')
    second_port=$(_call_at '^ufw allow 2222/tcp')
    enable_at=$(_call_at '^ufw enable')

    # Kept as separate statements: bash exempts every command of an AND-OR
    # list but the last from errexit, so chaining these with && would hide
    # a failure of the first two.
    [ -n "$first_port" ]
    [ -n "$second_port" ]
    [ -n "$enable_at" ]
    [ "$first_port" -lt "$enable_at" ]
    [ "$second_port" -lt "$enable_at" ]
}

@test "enable: a refused SSH rule aborts before the firewall is enabled" {
    # The lockout in one line: enabling with a default-deny policy and no
    # SSH rule. Failing to add the rule must stop the fix, not be shrugged
    # off on the way to `ufw enable`.
    _ufw_working 22
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called ufw 'enable'
}

@test "enable: the second port failing still aborts before enabling" {
    # The first port succeeding must not be read as "SSH is covered".
    _sshd_ports 22 2222
    _ufw_working 2222
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called ufw 'enable'
}

@test "enable: declining the confirmation leaves the firewall down" {
    confirm_critical() { return 1; }

    run _ufw_fix_enable
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called ufw 'enable'
}

@test "enable: the confirmation lists the rules ufw holds, though ufw is inactive" {
    # ufw.enable is only offered while ufw is inactive, and an inactive ufw's
    # `status` prints nothing but "Status: inactive"; `show added` lists them.
    # Store and listing are one recording of real ufw 0.36.2, commented rules too.
    local fx
    fx="$(_vpssec_repo_root)/tests/fixtures"
    cp "$fx/ufw-user-rules-comments-debian12.txt" "$UFW_USER_RULES"
    cp "$fx/ufw-user6-rules-comments-debian12.txt" "$UFW_USER6_RULES"
    cp "$fx/ufw-show-added-debian12.txt" "$ufw_shown"
    confirm_critical() { echo "CONFIRM-PROMPT" >&2; return 1; }

    run _ufw_fix_enable
    [[ "$output" == *"ufw deny 3306/tcp"*"CONFIRM-PROMPT"* ]]
    [[ "$output" == *"ufw allow 'Nginx Full' comment 'web'"*"CONFIRM-PROMPT"* ]]
}

@test "enable: public listeners no rule lets in are named before the confirmation" {
    # The second proxy host: xray and nginx on 0.0.0.0, a rule for neither. Saying
    # yes to the rule list alone took every proxy port down.
    i18n_load en_US
    _ss_says \
        'tcp   LISTEN 0      4096         0.0.0.0:443        0.0.0.0:*    users:(("xray",pid=812,fd=7))' \
        'tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=640,fd=6))' \
        'tcp   LISTEN 0      511             [::]:80            [::]:*    users:(("nginx",pid=640,fd=7))' \
        'tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=500,fd=3))' \
        'tcp   LISTEN 0      511        127.0.0.1:31300      0.0.0.0:*    users:(("nginx",pid=640,fd=8))'
    confirm_critical() { echo "CONFIRM-PROMPT" >&2; return 1; }

    run _ufw_fix_enable
    [[ "$output" == *"unreachable from outside"*"tcp/443 (xray)"*"CONFIRM-PROMPT"* ]]
    [[ "$output" == *"tcp/80 (nginx)"*"CONFIRM-PROMPT"* ]]
    [ "$(grep -c 'tcp/80 (nginx)' <<< "$output")" -eq 1 ]
    [[ "$output" != *"tcp/22 "* && "$output" != *31300* ]]
}

@test "enable: the listeners it names are not opened for the operator" {
    _ss_says 'tcp   LISTEN 0      4096         0.0.0.0:443        0.0.0.0:*    users:(("xray",pid=812,fd=7))'
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 0 ]
    [ "$(awk '{print $6}' "$UFW_USER_RULES")" = "22" ]
}

@test "enable: the session rescue rule does not hide what will be cut off" {
    # It admits every port from the operator's address, the rest of the world none.
    i18n_load en_US
    _operator_at 203.0.113.9
    _ss_says 'tcp   LISTEN 0      4096         0.0.0.0:443        0.0.0.0:*    users:(("xray",pid=812,fd=7))'
    confirm_critical() { echo "CONFIRM-PROMPT" >&2; return 1; }

    run _ufw_fix_enable
    [[ "$output" == *"tcp/443 (xray)"*"CONFIRM-PROMPT"* ]]
}

@test "enable: a rule lets a listener in on its own protocol only" {
    i18n_load en_US
    _tuple allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in
    _tuple allow any 8443 0.0.0.0/0 any 0.0.0.0/0 in
    _ss_says \
        'tcp   LISTEN 0      4096         0.0.0.0:443        0.0.0.0:*    users:(("xray",pid=812,fd=7))' \
        'udp   UNCONN 0      0            0.0.0.0:443        0.0.0.0:*    users:(("hysteria",pid=813,fd=7))' \
        'udp   UNCONN 0      0       203.0.113.10:8443       0.0.0.0:*    users:(("tuic",pid=814,fd=7))'
    confirm_critical() { echo "CONFIRM-PROMPT" >&2; return 1; }

    run _ufw_fix_enable
    [[ "$output" == *"udp/443 (hysteria)"*"CONFIRM-PROMPT"* ]]
    [[ "$output" != *"tcp/443"* && "$output" != *8443* ]]
}

@test "enable: what ufw lets in anyway is not named: the DHCP client, docker-proxy" {
    # before.rules admits DHCP replies; published ports are DNAT-forwarded past INPUT.
    i18n_load en_US
    _ss_says \
        'udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*    users:(("dhclient",pid=400,fd=7))' \
        'tcp   LISTEN 0      4096         0.0.0.0:8080       0.0.0.0:*    users:(("docker-proxy",pid=900,fd=4))'
    confirm_critical() { echo "CONFIRM-PROMPT" >&2; return 1; }

    run _ufw_fix_enable
    [[ "$output" == *"CONFIRM-PROMPT"* ]]
    [[ "$output" != *"unreachable"* ]]
}

@test "enable: UDP on an ephemeral port is named apart, as likely outbound" {
    # zoro: sing-box's outbound sockets; conntrack admits the replies to them.
    i18n_load en_US
    _vpssec_stub sysctl 0 "$(printf '32768\t60999')"
    _ss_says \
        'udp   UNCONN 0      0            0.0.0.0:11923      0.0.0.0:*    users:(("sing-box",pid=700,fd=9))' \
        'udp   UNCONN 0      0            0.0.0.0:52391      0.0.0.0:*    users:(("sing-box",pid=700,fd=12))'
    confirm_critical() { echo "CONFIRM-PROMPT" >&2; return 1; }

    run _ufw_fix_enable
    [[ "$output" == *"unreachable from outside"*"udp/11923 (sing-box)"*"ephemeral range"*"udp/52391 (sing-box)"*"CONFIRM-PROMPT"* ]]
    [ "$(grep -c 'udp/52391' <<< "$output")" -eq 1 ]

    # Nothing else unadmitted: the outbound line alone, no cut-off heading.
    _ss_says 'udp   UNCONN 0      0            0.0.0.0:52391      0.0.0.0:*    users:(("sing-box",pid=700,fd=12))'
    run _ufw_fix_enable
    [[ "$output" == *"ephemeral range"*"udp/52391 (sing-box)"*"CONFIRM-PROMPT"* ]]
    [[ "$output" != *"unreachable"* ]]
}

@test "enable: an ACCEPT input policy cuts nothing off, so nothing is named" {
    i18n_load en_US
    printf 'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_INPUT_POLICY="ACCEPT"\n#DEFAULT_INPUT_POLICY="DROP"\n' \
        > "$DISTRO_UFW_DEFAULTS"
    _ss_says 'tcp   LISTEN 0      4096         0.0.0.0:443        0.0.0.0:*    users:(("xray",pid=812,fd=7))'
    confirm_critical() { echo "CONFIRM-PROMPT" >&2; return 1; }

    run _ufw_fix_enable
    [[ "$output" == *"CONFIRM-PROMPT"* && "$output" != *"tcp/443"* ]]

    printf 'DEFAULT_INPUT_POLICY="DROP"\n' > "$DISTRO_UFW_DEFAULTS"
    run _ufw_fix_enable
    [[ "$output" == *"tcp/443 (xray)"*"CONFIRM-PROMPT"* ]]
}

@test "enable: sockets that cannot be listed are said before the confirmation" {
    i18n_load en_US
    _vpssec_stub ss 1
    confirm_critical() { echo "CONFIRM-PROMPT" >&2; return 1; }

    run _ufw_fix_enable
    [[ "$output" == *"Listening sockets could not be listed"*"CONFIRM-PROMPT"* ]]
}

@test "enable: declining removes every rule the fix added" {
    _operator_at 203.0.113.9
    confirm_critical() { return 1; }

    run _ufw_fix_enable
    [ "$status" -eq 1 ]
    [ ! -s "$UFW_USER_RULES" ]
}

@test "enable: ufw's sysctl file is aligned after the confirmation and before ufw enable" {
    # ufw installed after harden_network ran brings its own weaker values, and
    # enabling applies them: the plan's earlier fix is undone at once and at boot.
    confirm_critical() { echo "confirm" >> "$VPSSEC_STUB_LOG"; return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 0 ]

    local confirm_at align_at enable_at
    confirm_at=$(_call_at '^confirm')
    align_at=$(_call_at '^ufw-sysctl-align')
    enable_at=$(_call_at '^ufw enable')
    [ -n "$confirm_at" ]
    [ -n "$align_at" ]
    [ -n "$enable_at" ]
    [ "$confirm_at" -lt "$align_at" ]
    [ "$align_at" -lt "$enable_at" ]
}

@test "enable: declining leaves ufw's sysctl file alone" {
    confirm_critical() { return 1; }

    run _ufw_fix_enable
    [ "$status" -eq 1 ]
    _vpssec_refute grep -q '^ufw-sysctl-align' "$VPSSEC_STUB_LOG"
}

@test "enable: an alignment that fails is said, and the firewall still comes up" {
    _kernel_ufw_align_persisted() { return 1; }
    confirm_critical() { return 0; }
    i18n_load en_US
    VPSSEC_QUIET_SCAN=0

    run _ufw_fix_enable
    [ "$status" -eq 0 ]
    _vpssec_stub_called ufw 'enable'
    [[ "$output" == *"Could not hold the hardened network settings"* ]]
}

@test "enable: a successful enable logs how to undo it" {
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 0 ]
    grep -q 'Undo for ufw.enable: ufw disable && ufw delete allow 22/tcp' "$VPSSEC_LOGS/vpssec.log"
}

@test "enable: declining removes the session rescue rule" {
    # Nothing else changed, and a blanket allow-from-this-IP is the
    # broadest rule the fix adds — it should not outlive a cancelled run.
    _operator_at 203.0.113.9
    confirm_critical() { return 1; }

    run _ufw_fix_enable
    [ "$status" -eq 1 ]
    _vpssec_stub_called ufw 'delete allow from 203\.0\.113\.9'
}

@test "enable: the rescue rule survives a successful enable" {
    # Deliberate. If the detected SSH port does not actually cover the live
    # connection (NAT, a port sshd -T did not report), deleting this rule
    # right after enabling is precisely what locks the operator out.
    _operator_at 203.0.113.9
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 0 ]
    _vpssec_stub_called ufw 'allow from 203\.0\.113\.9'
    _vpssec_refute _vpssec_stub_called ufw 'delete'
}

@test "enable: no rescue rule is invented when the operator IP is unknown" {
    # A wrong `allow from` source is worse than none — guessing would open
    # the host to whatever address was guessed.
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 0 ]
    _vpssec_refute _vpssec_stub_called ufw 'allow from'
}

@test "enable: an unknown operator IP is said before the confirmation" {
    i18n_load en_US
    confirm_critical() { echo "CONFIRM-PROMPT" >&2; return 1; }

    run _ufw_fix_enable
    [[ "$output" == *"no rescue rule"*"CONFIRM-PROMPT"* ]]
}

@test "enable: a refused enable is reported as failure" {
    _ufw_refuses enable
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 1 ]
}

# ==============================================================================
# ufw.set_default_deny — the other way to cut the session
# ==============================================================================

@test "default deny: public listeners no rule lets in are named before its own confirmation" {
    # As ufw.enable: an active ufw with incoming allow is what a deny flip cuts.
    i18n_load en_US
    _ufw_active
    _ss_says 'tcp   LISTEN 0      4096         0.0.0.0:443        0.0.0.0:*    users:(("xray",pid=812,fd=7))'
    confirm_critical() { echo "CONFIRM-PROMPT $1" >&2; return 1; }

    run _ufw_fix_default_deny
    [ "$status" -eq 1 ]
    [[ "$output" == *"incoming traffic is denied"*"tcp/443 (xray)"*"CONFIRM-PROMPT Switch incoming traffic to deny?"* ]]
}

@test "default deny: declining keeps the policy and removes the rules it added" {
    _ufw_active
    confirm_critical() { return 1; }

    run _ufw_fix_default_deny
    [ "$status" -eq 1 ]
    [ "$(cat "$ufw_policy")" = allow ]
    [ ! -s "$UFW_USER_RULES" ]
    _vpssec_refute _vpssec_stub_called ufw 'default deny'
}

@test "default deny: the SSH rule is added before the policy flips" {
    confirm_critical() { return 0; }
    _ufw_active
    run _ufw_fix_default_deny
    [ "$status" -eq 0 ]

    local allow_at deny_at
    allow_at=$(_call_at '^ufw allow 22/tcp')
    deny_at=$(_call_at '^ufw default deny incoming')

    [ -n "$allow_at" ] && [ -n "$deny_at" ]
    [ "$allow_at" -lt "$deny_at" ]
}

@test "default deny: a refused SSH rule aborts before the policy flips" {
    confirm_critical() { return 0; }
    _ufw_working 22

    _ufw_active
    run _ufw_fix_default_deny
    [ "$status" -eq 1 ]
    _vpssec_refute _vpssec_stub_called ufw 'default deny'
}

@test "default deny: every sshd port is covered, not just the first" {
    confirm_critical() { return 0; }
    _sshd_ports 22 2222

    _ufw_active
    run _ufw_fix_default_deny
    [ "$status" -eq 0 ]
    _vpssec_stub_called ufw 'allow 22/tcp'
    _vpssec_stub_called ufw 'allow 2222/tcp'
}

@test "default deny: an already-allowed port is not re-added" {
    confirm_critical() { return 0; }
    _tuple allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in

    _ufw_active
    run _ufw_fix_default_deny
    [ "$status" -eq 0 ]
    _vpssec_refute _vpssec_stub_called ufw 'allow 22/tcp'
    _vpssec_stub_called ufw 'default deny incoming'
}

@test "default deny: an outbound rule on the SSH port is not inbound coverage" {
    confirm_critical() { return 0; }
    # `ufw allow out 22/tcp` once let this fix skip the inbound rule and flip
    # straight to deny, cutting the next login.
    _tuple allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 out

    _ufw_active
    run _ufw_fix_default_deny
    [ "$status" -eq 0 ]
    local allow_at deny_at
    allow_at=$(_call_at '^ufw allow 22/tcp')
    deny_at=$(_call_at '^ufw default deny incoming')
    [ -n "$allow_at" ]
    [ "$allow_at" -lt "$deny_at" ]
}

@test "default deny and enable: a LIMIT rule covers its port and is kept" {
    confirm_critical() { return 0; }
    # `ufw allow` on a LIMIT port rewrites the rule into a plain ALLOW, and
    # the rate limit disappears without a word.
    _tuple limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
    confirm_critical() { return 0; }

    run _ufw_fix_default_deny
    [ "$status" -eq 0 ]
    run _ufw_fix_enable
    [ "$status" -eq 0 ]
    _vpssec_refute _vpssec_stub_called ufw 'allow 22/tcp'
    grep -q '^### tuple ### limit tcp 22 ' "$UFW_USER_RULES"
}

@test "default deny: a rule confined to an interface still gets a rule open to anywhere" {
    confirm_critical() { return 0; }
    # The operator may be connected over the public address right now; the
    # interface rule does not cover that path, and the deny would.
    _tuple allow any any 0.0.0.0/0 any 0.0.0.0/0 in_tailscale0

    _ufw_active
    run _ufw_fix_default_deny
    [ "$status" -eq 0 ]
    _vpssec_stub_called ufw 'allow 22/tcp'
}

@test "default deny: the command that restores the old policy is printed and logged" {
    confirm_critical() { return 0; }
    i18n_load en_US
    VPSSEC_QUIET_SCAN=0

    _ufw_active
    run _ufw_fix_default_deny
    [ "$status" -eq 0 ]
    [[ "$output" == *"ufw default allow incoming"* ]]
    grep -q 'Undo for ufw.set_default_deny: ufw default allow incoming && ufw delete allow 22/tcp' \
        "$VPSSEC_LOGS/vpssec.log"
}

@test "default deny: outgoing traffic is left allowed" {
    confirm_critical() { return 0; }
    # Denying incoming without restoring allow-outgoing would break every
    # outbound connection on the host.
    _ufw_active
    run _ufw_fix_default_deny
    [ "$status" -eq 0 ]
    _vpssec_stub_called ufw 'default allow outgoing'
}

@test "default deny: a refused policy change is reported as failure" {
    confirm_critical() { return 0; }
    _ufw_refuses default

    _ufw_active
    run _ufw_fix_default_deny
    [ "$status" -eq 1 ]
}

# ==============================================================================
# ufw.allow_ssh — FIX_SAFE, so it is auto-applied without confirmation
# ==============================================================================

@test "allow ssh: every port is opened, not only the first" {
    _sshd_ports 22 2222 2022

    run _ufw_fix_allow_ssh
    [ "$status" -eq 0 ]
    _vpssec_stub_called ufw 'allow 22/tcp'
    _vpssec_stub_called ufw 'allow 2222/tcp'
    _vpssec_stub_called ufw 'allow 2022/tcp'
}

@test "allow ssh: SSH confined to a VPN interface gains no rule open to anywhere" {
    # Tailscale's documented ufw lockdown is `allow in on tailscale0` with no
    # 22/tcp rule; a SAFE fix must not undo it.
    _tuple allow any any 0.0.0.0/0 any 0.0.0.0/0 in_tailscale0

    _ufw_ssh_allowed
    run _ufw_fix_allow_ssh
    [ "$status" -eq 0 ]
    _vpssec_refute _vpssec_stub_called ufw 'allow 22/tcp'
}

@test "allow ssh: an app profile rule resolved to the SSH port counts" {
    # `ufw allow OpenSSH` as ufw stores it: ports resolved, app names kept.
    _tuple allow tcp 22 0.0.0.0/0 any 10.0.0.0/8 OpenSSH - in comment=6f7073
    _ufw_ssh_allowed
}

@test "allow ssh: the port sshd really listens on, from ListenAddress host:port" {
    # No Port line: sshd -T still prints `port 22`, but sshd listens only on
    # 2222. Opening 22 here and verifying 22 locked the operator out.
    _sshd_listening_on 0.0.0.0:2222 '[::]:2222'
    _tuple allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in

    _vpssec_refute _ufw_ssh_allowed
    run _ufw_fix_allow_ssh
    [ "$status" -eq 0 ]
    _vpssec_stub_called ufw 'allow 2222/tcp'
    _vpssec_refute _vpssec_stub_called ufw 'allow 22/tcp'
    _ufw_ssh_allowed
}

@test "ssh ports: an active ssh.socket's ports, not sshd -T's" {
    # Ubuntu after `systemctl edit ssh.socket`: sshd is handed the socket's
    # listeners and binds none itself, while sshd -T still says 22.
    _ssh_socket 0 '[::]:2200'

    run get_ssh_ports
    [ "$status" -eq 0 ]
    [ "$output" = "2200" ]
}

@test "ssh ports: every TCP listener of the socket, none of its unix paths" {
    _ssh_socket 0 0.0.0.0:2201 '[::1]:2203' /run/sshd.sock '[::]:2204'

    run get_ssh_ports
    [ "$output" = $'2201\n2203\n2204' ]
}

@test "ssh ports: an inactive ssh.socket's Listen lines are not ports" {
    # systemctl show prints them whether or not the socket is up.
    _ssh_socket 3 '[::]:2200'

    run get_ssh_ports
    [ "$output" = "22" ]
}

@test "enable: the port ssh.socket listens on is opened, not sshd -T's" {
    # Opening 22 here and confirming it was the lockout found on a real host.
    _ssh_socket 0 '[::]:2200'
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    [ "$status" -eq 0 ]
    local port_at enable_at
    port_at=$(_call_at '^ufw allow 2200/tcp')
    enable_at=$(_call_at '^ufw enable')
    [ -n "$port_at" ]
    [ -n "$enable_at" ]
    [ "$port_at" -lt "$enable_at" ]
    _vpssec_refute _vpssec_stub_called ufw 'allow 22/tcp'
    _ufw_ssh_allowed
}

@test "allow ssh: the undo command is logged" {
    run _ufw_fix_allow_ssh
    [ "$status" -eq 0 ]
    grep -q 'Undo for ufw.allow_ssh: ufw delete allow 22/tcp' "$VPSSEC_LOGS/vpssec.log"
}

@test "allow ssh: one refused port fails the fix even if another succeeded" {
    _sshd_ports 22 2222
    _ufw_working 2222

    run _ufw_fix_allow_ssh
    [ "$status" -eq 1 ]
}

# ==============================================================================
# Install and dispatch
# ==============================================================================

@test "install: a failed package install is propagated" {
    _vpssec_stub apt-get 100

    run _ufw_fix_install
    [ "$status" -eq 1 ]
}

@test "install: a failed index refresh alone does not fail the install" {
    _vpssec_stub_script apt-get <<'SH'
case "$*" in
    *update*) exit 100 ;;
esac
exit 0
SH

    run _ufw_fix_install
    [ "$status" -eq 0 ]
    _vpssec_stub_called apt-get 'update'
    _vpssec_stub_called apt-get 'install -y ufw'
}

@test "install: the logged undo command removes the package again" {
    _vpssec_stub apt-get

    run _ufw_fix_install
    [ "$status" -eq 0 ]
    grep -q 'Undo for ufw.install: apt purge ufw' "$VPSSEC_LOGS/vpssec.log"
}

@test "install: ufw is not installed over iptables-persistent, which apt would remove for it" {
    # Debian's ufw conflicts with iptables-persistent; -y used to remove it and
    # netfilter-persistent, so the operator's saved rules stopped loading at boot.
    i18n_load en_US
    _vpssec_stub_script apt-get <<'SH'
case "$*" in
    "-s install ufw") printf '%s\n' 'Remv iptables-persistent [1.0.23]' \
                          'Remv netfilter-persistent [1.0.23]' 'Inst ufw (0.36.2-9 Debian:13.7/stable [all])' ;;
esac
exit 0
SH

    run _ufw_fix_install
    [ "$status" -eq 1 ]
    [[ "$output" == *"would remove iptables-persistent netfilter-persistent"* ]]
    _vpssec_refute _vpssec_stub_called apt-get 'install -y'
    _vpssec_refute grep -q 'Undo for ufw.install' "$VPSSEC_LOGS/vpssec.log"
}

@test "ufw_fix: an unknown fix id fails instead of silently doing nothing" {
    run ufw_fix "ufw.not_a_real_fix"
    [ "$status" -eq 1 ]
}

@test "enable: a rescue rule that cannot be added is said before the confirmation, --json-only too" {
    _operator_at 203.0.113.9
    _vpssec_stub_script ufw <<SH
case "\$1" in
    allow)
        [[ "\$2" == from ]] && exit 1
        echo "### tuple ### allow tcp \${2%/*} 0.0.0.0/0 any 0.0.0.0/0 in" >> "$UFW_USER_RULES"
        ;;
esac
exit 0
SH
    i18n_load en_US
    VPSSEC_JSON_ONLY=1
    confirm_critical() { echo "CONFIRM-PROMPT" >&2; return 1; }

    run _ufw_fix_enable
    [[ "$output" == *"Could not add the rescue rule"*"CONFIRM-PROMPT"* ]]
}

@test "enable: a rescue rule that cannot be added is reported, not announced as done" {
    _operator_at 203.0.113.9
    # Same as _ufw_working, except the `allow from <ip>` form is refused.
    _vpssec_stub_script ufw <<SH
case "\$1" in
    allow)
        [[ "\$2" == from ]] && exit 1
        echo "### tuple ### allow tcp \${2%/*} 0.0.0.0/0 any 0.0.0.0/0 in" >> "$UFW_USER_RULES"
        ;;
esac
exit 0
SH
    i18n_load en_US
    VPSSEC_QUIET_SCAN=0
    confirm_critical() { return 0; }

    run _ufw_fix_enable
    # The port rules landed, so the firewall still comes up.
    [ "$status" -eq 0 ]
    _vpssec_stub_called ufw 'enable'
    grep -q 'Could not add the rescue rule' <<<"$output"
    _vpssec_refute grep -q 'temporarily whitelisted' <<<"$output"
    _vpssec_refute grep -q 'Kept the rescue rule' <<<"$output"
}
