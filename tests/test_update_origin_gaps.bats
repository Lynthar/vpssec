#!/usr/bin/env bats
# Which public services unattended-upgrade never updates: update.sh rebuilds its
# allowed origins and matches them as unattended-upgrade does. The fixtures are a
# Debian 13 host with nginx from nginx.org, pinned as the docs say, and sshd.

load helpers.bash

setup() {
    _vpssec_load core/distro.sh core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/networking.sh"
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/update.sh"
    declare -gA VPSSEC_MODULE_LOADED=([networking]=1)
    VPSSEC_PKG_MGR=apt
    _os_release debian "Debian GNU/Linux" trixie 13

    # The recorded host: nginx (pid 4996) and sshd (pid 5009) on public addresses.
    DISTRO_PROC="$BATS_TEST_TMPDIR/proc"
    mkdir -p "$DISTRO_PROC/4996" "$DISTRO_PROC/5009"
    ln -s /usr/sbin/nginx "$DISTRO_PROC/4996/exe"
    ln -s /usr/sbin/sshd "$DISTRO_PROC/5009/exe"
    _vpssec_stub_script ss <<'SH'
printf '%s\n' \
    'tcp LISTEN 0      128    0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=5009,fd=6)) ' \
    'tcp LISTEN 0      511    0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=4996,fd=6))' \
    'tcp LISTEN 0      128       [::]:22    [::]:* users:(("sshd",pid=5009,fd=7)) '
SH
    _vpssec_stub_script dpkg-query <<'SH'
for a; do
    case "$a" in
        /usr/sbin/nginx) echo "nginx: $a" ;;
        /usr/sbin/sshd) echo "openssh-server: $a" ;;
    esac
done
SH
    local fx
    fx="$(_vpssec_repo_root)/tests/fixtures"
    _vpssec_stub_script apt-cache <<SH
if (( \$# == 1 )); then cat "$fx/apt-cache-policy-nginxorg-debian13.txt"
else cat "$fx/apt-cache-policy-nginx-openssh-debian13.txt"; fi
SH
}

# os-release as unattended-upgrade reads it: ID, NAME, VERSION_CODENAME, VERSION_ID.
_os_release() {
    printf '%s="%s"\n' ID "$1" NAME "$2" VERSION_CODENAME "$3" VERSION_ID "$4" > "$BATS_TEST_TMPDIR/os-release"
    _distro_osrelease_field() {
        ( . "$BATS_TEST_TMPDIR/os-release"; printf '%s' "${!1:-}" )
    }
}

# Origins-Pattern lines of an `apt-config dump`, one argument each, after the
# empty anchor line Debian's file starts the list with.
_patterns() {
    printf 'Unattended-Upgrade::Origins-Pattern "";\n'
    printf 'Unattended-Upgrade::Origins-Pattern:: "%s";\n' "$@"
}

# The two lines Debian 13's stock 50unattended-upgrades leaves active for security.
_security_only() {
    _patterns 'origin=Debian,codename=${distro_codename},label=Debian-Security' \
        'origin=Debian,codename=${distro_codename}-security,label=Debian-Security'
}

# ---------- the origins, as unattended-upgrade builds them ----------

@test "origins: Debian 13's stock patterns, the codename put in" {
    run _update_uu_patterns "$(_patterns 'origin=Debian,codename=${distro_codename},label=Debian' \
        'origin=Debian,codename=$distro_codename-security,label=Debian-Security')"
    [ "$output" = "origin=Debian,codename=trixie,label=Debian
origin=Debian,codename=trixie-security,label=Debian-Security" ]
}

@test "origins: Allowed-Origins is origin and suite, Ubuntu's ID capitalised" {
    _os_release ubuntu Ubuntu noble 24.04
    run _update_uu_patterns 'Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";
Unattended-Upgrade::Allowed-Origins:: "${distro_id}ESM:${distro_codename}-infra-security";
Unattended-Upgrade::Allowed-Origins:: "Foo\:Bar:stable";
Unattended-Upgrade::Allowed-Origins:: "Docker stable";'
    [ "$output" = "o=Ubuntu,a=noble-security
o=UbuntuESM,a=noble-infra-security
o=Foo:Bar,a=stable
o=Docker,a=stable" ]
}

@test "origins: Debian's ID is capitalised, its NAME being more than that" {
    run _update_uu_patterns 'Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";'
    [ "$output" = "o=Debian,a=trixie-security" ]
}

@test "origins: an ID that NAME only capitalises is replaced by NAME" {
    _os_release almalinux AlmaLinux "" 9.4
    run _update_uu_patterns "$(_patterns 'o=${distro_id},a=${distro_release}')"
    [ "$output" = "o=AlmaLinux,a=9.4" ]
}

# ---------- one pattern against one package file ----------

@test "match: every key must match, by any of its spellings" {
    local -a f=(Debian stable-security trixie-security Debian-Security main deb.debian.org)
    _update_uu_pattern_matches "origin=Debian,codename=trixie-security,label=Debian-Security" "${f[@]}"
    _update_uu_pattern_matches "o=Debian,a=stable-security,n=trixie-security,l=Debian-Security,c=main" "${f[@]}"
    _update_uu_pattern_matches "suite=stable-security,component=main,site=deb.debian.org" "${f[@]}"
    _update_uu_pattern_matches "archive=stable-security" "${f[@]}"
    _vpssec_refute _update_uu_pattern_matches "origin=Debian,codename=trixie,label=Debian-Security" "${f[@]}"
}

@test "match: values are globs, as fnmatch reads them" {
    local -a f=(nginx stable trixie nginx nginx nginx.org)
    _update_uu_pattern_matches "site=*nginx.org" "${f[@]}"
    _update_uu_pattern_matches "origin=ngin?,codename=tri[xy]ie" "${f[@]}"
    _vpssec_refute _update_uu_pattern_matches "origin=Nginx" "${f[@]}"
}

@test "match: an escaped comma is part of the value, not a separator" {
    _update_uu_pattern_matches 'label=a\,b' x x x "a,b" x x
    _vpssec_refute _update_uu_pattern_matches 'label=a,b' x x x "a,b" x x
}

@test "match: an empty pattern or an unknown key matches nothing" {
    _vpssec_refute _update_uu_pattern_matches "" Debian a n l c s
    _vpssec_refute _update_uu_pattern_matches "  " Debian a n l c s
    _vpssec_refute _update_uu_pattern_matches "origin=Debian,flavour=x" Debian a n l c s
}

# ---------- the services, on the recorded host ----------

@test "services: nginx from nginx.org is named under the stock patterns" {
    run _update_uu_uncovered_services "$(_patterns 'origin=Debian,codename=${distro_codename},label=Debian' \
        'origin=Debian,codename=${distro_codename},label=Debian-Security' \
        'origin=Debian,codename=${distro_codename}-security,label=Debian-Security')"
    [ "$status" -eq 0 ]
    [ "$output" = "nginx (nginx.org)" ]
}

@test "services: Debian's sshd is covered by security-only patterns, though its candidate is from a point release" {
    # openssh-server's candidate came from trixie/main (13.8); its security updates
    # still arrive by trixie-security. vpssec's own fix writes exactly these patterns.
    run _update_uu_uncovered_services "$(_security_only)"
    [ "$status" -eq 0 ]
    [ "$output" = "nginx (nginx.org)" ]
}

@test "services: Debian's own nginx in an allowed origin does not cover the nginx.org stream" {
    # 1.26.3+deb13u11 sits in trixie-security, below the pinned 1.31.9: never installed.
    run _update_uu_uncovered_services "$(_security_only)"
    [[ "$output" == *"nginx (nginx.org)"* ]]
}

@test "services: a pattern for nginx.org covers it" {
    run _update_uu_uncovered_services "$(_security_only; _patterns 'site=nginx.org')"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "services: no pattern at all leaves every public service out" {
    run _update_uu_uncovered_services ""
    [ "$output" = "openssh-server (deb.debian.org)
nginx (nginx.org)" ]
}

@test "services: sockets that cannot be listed fail, not 'all covered'" {
    _vpssec_stub ss 1
    run _update_uu_uncovered_services "$(_security_only)"
    [ "$status" -ne 0 ]
}

@test "services: an apt that cannot answer fails, not 'all covered'" {
    local fx
    fx="$(_vpssec_repo_root)/tests/fixtures"
    # The package files unreadable, then the versions.
    _vpssec_stub_script apt-cache <<SH
(( \$# == 1 )) && exit 100
cat "$fx/apt-cache-policy-nginx-openssh-debian13.txt"
SH
    run _update_uu_uncovered_services "$(_security_only)"
    [ "$status" -ne 0 ]

    _vpssec_stub_script apt-cache <<SH
(( \$# == 1 )) && { cat "$fx/apt-cache-policy-nginxorg-debian13.txt"; exit 0; }
exit 100
SH
    run _update_uu_uncovered_services "$(_security_only)"
    [ "$status" -ne 0 ]
}

@test "services: a binary upgraded under its running process is still its package's" {
    # The kernel names a replaced executable "<path> (deleted)".
    rm "$DISTRO_PROC/4996/exe"
    ln -s "/usr/sbin/nginx (deleted)" "$DISTRO_PROC/4996/exe"
    run _update_uu_uncovered_services "$(_security_only)"
    [ "$output" = "nginx (nginx.org)" ]
}

# ---------- the check ----------

_emitted() {
    jq -r '[.[] | "\(.id) \(.severity) \(.status)"] | join(",")' "$VPSSEC_STATE/checks.json"
}

@test "audit: an unscored note names what is left out" {
    _vpssec_stub_script apt-config <<SH
cat <<'D'
$(_security_only)
D
SH
    _update_audit_origin_gaps
    [ "$(_emitted)" = "update.unattended_origins_uncovered info failed" ]
    [ "${CHECK_SCORE_CATEGORY[update.unattended_origins_uncovered]}" = "info" ]
    jq -e '.[0].desc | contains("nginx (nginx.org).")' "$VPSSEC_STATE/checks.json"
}

@test "audit: nothing left out, or apt unreadable, emits nothing" {
    _vpssec_stub_script apt-config <<SH
cat <<'D'
$(_security_only; _patterns 'site=nginx.org')
D
SH
    _update_audit_origin_gaps
    [ "$(_emitted)" = "" ]

    _vpssec_stub apt-cache 100
    _update_audit_origin_gaps
    [ "$(_emitted)" = "" ]
}

@test "audit: the note comes with the pass that automatic updates are on" {
    auto_update_status() { echo ok; }
    auto_update_installed() { return 0; }
    _vpssec_stub_script apt-config <<SH
cat <<'D'
$(_security_only)
D
SH
    _update_audit_unattended
    [ "$(_emitted)" = "update.unattended_enabled low passed,update.unattended_origins_uncovered info failed" ]
}

@test "audit: a host that is not apt is not asked" {
    VPSSEC_PKG_MGR=dnf
    _vpssec_stub apt-config 0 'Unattended-Upgrade::Origins-Pattern:: "x=y";'
    _update_audit_origin_gaps
    _vpssec_refute _vpssec_stub_called apt-config
}
