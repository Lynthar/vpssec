#!/usr/bin/env bats
# A listen address the config holds but nginx has no socket for: the files were
# changed and not reloaded, or the reload failed. The nginx and webapp checks
# read the files, so this is said once, unscored, beside them.

load helpers.bash

setup() {
    _vpssec_load core/state.sh core/security_levels.sh
    i18n_load en_US
    state_init
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/nginx.sh"
    # shellcheck source=/dev/null
    source "$(_vpssec_repo_root)/modules/networking.sh"
    declare -gA VPSSEC_MODULE_LOADED=([networking]=1)
}

_config() {
    NGINX_DUMP="# configuration file /etc/nginx/nginx.conf:
$1"
}

# `ss -tulnpH` lines, as ss prints them, one argument each.
_ss_says() {
    printf '%s\n' "$@" > "$BATS_TEST_TMPDIR/ss.out"
    _vpssec_stub_script ss <<SH
cat "$BATS_TEST_TMPDIR/ss.out"
SH
}

_nginx_holds() {
    local a lines=()
    for a; do
        lines+=("tcp   LISTEN 0      511    $a      0.0.0.0:*    users:((\"nginx\",pid=641,fd=6),(\"nginx\",pid=640,fd=6))")
    done
    _ss_says "${lines[@]}"
}

_unloaded() {
    _nginx_audit_listen_loaded >/dev/null
    jq -r '.[] | select(.id == "nginx.listen_not_loaded") | .desc' "$VPSSEC_STATE/checks.json"
}

@test "loaded: a listen written but not reloaded is named, with its server" {
    # DMIT LA: Proxy-agent added the 31305 server and did not reload nginx.
    _config 'http {
    server { listen 80; server_name _; return 444; }
    server { listen 127.0.0.1:31300; server_name a.example; }
    server { listen 127.0.0.1:31305 ssl; server_name b.example c.example; }
}'
    _nginx_holds '0.0.0.0:80' '127.0.0.1:31300'
    [ "$(_unloaded)" = "In the config, but nginx holds no socket for them: 127.0.0.1:31305 (b.example). The files changed and nginx has not reloaded them, or a reload failed (another process holding the port, say); the nginx and webapp checks judge the files on disk, not what is running." ]
    [ "${CHECK_SCORE_CATEGORY[nginx.listen_not_loaded]}" = "info" ]
}

@test "loaded: every listen held, nothing is said" {
    _config 'http {
    server { listen 80; listen [::]:80; server_name a.example; }
    server { listen 127.0.0.1:31300; listen [::1]:31301; }
}'
    _nginx_holds '0.0.0.0:80' '[::]:80' '127.0.0.1:31300' '[::1]:31301'
    [ -z "$(_unloaded)" ]
}

@test "loaded: a wildcard socket answers the port's specific addresses of its family" {
    # nginx binds only *:port when a wildcard listens there, unless told to bind.
    _config 'http {
    server { listen 8443; listen [::]:8443; }
    server { listen 203.0.113.10:8443; listen [2001:db8::10]:8443; }
    server { listen [2001:db8::10]:9443; }
}'
    _nginx_holds '0.0.0.0:8443' '[::]:8443' '0.0.0.0:9443'
    [ "$(_unloaded)" = "In the config, but nginx holds no socket for them: [2001:db8::10]:9443. The files changed and nginx has not reloaded them, or a reload failed (another process holding the port, say); the nginx and webapp checks judge the files on disk, not what is running." ]
}

@test "loaded: a dual-stack socket answers both families" {
    _config 'http { server { listen 80; listen [::]:80 ipv6only=off; } }'
    _nginx_holds '*:80'
    [ -z "$(_unloaded)" ]
}

@test "loaded: stream servers count, UDP, unix and hostname listens are not compared" {
    _config 'stream { server { listen 127.0.0.1:31310; proxy_pass 127.0.0.1:1; }
    server { listen 127.0.0.1:53 udp; proxy_pass 127.0.0.1:2; } }
http {
    server { listen 443 quic; listen unix:/run/nginx.sock; listen a.example:8080; listen 80; }
}'
    _nginx_holds '0.0.0.0:80'
    [[ "$(_unloaded)" == *"for them: 127.0.0.1:31310. The files"* ]]
}

@test "loaded: a socket held by another process is not nginx's" {
    _config 'http { server { listen 80; } server { listen 8080; } }'
    _ss_says \
        'tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=640,fd=6))' \
        'tcp   LISTEN 0      4096         0.0.0.0:8080       0.0.0.0:*    users:(("xray",pid=812,fd=7))'
    [[ "$(_unloaded)" == *"for them: *:8080. The files"* ]]
}

@test "loaded: not judged when no socket in view is nginx's, or none can be listed" {
    # No root to see owners, or nginx not running: every listen would read as unloaded.
    _config 'http { server { listen 80; } }'
    _ss_says 'tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*'
    [ -z "$(_unloaded)" ]

    _vpssec_stub ss 1
    [ -z "$(_unloaded)" ]
    [ "$(jq length "$VPSSEC_STATE/checks.json")" = 0 ]
}

@test "loaded: the nginx audit asks, before it reads the files" {
    printf '%s\n' '# configuration file /etc/nginx/nginx.conf:' \
        'http { server { listen 80; } server { listen 127.0.0.1:31305 ssl; } }' > "$BATS_TEST_TMPDIR/dump"
    _vpssec_stub_script nginx <<SH
[[ "\$1" == -T || "\$1" == -t ]] && cat "$BATS_TEST_TMPDIR/dump"
exit 0
SH
    _nginx_holds '0.0.0.0:80'
    nginx_audit >/dev/null
    [ "$(jq -r '[.[].id] | index("nginx.listen_not_loaded")' "$VPSSEC_STATE/checks.json")" = 0 ]
}
