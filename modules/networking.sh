#!/usr/bin/env bash
# Networking module: listening-socket analysis and interface posture.
# Surfaces services bound to a public address; all findings are alert-only.

# --- Configuration ---

# Ports that should almost never face the public internet; HIGH when bound
# to a wildcard. Deliberately conservative — 22/80/443/53 are omitted.
declare -ga NET_DANGEROUS_PUBLIC_PORTS=(
    21      # FTP (cleartext credentials)
    23      # Telnet (cleartext credentials/session) — merged from preflight
    2375    # Docker daemon (unencrypted!) — direct root RCE
    2376    # Docker daemon (TLS, but still mgmt plane on public is risky)
    3306    # MySQL / MariaDB
    4505    # SaltStack master publish
    4506    # SaltStack master return
    5432    # PostgreSQL
    5601    # Kibana
    5984    # CouchDB
    6379    # Redis
    7474    # Neo4j HTTP
    8086    # InfluxDB
    9090    # Prometheus / Cockpit
    9100    # node_exporter
    9200    # Elasticsearch HTTP
    9300    # Elasticsearch transport
    11211   # memcached
    25826   # collectd
    27017   # MongoDB
    27018   # MongoDB shard
    27019   # MongoDB config server
)

# Ports where wildcard binding is expected on a VPS: no finding even when
# public. SSH on 0.0.0.0 is covered by the ssh module instead.
declare -ga NET_PUBLIC_PORTS_OK=(
    22      # SSH (default port)
    80      # HTTP
    443     # HTTPS
    53      # DNS (when host runs a resolver)
    68      # DHCP client (bootpc) — udp/68 on 0.0.0.0 is the DHCP client on
            # virtually every cloud image using isc-dhcp/dhcpcd; flagging it as
            # a "non-standard public listener" was a scored false positive.
)

# --- Helpers ---

_net_have_ss() { command -v ss >/dev/null 2>&1; }

# Emit TSV: proto, family, ip, port, process, pid per listening socket; fails
# when no tool could list them, which is not "nothing listens". Prefers
# `ss -tulnpH`, falling back to netstat. The family field keys the checks.
_net_list_listeners() {
    local raw
    if _net_have_ss; then
        # -t TCP, -u UDP, -l listening, -n numeric, -p process,
        # -H suppress header (older ss lacks it).
        if ! raw=$(ss -tulnpH 2>/dev/null); then
            raw=$(ss -tulnp 2>/dev/null) || return 1
            raw=$(tail -n +2 <<<"$raw")
        fi
    elif command -v netstat >/dev/null 2>&1; then
        raw=$(netstat -tulnp 2>/dev/null) || return 1
        raw=$(awk '/^(tcp|udp)/' <<<"$raw")
    else
        return 1
    fi
    [[ -z "$raw" ]] && return 0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local proto local_addr proc="" pid=""
        # Both ss and netstat list proto in column 1.
        proto=$(awk '{print $1}' <<< "$line")

        if _net_have_ss; then
            # `ss -tulnpH` column 5 is the local address:port.
            local_addr=$(awk '{print $5}' <<< "$line")
        else
            # `netstat -tulnp` column 4 is the local address:port.
            local_addr=$(awk '{print $4}' <<< "$line")
        fi

        # Strip [] and split addr/port. IPv6 form is [::]:port,
        # IPv4 is plain a.b.c.d:port. Port is always after the
        # last colon; everything before is the address.
        local port="${local_addr##*:}"
        local ip="${local_addr%:*}"
        ip="${ip#[}"
        ip="${ip%]}"

        # Family: presence of ':' inside `ip` means IPv6.
        local family="v4"
        [[ "$ip" == *:* || "$ip" == "*" && "$proto" == *6 ]] && family="v6"

        # ss: users:(("name",pid=N,fd=N)), a name may hold a quote (comm is settable)
        # and ends at `",pid=`; netstat: pid/name, last. Name and pid are known or empty
        # together: neither is ever a blank middle field, which a tab-split read skips.
        if _net_have_ss && [[ "$line" =~ users:\(\(\"(([^\"]|\"[^,])+)\",pid=([0-9]+) ]]; then
            proc="${BASH_REMATCH[1]}"
            pid="${BASH_REMATCH[3]}"
        elif ! _net_have_ss; then
            proc=$(awk '{print $NF}' <<< "$line")
            if [[ "$proc" =~ ^([0-9]+)/(.+)$ ]]; then
                pid="${BASH_REMATCH[1]}" proc="${BASH_REMATCH[2]}"
            else
                proc=""
            fi
        fi

        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$proto" "$family" "$ip" "$port" "$proc" "$pid"
    done <<< "$raw"
}

# Classify a (family, ip) pair as "loopback" / "wildcard" / "specific".
_net_classify_addr() {
    local family="$1" ip="$2"
    case "$family" in
        v4)
            [[ "$ip" =~ ^127\. ]] && { echo loopback; return; }
            [[ "$ip" == "0.0.0.0" || "$ip" == "*" ]] && { echo wildcard; return; }
            ;;
        v6)
            [[ "$ip" == "::1" ]] && { echo loopback; return; }
            [[ "$ip" == "::" || "$ip" == "*" ]] && { echo wildcard; return; }
            ;;
    esac
    echo specific
}

# Is a specific bind routable from off-host? A service on the VPS's own
# public IP is as reachable as one on 0.0.0.0. Private/link-local/CGNAT
# return 1, and so does anything unparseable — never a false HIGH.
_net_specific_addr_is_public() {
    local family="$1" ip="$2"
    case "$family" in
        v4)
            [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\. ]] || return 1
            local o1="${BASH_REMATCH[1]}" o2="${BASH_REMATCH[2]}"
            (( o1 == 10 )) && return 1                          # 10/8
            (( o1 == 172 && o2 >= 16 && o2 <= 31 )) && return 1 # 172.16/12
            (( o1 == 192 && o2 == 168 )) && return 1            # 192.168/16
            (( o1 == 169 && o2 == 254 )) && return 1            # link-local
            (( o1 == 100 && o2 >= 64 && o2 <= 127 )) && return 1 # CGNAT 100.64/10
            (( o1 == 127 )) && return 1                         # loopback (defensive)
            (( o1 == 0 || o1 >= 224 )) && return 1              # 0/8, multicast+
            return 0
            ;;
        v6)
            local lc="${ip,,}"
            [[ "$lc" == fe8* || "$lc" == fe9* || "$lc" == fea* || "$lc" == feb* ]] && return 1  # fe80::/10
            [[ "$lc" == fc* || "$lc" == fd* ]] && return 1      # ULA fc00::/7
            [[ "$lc" == ::* ]] && return 1                      # ::/… specials
            return 0
            ;;
    esac
    return 1
}

# Listeners reachable from off-host from _net_list_listeners rows on stdin, deduplicated
# (ss lists a dual-stack bind per family), a TSV row each: proto, port, address ("*" for
# a wildcard bind), process, pid (both empty when unknown).
_net_public_listeners() {
    local -A seen=()
    local proto family ip port proc pid addr key
    while IFS=$'\t' read -r proto family ip port proc pid; do
        [[ -n "$port" ]] || continue
        case "$(_net_classify_addr "$family" "$ip")" in
            wildcard) addr="*" ;;
            specific)
                # A service on the VPS's own public IP is as exposed as a wildcard.
                _net_specific_addr_is_public "$family" "$ip" || continue
                addr="$ip"
                ;;
            *) continue ;;
        esac
        key="$proto/$port/$addr/$proc"
        [[ -n "${seen[$key]:-}" ]] && continue
        seen[$key]=1
        printf '%s\t%s\t%s\t%s\t%s\n' "$proto" "$port" "$addr" "$proc" "$pid"
    done
}

# A public listener as findings name it: proto/port, @address unless the bind
# is a wildcard, then the process when known.
_net_listener_label() {
    local at="@$3"
    [[ "$3" == "*" ]] && at=""
    printf '%s/%s%s%s\n' "$1" "$2" "$at" "${4:+ ($4)}"
}

_net_port_in() {
    local needle="$1"
    shift
    local p
    for p in "$@"; do
        [[ "$needle" == "$p" ]] && return 0
    done
    return 1
}

# The kernel's ephemeral port range as "<low> <high>"; fails when it cannot be read.
_net_ephemeral_range() {
    local r
    r=$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null) || return 1
    [[ "$r" =~ ^[[:space:]]*([0-9]+)[[:space:]]+([0-9]+)[[:space:]]*$ ]] || return 1
    printf '%s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}

# UDP ($1 proto) on port $2 inside range $3 (from _net_ephemeral_range, "" = unknown):
# ss lists an unconnected outbound socket as a listener, but a service may bind there too.
_net_udp_in_ephemeral() {
    [[ "$1" == udp* && -n "$3" ]] || return 1
    (( $2 >= ${3% *} && $2 <= ${3#* } ))
}

# Interfaces in promiscuous mode, excluding loopback and the virtual/bridge/
# container families, for which it is the normal mode; fails when `ip` cannot
# list links. veth pairs render as "vethXXXX@ifN": the @peer suffix is stripped.
_net_promiscuous_interfaces() {
    local links
    links=$(ip -o link show 2>/dev/null) || return 1
    awk -F': ' '/PROMISC/{print $2}' <<<"$links" \
        | awk '{sub(/@.*/, "", $1); print $1}' \
        | grep -vE '^(lo|docker[0-9]*|br-[0-9a-f]+|veth[0-9a-z]*|virbr[0-9]*(-nic)?|cni[0-9]*|flannel\.[0-9]+|kube-[a-z0-9-]+)$' \
        || true
}

# --- Audit ---

networking_audit() {
    local module="networking"

    print_item "$(i18n 'networking.check_listeners')"
    _net_audit_listeners

    print_item "$(i18n 'networking.check_promisc')"
    _net_audit_promisc
}

_net_audit_listeners() {
    local listeners
    if ! listeners=$(_net_list_listeners); then
        check_emit "networking.listeners_unknown" low failed \
            desc="$(i18n 'networking.listeners_unknown_desc')"
        print_severity "low" "$(i18n 'networking.listeners_unknown')"
        return
    fi

    if [[ -z "$listeners" ]]; then
        # Nothing listening is unusual but not a finding per se —
        # the host might be quiescent or the audit ran without root.
        return
    fi

    # Every socket on loopback: the pass says so rather than "nothing exposed".
    local loopback_only=1 proto family ip port proc pid
    while IFS=$'\t' read -r proto family ip port proc pid; do
        [[ -n "$port" && "$(_net_classify_addr "$family" "$ip")" != loopback ]] || continue
        loopback_only=0
        break
    done <<< "$listeners"

    local ssh_ports=" $(get_ssh_ports | tr '\n' ' ')"
    local ephemeral
    ephemeral=$(_net_ephemeral_range) || ephemeral=""
    local dangerous=()  # known-bad ports on a public address
    local exposed=()    # any other non-whitelisted port/proc on one
    local outbound=()   # UDP in the ephemeral range: listed, never scored
    local addr label
    while IFS=$'\t' read -r proto port addr proc pid; do
        # A port sshd listens on is SSH, wherever ssh.sh approved moving it.
        # Never by process name: any local user can set one, `sshd` included.
        [[ "$proto" == tcp* && "$ssh_ports" == *" $port "* ]] && continue

        label=$(_net_listener_label "$proto" "$port" "$addr" "$proc")
        if _net_port_in "$port" "${NET_DANGEROUS_PUBLIC_PORTS[@]}"; then
            dangerous+=("$label")
        elif _net_udp_in_ephemeral "$proto" "$port" "$ephemeral"; then
            outbound+=("$label")
        elif ! _net_port_in "$port" "${NET_PUBLIC_PORTS_OK[@]}"; then
            exposed+=("$label")
        fi
    done < <(_net_public_listeners <<< "$listeners")

    if (( ${#dangerous[@]} > 0 )); then
        local list; list=$(printf '%s ' "${dangerous[@]}")
        check_emit "networking.exposed_dangerous_ports" high failed \
            title="$(i18n 'networking.exposed_dangerous_ports' "count=${#dangerous[@]}")" \
            desc="$(i18n 'networking.exposed_dangerous_ports_desc' "list=${list% }")" \
            suggestion="$(i18n 'networking.exposed_dangerous_ports_suggestion')"
        print_severity "high" "$(i18n 'networking.exposed_dangerous_ports' "count=${#dangerous[@]}")"
    fi

    if (( ${#exposed[@]} > 0 )); then
        local list; list=$(printf '%s ' "${exposed[@]}")
        check_emit "networking.public_listeners_present" medium failed \
            title="$(i18n 'networking.public_listeners_present' "count=${#exposed[@]}")" \
            desc="$(i18n 'networking.public_listeners_present_desc' "list=${list% }")" \
            suggestion="$(i18n 'networking.public_listeners_present_suggestion')"
        print_severity "medium" "$(i18n 'networking.public_listeners_present' "count=${#exposed[@]}")"
    fi

    if (( ${#outbound[@]} > 0 )); then
        local list; list=$(printf '%s ' "${outbound[@]}")
        check_emit "networking.udp_ephemeral_sockets" info failed \
            title="$(i18n 'networking.udp_ephemeral_sockets' "count=${#outbound[@]}")" \
            desc="$(i18n 'networking.udp_ephemeral_sockets_desc' "list=${list% }" "range=${ephemeral/ /-}")" \
            suggestion="$(i18n 'networking.udp_ephemeral_sockets_suggestion')"
        print_info "$(i18n 'networking.udp_ephemeral_sockets' "count=${#outbound[@]}")"
    fi

    if (( ${#dangerous[@]} == 0 && ${#exposed[@]} == 0 )); then
        local title
        if (( loopback_only == 1 )); then
            title=$(i18n 'networking.listeners_loopback_only')
        else
            title=$(i18n 'networking.listeners_ok')
        fi
        check_emit "networking.listeners_ok" low passed \
            title="$title"
        print_ok "$title"
    fi
}

_net_audit_promisc() {
    local promisc
    if ! promisc=$(_net_promiscuous_interfaces); then
        check_emit "networking.promisc_unknown" low failed \
            desc="$(i18n 'networking.promisc_unknown_desc')"
        print_severity "low" "$(i18n 'networking.promisc_unknown')"
        return
    fi
    promisc=$(echo "$promisc" | grep -v '^$' || true)

    if [[ -n "$promisc" ]]; then
        local list; list=$(echo "$promisc" | tr '\n' ' ')
        check_emit "networking.promiscuous_interface" medium failed \
            desc="$(i18n 'networking.promiscuous_interface_desc' "list=${list% }")" \
            suggestion="$(i18n 'networking.promiscuous_interface_suggestion')"
        print_severity "medium" "$(i18n 'networking.promiscuous_interface')"
    else
        check_emit "networking.no_promisc" low passed
        print_ok "$(i18n 'networking.no_promisc')"
    fi
}

# No fix functions: all networking findings are alert-only. Rebinding a
# service to localhost is per-daemon config that cannot be safely automated.

networking_fix() {
    local fix_id="$1"
    log_error "networking module has no automated fixes (fix_id=$fix_id)"
    return 1
}
