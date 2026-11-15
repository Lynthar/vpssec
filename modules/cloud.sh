#!/usr/bin/env bash
# Cloud environment and monitoring-agent detection.
# Every check here is informational; nothing is modified.

# --- Known Cloud Vendor Agents Database ---

# Format: process_name|service_name|vendor_key|desc_key|can_disable; column 2
# lists units space-separated, none for a plugin found only by its process. Columns
# 3 and 4 are i18n KEY SUFFIXES, rendered at display; vendor shares the provider ids.
declare -ga KNOWN_CLOUD_AGENTS=(
    # Alibaba Cloud
    "AliYunDun|aegis|alibaba|aliyundun|yes"
    "AliYunDunMonitor|aegis|alibaba|aliyundun_monitor|yes"
    "AliYunDunUpdate|aegis|alibaba|aliyundun_update|yes"
    "aliyun-service|aliyun|alibaba|aliyun_service|yes"
    "cloudmonitor|cloudmonitor|alibaba|cloudmonitor|yes"

    # Tencent Cloud
    "YDService|YDService|tencent|ydservice|yes"
    "YDLive|YDService|tencent|ydlive|yes"
    "tat_agent|tat_agent|tencent|tat_agent|yes"
    "sgagent|sgagent|tencent|sgagent|yes"
    "barad_agent|barad_agent|tencent|barad_agent|yes"

    # Huawei Cloud
    "telescope|telescope|huawei|telescope|yes"
    "hostguard|hostguard|huawei|hostguard|yes"
    "uniagent|uniagent|huawei|uniagent|yes"

    # AWS; Ubuntu's EC2 images ship the SSM agent as a snap, under its own unit.
    "amazon-ssm-agent|amazon-ssm-agent snap.amazon-ssm-agent.amazon-ssm-agent|aws|ssm|optional"
    "amazon-cloudwatch-agent|amazon-cloudwatch-agent|aws|cloudwatch|optional"

    # Azure: the agent runs under python3, so only its unit finds it, and the
    # unit is walinuxagent on Debian/Ubuntu, waagent on RHEL.
    "waagent|walinuxagent waagent|azure|walinuxagent|no"
    "OMSAgentForLinux|omsagent|azure|omsagent|yes"

    # Google Cloud
    "google_guest_agent|google-guest-agent|gcp|google_guest|optional"
    "google_osconfig_agent|google-osconfig-agent|gcp|google_osconfig|optional"
    # A plugin the guest agent's manager runs, and metadata can switch off: no unit.
    "guest_telemetry||gcp|google_telemetry|optional"

    # DigitalOcean
    "do-agent|do-agent|digitalocean|do_agent|yes"

    # Vultr
    "vultr-helper|vultr-helper|vultr|vultr_helper|yes"

    # Linode
    "linode-cli|linode-cli|linode|linode_cli|yes"
    "longview|longview|linode|longview|yes"

    # Oracle Cloud
    "oracle-cloud-agent|oracle-cloud-agent|oracle|oracle_agent|optional"

    # Generic/Common monitoring tools
    "zabbix_agentd|zabbix-agent|generic|zabbix|optional"
    "node_exporter|prometheus-node-exporter|generic|node_exporter|optional"
    "telegraf|telegraf|generic|telegraf|optional"
    "collectd|collectd|generic|collectd|optional"
    "netdata|netdata|generic|netdata|optional"
    "datadog-agent|datadog-agent|generic|datadog|optional"
    "newrelic-infra|newrelic-infra|generic|newrelic|optional"
)

# Suspicious process name patterns (regex)
declare -ga SUSPICIOUS_AGENT_PATTERNS=(
    ".*[Aa]gent.*"
    ".*[Mm]onitor.*"
    ".*[Gg]uard.*"
    ".*[Ww]atcher.*"
    ".*[Cc]ollector.*"
    ".*[Tt]elemetry.*"
    ".*[Ss]py.*"
    ".*[Tt]racker.*"
)

# Known safe system processes (to exclude from suspicious detection)
declare -ga SAFE_SYSTEM_PROCESSES=(
    "gpg-agent"
    "ssh-agent"
    "dbus-daemon"
    "polkitd"
    "packagekitd"
    "systemd-journald"
    "systemd-logind"
    "systemd-networkd"
    "systemd-resolved"
    "systemd-timesyncd"
    "systemd-udevd"
    "udisksd"
    "accounts-daemon"
    "avahi-daemon"
    "ModemManager"
    "NetworkManager"
    "wpa_supplicant"
    "cupsd"
    "cron"
    "atd"
    "rsyslogd"
    "sshd"
    "nginx"
    "apache2"
    "httpd"
    "mysqld"
    "postgres"
    "redis-server"
    "mongod"
    "docker"
    "containerd"
    # Virtualization guest tools: shipped by default on most VPS providers,
    # and several superficially match the suspicious-agent patterns.
    "qemu-ga"
    "spice-vdagent"
    "spice-vdagentd"
    "vmtoolsd"
    "VBoxService"
    "VBoxClient"
    "xe-daemon"
    "hv_kvp_daemon"
    "hv_vss_daemon"
    "hv_fcopy_daemon"
)

# Provider display name. The names live in i18n, never as literals here —
# the provider ids below are the machine-side identity and never move.
_get_provider_name() {
    local provider="$1"
    case "$provider" in
        alibaba|tencent|huawei|aws|azure|gcp|digitalocean|vultr|linode|oracle|hetzner|ovh|scaleway)
            i18n "cloud.provider_name_${provider}" ;;
        aws-or-compatible)
            # Not a key on its own line only because of the dash.
            i18n 'cloud.provider_name_aws_compatible' ;;
        unknown)      echo "$(i18n 'common.unknown')" ;;
        *)            echo "$provider" ;;
    esac
}

# Render an agent's vendor column (a stable key) for display.
_cloud_vendor_name() {
    i18n "cloud.vendor_${1}"
}

# Render an agent's description column (a stable key) for display.
_cloud_agent_desc() {
    i18n "cloud.agent_${1}"
}

# Check if a process is in the safe list
_is_safe_process() {
    local proc="$1"
    for safe in "${SAFE_SYSTEM_PROCESSES[@]}"; do
        [[ "$proc" == "$safe" ]] && return 0
    done
    return 1
}

# Find running monitoring agents from known list
_find_known_agents() {
    local found=()

    # The vendor/desc keys travel unresolved: resolving here bakes the active
    # language into the data, and anything matching on vendor downstream would
    # then be matching a translated string.
    local -a units
    for entry in "${KNOWN_CLOUD_AGENTS[@]}"; do
        IFS='|' read -r proc_name service_name vendor_key desc_key can_disable <<< "$entry"
        read -ra units <<< "$service_name"

        # pgrep -x matches the kernel's comm, which is cut to 15 bytes: the
        # full name of a longer agent never matches.
        if pgrep -x "${proc_name:0:15}" &>/dev/null; then
            found+=("$proc_name|$service_name|$vendor_key|$desc_key|$can_disable|running")
        # is-active succeeds when any of the units is active, and fails given none.
        elif systemctl is-active "${units[@]}" &>/dev/null; then
            found+=("$proc_name|$service_name|$vendor_key|$desc_key|$can_disable|service")
        fi
    done

    printf '%s\n' "${found[@]}"
}

# Find suspicious agent-like processes
_find_suspicious_agents() {
    local suspicious=()

    # Get all running processes
    local procs=$(ps -eo comm= 2>/dev/null | sort -u)

    while read -r proc; do
        [[ -z "$proc" ]] && continue

        # Skip known safe processes
        _is_safe_process "$proc" && continue

        # Skip if it's a known cloud agent (already detected)
        local is_known=false
        for entry in "${KNOWN_CLOUD_AGENTS[@]}"; do
            local known_proc="${entry%%|*}"
            # ps prints the same 15-byte comm.
            [[ "$proc" == "${known_proc:0:15}" ]] && is_known=true && break
        done
        [[ "$is_known" == "true" ]] && continue

        # Check against suspicious patterns
        for pattern in "${SUSPICIOUS_AGENT_PATTERNS[@]}"; do
            if [[ "$proc" =~ $pattern ]]; then
                # Get more info about the process
                local pid=$(pgrep -x "$proc" 2>/dev/null | head -1)
                local cmdline=""
                local user=""
                if [[ -n "$pid" ]]; then
                    cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | head -c 200)
                    user=$(ps -o user= -p "$pid" 2>/dev/null)
                fi
                suspicious+=("$proc|$pid|$user|$cmdline")
                break
            fi
        done
    done <<< "$procs"

    printf '%s\n' "${suspicious[@]}"
}

# --- IMDS helpers. Three rules hold throughout this section: NEVER log or
# echo a response body (they carry credentials), keep the timeouts at 1-2s so
# non-cloud hosts fail fast, and run only for tier1/tier2 providers. ---

# Capture only HTTP status (3-digit, or "000" on connection failure).
_cloud_imds_curl_status() {
    local url="$1"; shift
    curl -sS --max-time 1 --connect-timeout 1 \
        -o /dev/null -w '%{http_code}' \
        "$@" "$url" 2>/dev/null
}

# GET metadata URL $1, further curl options after it. -f: an error page is not
# a body, so a 4xx/5xx answer gives no output and a non-zero status.
_cloud_imds_fetch() {
    local url="$1"; shift
    curl -fsS --max-time 2 --connect-timeout 1 "$@" "$url" 2>/dev/null
}

# The raw user-data bytes from the detected provider's endpoint, written to
# stdout and never held in a variable, which would drop NUL bytes. Decodes
# base64 only where the provider's API contract requires it (Azure, OCI).
_cloud_imds_get_user_data() {
    local provider; provider=$(vpssec_cloud_provider)
    case "$provider" in
        aws|aws-or-compatible)
            # Prefer IMDSv2; fall back to v1 only if v2 unavailable.
            local token
            token=$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" \
                -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
                --max-time 1 --connect-timeout 1 2>/dev/null)
            { [[ -n "$token" ]] && _cloud_imds_fetch "http://169.254.169.254/latest/user-data" \
                -H "X-aws-ec2-metadata-token: $token"; } \
                || _cloud_imds_fetch "http://169.254.169.254/latest/user-data"
            ;;
        alibaba)
            _cloud_imds_fetch "http://100.100.100.200/latest/user-data" \
                || _cloud_imds_fetch "http://169.254.169.254/latest/user-data"
            ;;
        azure)
            # customData is base64-encoded per Azure API contract.
            _cloud_imds_fetch "http://169.254.169.254/metadata/instance/compute/customData?api-version=2021-01-01&format=text" \
                -H "Metadata: true" | base64 -d 2>/dev/null
            ;;
        gcp)
            _cloud_imds_fetch "http://169.254.169.254/computeMetadata/v1/instance/attributes/user-data" \
                -H "Metadata-Flavor: Google"
            ;;
        digitalocean)
            _cloud_imds_fetch "http://169.254.169.254/metadata/v1/user-data"
            ;;
        hetzner)
            _cloud_imds_fetch "http://169.254.169.254/hetzner/v1/userdata"
            ;;
        vultr|linode)
            _cloud_imds_fetch "http://169.254.169.254/v1/user-data"
            ;;
        tencent)
            _cloud_imds_fetch "http://metadata.tencentyun.com/latest/user-data"
            ;;
        huawei|ovh)
            # Both are OpenStack-based; user-data lives at the standard
            # OpenStack metadata path (plaintext).
            _cloud_imds_fetch "http://169.254.169.254/openstack/latest/user_data"
            ;;
        oracle)
            # OCI: base64-encoded user_data behind the mandatory v2 auth header.
            _cloud_imds_fetch "http://169.254.169.254/opc/v2/instance/metadata/user_data" \
                -H "Authorization: Bearer Oracle" | base64 -d 2>/dev/null
            ;;
        scaleway)
            # Scaleway serves user_data only to a privileged source port, so
            # one is bound. --local-port fails closed on a curl without it.
            _cloud_imds_fetch "http://169.254.42.42/user_data" --local-port 1-1023
            ;;
    esac
}

# User-data as text to scan, on stdout; empty when there is none. gzip -f
# decompresses a compressed body and passes any other through. Fails when a
# body came back but not as text, so the caller must not call it clean.
_cloud_imds_user_data_text() {
    local raw text fetched=1
    # base64 carries the raw bytes through $(...), which would drop NULs.
    raw=$(_cloud_imds_get_user_data | base64 -w0) || fetched=0
    [[ -n "$raw" ]] || return 0
    (( fetched )) || return 1
    text=$(base64 -d <<<"$raw" | gzip -cdf 2>/dev/null | tr '\0' '\1') || return 1
    [[ "$text" != *$'\1'* ]] || return 1
    printf '%s' "$text"
}

# True if any host-firewall rule MENTIONS an IMDS IP — a weak signal, since
# telling a blocking rule from a logging one needs full ruleset parsing.
# The finding must be worded as "mentions", never "restricted".
_cloud_imds_firewall_restricted() {
    # Each dump is captured whole: under pipefail, a grep -q stopping at the
    # first match sends SIGPIPE to a large dump still writing, and reads false.
    local rules=""
    if check_command iptables-save; then rules+=$(iptables-save 2>/dev/null || true)$'\n'; fi
    if check_command ip6tables-save; then rules+=$(ip6tables-save 2>/dev/null || true)$'\n'; fi
    if check_command nft; then rules+=$(nft list ruleset 2>/dev/null || true); fi
    grep -qE '169\.254\.169\.254|100\.100\.100\.200' <<<"$rules"
}

# Lightweight container check (cloud.sh shouldn't depend on kernel.sh
# being loaded). Skips host-firewall checks in containers since the
# container can't see the host's nftables.
_cloud_imds_in_container() {
    [[ -f /.dockerenv ]] && return 0
    [[ -f /run/.containerenv ]] && return 0
    if [[ -r /proc/1/cgroup ]]; then
        grep -qE '/(docker|kubepods|libpod|containerd|lxc)/' /proc/1/cgroup 2>/dev/null \
            && return 0
    fi
    return 1
}

# Main IMDS audit orchestrator. Silent no-op on unknown tier.
_cloud_audit_imds() {
    local tier; tier=$(vpssec_cloud_tier)
    [[ "$tier" == "unknown" ]] && return 0

    local provider; provider=$(vpssec_cloud_provider)

    # 1. AWS-specific: IMDSv1 still open?
    if [[ "$provider" == "aws" ]]; then
        local v1_status v2_token
        v1_status=$(_cloud_imds_curl_status "http://169.254.169.254/latest/meta-data/")
        v2_token=$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
            --max-time 1 --connect-timeout 1 2>/dev/null)

        if [[ "$v1_status" == "200" ]]; then
            check_emit "cloud.imds_v1_enabled" medium failed \
                desc="$(i18n 'cloud.imds_v1_enabled_desc')" \
                suggestion="$(i18n 'cloud.fix_imds_v1')"
            print_severity "medium" "$(i18n 'cloud.imds_v1_enabled')"
        elif [[ "$v1_status" == "401" && -n "$v2_token" ]]; then
            check_emit "cloud.imds_v2_only" info passed
            print_ok "$(i18n 'cloud.imds_v2_only')"
        fi
    fi

    # 2. Alibaba-specific: security hardening mode enforced?
    if [[ "$provider" == "alibaba" ]]; then
        local ali_status
        ali_status=$(_cloud_imds_curl_status "http://100.100.100.200/latest/meta-data/")
        [[ "$ali_status" != "200" ]] && ali_status=$(_cloud_imds_curl_status "http://169.254.169.254/latest/meta-data/")

        if [[ "$ali_status" == "200" ]]; then
            check_emit "cloud.imds_alibaba_normal_mode" medium failed \
                desc="$(i18n 'cloud.imds_alibaba_normal_mode_desc')" \
                suggestion="$(i18n 'cloud.fix_imds_alibaba')"
            print_severity "medium" "$(i18n 'cloud.imds_alibaba_normal_mode')"
        elif [[ "$ali_status" == "403" || "$ali_status" == "401" ]]; then
            check_emit "cloud.imds_alibaba_hardened" info passed
            print_ok "$(i18n 'cloud.imds_alibaba_hardened')"
        fi
    fi

    # 3. user-data secret scan (universal across tier1 + tier2).
    local user_data
    if ! user_data=$(_cloud_imds_user_data_text); then
        check_emit "cloud.user_data_not_scanned" low failed \
            desc="$(i18n 'cloud.user_data_not_scanned_desc')" \
            suggestion="$(i18n 'cloud.fix_user_data_not_scanned')"
        print_severity "low" "$(i18n 'cloud.user_data_not_scanned')"
    elif [[ -n "$user_data" ]]; then
        local hits; hits=$(_vpssec_scan_secrets_in_content "$user_data")
        hits="${hits% }"
        if [[ -n "$hits" ]]; then
            # NEVER log user_data body — only kinds + counts.
            log_info "user-data secret hits (kinds): $hits"
            check_emit "cloud.user_data_leaked_secrets" high failed \
                desc="$(i18n 'cloud.user_data_leaked_secrets_desc' "hits=$hits")" \
                suggestion="$(i18n 'cloud.fix_user_data_secrets')"
            print_severity "high" "$(i18n 'cloud.user_data_leaked_secrets'): $hits"
        else
            check_emit "cloud.user_data_clean" info passed
            print_ok "$(i18n 'cloud.user_data_clean')"
        fi
    fi

    # 4. Defense-in-depth: host firewall rule referencing IMDS IPs?
    # Skip in containers (no view of host nftables).
    if ! _cloud_imds_in_container; then
        if _cloud_imds_firewall_restricted; then
            check_emit "cloud.imds_restricted" info passed
            print_ok "$(i18n 'cloud.imds_restricted')"
        else
            check_emit "cloud.imds_unrestricted" low failed \
                desc="$(i18n 'cloud.imds_unrestricted_desc')" \
                suggestion="$(i18n 'cloud.fix_imds_firewall')"
            print_severity "low" "$(i18n 'cloud.imds_unrestricted')"
        fi
    fi
}

# --- Audit Functions ---

cloud_audit() {
    log_info "Running cloud environment audit"

    # The public getter, so the result caches into VPSSEC_CLOUD_PROVIDER and
    # every later module reads it without rerunning DMI inspection.
    local provider=$(vpssec_cloud_provider)
    local provider_name=$(_get_provider_name "$provider")

    if [[ "$provider" != "unknown" ]]; then
        check_emit "cloud.provider_detected" info passed \
            title="$(i18n 'cloud.provider_detected'): $provider_name" \
            desc="$(i18n 'cloud.provider_info')"
    else
        check_emit "cloud.provider_unknown" info passed \
            desc="$(i18n 'cloud.provider_unknown_desc')"
    fi

    # 2. Find known cloud agents
    local known_agents=$(_find_known_agents)
    local agent_count=$(count_lines "$known_agents" '|')

    if [[ -n "$known_agents" && "$agent_count" -gt 0 ]]; then
        # Build agent list for display. Both keys render here, at the edge, so
        # the text follows --lang; the description says what the agent IS, which
        # is the whole basis for deciding whether to keep it.
        local agent_list=""
        while IFS='|' read -r proc_name service_name vendor_key desc_key can_disable status; do
            [[ -z "$proc_name" ]] && continue
            agent_list+="$proc_name ($(_cloud_vendor_name "$vendor_key")): $(_cloud_agent_desc "$desc_key"); "
        done <<< "$known_agents"
        agent_list="${agent_list%; }"

        # Vendor agents are inventory, not exposure, so low on every host.
        # There is deliberately no foreign-vendor escalation: it must arrive
        # with a test that can observe the severity actually moving.
        local severity="low"

        check_emit "cloud.agents_found" "$severity" failed \
            title="$(i18n 'cloud.agents_found'): $agent_count" \
            desc="$agent_list" \
            suggestion="$(i18n 'cloud.review_agents')"
    else
        check_emit "cloud.no_known_agents" info passed \
            desc="$(i18n 'cloud.no_known_agents_desc')"
    fi

    # 3. Find suspicious agent-like processes (strict level only)
    local suspicious=$(_find_suspicious_agents)
    local suspicious_count=$(count_lines "$suspicious" '|')

    if [[ -n "$suspicious" && "$suspicious_count" -gt 0 ]]; then
        local proc_list=""
        while IFS='|' read -r proc pid user cmdline; do
            [[ -z "$proc" ]] && continue
            proc_list+="$proc (pid:$pid, user:$user), "
        done <<< "$suspicious"
        proc_list="${proc_list%, }"

        check_emit "cloud.suspicious_agents" low failed \
            title="$(i18n 'cloud.suspicious_agents'): $suspicious_count" \
            desc="$proc_list" \
            suggestion="$(i18n 'cloud.review_suspicious')"
    fi

    # 4. IMDS posture audit (tier1 + tier2 only; silent on independent VPS).
    _cloud_audit_imds

    return 0
}

# --- Fix Function ---

# Vendor agents are inventory and disabling one is the operator's call:
# nothing here is auto-fixable. The entry point stays because the engine
# dispatches <module>_fix by name, and a missing one reads as a silent no-op.
cloud_fix() {
    log_warn "cloud has no automatic fix; every finding needs human review: ${1:-}"
    return 1
}
