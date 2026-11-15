#!/usr/bin/env bash
# Which cloud this host runs on, from DMI, cloud-init and the metadata service:
# context for every module, so it is detected whichever modules the audit runs.

CLOUD_DMI_DIR="${CLOUD_DMI_DIR:-/sys/class/dmi/id}"
CLOUD_INIT_RUN_DIR="${CLOUD_INIT_RUN_DIR:-/run/cloud-init}"
# Azure stamps every VM's chassis with this tag; other Hyper-V guests share
# its "Microsoft Corporation" / "Virtual Machine" DMI strings.
CLOUD_AZURE_ASSET_TAG="7783-7084-3265-9085-8269-3286-77"

# Lazily filled by the getters below. Any module may call them, whichever
# modules the audit runs: --exclude=cloud drops only the cloud module's checks.
declare -g VPSSEC_CLOUD_PROVIDER=""
declare -g VPSSEC_CLOUD_TIER=""

# One of: aws azure gcp alibaba tencent huawei oracle digitalocean
# vultr linode hetzner ovh scaleway unknown
vpssec_cloud_provider() {
    [[ -n "$VPSSEC_CLOUD_PROVIDER" ]] || VPSSEC_CLOUD_PROVIDER=$(_detect_cloud_provider)
    echo "$VPSSEC_CLOUD_PROVIDER"
}

# Coarse tier for modules that vary on "what kind of cloud", not which vendor:
# tier1 = IAM credentials in IMDS, tier2 = link-local IMDS without them,
# unknown = no network IMDS. aws-or-compatible is tier1: an EC2-shaped IMDS answered.
vpssec_cloud_tier() {
    if [[ -n "$VPSSEC_CLOUD_TIER" ]]; then
        echo "$VPSSEC_CLOUD_TIER"
        return
    fi
    case "$(vpssec_cloud_provider)" in
        aws|aws-or-compatible|azure|gcp|alibaba|tencent|huawei|oracle)
            VPSSEC_CLOUD_TIER="tier1" ;;
        digitalocean|vultr|linode|hetzner|ovh|scaleway)
            VPSSEC_CLOUD_TIER="tier2" ;;
        *)
            VPSSEC_CLOUD_TIER="unknown" ;;
    esac
    echo "$VPSSEC_CLOUD_TIER"
}

# Map an EC2-compatible IMDS payload — a placement/region string or an
# instance-id — onto a provider name. Pure: no network, no globals, so the
# disambiguation rules below are directly regression-testable.
_cloud_provider_from_imds() {
    # Strip whitespace; lower-case for region match.
    local _b
    _b=$(printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')

    case "$_b" in
        # Tencent regions: ap-* (overlaps with AWS Asia-Pacific) plus
        # eu-frankfurt, na-* — but the real giveaway is the instance-id
        # prefix "ins-".
        ins-*)                echo "tencent" ;;
        # AWS Nitro / Xen instance IDs.
        i-*)                  echo "aws" ;;
        # AWS China (Ningxia). cn-northwest-* exists only on AWS, and it has
        # to be matched before the Huawei cn-* shapes below, which would
        # otherwise claim it.
        cn-northwest-*)       echo "aws" ;;
        # Huawei-EXCLUSIVE shapes, and they MUST precede the generic
        # `*-[0-9])` AWS rule: every Huawei region also ends in a digit, so
        # that rule matches first and this branch becomes unreachable.
        cn-east-*|cn-south*|la-north-*|la-south-*|ru-northwest-*|na-mexico-*)
                              echo "huawei" ;;
        # A TRUE collision: both AWS Beijing and Huawei use cn-north-1 and
        # the region string cannot separate them. Keeping AWS trades no
        # misdetection for another; every other cn-north-* is Huawei-only.
        cn-north-1)           echo "aws" ;;
        cn-north-*)           echo "huawei" ;;
        # AWS region tokens always carry a single trailing digit, which
        # Tencent's eu-frankfurt and ap-guangzhou do not. The shapes shared
        # with Huawei stay AWS for the same reason as cn-north-1.
        *-[0-9])              echo "aws" ;;
        ap-guangzhou|ap-shanghai|ap-beijing|ap-chengdu|ap-chongqing|ap-nanjing|ap-hongkong|ap-singapore|ap-bangkok|ap-jakarta|ap-mumbai|ap-seoul|ap-tokyo|na-siliconvalley|na-ashburn|na-toronto|sa-saopaulo|eu-frankfurt|eu-moscow)
                              echo "tencent" ;;
        # Last resort: we got *something* from 169.254.169.254 with the EC2
        # path shape; fall back to AWS but flag via the ambiguous return.
        *)                    echo "aws-or-compatible" ;;
    esac
}

_detect_cloud_provider() {
    local provider="unknown"
    # OpenStack (Nova) answers the EC2 metadata paths with i- instance ids;
    # once it is known, the shared-IP guessing below would only invent AWS.
    local openstack=0

    # ---------- 1. DMI sys_vendor ----------
    if [[ -r "$CLOUD_DMI_DIR/sys_vendor" ]]; then
        local vendor=$(cat "$CLOUD_DMI_DIR/sys_vendor" 2>/dev/null)
        case "$vendor" in
            *"Alibaba"*)     provider="alibaba" ;;
            *"Tencent"*)     provider="tencent" ;;
            *"HUAWEI"*|*"Huawei"*) provider="huawei" ;;
            *"Amazon"*)      provider="aws" ;;
            *"Microsoft"*)
                [[ "$(cat "$CLOUD_DMI_DIR/chassis_asset_tag" 2>/dev/null)" == "$CLOUD_AZURE_ASSET_TAG" ]] \
                    && provider="azure" ;;
            *"Google"*)      provider="gcp" ;;
            *"DigitalOcean"*) provider="digitalocean" ;;
            *"Vultr"*|*"Choopa"*) provider="vultr" ;;
            *"Linode"*|*"Akamai"*) provider="linode" ;;
            *"Oracle"*)      provider="oracle" ;;
            *"Hetzner"*)     provider="hetzner" ;;
            *"OVH"*)         provider="ovh" ;;
            *"Scaleway"*|*"Online"*) provider="scaleway" ;;
        esac
    fi

    # ---------- 2. DMI product_name ----------
    if [[ "$provider" == "unknown" && -r "$CLOUD_DMI_DIR/product_name" ]]; then
        local product=$(cat "$CLOUD_DMI_DIR/product_name" 2>/dev/null)
        case "$product" in
            *"Alibaba"*|*"Aliyun"*|*"ECS"*)  provider="alibaba" ;;
            *"CVM"*|*"Tencent"*)             provider="tencent" ;;
            # Not "HVM domU" (any Xen guest; EC2's uuid prefix decides below)
            # nor "Virtual Machine" (any Hyper-V guest).
            *"OpenStack"*)                   openstack=1 ;;   # Nova's default product
            *"Google Compute Engine"*)       provider="gcp" ;;
            *"Droplet"*)                     provider="digitalocean" ;;
            *"Standard PC (Q35"*) ;;  # very generic — KVM default, do not classify
            *"OracleCloud"*)                 provider="oracle" ;;
            *"VirtualBox"*) ;;        # local dev — leave as unknown
        esac
    fi

    # ---------- 2b. board_vendor / bios_vendor (rare; some providers
    # only stamp these). Only consult if still unknown.
    if [[ "$provider" == "unknown" ]]; then
        local extra
        for extra in "$CLOUD_DMI_DIR/board_vendor" "$CLOUD_DMI_DIR/bios_vendor" "$CLOUD_DMI_DIR/chassis_vendor"; do
            [[ -r "$extra" ]] || continue
            local val=$(cat "$extra" 2>/dev/null)
            case "$val" in
                *"Tencent"*)     provider="tencent"; break ;;
                *"Alibaba"*)     provider="alibaba"; break ;;
                *"Amazon"*)      provider="aws"; break ;;
                *"DigitalOcean"*) provider="digitalocean"; break ;;
                *"Hetzner"*)     provider="hetzner"; break ;;
                *"Oracle"*)      provider="oracle"; break ;;
            esac
        done
    fi

    # --- 3. product_uuid prefix: EC2 on Xen, random on Nitro. A tiebreaker
    # for when the DMI vendor is generic. ---
    if [[ "$provider" == "unknown" && -r "$CLOUD_DMI_DIR/product_uuid" ]]; then
        # Read may fail with EACCES for non-root; ignore quietly.
        local uuid=$(cat "$CLOUD_DMI_DIR/product_uuid" 2>/dev/null | tr '[:upper:]' '[:lower:]')
        if [[ "$uuid" == ec2* ]]; then
            provider="aws"
        fi
    fi

    # ---------- 4. cloud-init datasource ----------
    if [[ "$provider" == "unknown" ]]; then
        local ds=""

        # Preferred: cloud-init's resolved cloud-id (single token).
        if [[ -r "$CLOUD_INIT_RUN_DIR/cloud-id" ]]; then
            ds=$(head -n1 "$CLOUD_INIT_RUN_DIR/cloud-id" 2>/dev/null | tr -d '[:space:]')
        fi

        # Next: ds-identify.log (multi-line; first datasource: line wins).
        if [[ -z "$ds" && -f "$CLOUD_INIT_RUN_DIR/ds-identify.log" ]]; then
            ds=$(grep -oP 'datasource: \K\w+' "$CLOUD_INIT_RUN_DIR/ds-identify.log" 2>/dev/null | head -1)
        fi

        # Persisted datasource (survives reboot, set by cloud-init init).
        if [[ -z "$ds" && -r /var/lib/cloud/data/datasource ]]; then
            ds=$(head -n1 /var/lib/cloud/data/datasource 2>/dev/null | awk -F': ' '{print $1}')
        fi

        # /etc/cloud/cloud.cfg.d/ drop-ins. Vendors ship distinct names;
        # we look at filenames rather than parse the YAML.
        if [[ -z "$ds" && -d /etc/cloud/cloud.cfg.d ]]; then
            local f
            for f in /etc/cloud/cloud.cfg.d/*.cfg; do
                [[ -f "$f" ]] || continue
                case "$f" in
                    *aliyun*|*alicloud*) ds="AliYun"; break ;;
                    *tencent*|*qcloud*)  ds="Tencent"; break ;;
                    *digitalocean*)      ds="DigitalOcean"; break ;;
                    *hetzner*)           ds="Hetzner"; break ;;
                    *vultr*)             ds="Vultr"; break ;;
                    *oracle*)            ds="Oracle"; break ;;
                esac
            done
        fi

        case "$ds" in
            "Ec2"|"aws"|"AWS")                   provider="aws" ;;
            "Azure"|"azure")                     provider="azure" ;;
            "GCE"|"gce"|"gcp")                   provider="gcp" ;;
            "DigitalOcean"|"digitalocean")       provider="digitalocean" ;;
            "Vultr"|"vultr")                     provider="vultr" ;;
            "Hetzner"|"hetzner"|"hcloud")        provider="hetzner" ;;
            "AliYun"|"aliyun"|"alibaba")         provider="alibaba" ;;
            "Tencent"|"tencent")                 provider="tencent" ;;
            "Oracle"|"oracle"|"oci")             provider="oracle" ;;
            "Linode"|"linode")                   provider="linode" ;;
            "Scaleway"|"scaleway")               provider="scaleway" ;;
            "OpenStack"|"openstack")
                # OVH and several Chinese clouds use OpenStack — stays
                # unknown unless one of the offline signals above
                # already pinned it.
                openstack=1 ;;
        esac
    fi

    # A vendor named offline stands; only an OpenStack host nothing named stops.
    if [[ "$provider" == "unknown" ]] && (( openstack )); then
        echo "unknown"
        return 0
    fi

    # ---------- 5. Provider-specific files ----------
    if [[ "$provider" == "unknown" ]]; then
        if [[ -e /etc/digitalocean ]] || [[ -e /var/lib/digitalocean ]]; then
            provider="digitalocean"
        elif [[ -e /etc/hetzner-build ]] || [[ -e /var/lib/hetzner ]]; then
            provider="hetzner"
        elif [[ -e /etc/oracle-cloud-agent ]] || [[ -d /etc/oci-hostname.conf ]]; then
            provider="oracle"
        fi
    fi

    # --- 6. Provider-specific NETWORK endpoints. Unique per provider, so a
    # 200 is conclusive — and they MUST precede the shared 169.254.169.254
    # fallback, or an EC2-compatible mirror reads as AWS. ---
    if [[ "$provider" == "unknown" ]]; then
        # Tencent serves its own metadata name AND mirrors an EC2-compatible
        # service at the shared IP, so the specific name is tried first.
        if curl -fs --connect-timeout 1 -m 2 \
            http://metadata.tencentyun.com/latest/meta-data/ >/dev/null 2>&1; then
            provider="tencent"
        # Alibaba IMDS at its dedicated 100.100.100.200.
        elif curl -fs --connect-timeout 1 -m 2 \
            http://100.100.100.200/latest/meta-data/ >/dev/null 2>&1; then
            provider="alibaba"
        # Oracle Cloud (OCI) IMDS — distinct path /opc/v2/instance/.
        elif curl -fs --connect-timeout 1 -m 2 \
            -H "Authorization: Bearer Oracle" \
            http://169.254.169.254/opc/v2/instance/ >/dev/null 2>&1; then
            provider="oracle"
        # Hetzner Cloud IMDS — distinct path /hetzner/v1/metadata.
        elif curl -fs --connect-timeout 1 -m 2 \
            http://169.254.169.254/hetzner/v1/metadata/ >/dev/null 2>&1; then
            provider="hetzner"
        # DigitalOcean IMDS — distinct path /metadata/v1/.
        elif curl -fs --connect-timeout 1 -m 2 \
            http://169.254.169.254/metadata/v1/id >/dev/null 2>&1; then
            provider="digitalocean"
        # Vultr IMDS — distinct path /v1.json.
        elif curl -fs --connect-timeout 1 -m 2 \
            http://169.254.169.254/v1.json >/dev/null 2>&1; then
            provider="vultr"
        fi
    fi

    # --- 7. Shared 169.254.169.254, which several providers all answer.
    # A bare 200 is NOT enough: the region or instance-id payload has to be
    # read and matched. ---
    if [[ "$provider" == "unknown" ]]; then
        local _imds_body=""

        # IMDSv2 token-required path (AWS/Tencent both support this).
        local _aws_token
        _aws_token=$(curl -fs -X PUT --connect-timeout 1 -m 2 \
            -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
            http://169.254.169.254/latest/api/token 2>/dev/null) || true
        if [[ -n "$_aws_token" ]]; then
            _imds_body=$(curl -fs --connect-timeout 1 -m 2 \
                -H "X-aws-ec2-metadata-token: $_aws_token" \
                http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null) || true
            if [[ -z "$_imds_body" ]]; then
                # Fallback to instance-id; AWS Nitro IDs start with "i-"
                # (Tencent uses "ins-").
                _imds_body=$(curl -fs --connect-timeout 1 -m 2 \
                    -H "X-aws-ec2-metadata-token: $_aws_token" \
                    http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null) || true
            fi
        fi

        # IMDSv1 fallback (rare on AWS post-2024; common on Tencent /
        # several local cloud appliances).
        if [[ -z "$_imds_body" ]]; then
            _imds_body=$(curl -fs --connect-timeout 1 -m 2 \
                http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null) || true
            if [[ -z "$_imds_body" ]]; then
                _imds_body=$(curl -fs --connect-timeout 1 -m 2 \
                    http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null) || true
            fi
        fi

        if [[ -n "$_imds_body" ]]; then
            provider=$(_cloud_provider_from_imds "$_imds_body")
            # Nova serves i-%08x ids too; its own metadata tree tells it apart.
            if [[ "$provider" == aws* ]] && curl -fs --connect-timeout 1 -m 2 \
                http://169.254.169.254/openstack/latest/meta_data.json >/dev/null 2>&1; then
                provider="unknown"
            fi
        else
            # Try Azure (header-required path) and GCP (header + path).
            if curl -fs --connect-timeout 1 -m 2 -H "Metadata: true" \
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
                >/dev/null 2>&1; then
                provider="azure"
            elif curl -fs --connect-timeout 1 -m 2 \
                -H "Metadata-Flavor: Google" \
                http://169.254.169.254/computeMetadata/v1/ >/dev/null 2>&1; then
                provider="gcp"
            fi
        fi
    fi

    echo "$provider"
}
