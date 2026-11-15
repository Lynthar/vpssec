#!/usr/bin/env bats
# _vpssec_absent_command makes a command absent by redefining check_command. A
# production probe that bypasses it (command -v, type -P, hash, which) still
# finds the command, so the absent branch the test claims to cover never runs.

load helpers

@test "a command some test makes absent is probed only through check_command" {
    local root cmds alt hits
    root=$(_vpssec_repo_root)
    cmds=$(grep -hoE '_vpssec_absent_command +[A-Za-z0-9_.+-]+' "$root"/tests/*.bats \
        | awk '{ print $2 }' | sort -u)
    [ "$(wc -l <<<"$cmds")" -gt 10 ]
    alt=$(sed 's/[.+]/\\&/g' <<<"$cmds" | paste -sd'|' -)
    hits=$(grep -nE "(command -v|type -P|hash|which)[[:space:]]+\"?($alt)\"?([^A-Za-z0-9_.+-]|\$)" \
        "$root"/vpssec "$root"/core/*.sh "$root"/modules/*.sh \
        | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)
    [ -z "$hits" ] || { printf 'probed past check_command:\n%s\n' "$hits" >&2; return 1; }
}
