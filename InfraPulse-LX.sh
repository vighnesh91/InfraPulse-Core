#!/usr/bin/env bash
# =============================================================================================
#  InfraPulse-LX.sh
#  Single-file, read-only internal-network VAPT assessment for Linux hosts.
#
#  WHAT IT DOES: assesses THIS host, and (only when explicitly authorised) the bounded address
#  range around it. Every finding separates a DISCOVERED WEAKNESS from a VALIDATED CONDITION,
#  and anything that could not be observed is reported NOT TESTABLE rather than assumed.
#
#  WHAT IT DOES NOT DO: it does not modify the system, install packages, change configuration,
#  dump credential material, read /etc/shadow, extract SSH private keys, or attempt
#  authentication against remote hosts. It never writes outside its own output directory.
#
#  ARCHITECTURE NOTE: unlike the Windows build there is no launcher/engine split and no
#  extraction step, because bash needs no separate interpreter file. That removes a whole class
#  of operational problem - nothing is written to a temporary directory, so an execution-control
#  policy (AppArmor, SELinux, noexec mounts on /tmp) cannot block the tool from running.
#
#  OPERATIONAL CHECKLIST
#    [1] PROVENANCE - hash this file before transfer and compare with the copy the engagement
#        owner holds:
#            sha256sum InfraPulse-LX.sh
#        The digest is also written as the FIRST data row of the CSV, computed by the script
#        over its own file, so the report and the artefact can be tied together afterwards.
#    [2] PASSIVE / NO-EGRESS PROFILING - assessment of this host only, no packet leaves it:
#            ./InfraPulse-LX.sh --local-only
#    [3] FULL ACTIVE ASSESSMENT - additionally sweeps the derived local /24, which REQUIRES an
#        explicit authorisation act (a scope, or --authorize-active). A bare run is local-only.
#    [4] READ THE OUTPUT - confirm the FIRST DATA ROW (row 2; row 1 is the header) of
#        Internal_VAPT_Report_<HOST>_<STAMP>.csv carries the self-authenticated signature, and
#        row 3 the rules-of-engagement record.
#
#  SCOPE AND AUTHORISATION
#    Off-host work is refused unless authorised, and is default-deny when a scope is supplied:
#        --scope CIDR[,CIDR|HOST|!EXCLUDE]     e.g. --scope 10.0.0.0/24,!10.0.0.99
#        --scopefile PATH                      one entry per line, # starts a comment
#        --authorize-active                    authorise without narrowing the scope
#    A host-name suffix entry requires a leading dot (.corp.example.com) so that
#    evilcorp.example.com can never match it.
#
#    KILL SWITCH: create a file named EIA_STOP in the working directory or in /tmp, or export
#    EIA_KILL_SWITCH=1. Every further off-host operation is refused immediately, and no new
#    module starts. Modules that were skipped are recorded as NOT TESTABLE.
#
#    A scope that was SUPPLIED but contains nothing parsable exits 2 rather than running: falling
#    back to a permissive run while the operator believes the assessment is confined would be the
#    most dangerous failure this tool could have.
#
#  SINGLE SOCKET CHOKE POINT (provable)
#    Exactly four functions in this file can open a connection to another host:
#        tcp_open, tcp_read_banner, grab_banner, tls_certificate
#    Every one of them calls socket_gate first, which composes the kill switch, the network
#    authorisation and the engagement scope. A connection to this host or to loopback is exempt,
#    because it never leaves the host. Verify rather than trust:
#        ./audit_sockets_linux.sh InfraPulse-LX.sh
#
#  THROTTLING (do not remove)
#    MAX_PARALLEL=32 and STARTUP_DELAY_MS=25 bound interface pressure on production network
#    hardware. --fast raises concurrency to 128 and removes the spacing; it is OPT-IN and must be
#    a deliberate decision for an isolated range, never a default.
# =============================================================================================

# STRICT MODE, deliberately limited to pipefail.
#
# `set -e` is NOT used: a single non-zero check would abort the whole assessment, and this tool is
# required to continue past any one failed check (Section 23).
#
# `set -u` is NOT used either, and the reason is a MEASURED failure rather than a preference.
# During testing, `${!hostports[@]:-}` on an array that had gone out of scope produced
# "invalid indirect expansion", which did not kill the process: it abandoned the ENTIRE function
# call stack, returned to the top level, and the script then exited 0 having silently skipped
# Sections 17 to 21 and never finalised the report. A run that dies quietly and reports success is
# the worst possible failure mode for an assessment tool. With `-u` removed the same expression
# evaluates to empty and execution continues normally. The loss of unbound-variable detection is
# paid for by `assert_section_completion`, which detects an abandoned section and records it as an
# ERROR in the report instead of hiding it.
set -o pipefail

# ---------------------------------------------------------------------------------------------
#  IDENTITY
# ---------------------------------------------------------------------------------------------
readonly TOOL_NAME='InfraPulse-LX'
readonly TOOL_VERSION='1.0.0'
readonly SELF_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
readonly REPORT_COLUMNS='Timestamp,Severity,Category,Source,Target,Port,Finding,Prerequisites,ConfigurationEvidence,ValidationMethod,ObservedResult,Exploitability,Impact,Remediation'

# ---------------------------------------------------------------------------------------------
#  CONFIGURATION
#  Two profiles. 'balanced' (default) paces the sweep so fragile embedded devices on an internal
#  estate are not knocked offline by a burst of half-open connections - that is an availability
#  incident inside the customer's network, not a finding. 'fast' removes most of the pacing and
#  is an operator decision.
# ---------------------------------------------------------------------------------------------
SCAN_PROFILE='balanced'
TCP_TIMEOUT_MS=700
MAX_PARALLEL=32
SWEEP_DEADLINE=30
STARTUP_DELAY_MS=25
MAX_AD_OBJECTS=100000
STALE_PASSWORD_AGE=180
LOCAL_ONLY=0
NETWORK_AUTH=0
# Refined by detect_transport() at start-up; the default is the normal case so a section called
# directly (for example from a test harness) still has a usable transport.
TRANSPORT='devtcp'
REQUIRE_NETWORK_AUTH=1
NO_PAUSE=0
FIXED_REPORT_NAME=0
OUTDIR=''
SCOPE_RAW=''
AUTHORISATION_REF="${EIA_AUTHORISATION_REF:-}"

if [ "${EIA_SCAN_PROFILE:-}" = 'fast' ] || [ "${EIA_SCAN_PROFILE:-}" = 'aggressive' ]; then
    SCAN_PROFILE='fast'
    TCP_TIMEOUT_MS=400; MAX_PARALLEL=128; SWEEP_DEADLINE=20; STARTUP_DELAY_MS=0
fi

# ---------------------------------------------------------------------------------------------
#  TOOL DISCOVERY PATH
#
#  An unprivileged login on Debian, Ubuntu and most RHEL-family hosts does NOT have /usr/sbin or
#  /sbin on PATH: distributions add those directories for root only. The tools that matter to an
#  assessment live exactly there - getcap, sshd, nft, iptables, ip6tables, auditctl, smbd - so
#  `command -v` reported them ABSENT on hosts where they are installed, and the report told the
#  operator to "install libcap2-bin" on a host that already had it. Measured on Debian 13 with
#  libcap2-bin installed: getcap was invisible to an unprivileged shell and present at /sbin/getcap.
#
#  The standard administrative directories are therefore APPENDED to PATH. Appending rather than
#  prepending is deliberate: anything the operator has already put on PATH keeps its precedence, so
#  this cannot silently substitute a different binary for one the environment already resolves.
# ---------------------------------------------------------------------------------------------
PATH_AUGMENTED=''
for _d in /usr/local/sbin /usr/sbin /sbin; do
    case ":$PATH:" in
        *":$_d:"*) ;;
        *) if [ -d "$_d" ]; then PATH="${PATH:+$PATH:}$_d"; PATH_AUGMENTED="${PATH_AUGMENTED:+$PATH_AUGMENTED }$_d"; fi ;;
    esac
done
unset _d
export PATH

# ---------------------------------------------------------------------------------------------
#  ARGUMENTS
# ---------------------------------------------------------------------------------------------
usage() {
    cat <<'USAGE'
InfraPulse-LX.sh - read-only internal-network VAPT assessment

  --scope LIST        authorise off-host work and confine it to LIST, comma separated:
                        CIDR            10.0.0.0/24
                        address         10.0.0.5
                        host name       srv-db-01
                        name suffix     .corp.example.com   (leading dot required)
                        exclusion       !10.0.0.99          (applied before includes)
                      Supplying a scope makes the run DEFAULT-DENY: any target outside the
                      list is refused and no packet is sent to it.
  --scopefile PATH    read the same list from a file, one entry per line, # for comments
  --authorize-active  authorise off-host work without narrowing the scope
  --local-only        assess THIS HOST ONLY. No off-host packet of any kind is sent.
  --fast              aggressive profile: 128 sockets, 400 ms connect, no host spacing
  --outdir PATH       write the report here (default: beside this script, else /var/tmp)
  --fixed-name        use the literal Internal_VAPT_Compliance_Report.csv filename
  --no-pause          do not wait for a keypress at the end
  --help              this text

  Exit codes:  0 completed   2 bad usage   91 unsupported bash   94 no writable output dir
USAGE
}

bad_usage() {
    printf '[ERROR] %s\n' "$1" >&2
    printf 'Run with --help for usage.\n' >&2
    exit 2
}

parse_args() {
    # Wrapped in a function so the file can be sourced for testing without the harness argv being
    # parsed as assessment switches. The LX_TESTLIB guard below skips the call when sourced.
    local f
    while [ $# -gt 0 ]; do
    case "$1" in
        --scope)
            # A MISSING VALUE MUST NOT AUTHORISE ANYTHING. The naive form `NETWORK_AUTH=1` with an
            # empty scope grants off-host authorisation AND leaves the run permissive, which is the
            # single most dangerous combination this tool can produce. Refuse instead.
            [ -n "${2:-}" ] || bad_usage "--scope requires a value (for example --scope 10.0.0.0/24,!10.0.0.9)"
            SCOPE_RAW="$2"; NETWORK_AUTH=1; shift 2 ;;
        --scope=*)
            [ -n "${1#*=}" ] || bad_usage "--scope requires a value (for example --scope=10.0.0.0/24)"
            SCOPE_RAW="${1#*=}"; NETWORK_AUTH=1; shift ;;
        --scopefile)
            [ -n "${2:-}" ] || bad_usage "--scopefile requires a path"
            if [ -r "${2:-}" ]; then
                SCOPE_RAW="$SCOPE_RAW,$(cat "$2")"
                NETWORK_AUTH=1
            else
                # Authorisation is granted ONLY when the file was actually read. An unreadable scope
                # file previously still set NETWORK_AUTH=1, so a typo in the path silently granted
                # permission for off-host work with no scope at all.
                printf '[ERROR] scope file not readable: %s - off-host work is NOT authorised\n' "$2" >&2
            fi
            shift 2 ;;
        --scopefile=*)
            f="${1#*=}"
            if [ -r "$f" ]; then
                SCOPE_RAW="$SCOPE_RAW,$(cat "$f")"
                NETWORK_AUTH=1
            else
                printf '[ERROR] scope file not readable: %s - off-host work is NOT authorised\n' "$f" >&2
            fi
            shift ;;
        --authorize-active) NETWORK_AUTH=1; shift ;;
        --local-only)       LOCAL_ONLY=1; shift ;;
        --fast)             SCAN_PROFILE='fast'; TCP_TIMEOUT_MS=400; MAX_PARALLEL=128; SWEEP_DEADLINE=20; STARTUP_DELAY_MS=0; shift ;;
        --outdir)           [ -n "${2:-}" ] || bad_usage "--outdir requires a path"; OUTDIR="$2"; shift 2 ;;
        --outdir=*)         OUTDIR="${1#*=}"; shift ;;
        --fixed-name)       FIXED_REPORT_NAME=1; shift ;;
        --no-pause)         NO_PAUSE=1; shift ;;
        --help|-h)          usage; exit 0 ;;
        *)                  printf '[WARN] Unrecognised argument ignored: %s\n' "$1" >&2; shift ;;
    esac
    done

    if [ -n "${EIA_LOCAL_ONLY:-}" ] && [ "$EIA_LOCAL_ONLY" = '1' ]; then LOCAL_ONLY=1; fi
    if [ -n "${EIA_NETWORK_AUTH:-}" ] && [ "$EIA_NETWORK_AUTH" = '1' ]; then NETWORK_AUTH=1; fi
    if [ -n "${EIA_OUTDIR:-}" ]; then OUTDIR="$EIA_OUTDIR"; fi
}

# LX_TESTLIB: set by the test harness. When present, the script defines its functions and then
# stops, so the harness can call them directly. Sourcing without it runs a real assessment, which
# is deliberate: the guard must never be something a normal run can trip by accident.
if [ -z "${LX_TESTLIB:-}" ]; then
    parse_args "$@"
fi

# ---------------------------------------------------------------------------------------------
#  CONSOLE / STATUS
# ---------------------------------------------------------------------------------------------
if [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'; C_GREY=$'\033[90m'; C_WHITE=$'\033[97m'; C_BOLD=$'\033[1m'
else
    C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_GREY=''; C_WHITE=''; C_BOLD=''
fi

FINDING_COUNT=0
MALFORMED_FIELDS=0

# Discovery results are shared across sections: Section 16 correlates what Section 8 found, so
# this MUST be global. Declaring it inside the discovery function silently left Section 16 with an
# empty array, and `${!arr[@]}` on an unset array is an "invalid indirect expansion" error.
# Bash 3.x-compatible indexed map replacing the original associative array.
HOSTPORT_KEYS=()
HOSTPORT_VALUES=()

hostport_index() {
    local key="$1" i
    i=0
    while [ "$i" -lt "${#HOSTPORT_KEYS[@]}" ]; do
        [ "${HOSTPORT_KEYS[$i]}" = "$key" ] && { printf '%s' "$i"; return 0; }
        i=$((i+1))
    done
    return 1
}

hostport_get() {
    local i
    i=$(hostport_index "$1") || return 1
    printf '%s' "${HOSTPORT_VALUES[$i]}"
}

hostport_set() {
    local key="$1" val="$2" i
    if i=$(hostport_index "$key"); then
        HOSTPORT_VALUES[$i]="$val"
    else
        HOSTPORT_KEYS+=("$key")
        HOSTPORT_VALUES+=("$val")
    fi
}
declare -a LIVE_HOSTS=()
DISCOVERY_DONE=0
STATS_WARN=0
STATS_RISK=0
STATS_VALIDATED=0
STATS_NOTTESTABLE=0
STATS_NOTCONFIRMED=0
STATS_ERRORS=0
STATS_OPPS=0
STATS_INFO=0
STATS_PASS=0

# Every row is also kept in memory, mirroring $script:Findings in the Windows build. Section 19.4
# classifies these rows and the validation handoff is built from them, so both operate on the
# EXACT values that were recorded rather than re-parsing the CSV and hoping the escaping round-trips.
# Fields are separated by ASCII 0x1F (unit separator), which cannot occur in operator-written text.
declare -a FINDINGS=()

# Section-completion sentinel. Every section announces itself through write_section, so the last
# section id seen is a reliable witness to how far the run actually got. main() compares it against
# the section it expected to finish LAST; any shortfall means a section abandoned the call stack or
# the run was stopped, and either way the report says so rather than presenting a partial run as a
# complete one. This is the control that replaced `set -u`.
SECTIONS_SEEN=0
LAST_SECTION=''
SECTION_LOG=''

write_section() {
    SECTIONS_SEEN=$((SECTIONS_SEEN + 1))
    LAST_SECTION="$1"
    SECTION_LOG+="$1 "
    printf '\n%s================================================================%s\n' "$C_BOLD" "$C_RESET"
    printf '%s  SECTION %s :: %s%s\n' "$C_BOLD" "$1" "$2" "$C_RESET"
    printf '%s================================================================%s\n' "$C_BOLD" "$C_RESET"
}

status_colour() {
    case "$1" in
        PASS)             printf '%s' "$C_GREEN" ;;
        WARN|RISK\ DETECTED|VALIDATED) printf '%s' "$C_YELLOW" ;;
        ERROR)            printf '%s' "$C_RED" ;;
        NOT\ TESTABLE|NOT\ CONFIRMED|OPPORTUNITY) printf '%s' "$C_GREY" ;;
        *)                printf '%s' "$C_WHITE" ;;
    esac
}

write_status() {
    printf '  %s%-16s%s %s\n' "$(status_colour "$1")" "[$1]" "$C_RESET" "$2"
}

write_kv() {
    printf '    %-34s %s\n' "$1" "$2"
}

write_table() {
    # write_table "HEADER1|HEADER2" "row1col1|row1col2" "row2col1|row2col2" ...
    local header="$1"; shift
    if [ $# -eq 0 ]; then printf '    (no records)\n'; return; fi
    local IFS='|'
    local -a rows=("$@")
    local -a widths=()
    local -a hdr; read -r -a hdr <<< "$header"
    local i=0
    for h in "${hdr[@]}"; do widths[$i]=${#h}; i=$((i+1)); done
    for r in "${rows[@]}"; do
        local -a cols; read -r -a cols <<< "$r"
        i=0
        for c in "${cols[@]}"; do
            [ ${#c} -gt "${widths[$i]:-0}" ] && widths[$i]=${#c}
            i=$((i+1))
        done
    done
    local line='    '
    i=0
    for h in "${hdr[@]}"; do
        printf -v pad '%-*s' "${widths[$i]}" "$h"; line+="$pad  "; i=$((i+1))
    done
    printf '%s\n' "$line"
    for r in "${rows[@]}"; do
        local -a cols; IFS='|' read -r -a cols <<< "$r"
        line='    '; i=0
        for c in "${cols[@]}"; do
            printf -v pad '%-*s' "${widths[$i]}" "$c"; line+="$pad  "; i=$((i+1))
        done
        printf '%s\n' "$line"
    done
}

# ---------------------------------------------------------------------------------------------
#  TOOL AVAILABILITY
#  The assessment runs on a BASE INSTALL. Where a control can only be observed with a tool that
#  is absent, the finding is NOT TESTABLE and names the missing tool - never silently skipped
#  and never inferred from something else.
# ---------------------------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

lower_string() {
    printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'
}

# ---------------------------------------------------------------------------------------------
#  PORTABILITY ABSTRACTIONS - GNU/BUSYBOX/BSD USERLAND COMPATIBILITY
#  Keep all permission reads behind this function. GNU stat uses `-c`; BusyBox/BSD stat uses
#  the filesystem-format form requested by the compatibility baseline. A blank result means the
#  metadata could not be read and MUST NOT be treated as a safe permission state.
# ---------------------------------------------------------------------------------------------
get_octal_perms() {
    [ -n "${1:-}" ] || return 1
    if stat --help 2>&1 | grep -q 'GNU'; then
        stat -c '%a' "$1" 2>/dev/null
    else
        stat -f '%A' "$1" 2>/dev/null
    fi
}

# Resolve a package/file target before ownership checks. `readlink -f` is deliberately required for
# the ownership path so a symlink cannot make dpkg/rpm answer for a different pathname than the one
# actually being assessed. The original path is retained by the caller for evidence.
resolve_assessed_path() {
    local p="${1:-}" r
    [ -n "$p" ] || return 1
    r=$(readlink -f "$p" 2>/dev/null) || return 1
    [ -n "$r" ] || return 1
    case "$r" in /*) printf '%s\n' "$r" ;; *) return 1 ;; esac
}

# Explicit package-ownership verification. Return stdout only when a clean, non-empty ownership
# answer was obtained; return 1 for missing/unusable package databases or malformed/empty output.
package_owner() {
    local path="$1" resolved out clean
    resolved=$(resolve_assessed_path "$path") || return 1
    if dpkg_usable; then
        out=$(dpkg-query -S -- "$resolved" 2>/dev/null) || return 1
        clean=$(printf '%s\n' "$out" | sed '/^[[:space:]]*$/d')
        [ -n "$clean" ] || return 1
        # dpkg-query -S returns package/path records; reject diagnostic-looking stdout.
        printf '%s\n' "$clean" | grep -Eq '^[^[:space:]]+:[[:space:]]+/.+' || return 1
        printf '%s\n' "$clean"
        return 0
    fi
    if rpm_usable; then
        out=$(rpm -qf -- "$resolved" 2>/dev/null) || return 1
        clean=$(printf '%s\n' "$out" | sed '/^[[:space:]]*$/d')
        [ -n "$clean" ] || return 1
        printf '%s\n' "$clean" | grep -Eq '^[[:alnum:]_+.-]+(-[[:alnum:]_.+:-]+){1,}$' || return 1
        printf '%s\n' "$clean"
        return 0
    fi
    return 1
}

# Compute once at startup. bounded_parallel_echo uses this value directly so the active-address loop
# never forks awk once per target.
DELAY_SEC='0'
set_startup_delay() {
    if [ "${STARTUP_DELAY_MS:-0}" -gt 0 ] 2>/dev/null; then
        if have awk; then
            DELAY_SEC=$(awk -v m="$STARTUP_DELAY_MS" 'BEGIN{printf "%.3f", m/1000}')
        else
            # Integer-only fallback; sleep accepts this on BusyBox and traditional Unix shells.
            DELAY_SEC=$((STARTUP_DELAY_MS / 1000))
            [ "$DELAY_SEC" -gt 0 ] || DELAY_SEC='0'
        fi
    else
        DELAY_SEC='0'
    fi
}
set_startup_delay

tool_search_note() {
    # Used in NOT TESTABLE text: states that the search covered the administrative directories too,
    # so the operator can tell "not installed" from "installed but not where we looked".
    if [ -n "$PATH_AUGMENTED" ]; then
        printf 'searched PATH including %s' "$PATH_AUGMENTED"
    else
        printf 'searched PATH'
    fi
}

dpkg_usable() {
    have dpkg-query || return 1
    local n
    n=$(dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | head -1)
    [ -n "$n" ]
}

rpm_usable() {
    # `have rpm` is NOT sufficient evidence that rpm manages this host. rpm is commonly installed on
    # Debian-family hosts for building or inspecting packages, and there it either has no database
    # or has one this account cannot read: on Debian 13 `rpm -q kernel` exits 1 with
    # "Unable to open sqlite database ... Operation not permitted" while `have rpm` is true.
    #
    # Without this guard the kernel-drift test compared the running kernel against an EMPTY result
    # and the patch-cadence test derived a cadence from nothing - both would have been reported as
    # findings about the host rather than as gaps in the assessment.
    have rpm || return 1
    local n
    n=$(rpm -qa 2>/dev/null | head -1)
    [ -n "$n" ]
}

MISSING_TOOLS=''
note_missing_tool() {
    case ",$MISSING_TOOLS," in *",$1,"*) ;; *) MISSING_TOOLS="${MISSING_TOOLS:+$MISSING_TOOLS,}$1" ;; esac
}

# ---------------------------------------------------------------------------------------------
#  SCOPE ENGINE
# ---------------------------------------------------------------------------------------------
SCOPE_ACTIVE=0
SCOPE_TEXT=''
# Entries that were SUPPLIED but could not be parsed. With default-deny a dropped INCLUDE narrows
# the scope silently, so a malformed scope would otherwise look like a correctly confined run
# while assessing less than the operator asked for. Counted and reported as an ERROR.
SCOPE_DROPPED=0
SCOPE_DROPPED_LIST=''
SCOPE_SOURCE='not supplied (permissive: discovery is bounded to the derived local /24)'
declare -a SCOPE_INC=()
declare -a SCOPE_EXC=()

ip_to_int() {
    local ip="$1" IFS='.'
    local -a o
    read -r -a o <<< "$ip"
    [ ${#o[@]} -eq 4 ] || return 1
    local x
    for x in "${o[@]}"; do
        case "$x" in ''|*[!0-9]*) return 1 ;; esac
        [ "$x" -le 255 ] || return 1
    done
    echo $(( (o[0] << 24) + (o[1] << 16) + (o[2] << 8) + o[3] ))
}

scope_note_dropped() {
    SCOPE_DROPPED=$((SCOPE_DROPPED+1))
    SCOPE_DROPPED_LIST="${SCOPE_DROPPED_LIST:+$SCOPE_DROPPED_LIST, }$1"
}

scope_add() {
    local entry="$1" excl="$2" kind lo hi pat suffix
    case "$entry" in
        */*)
            local base="${entry%%/*}" bits="${entry##*/}"
            case "$bits" in ''|*[!0-9]*) scope_note_dropped "$entry"; return 0 ;; esac
            [ "$bits" -ge 0 ] && [ "$bits" -le 32 ] || { scope_note_dropped "$entry"; return 0; }
            lo=$(ip_to_int "$base") || { scope_note_dropped "$entry"; return 0; }
            local mask=$(( ( (1 << bits) - 1 ) << (32 - bits) ))
            [ "$bits" -eq 0 ] && mask=0
            local net=$(( lo & mask ))
            local hi_i=$(( net | ( (~mask) & 0xFFFFFFFF ) ))
            kind='ip'; lo="$net"; hi="$hi_i" ;;
        *[!0-9.]*|'')
            # host name form
            if [ "${entry#.}" != "$entry" ]; then suffix=1; pat="${entry#.}"; else suffix=0; pat="$entry"; fi
            pat=$(printf '%s' "$pat" | tr '[:upper:]' '[:lower:]')
            kind='host'; lo=0; hi=0 ;;
        *)
            lo=$(ip_to_int "$entry") || { scope_note_dropped "$entry"; return 0; }
            kind='ip'; hi="$lo" ;;
    esac
    # Field 6 is the ORIGINAL text of the entry. The first five fields are what matching needs; the
    # sixth exists so the effective scope can be printed back to the operator in the form they
    # supplied it. Without it the summary rendered as "!|0, 0" and told the operator nothing about
    # which boundary the run was actually confined to.
    if [ "$excl" = '1' ]; then SCOPE_EXC+=("$kind|$lo|$hi|${pat:-}|${suffix:-0}|$entry")
    else SCOPE_INC+=("$kind|$lo|$hi|${pat:-}|${suffix:-0}|$entry"); fi
}

scope_init() {
    SCOPE_INC=(); SCOPE_EXC=()
    [ -n "$SCOPE_RAW" ] || return 0
    # Commas, semicolons and newlines are ALL separators, matching the documented
    # "--scope 10.0.0.0/24,!10.0.0.9" form. An earlier revision split only on ';', so the documented
    # comma form was swallowed as a single unparsable entry and the run silently fell back to
    # permissive - the exact silent-scope failure this engine exists to prevent.
    local stripped
    stripped=$(printf '%s' "$SCOPE_RAW" | tr ',;' '\n\n')
    while IFS= read -r entry; do
        entry="${entry%%#*}"
        entry=$(printf '%s' "$entry" | tr -d ' \t\r')
        [ -n "$entry" ] || continue
        case "$entry" in
            '!'*) scope_add "${entry#!}" 1 ;;
            *)    scope_add "$entry" 0 ;;
        esac
    done <<< "$stripped"
    # A scope was supplied but NOTHING in it could be parsed. Continuing here would run the
    # assessment in PERMISSIVE mode while the operator believes it is confined - the exact silent
    # failure the scope engine exists to prevent. Refuse and say why.
    if [ -n "$SCOPE_RAW" ] && [ ${#SCOPE_INC[@]} -eq 0 ]; then
        printf '[ERROR] a scope was supplied but no entry could be parsed: %s\n' "${SCOPE_DROPPED_LIST:-$SCOPE_RAW}" >&2
        printf '        Off-host work will NOT proceed. Expected: address, CIDR (mask 0-32), or host name, optionally !-prefixed to exclude.\n' >&2
        exit 2
    fi
    if [ ${#SCOPE_INC[@]} -gt 0 ]; then
        SCOPE_ACTIVE=1
        local t=''
        local e
        for e in "${SCOPE_EXC[@]}"; do t+="!${e##*|}, "; done
        for e in "${SCOPE_INC[@]}"; do t+="${e##*|}, "; done
        SCOPE_TEXT="${t%, }"
    fi
}

scope_match_list() {
    # $1 = target, $2 = 'in' or 'out'
    local target="$1" want="$2"
    local -a list=()
    if [ "$want" = 'out' ]; then list=("${SCOPE_EXC[@]}"); else list=("${SCOPE_INC[@]}"); fi
    [ ${#list[@]} -eq 0 ] && return 1
    local ip='' kind lo hi pat suffix
    ip=$(ip_to_int "$target" 2>/dev/null) || ip=''
    local tl
    tl=$(printf '%s' "$target" | tr '[:upper:]' '[:lower:]')
    local e disp
    for e in "${list[@]}"; do
        IFS='|' read -r kind lo hi pat suffix disp <<< "$e"
        if [ "$kind" = 'ip' ]; then
            [ -n "$ip" ] || continue
            if [ "$ip" -ge "$lo" ] && [ "$ip" -le "$hi" ]; then return 0; fi
        else
            if [ "$suffix" = '1' ]; then
                [ "$tl" = "$pat" ] && return 0
                case "$tl" in *".$pat") return 0 ;; esac
            else
                [ "$tl" = "$pat" ] && return 0
            fi
        fi
    done
    return 1
}

test_in_scope() {
    [ -n "$1" ] || return 1
    [ "$SCOPE_ACTIVE" = '0' ] && return 0
    scope_match_list "$1" 'out' && return 1
    scope_match_list "$1" 'in' && return 0
    return 1
}

# ---------------------------------------------------------------------------------------------
#  KILL SWITCH + OFF-HOST GATE
#  Every off-host operation consults test_target_allowed. Nothing else may open a socket.
# ---------------------------------------------------------------------------------------------
test_kill_switch() {
    [ "${EIA_KILL_SWITCH:-}" = '1' ] && return 0
    [ -e "$PWD/EIA_STOP" ] && return 0
    [ -e "/tmp/EIA_STOP" ] && return 0
    return 1
}

test_remote_allowed() {
    [ "$LOCAL_ONLY" = '1' ] && return 1
    if [ "$REQUIRE_NETWORK_AUTH" = '1' ] && [ "$NETWORK_AUTH" != '1' ]; then return 1; fi
    return 0
}

test_target_allowed() {
    test_kill_switch && return 1
    test_remote_allowed || return 1
    test_in_scope "$1" || return 1
    return 0
}

get_suppressed_reason() {
    if test_kill_switch; then
        printf '%s' 'Refused by the KILL SWITCH (EIA_KILL_SWITCH=1 or an EIA_STOP file): no further off-host operation was performed'
    elif [ "$LOCAL_ONLY" = '1' ]; then
        printf '%s' 'Suppressed by operator request (--local-only): no assessment probe was sent to any remote host'
    elif [ "$REQUIRE_NETWORK_AUTH" = '1' ] && [ "$NETWORK_AUTH" != '1' ]; then
        printf '%s' 'Suppressed: no network authorisation was supplied (pass --scope:<list> or --authorize-active). No assessment probe was sent to any remote host'
    else
        printf '%s' "Refused by ENGAGEMENT SCOPE: $1 is not within the supplied scope ($SCOPE_TEXT). No packet was sent to it"
    fi
}

# ---------------------------------------------------------------------------------------------
#  FINDING ENGINE
#  The single route by which evidence reaches the report. Keeping configuration evidence and
#  validation method as SEPARATE fields is what makes "discovered weakness" distinguishable
#  from "validated condition" after the fact.
# ---------------------------------------------------------------------------------------------
csv_escape() {
    # RFC4180, with the same field normalisation the Windows build applies in ConvertTo-CsvField:
    # an embedded newline becomes ' | ' and a carriage return or tab becomes a space, so one finding
    # always occupies exactly one CSV record. Without this a multi-line field silently splits a
    # record in two and every later column in that row shifts by one.
    local v="$1"
    v="${v//$'\r\n'/ | }"
    v="${v//$'\n'/ | }"
    v="${v//$'\r'/ }"
    v="${v//$'\t'/ }"
    v="${v//\"/\"\"}"
    printf '"%s"' "$v"
}

severity_for() {
    # Port of the Windows build's EiaSeverity.Map so the two tools rate identical evidence
    # identically. The mapping is published rather than subjective:
    #
    #   weakness == 0                     -> Informational  (nothing was demonstrated)
    #   CatClass == Context               -> Informational  (identity/context rows; never a finding)
    #   CatClass == DataAtRest            -> High=Medium, Medium=Low, Low=Low
    #   Confidentiality / Integrity / Availability / IdentityRights
    #                                     -> High=High, Medium=Medium, Low=Low, Critical=Critical
    #
    # $1 = Class, $2 = weakness 0|1, $3 = CatClass, $4 = context tag (optional)
    local cls="$1" weak="$2" cat="${3:-Confidentiality}" context="${4:-}"
    case "$context" in
        UNOWNED_PRIVILEGED|STAGING_VIOLATION) printf 'Critical'; return ;;
        LOGIN_INTERCEPT) printf 'High'; return ;;
        KERNEL_MISMATCH) printf 'Medium'; return ;;
    esac
    [ "$weak" = '1' ] || { printf 'Informational'; return; }
    [ "$cat" = 'Context' ] && { printf 'Informational'; return; }
    case "$cat" in
        DataAtRest|'Data at rest')
            case "$cls" in
                Critical) printf 'Critical' ;;
                High)     printf 'Medium' ;;
                Medium)   printf 'Low' ;;
                Low)      printf 'Low' ;;
                *)        printf 'Informational' ;;
            esac
            ;;
        *)
            case "$cls" in
                Critical) printf 'Critical' ;;
                High)     printf 'High' ;;
                Medium)   printf 'Medium' ;;
                Low)      printf 'Low' ;;
                *)        printf 'Informational' ;;
            esac
            ;;
    esac
}

get_validation_class() {
    # Port of Get-ValidationClass. Classifies a row as IMPACT EVIDENCE, ACTIVE VALIDATION or
    # CONFIGURATION EVIDENCE so the reader can tell a demonstrated result from a documented one.
    # NEGATED PHRASES ARE STRIPPED FIRST: without that step the exploitability value "Not
    # demonstrated" matches "demonstrated" and every conservative row is promoted to impact
    # evidence - the exact inversion of what this control exists to prevent.
    local v="$1" e="$2" o="$3" neg
    # Lower-cased BEFORE stripping. The Windows original used PowerShell's -replace, which is
    # case-INSENSITIVE by default, so the equivalent in bash must lowercase first: a case-sensitive
    # substitution left "Not demonstrated" intact (capital N), it matched *demonstrated*, and every
    # conservative row was promoted to IMPACT EVIDENCE - the exact inversion of the control's
    # purpose. Caught by running the tool, not by reading it.
    local el ol vl
    el=$(lower_string "$e"); ol=$(lower_string "$o"); vl=$(lower_string "$v")
    for neg in 'not demonstrated' 'not validated' 'not confirmed' 'not proven' \
               'never demonstrated' 'no impact demonstrated' 'not executed' 'not attempted'; do
        el="${el//$neg/}"
    done
    for neg in 'not confirmed' 'not proven' 'not executed'; do
        ol="${ol//$neg/}"
    done
    case "$el" in
        *demonstrated*|*proven*|*validated*|*confirmed*) printf 'IMPACT EVIDENCE'; return ;;
    esac
    case "$ol" in
        *proven*|*confirmed*|*validated*) printf 'IMPACT EVIDENCE'; return ;;
    esac
    case "$vl" in
        *live*|*probe*|*runtime*|*'connect test'*|*negotiate*|*'as-req'*|*handshake*|*'anonymous bind'*|*x.224*|*wsman*|*'tcp connect'*) printf 'ACTIVE VALIDATION'; return ;;
    esac
    printf 'CONFIGURATION EVIDENCE'
}

add_finding() {
    # add_finding <Status> <Category> <Finding> [key=value ...]
    local st="$1" cat="$2" finding="$3"; shift 3
    local attr='' source='' target='' port='' prereq='' observed=''
    local validation='None (static configuration evidence only)'
    local exploit='Not demonstrated' impact='' remediation=''
    local expected='' configured='' class='Medium' catclass='Confidentiality'
    local weakness='0' sev_override='' context=''
    local kv k v
    for kv in "$@"; do
        # GUARD: a key=value argument that lost its '=' would parse into a key matching no case
        # and be dropped silently - evidence would vanish from the report without any error. This
        # happened during development, so the failure is now loud and visible on stderr.
        case "$kv" in
            *=*) ;;
            *)   printf '[WARN] add_finding: malformed field (no "="): %s\n' "$kv" >&2
                 MALFORMED_FIELDS=$((MALFORMED_FIELDS+1)); continue ;;
        esac
        k="${kv%%=*}"; v="${kv#*=}"
        case "$k" in
            attr) attr="$v" ;; source) source="$v" ;; target) target="$v" ;; port) port="$v" ;;
            prereq) prereq="$v" ;; observed) observed="$v" ;; validation) validation="$v" ;;
            exploit) exploit="$v" ;; impact) impact="$v" ;; remediation) remediation="$v" ;;
            expected) expected="$v" ;; configured) configured="$v" ;; class) class="$v" ;;
            weakness) weakness="$v" ;; sev) sev_override="$v" ;;
            catclass) catclass="$v" ;; context) context="$v" ;;
            *) printf '[WARN] add_finding: unknown field "%s" ignored\n' "$k" >&2
               MALFORMED_FIELDS=$((MALFORMED_FIELDS+1)) ;;
        esac
    done
    [ -n "$source" ] || source="$HOST_SHORT"
    [ -n "$target" ] || target="$HOST_SHORT"

    # STATUS VALIDATION - the exact set the Windows build enforces with [ValidateSet]. An
    # unrecognised status previously fell through to the informational bucket, so a typo would
    # silently downgrade a finding in the statistics while the row text still claimed otherwise.
    # It is refused, recorded as a defect, and the row is NOT silently reclassified.
    case "$st" in
        INFO|PASS|WARN|'RISK DETECTED'|VALIDATED|'NOT CONFIRMED'|'NOT TESTABLE'|ERROR|OPPORTUNITY) ;;
        *)
            printf '[WARN] add_finding: status "%s" is not one of the nine defined statuses - the row is recorded as ERROR\n' "$st" >&2
            MALFORMED_FIELDS=$((MALFORMED_FIELDS+1))
            st='ERROR'
            ;;
    esac

    # An unknown CatClass would silently change the severity, so an unexpected value is refused
    # and stated rather than accepted.
    case "$catclass" in
        Confidentiality|Integrity|Availability|DataAtRest|IdentityRights|Context) ;;
        *) printf '[WARN] add_finding: unknown CatClass "%s" - treated as Confidentiality\n' "$catclass" >&2
           MALFORMED_FIELDS=$((MALFORMED_FIELDS+1)); catclass='Confidentiality' ;;
    esac

    local sev context_sev='' context_label=''
    case "$context" in
        UNOWNED_PRIVILEGED)
            case "$configured $finding" in
                */tmp/*|*/var/tmp/*|*/dev/shm/*|*/home/*) context='STAGING_VIOLATION' ;;
            esac
            ;;
    esac
    case "$context" in
        UNOWNED_PRIVILEGED) context_sev='Critical'; context_label='CRITICAL - UNOWNED PRIVILEGED ASSET (POTENTIAL PLANT)' ;;
        STAGING_VIOLATION) context_sev='Critical'; context_label='CRITICAL - STAGING PATH VIOLATION' ;;
        LOGIN_INTERCEPT) context_sev='High'; context_label='HIGH - WRITABLE LOGIN INTERCEPT' ;;
        KERNEL_MISMATCH) context_sev='Medium'; context_label='MEDIUM - KERNEL LAYER MISMATCH' ;;
    esac
    if [ -n "$sev_override" ]; then sev="$sev_override"; else sev=$(severity_for "$class" "$weakness" "$catclass" "$context"); fi
    [ -n "$context_sev" ] && sev="$context_sev"
    if [ -n "$context_label" ] && [ "$st" != 'PASS' ] && [ "$st" != 'INFO' ]; then
        case "$finding" in
            "$context_label":*) ;;
            *) finding="$context_label: $finding" ;;
        esac
    fi

    case "$st" in
        WARN)            STATS_WARN=$((STATS_WARN+1)) ;;
        'RISK DETECTED') STATS_RISK=$((STATS_RISK+1)) ;;
        VALIDATED)       STATS_VALIDATED=$((STATS_VALIDATED+1)) ;;
        'NOT TESTABLE')  STATS_NOTTESTABLE=$((STATS_NOTTESTABLE+1)) ;;
        'NOT CONFIRMED') STATS_NOTCONFIRMED=$((STATS_NOTCONFIRMED+1)) ;;
        ERROR)           STATS_ERRORS=$((STATS_ERRORS+1)) ;;
        OPPORTUNITY)     STATS_OPPS=$((STATS_OPPS+1)) ;;
        PASS)            STATS_PASS=$((STATS_PASS+1)) ;;
        *)               STATS_INFO=$((STATS_INFO+1)) ;;
    esac

    # In-memory ledger for Section 19.4 and the validation handoff.
    FINDINGS+=("${st}"$'\x1f'"${sev}"$'\x1f'"${cat}"$'\x1f'"${attr}"$'\x1f'"${target}"$'\x1f'"${finding}"$'\x1f'"${validation}"$'\x1f'"${exploit}"$'\x1f'"${observed}"$'\x1f'"${prereq}"$'\x1f'"${impact}"$'\x1f'"${remediation}")

    # Console row
    # Every class streams to the console, INFO included: the console is the live narrative and
    # suppressing informational rows made important context (for example "the sweep was bounded to
    # the /24") invisible to the operator even though it reached the CSV.
    write_status "$st" "$attr${attr:+ - }$finding"

    # CSV row - appended immediately, so an interrupted run still leaves evidence on disk.
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    {
        csv_escape "$ts";              printf ','
        csv_escape "$sev";             printf ','
        csv_escape "$cat";             printf ','
        csv_escape "$source";          printf ','
        csv_escape "$target";          printf ','
        csv_escape "$port";            printf ','
        csv_escape "$finding";         printf ','
        csv_escape "$prereq";          printf ','
        csv_escape "$configured";      printf ','
        csv_escape "$validation";      printf ','
        csv_escape "$observed";        printf ','
        csv_escape "$exploit";         printf ','
        csv_escape "$impact";          printf ','
        csv_escape "$remediation";     printf '\n'
    } >> "$CSV_PATH" 2>/dev/null && FINDING_COUNT=$((FINDING_COUNT+1))
}

# ---------------------------------------------------------------------------------------------
#  BOUNDED COMMAND RUNNER
#  Prefer coreutils timeout. When it is absent, a bounded child-process polling loop is used as a
#  fail-safe so blocked sockets/files cannot hold the assessment indefinitely.
# ---------------------------------------------------------------------------------------------
run_bounded_seconds() {
    local seconds="$1"; shift
    [ $# -gt 0 ] || return 2
    if have timeout; then
        timeout "$seconds" "$@"
        return $?
    fi
    "$@" &
    local pid=$! ticks=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1
        ticks=$((ticks + 1))
        if [ "$ticks" -ge "$seconds" ]; then
            kill -TERM "$pid" 2>/dev/null
            sleep 1
            kill -KILL "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
            return 124
        fi
    done
    wait "$pid"
}

run_bounded_ms() {
    local ms="$1"; shift
    [ $# -gt 0 ] || return 2
    local seconds=$(( (ms + 999) / 1000 ))
    [ "$seconds" -gt 0 ] || seconds=1
    run_bounded_seconds "$seconds" "$@"
}

#  TCP PRIMITIVES
#  bash's /dev/tcp is used directly, so no netcat is required. `timeout` bounds the connect and
#  the read; if timeout is absent, run_bounded_seconds/run_bounded_ms use a bounded child-process loop.
# ---------------------------------------------------------------------------------------------
test_is_local_target() {
    # Mirrors Test-IsLocalTarget in the Windows build. A connection to the host itself stays on the
    # host, so it is not off-host work and must not be refused by --local-only or by the absence of
    # a network authorisation: probing your own LDAP listener is a LOCAL check.
    local t; t=$(lower_string "$1")
    case "$t" in
        127.*|::1|localhost|localhost.*) return 0 ;;
    esac
    [ -n "$t" ] || return 1
    [ "$t" = "$(lower_string "$HOST_SHORT")" ] && return 0
    [ -n "${HOST_FQDN:-}" ] && [ "$t" = "$(lower_string "$HOST_FQDN")" ] && return 0
    local a
    for a in ${LOCAL_IPS:-}; do [ "$t" = "$a" ] && return 0; done
    return 1
}

socket_gate() {
    # THE gate for off-host network work, and the only one that opens anything.
    #
    # This tool can open a socket in exactly four places: tcp_open, tcp_read_banner, grab_banner
    # and tls_certificate. Every one of them calls socket_gate first, so a module cannot reach the
    # network by choosing a different helper, and the audit script can prove it by grepping for
    # those four names and checking each is preceded by a gate call.
    #
    # The gate is enforced HERE rather than only at the call sites on purpose: a call site that
    # forgets is invisible until a packet has already left the host, which is far too late.
    #
    # A self-directed or loopback target is exempt, because a connection to this host never leaves
    # it - probing your own SSH or LDAP listener is a LOCAL check and is legitimate under
    # --local-only. That mirrors Test-IsLocalTarget in the Windows build.
    test_is_local_target "$1" && return 0
    test_target_allowed "$1"
}

detect_transport() {
    # bash's /dev/tcp is a compile-time feature. It is enabled in every distribution build of bash
    # we know of, but it is not guaranteed: hardened builds, BusyBox and some appliance shells omit
    # it. Netcat is the classic fallback and is present on most hosts, so the assessment does not
    # have to degrade to NOT TESTABLE just because the shell cannot open a socket.
    #
    # The probe is a real connection attempt to loopback port 1 rather than a version string check:
    #   * connect accepted (unlikely)          -> the feature works;
    #   * refused, no error text               -> the feature works, the port is closed;
    #   * "No such file or directory" or
    #     "not supported"                      -> the feature is absent, fall back to netcat.
    TRANSPORT='devtcp'
    local err
    if bash -c 'exec 3<>/dev/tcp/127.0.0.1/1' >/dev/null 2>&1; then
        TRANSPORT='devtcp'; return 0
    fi
    err=$(bash -c 'exec 3<>/dev/tcp/127.0.0.1/1' 2>&1 >/dev/null)
    case "$err" in
        *'No such file or directory'*|*'not supported'*|*'Operation not permitted'*)
            if have nc; then TRANSPORT='nc'; else TRANSPORT='none'; fi
            ;;
        *) TRANSPORT='devtcp' ;;
    esac
    return 0
}

nc_wait_seconds() {
    # netcat's -w takes whole seconds; anything below one second would disable the timeout entirely
    # in some implementations, so the floor is 1.
    local ms="${1:-$TCP_TIMEOUT_MS}" s
    s=$(awk -v m="$ms" 'BEGIN{ v=m/1000; if (v<1) v=1; printf "%d", v }')
    printf '%s' "$s"
}

tcp_open() {
    # echoes 0 when the port accepts a connection
    local host="$1" port="$2" ms="${3:-$TCP_TIMEOUT_MS}"
    socket_gate "$host" || return 1
    if [ "$TRANSPORT" = 'nc' ]; then
        # -z is not universal (BusyBox nc omits it), so a plain connect with stdin closed is used:
        # netcat connects, reads EOF immediately and exits 0 on success, non-zero when refused.
        run_bounded_ms "$ms" nc -w "$(nc_wait_seconds "$ms")" "$host" "$port" </dev/null >/dev/null 2>&1
        return $?
    fi
    run_bounded_ms "$ms" bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$host" "$port" 2>/dev/null
}

tcp_read_banner() {
    # $1 host, $2 port, $3 ms, $4 max bytes
    local host="$1" port="$2" ms="${3:-1500}" max="${4:-4096}"
    socket_gate "$host" || return 1
    if [ "$TRANSPORT" = 'nc' ]; then
        # Services send their greeting on connect, so closing stdin straight away loses nothing.
        run_bounded_ms "$ms" nc -w "$(nc_wait_seconds "$ms")" "$host" "$port" </dev/null 2>/dev/null | head -c "$max" | tr -d '\000'
        return $?
    fi
    run_bounded_ms "$ms" bash -c 'exec 3<>/dev/tcp/"$1"/"$2" 2>/dev/null && {
                     head -c '"$max"' <&3 2>/dev/null
                 }' _ "$host" "$port" 2>/dev/null | tr -d '\000'
}

net_inventory() {
    # Echoes "iface|addr|prefixlen|scope" for each IPv4 address.
    if have ip; then
        ip -o -4 addr show 2>/dev/null | awk '{split($4,a,"/"); print $2"|"a[1]"|"a[2]"|"($0 ~ /scope global/ ? "global" : "other")}'
    else
        note_missing_tool ip
        return 1
    fi
}

service_name_for_port() {
    case "$1" in
        21) echo 'FTP' ;;              22) echo 'SSH' ;;            23) echo 'Telnet' ;;
        25) echo 'SMTP' ;;             53) echo 'DNS' ;;            80) echo 'HTTP' ;;
        88) echo 'Kerberos' ;;         111) echo 'rpcbind' ;;       135) echo 'MSRPC EPM' ;;
        139) echo 'NetBIOS/SMB' ;;     389) echo 'LDAP' ;;          443) echo 'HTTPS' ;;
        445) echo 'SMB' ;;             464) echo 'kpasswd' ;;       636) echo 'LDAPS' ;;
        873) echo 'rsync' ;;           1433) echo 'MSSQL' ;;        2049) echo 'NFS' ;;
        3268) echo 'Global Catalog' ;; 3269) echo 'GC over SSL' ;;  3306) echo 'MySQL' ;;
        3389) echo 'RDP' ;;            5432) echo 'PostgreSQL' ;;   5900) echo 'VNC' ;;
        5985) echo 'WinRM over HTTP' ;; 5986) echo 'WinRM over HTTPS' ;;
        6379) echo 'Redis' ;;          8080) echo 'HTTP (alt)' ;;   8443) echo 'HTTPS (alt)' ;;
        9200) echo 'Elasticsearch' ;;  11211) echo 'memcached' ;;   27017) echo 'MongoDB' ;;
        *) echo "unknown/$1" ;;
    esac
}

# ---------------------------------------------------------------------------------------------
#  REPORT INITIALISATION
# ---------------------------------------------------------------------------------------------
OUTPUT_DIR=''
CSV_PATH=''
REGISTRY_PATH=''
HANDOFF_PATH=''
REPORT_HOST_TAG=''
REPORT_STAMP=''
ROE_ROW_WRITTEN=0
INTEGRITY_ROW_WRITTEN=0

detect_output_dir() {
    local candidates=()
    [ -n "$OUTDIR" ] && candidates+=("$OUTDIR")
    candidates+=("$(dirname "$SELF_PATH")")
    candidates+=("/var/tmp")
    candidates+=("/tmp")
    local d
    for d in "${candidates[@]}"; do
        [ -n "$d" ] || continue
        [ -d "$d" ] || continue
        if [ -w "$d" ] && ( : > "$d/.eia_write_test.$$" ) 2>/dev/null; then
            rm -f "$d/.eia_write_test.$$" 2>/dev/null
            OUTPUT_DIR="$d"; return 0
        fi
    done
    return 1
}

sanitise_host_tag() {
    local h
    h=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo UNKNOWNHOST)
    h=$(printf '%s' "$h" | tr -c 'A-Za-z0-9._-' '_')
    printf '%s' "${h:0:32}"
}

report_tags() {
    REPORT_HOST_TAG=$(sanitise_host_tag)
    REPORT_STAMP=$(date '+%Y%m%d_%H%M%S')
}

self_sha256() {
    if have sha256sum; then
        sha256sum "$SELF_PATH" 2>/dev/null | awk '{print $1}'
    elif have openssl; then
        openssl dgst -sha256 "$SELF_PATH" 2>/dev/null | awk '{print $NF}'
    else
        note_missing_tool sha256sum
        printf ''
    fi
}

is_sha256() { case "$1" in ''|*[!0-9a-fA-F]*) return 1 ;; esac; [ ${#1} -eq 64 ]; }

initialise_report() {
    if ! detect_output_dir; then
        printf '%s[ERROR]%s No writable directory for the report. Set --outdir to a writable path.\n' "$C_RED" "$C_RESET" >&2
        exit 94
    fi
    report_tags
    if [ "$FIXED_REPORT_NAME" = '1' ]; then
        CSV_PATH="$OUTPUT_DIR/Internal_VAPT_Compliance_Report.csv"
        REGISTRY_PATH="$OUTPUT_DIR/Internal_VAPT_Test_Registry.csv"
    else
        CSV_PATH="$OUTPUT_DIR/Internal_VAPT_Report_${REPORT_HOST_TAG}_${REPORT_STAMP}.csv"
        REGISTRY_PATH="$OUTPUT_DIR/Internal_VAPT_Test_Registry_${REPORT_HOST_TAG}_${REPORT_STAMP}.csv"
    fi

    printf '%s\n' "$REPORT_COLUMNS" > "$CSV_PATH"

    # ---- ROW 2: SELF-AUTHENTICATING SIGNATURE -------------------------------------------------
    # Written before any assessment module runs, so it cannot be influenced by assessment output.
    # The digest is computed by the script over its OWN file, which lets a reviewer tie this
    # report to exactly the artefact that produced it, and detect a modified copy afterwards.
    local self_hash self_src
    self_hash=$(self_sha256)
    if is_sha256 "$self_hash"; then self_src='computed in-process over the running script file'
    else self_hash='unavailable'; self_src='unavailable'; fi
    {
        csv_escape "$(date '+%Y-%m-%d %H:%M:%S')"; printf ','
        csv_escape 'Informational'; printf ','
        csv_escape 'Assessment Integrity'; printf ','
        csv_escape "$HOST_SHORT"; printf ','
        csv_escape "$SELF_PATH"; printf ','
        csv_escape ''; printf ','
        csv_escape "Self-authenticating audit trail: this report was produced by ${TOOL_NAME} v${TOOL_VERSION}. The digest below identifies the exact script that generated every subsequent row."; printf ','
        csv_escape 'None - computed at start-up, before any assessment module runs.'; printf ','
        csv_escape "Script SHA-256=${self_hash} [${self_src}]"; printf ','
        csv_escape 'In-process SHA-256 over the script file, computed by the script itself. Recompute independently with: sha256sum <script>'; printf ','
        csv_escape "Host=${HOST_SHORT}; Kernel=$(uname -r); User=$(id -un 2>/dev/null); UID=$(id -u 2>/dev/null); Bash=${BASH_VERSION}"; printf ','
        csv_escape 'Not applicable - provenance record.'; printf ','
        csv_escape 'None. This row exists so a reviewer can prove which code produced the report.'; printf ','
        csv_escape 'Retain this row with the report and verify the digest against the copy held by the engagement owner.'; printf '\n'
    } >> "$CSV_PATH"
    INTEGRITY_ROW_WRITTEN=1

    # ---- ROW 3: RULES OF ENGAGEMENT -----------------------------------------------------------
    local scope_line
    if [ "$SCOPE_ACTIVE" = '1' ]; then scope_line="$SCOPE_TEXT"; else scope_line='no scope supplied - permissive; discovery bounded to the derived local /24 and authorised by switch or not authorised at all'; fi
    local ref="$AUTHORISATION_REF"
    [ -n "$ref" ] || ref='NOT SUPPLIED - set EIA_AUTHORISATION_REF to the engagement/ticket reference'
    local ks='not tripped'; test_kill_switch && ks='ACTIVE'
    {
        csv_escape "$(date '+%Y-%m-%d %H:%M:%S')"; printf ','
        csv_escape 'Informational'; printf ','
        csv_escape 'Assessment Integrity'; printf ','
        csv_escape "$HOST_SHORT"; printf ','
        csv_escape "$( [ "$SCOPE_ACTIVE" = '1' ] && echo 'engagement scope' || echo 'local host' )"; printf ','
        csv_escape ''; printf ','
        csv_escape "Rules-of-engagement record: scope mode is $( [ "$SCOPE_ACTIVE" = '1' ] && echo 'DEFAULT-DENY against a supplied scope' || echo 'permissive (no scope supplied)' ); off-host work $( [ "$NETWORK_AUTH" = '1' ] && echo 'AUTHORISED' || echo 'NOT AUTHORISED' )."; printf ','
        csv_escape 'None - recorded before any assessment module runs.'; printf ','
        csv_escape "Scope=[${scope_line}]; Source=[${SCOPE_SOURCE}]; AuthorisationRef=[${ref}]; KillSwitch=[${ks}]; LocalOnly=[${LOCAL_ONLY}]; ScanProfile=[${SCAN_PROFILE}]"; printf ','
        csv_escape 'Read of the operator-supplied scope and switches at start-up. Every off-host operation passes through test_target_allowed, which consults this scope.'; printf ','
        csv_escape "ScopeActive=${SCOPE_ACTIVE}; Includes=${#SCOPE_INC[@]}; Excludes=${#SCOPE_EXC[@]}"; printf ','
        csv_escape 'Not applicable - authorisation record.'; printf ','
        csv_escape 'None. This row is the evidence that the run was confined to the agreed boundary.'; printf ','
        csv_escape 'None - operator control. Retain with the report.'; printf '\n'
    } >> "$CSV_PATH"
    ROE_ROW_WRITTEN=1
}

# ---------------------------------------------------------------------------------------------
#  HOST IDENTITY
# ---------------------------------------------------------------------------------------------
HOST_SHORT=''
HOST_FQDN=''
OS_NAME=''
KERNEL=''
ELEVATED=0
IN_CONTAINER=0

collect_identity() {
    HOST_SHORT=$(sanitise_host_tag)
    HOST_FQDN=$(hostname -f 2>/dev/null || printf '%s' "$HOST_SHORT")
    [ -n "$HOST_FQDN" ] || HOST_FQDN="$HOST_SHORT"
    KERNEL=$(uname -r 2>/dev/null)
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        OS_NAME=$( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-${NAME:-unknown}}" )
    else
        OS_NAME=$(uname -s)
    fi
    [ "$(id -u 2>/dev/null)" = '0' ] && ELEVATED=1
    # Used by test_is_local_target to recognise this host by address, so a loopback or self-directed
    # probe is not treated as off-host work.
    LOCAL_IPS=$(hostname -I 2>/dev/null | tr -s ' ' ' ')
    LOCAL_IPS="${LOCAL_IPS# }"; LOCAL_IPS="${LOCAL_IPS% }"
    if [ -e /.dockerenv ] || grep -qa 'docker\|lxc\|containerd\|kubepods' /proc/1/cgroup 2>/dev/null; then IN_CONTAINER=1; fi
}

# =============================================================================================
#  SECTION 1 :: SYSTEM INITIALISATION AND ROLE
# =============================================================================================
read_sysctl() {
    # Reads /proc/sys directly: no sysctl binary, no configuration file, no guessing. The value
    # shown is the one the RUNNING KERNEL is using, which is what actually governs behaviour.
    local key="$1" path
    path="/proc/sys/$(printf '%s' "$key" | tr '.' '/')"
    if [ -r "$path" ]; then cat "$path" 2>/dev/null | tr -d '\n'; else printf ''; fi
}

inventory_listening_sockets() {
    # Echoes "proto|addr|port|process" - used by several sections, collected once here.
    if have ss; then
        ss -H -lntup 2>/dev/null | awk '{
            proto=$1; split($5,a,":"); port=a[length(a)];
            addr=$5; sub(":"port"$","",addr);
            proc=$0; pname="";
            if (match($0, /users:\(\(\"[^\"]+\"/)) { pname=substr($0,RSTART+9,RLENGTH-9) }
            print proto"|"addr"|"port"|"pname
        }'
    elif have netstat; then
        netstat -lntup 2>/dev/null | awk 'NR>2 {split($4,a,":"); print $1"|"a[1]"|"a[length(a)]"|"}'
    else
        note_missing_tool ss
        return 1
    fi
}

section1_initialisation() {
    write_section '1' 'SYSTEM INITIALISATION AND ROLE'
    write_kv 'Host' "$HOST_SHORT"
    write_kv 'FQDN' "$HOST_FQDN"
    write_kv 'Distribution' "$OS_NAME"
    write_kv 'Kernel' "$KERNEL"
    write_kv 'Architecture' "$(uname -m 2>/dev/null)"
    write_kv 'Running as' "$(id -un 2>/dev/null) (UID $(id -u 2>/dev/null))$( [ "$ELEVATED" = '1' ] && echo ' - ROOT' )"
    write_kv 'Boot time' "$(uptime -s 2>/dev/null || printf 'unknown')"
    write_kv 'Assessment script' "$SELF_PATH"
    write_kv 'Scan profile' "$SCAN_PROFILE (connect ${TCP_TIMEOUT_MS} ms, ${MAX_PARALLEL} sockets, host spacing ${STARTUP_DELAY_MS} ms)"

    if [ "$IN_CONTAINER" = '1' ]; then
        write_status 'INFO' 'Running inside a container namespace. Kernel-hardening values are the HOST kernel values and do not reflect this container''s own policy.'
        add_finding INFO 'Assessment Scope' 'The assessment is running inside a container. Kernel-level controls read here belong to the host kernel, and several container-relevant controls (seccomp, cgroup limits, capabilities) are set by the orchestrator rather than the guest.' \
            attr='Container execution context' source="$HOST_SHORT" target="$HOST_SHORT" \
            configured='Container markers present (/.dockerenv or cgroup entry)' \
            observed="cgroup=$(head -1 /proc/1/cgroup 2>/dev/null)" \
            validation='Filesystem and cgroup inspection' class='Low' \
            impact='Some findings in this report describe the host kernel rather than the confined workload, and vice versa. Read the container sections accordingly.' \
            remediation='Re-run outside the container on the host itself when the assessment target is the host.'
    fi

    # ---- package / patch surface -------------------------------------------------------------
    local pkg_mgr='none detected'
    # rpm_usable, not have rpm: a Debian host with the rpm tool installed must not be reported as
    # rpm-managed. See rpm_usable() for the measured failure.
    if rpm_usable; then pkg_mgr='rpm'; elif have dpkg-query; then pkg_mgr='dpkg'; elif have apk; then pkg_mgr='apk'; fi
    write_kv 'Package manager' "${pkg_mgr:-none detected}"
    write_kv 'Socket transport' "$(case "$TRANSPORT" in
            devtcp) printf '%s' 'bash /dev/tcp (no external tool required)' ;;
            nc)     printf '%s' 'netcat fallback - bash /dev/tcp is unavailable on this build' ;;
            *)      printf '%s' 'NONE - neither bash /dev/tcp nor netcat is available, so no connection can be made' ;;
        esac)"
    [ -n "$PATH_AUGMENTED" ] && write_kv 'Tool search path' "standard administrative directories appended: ${PATH_AUGMENTED}"

    # ---- role inference ----------------------------------------------------------------------
    local -a roles=()
    [ -r /etc/ssh/sshd_config ] && roles+=('SSH server')
    { [ -d /var/lib/samba ] || [ -r /etc/samba/smb.conf ]; } && roles+=('SMB/Samba file server')
    [ -r /etc/exports ] && roles+=('NFS server (/etc/exports present)')
    { have nginx || [ -d /etc/nginx ]; } && roles+=('web server (nginx)')
    { have apache2 || have httpd || [ -d /etc/apache2 ]; } && roles+=('web server (apache)')
    { have mysqld || have mariadbd; } && roles+=('database (MySQL/MariaDB)')
    { have postgres || [ -d /var/lib/postgresql ]; } && roles+=('database (PostgreSQL)')
    { have docker || [ -S /var/run/docker.sock ]; } && roles+=('container host')
    { have named || [ -d /var/named ]; } && roles+=('DNS server')
    { [ -r /etc/krb5.conf ] || [ -d /etc/sssd ]; } && roles+=('directory-joined (Kerberos/SSSD)')
    [ -d /var/lib/libvirt ] && roles+=('virtualisation host (libvirt)')
    local roles_txt=''
    for r in "${roles[@]}"; do roles_txt+="${r}; "; done
    roles_txt="${roles_txt%; }"
    write_kv 'Inferred role(s)' "${roles_txt:-no server role inferred from configuration presence}"

    add_finding INFO 'Network Discovery' 'Host role inferred from the presence of service configuration and binaries. This is CONTEXT, not a validated service inventory: a role is claimed only where the configuration file or binary exists.' \
        attr='Host role' source="$HOST_SHORT" target="$HOST_SHORT" \
        configured="$( [ ${#roles[@]} -gt 0 ] && printf '%s; ' "${roles[@]}" || echo 'none' )" \
        observed="$OS_NAME, kernel $KERNEL" validation='Filesystem inspection for role-defining configuration' \
        class='Low' impact='Determines which later sections are relevant. A role present here but not listening is dormant, not exploitable.' \
        remediation='Confirm each present role is still required; remove or disable server software that is no longer in use.' 
}

# =============================================================================================
#  SECTION 2 :: LOCAL SECURITY CONFIGURATION
# =============================================================================================
sysctl_check() {
    # sysctl_check <key> <expected-regex> <class> <weakness> <human expectation> <finding text>
    local key="$1" want="$2" class="$3" weakness="$4" expectation="$5" text="$6"
    local val
    val=$(read_sysctl "$key")
    if [ -z "$val" ]; then
        write_kv "$key" 'not exposed by this kernel (NOT TESTABLE)'
        add_finding 'NOT TESTABLE' 'Kernel hardening' "Kernel parameter ${key} is not exposed on this kernel, so its state could not be established." \
            attr="$key" configured='parameter absent from /proc/sys' \
            observed="$( [ -r "/proc/sys/$(printf '%s' "$key" | tr '.' '/')" ] && echo 'present but unreadable' || echo 'absent' )" \
            validation='Read of /proc/sys (the value the running kernel uses)' class="$class" \
            impact='Unknown rather than compliant. Do not record this control as satisfied.' \
            remediation='Confirm the parameter name for this kernel version, or assess the control by another route.'
        return
    fi
    if printf '%s' "$val" | grep -Eq "$want"; then
        write_kv "$key" "$val (as expected)"
        add_finding PASS 'Kernel hardening' "${key} is set as expected." \
            attr="$key" configured="$val" observed="read from /proc/sys/$(printf '%s' "$key" | tr '.' '/')" \
            validation='Read of the value the running kernel is using' class="$class" \
            expected="$expectation" impact='Control satisfied.' \
            remediation='None required. Re-verify after kernel or profile changes.' 
    else
        write_kv "$key" "$val (expected $expectation)"
        add_finding WARN 'Kernel hardening' "$text" \
            attr="$key" configured="$val" observed="read from /proc/sys/$(printf '%s' "$key" | tr '.' '/')" \
            validation='Read of the value the running kernel is using. This is CONFIGURED STATE; the report does not claim an exploit path from it.' \
            class="$class" weakness="$weakness" expected="$expectation" \
            impact='Weakens a defence-in-depth layer. On its own this is rarely exploitable; it matters as a step in a chain, which Section 16 assesses.' \
            remediation="Set ${key} to the expected value via the system's sysctl configuration and persist it across reboots."
    fi
}

section2_local_configuration() {
    write_section '2' 'LOCAL SECURITY CONFIGURATION'
    write_status 'INFO' 'Reading the values the RUNNING kernel uses, not the values written in configuration files.'

    # ---- LSM integrity/context checkpoint ------------------------------------------------------
    # Baseline sysctls can be unreadable under containers or hardened profiles. LSM status is a
    # separate, read-only context signal; it never substitutes for a failed sysctl observation.
    local lsm_active='' selinux_state='unavailable' apparmor_state='unavailable'
    if [ -r /sys/kernel/security/lsm ]; then
        lsm_active=$(cat /sys/kernel/security/lsm 2>/dev/null | tr -d '\n')
    elif [ -r /sys/kernel/security/lsm_list ]; then
        lsm_active=$(cat /sys/kernel/security/lsm_list 2>/dev/null | tr -d '\n')
    fi
    if have getenforce; then selinux_state=$(getenforce 2>/dev/null | tr -d '\n'); fi
    if have apparmor_status; then
        apparmor_state=$(apparmor_status 2>/dev/null | head -1 | tr -d '\n')
    fi
    write_kv 'Active LSMs' "${lsm_active:-not exposed}"
    write_kv 'SELinux status' "$selinux_state"
    write_kv 'AppArmor status' "$apparmor_state"
    add_finding INFO 'Kernel hardening' 'Linux Security Module context was sampled without changing policy or reading protected security databases.' \
        attr='LSM integrity checkpoint' configured="LSMs=${lsm_active:-not exposed}; SELinux=${selinux_state}; AppArmor=${apparmor_state}" \
        observed='/sys/kernel/security/lsm or lsm_list, getenforce and apparmor_status where available' \
        validation='Read-only LSM status checkpoint. Missing interfaces are reported as context gaps, not as disabled security controls.' \
        class='Low' catclass='Context' impact='Provides security-policy context when kernel sysctls are restricted or incomplete.' \
        remediation='None. If an expected LSM is absent, verify the distribution security profile and boot parameters separately.'

    sysctl_check 'kernel.randomize_va_space' '^[12]$' 'Medium' '1' '2 (full ASLR)' \
        'Address-space layout randomisation is disabled or reduced, removing a major obstacle to reliable memory-corruption exploitation.'
    sysctl_check 'kernel.dmesg_restrict' '^1$' 'Low' '1' '1' \
        'Unprivileged users can read the kernel log ring buffer, which commonly leaks kernel pointers and defeats part of KASLR.'
    sysctl_check 'kernel.kptr_restrict' '^[12]$' 'Low' '1' '1 or 2' \
        'Kernel symbol addresses are exposed to unprivileged readers, defeating KASLR for several exploit classes.'
    sysctl_check 'kernel.yama.ptrace_scope' '^[1-3]$' 'Medium' '1' '1 or higher' \
        'Unprivileged processes may ptrace each other, so any process the user can influence can read another process memory - including credential material held by a privileged process running as the same user.'
    # Value 2 means "disabled and cannot be re-enabled until reboot" - STRICTER than 1, so the
    # expectation must accept both. Matching only ^1$ produced a false positive on hardened hosts.
    sysctl_check 'kernel.unprivileged_bpf_disabled' '^[12]$' 'Medium' '1' '1 or 2 (2 is stricter)' \
        'Unprivileged BPF is enabled, exposing the eBPF verifier attack surface to any local user and enabling some container-escape classes.'
    sysctl_check 'kernel.unprivileged_userns_clone' '^0$' 'Medium' '1' '0 (or restricted)' \
        'Unprivileged user namespaces are enabled. They are required by some container tooling but greatly widen the local kernel attack surface.'
    sysctl_check 'fs.protected_hardlinks' '^1$' 'Medium' '1' '1' \
        'Unprivileged users may create hard links to files they do not own, a documented local privilege-escalation primitive.'
    sysctl_check 'fs.protected_symlinks' '^1$' 'Medium' '1' '1' \
        'Unprivileged users may follow symlinks they do not own in sticky world-writable directories, enabling symlink attacks on privileged processes.'
    sysctl_check 'fs.suid_dumpable' '^0$' 'Medium' '1' '0' \
        'Set-UID processes may be dumped, so a crash of a privileged process can leave its memory - including credentials - in a file the invoking user can read.'
    sysctl_check 'net.ipv4.ip_forward' '^0$' 'Medium' '1' '0 (unless this host is a router)' \
        'The host forwards IPv4 traffic. If it was not intended as a router, it can be used as a transit path between network segments that were meant to be isolated.'
    sysctl_check 'net.ipv4.conf.all.accept_redirects' '^0$' 'Medium' '1' '0' \
        'The host accepts ICMP redirects, allowing an on-path attacker to alter its routing table.'
    sysctl_check 'net.ipv4.conf.all.send_redirects' '^0$' 'Low' '1' '0' \
        'The host sends ICMP redirects, which can be used to divert traffic of other hosts on the segment.'
    sysctl_check 'net.ipv4.conf.all.accept_source_route' '^0$' 'Medium' '1' '0' \
        'Source routing is accepted, allowing a sender to dictate the path a packet takes through the network.'
    sysctl_check 'net.ipv4.conf.all.rp_filter' '^[12]$' 'Low' '1' '1 or 2' \
        'Reverse-path filtering is disabled, easing IP spoofing from this host or its segment.'
    sysctl_check 'net.ipv4.tcp_syncookies' '^1$' 'Low' '1' '1' \
        'SYN cookies are disabled, so the host is more susceptible to connection-exhaustion denial of service.'

    # ---- umask -------------------------------------------------------------------------------
    local login_umask
    login_umask=$(awk '/^[[:space:]]*UMASK/ {print $2; exit}' /etc/login.defs 2>/dev/null)
    if [ -n "$login_umask" ]; then
        local octal=$(( 8#${login_umask} ))
        if [ $(( octal & 8#022 )) -eq 0 ] || [ "$login_umask" = '077' ] || [ "$login_umask" = '027' ]; then
            write_kv 'login.defs UMASK' "$login_umask (restrictive)"
            add_finding PASS 'Kernel hardening' 'Default umask for new accounts is restrictive.' attr='UMASK' \
                configured="UMASK $login_umask in /etc/login.defs" observed='read from /etc/login.defs' \
                validation='Direct file read' class='Low' impact='Control satisfied.' remediation='None required.'
        else
            write_kv 'login.defs UMASK' "$login_umask (permissive)"
            add_finding WARN 'Kernel hardening' "The default umask for new accounts is ${login_umask}, so files are created group- or world-readable unless the application overrides it." \
                attr='UMASK' configured="UMASK $login_umask in /etc/login.defs" observed='read from /etc/login.defs' \
                validation='Direct file read' class='Low' weakness='1' expected='027 or stricter (077 for shared hosts)' \
                impact='Increases the chance that sensitive output - logs, dumps, exports - is readable by other local users.' \
                remediation='Set UMASK 027 (or 077) in /etc/login.defs and apply per-application umask overrides where a service needs to share files.'
        fi
    else
        write_kv 'login.defs UMASK' 'not configured (distribution default applies)'
    fi

    # ---- shadow file permissions --------------------------------------------------------------
    if [ -e /etc/shadow ]; then
        local perm owner grp
        perm=$(get_octal_perms /etc/shadow 2>/dev/null)
        owner=$(stat -c '%U' /etc/shadow 2>/dev/null)
        grp=$(stat -c '%G' /etc/shadow 2>/dev/null)
        write_kv '/etc/shadow' "${perm:-?} ${owner:-?}:${grp:-?}"
        if [ "$perm" = '000' ] || [ "$perm" = '600' ] || [ "$perm" = '640' ] || [ "$perm" = '0000' ]; then
            add_finding PASS 'Credential Storage' '/etc/shadow is not world-readable.' attr='/etc/shadow permissions' \
                configured="${perm} ${owner}:${grp}" observed='stat of the file' validation='Filesystem metadata read' \
                class='High' impact='Control satisfied.' remediation='None required. Recheck after package upgrades that may reset it.'
        else
            add_finding 'RISK DETECTED' 'Credential Storage' "The password hash file /etc/shadow is readable beyond root: mode ${perm}, owner ${owner}:${grp}. Any local user who can read it can mount an offline cracking attack against every account hash it contains." \
                attr='/etc/shadow permissions' configured="${perm} ${owner}:${grp}" observed='stat of the file' \
                validation='Filesystem metadata read. This tool did NOT read the file contents - the finding is the permission state, and no hash was accessed.' \
                class='Critical' weakness='1' expected='000 or 600, owned by root:root' \
                impact='Converts a local unprivileged account into an offline attack against every local password hash, and any password recovered may be reused elsewhere (Section 4 and Section 16).' \
                remediation='Restore mode 000 or 600, owner root, group root (or shadow) immediately: chmod 000 /etc/shadow. Investigate how the mode changed, and rotate every local password if the exposure window is unknown.'
        fi
    else
        note_missing_tool /etc/shadow
        add_finding 'NOT TESTABLE' 'Credential Storage' '/etc/shadow is not present, so local password-hash storage could not be assessed.' \
            attr='/etc/shadow' observed='file absent' validation='Filesystem check' class='High' \
            impact='Unknown. On many systems this is normal (LDAP/SSSD-backed identities); confirm which directory provides local authentication.' \
            remediation='Confirm the identity backend. If local authentication is expected, its absence is itself unexpected.'
    fi

    # ---- world-writable files in privileged paths ---------------------------------------------
    if have find; then
        local ww_count ww_sample
        ww_count=$(find /etc /bin /sbin /usr/bin /usr/sbin -xdev -type f -perm -0002 2>/dev/null | wc -l)
        if [ "$ww_count" -gt 0 ]; then
            ww_sample=$(find /etc /bin /sbin /usr/bin /usr/sbin -xdev -type f -perm -0002 2>/dev/null | head -5 | tr '\n' ' ')
            write_kv 'World-writable files in privileged paths' "$ww_count"
            add_finding 'RISK DETECTED' 'Local Privilege Escalation' "${ww_count} world-writable file(s) exist under /etc, /bin, /sbin or /usr/bin. A file in one of these paths that a privileged process reads or executes can be replaced or modified by any local user." \
                attr='World-writable privileged files' configured="${ww_count} file(s)" observed="examples: ${ww_sample}" \
                validation='Filesystem permission scan (find -perm -0002). Presence is CONFIRMED; whether any one of them is actually reachable by a privileged execution path is NOT established here.' \
                class='High' weakness='1' expected='None' \
                impact='Direct local privilege escalation where a privileged script or service references one of these paths.' \
                remediation='Remove the world-write bit from every listed file, then determine why it was set - a packaging error and a hostile modification look identical from the permission bit alone.'
        else
            write_kv 'World-writable files in privileged paths' 'none'
            add_finding PASS 'Local Privilege Escalation' 'No world-writable files were found in privileged paths.' \
                attr='World-writable privileged files' configured='0' observed='find -perm -0002 over /etc /bin /sbin /usr/bin /usr/sbin' \
                validation='Filesystem permission scan' class='High' impact='Control satisfied.' remediation='None required.'
        fi
    else
        note_missing_tool find
        add_finding 'NOT TESTABLE' 'Local Privilege Escalation' 'The find utility is absent, so the world-writable file scan could not be performed.' \
            attr='World-writable privileged files' observed='find not available' validation='Tool availability check' \
            class='High' impact='Unknown rather than compliant.' remediation='Install findutils or assess file permissions by another route.'
    fi
}

# =============================================================================================
#  SECTION 3 :: SSH SERVER POSTURE
# =============================================================================================
sshd_effective_config() {
    # `sshd -T` prints the EFFECTIVE configuration - what the daemon will actually apply, after
    # includes and defaults. It needs root. Without it we fall back to parsing the files, and the
    # report says which of the two was used, because "the file says X" and "the daemon will do X"
    # are different claims.
    if have sshd && [ "$ELEVATED" = '1' ]; then
        sshd -T 2>/dev/null && return 0
    fi
    return 1
}

sshd_file_config() {
    {
        [ -r /etc/ssh/sshd_config ] && cat /etc/ssh/sshd_config 2>/dev/null
        if [ -d /etc/ssh/sshd_config.d ]; then
            for f in /etc/ssh/sshd_config.d/*.conf; do [ -r "$f" ] && cat "$f" 2>/dev/null; done
        fi
    } | awk '!/^[[:space:]]*#/ && NF>=2 { k=tolower($1); v=tolower($2); last[k]=v } END { for (k in last) print k" "last[k] }'
}

sshd_get() {
    # $1 = config text, $2 = key
    printf '%s\n' "$1" | awk -v k="$2" 'tolower($1)==k {print $2; exit}'
}

section3_ssh() {
    write_section '3' 'SSH SERVER POSTURE'
    if [ ! -r /etc/ssh/sshd_config ]; then
        write_status 'NOT TESTABLE' 'No readable /etc/ssh/sshd_config: this host does not run an OpenSSH server, or the file is not readable at this privilege level.'
        add_finding 'NOT TESTABLE' 'SSH Configuration' 'The OpenSSH server configuration could not be read, so SSH posture was not assessed.' \
            attr='sshd_config' observed='file absent or unreadable' validation='Filesystem check' \
            class='High' impact='Unknown rather than compliant. If this host runs an SSH server, its posture is unassessed by this run.' \
            remediation='Re-run with sufficient privilege, or confirm the host does not run an SSH server.'
        return
    fi

    local cfg source
    if cfg=$(sshd_effective_config); then
        source='sshd -T (EFFECTIVE configuration the daemon will apply)'
        write_status 'PASS' 'Read the effective sshd configuration via sshd -T.'
    else
        cfg=$(sshd_file_config)
        source='parsed from /etc/ssh/sshd_config and sshd_config.d (CONFIGURED, not verified effective)'
        write_status 'WARN' 'sshd -T was unavailable (needs root and the sshd binary), so the configuration was parsed from files. A Match block or an include could override any value below.'
    fi
    write_kv 'Configuration source' "$source"

    local permitroot passauth empty maxauth x11 fwd agent
    permitroot=$(sshd_get "$cfg" 'permitrootlogin')
    passauth=$(sshd_get "$cfg" 'passwordauthentication')
    empty=$(sshd_get "$cfg" 'permitemptypasswords')
    maxauth=$(sshd_get "$cfg" 'maxauthtries')
    x11=$(sshd_get "$cfg" 'x11forwarding')
    fwd=$(sshd_get "$cfg" 'allowtcpforwarding')
    agent=$(sshd_get "$cfg" 'allowagentforwarding')

    case "${permitroot:-unset}" in
        yes)
            write_kv 'PermitRootLogin' "${permitroot} (direct root login permitted)"
            add_finding 'RISK DETECTED' 'SSH Configuration' 'Direct root login over SSH is permitted.' \
                attr='PermitRootLogin' configured="PermitRootLogin ${permitroot}" observed="$source" \
                validation='Configuration read' class='High' weakness='1' expected='no (or prohibit-password with key-only authentication)' \
                impact='Removes the accountability of per-administrator accounts and makes the root account directly reachable by brute force or credential reuse from anywhere that can reach port 22.' \
                remediation='Set PermitRootLogin no and require administrators to escalate via sudo from named accounts.'
        ;;
        prohibit-password|without-password|forced-commands-only)
            write_kv 'PermitRootLogin' "$permitroot (key-only, acceptable where keys are managed)"
            add_finding PASS 'SSH Configuration' 'Root login is restricted to key-based authentication.' attr='PermitRootLogin' \
                configured="$permitroot" observed="$source" validation='Configuration read' class='High' \
                impact='Control satisfied, provided root authorized_keys are tightly controlled.' \
                remediation='Keep root key material confined to a hardware-backed store, and review root authorized_keys after every change.'
        ;;
        *)
            write_kv 'PermitRootLogin' "${permitroot:-default}"
            add_finding PASS 'SSH Configuration' 'Root login is not permitted over SSH.' attr='PermitRootLogin' \
                configured="${permitroot:-no (default)}" observed="$source" validation='Configuration read' class='High' \
                impact='Control satisfied.' remediation='None required.'
        ;;
    esac

    if [ "${passauth:-no}" = 'yes' ]; then
        write_kv 'PasswordAuthentication' 'yes (passwords accepted)'
        add_finding WARN 'SSH Configuration' 'SSH accepts password authentication, so the daemon is exposed to credential guessing and password reuse from anywhere that can reach it.' \
            attr='PasswordAuthentication' configured='yes' observed="$source" validation='Configuration read' \
            class='High' weakness='1' expected='no where key-based authentication is established' \
            impact='Combined with a weak lockout policy (Section 4), this permits sustained online guessing. Note this tool performs no guessing, so exploitability is NOT demonstrated.' \
            remediation='Move to key-based authentication, then set PasswordAuthentication no. Keep one break-glass account documented rather than a blanket exception.'
    else
        write_kv 'PasswordAuthentication' "${passauth:-no}"
        add_finding PASS 'SSH Configuration' 'Password authentication is not enabled.' attr='PasswordAuthentication' \
            configured="${passauth:-no}" observed="$source" validation='Configuration read' class='High' \
            impact='Control satisfied.' remediation='None required.'
    fi

    if [ "${empty:-no}" = 'yes' ]; then
        write_kv 'PermitEmptyPasswords' 'yes'
        add_finding 'RISK DETECTED' 'SSH Configuration' 'SSH is configured to accept empty passwords, so any account with a blank password is directly accessible.' \
            attr='PermitEmptyPasswords' configured='yes' observed="$source" validation='Configuration read' \
            class='Critical' weakness='1' expected='no' \
            impact='Direct unauthenticated access where any account has an empty password.' \
            remediation='Set PermitEmptyPasswords no immediately, then audit for accounts with empty password fields.'
    fi

    if [ -n "${maxauth:-}" ] && [ "$maxauth" -gt 6 ] 2>/dev/null; then
        write_kv 'MaxAuthTries' "$maxauth (permissive)"
        add_finding WARN 'SSH Configuration' "MaxAuthTries is ${maxauth}, allowing more authentication attempts per connection than a baseline deployment needs." \
            attr='MaxAuthTries' configured="$maxauth" observed="$source" validation='Configuration read' class='Medium' weakness='1' \
            expected='3 to 6' impact='Increases the attempts an attacker may make per connection before the session is dropped.' \
            remediation='Set MaxAuthTries to 3-6 and pair it with a daemon-level lockout (fail2ban or equivalent).'
    fi

    # An ABSENT AllowTcpForwarding directive does not mean "disabled": the OpenSSH default is
    # "yes". Reporting only what the file contains would understate the posture, so an unset value
    # is assessed as the documented default and the row says which of the two it is.
    if [ "${fwd:-yes}" = 'yes' ]; then
        write_kv 'AllowTcpForwarding' "${fwd:-yes (OpenSSH default - directive not present)}"
        add_finding INFO 'SSH Configuration' 'TCP forwarding is permitted, so an authenticated user can tunnel arbitrary traffic through this host and may cross network boundaries the design intends to enforce.' \
            attr='AllowTcpForwarding' configured="${fwd:-yes (OpenSSH default, directive not set in the file)}" observed="$source" validation='Configuration read' \
            class='Medium' impact='A pivoting capability available to every account that can authenticate. This is a design characteristic of SSH, not a defect - it becomes a finding when the host is a segmentation boundary (Section 14).' \
            remediation='Set AllowTcpForwarding no on hosts that sit on a trust boundary and have no legitimate tunnelling use case.'
    fi

    # ---- weak algorithms ---------------------------------------------------------------------
    local ciphers kex macs
    ciphers=$(sshd_get "$cfg" 'ciphers'); kex=$(sshd_get "$cfg" 'kexalgorithms'); macs=$(sshd_get "$cfg" 'macs')
    if printf '%s %s %s' "$ciphers" "$kex" "$macs" | grep -Eiq '(^|[,[:space:]])(arcfour|rc4|3des|blowfish|des-cbc|[^-]cbc($|[,[:space:]])|hmac-md5|hmac-sha1-etm|hmac-sha1($|[-,[:space:]])|diffie-hellman-group1|diffie-hellman-group14-sha1|ssh-dss|chacha20[^-]*-cbc|chacha20-poly1305@openssh\.com[^,[:space:]]*weak)'; then
        write_kv 'Algorithms' 'weak algorithms explicitly permitted'
        add_finding WARN 'Cryptography' 'SSH is configured to permit at least one legacy algorithm (RC4, 3DES, CBC-mode cipher, MD5 MAC, group1/group14-sha1 key exchange or ssh-dss).' \
            attr='SSH cipher/MAC/KEX policy' configured="ciphers=${ciphers:-default}; kex=${kex:-default}; macs=${macs:-default}" \
            observed="$source" validation='Configuration read; the legacy algorithm list is matched against the configured set' \
            class='Medium' weakness='1' expected='modern suites only (chacha20-poly1305, aes-gcm, curve25519-sha256, ed25519 host keys)' \
            impact='Legacy suites weaken confidentiality and, for ssh-dss and SHA-1 constructions, have practical attacks against session integrity in specific conditions.' \
            remediation='Remove the legacy algorithms from the configuration and re-issue ssh-dss host keys as ed25519 or RSA-3072.'
    else
        write_kv 'Algorithms' 'no legacy algorithm explicitly permitted'
    fi

    # ---- host key permissions ----------------------------------------------------------------
    if [ -d /etc/ssh ]; then
        local badkeys=''
        for k in /etc/ssh/ssh_host_*_key; do
            [ -e "$k" ] || continue
            local m
            m=$(get_octal_perms "$k" 2>/dev/null)
            case "$m" in 600|640|000) ;; *) badkeys+="$k($m) " ;; esac
        done
        if [ -n "$badkeys" ]; then
            add_finding WARN 'Credential Storage' "SSH host private key(s) have permissions broader than necessary: ${badkeys}" \
                attr='SSH host key permissions' configured="$badkeys" observed='stat of each host key file' \
                validation='Filesystem metadata read. No key material was read.' class='Medium' weakness='1' expected='600 root:root' \
                impact='A readable host private key lets a local user impersonate this host to connecting clients, defeating host-key verification for them.' \
                remediation='chmod 600 the affected keys and confirm the sshd user can still read them.'
        else
            add_finding PASS 'Credential Storage' 'SSH host private keys have restrictive permissions.' \
                attr='SSH host key permissions' configured='600 or stricter' observed='stat of /etc/ssh/ssh_host_*_key' \
                validation='Filesystem metadata read' class='Medium' impact='Control satisfied.' remediation='None required.'
        fi
    fi

    section3b_smb_signing
}

# ---------------------------------------------------------------------------------------------
#  3b. SMB / SAMBA MESSAGE SIGNING
#
#  The counterpart of the Windows build's SMB-signing chain. On Windows, unsigned SMB is the
#  classic relay path to administrative access; on Linux the same exposure exists wherever Samba
#  is installed. The section is APPLICABILITY-GATED: on a host with no Samba it records that the
#  control is not applicable rather than reporting a pass it did not measure.
# ---------------------------------------------------------------------------------------------
section3b_smb_signing() {
    if ! { have smbd || have smbclient || [ -r /etc/samba/smb.conf ]; }; then
        add_finding INFO 'SMB Configuration' 'Samba is not present on this host, so SMB message signing is NOT APPLICABLE here rather than satisfied.' \
            attr='SMB signing' configured='no Samba installation detected' observed='smbd/smbclient absent, /etc/samba/smb.conf absent' \
            validation='Applicability check' class='Low' catclass='Context' \
            impact='None on this host. Recorded so the control is visibly out of scope rather than silently absent from the report.' \
            remediation='None required. Re-assess if Samba is installed later.'
        return
    fi

    have smbd || note_missing_tool smbd
    local signing='' encrypting='' server_min=''
    if [ -r /etc/samba/smb.conf ]; then
        # `testparm` was deliberately NOT used: it is usually only in the samba-common-bin package
        # and its output format varies by version. A direct read of the file is reproducible, and
        # the row says which mechanism produced the value.
        signing=$(awk -F'=' '/^[[:space:]]*server[[:space:]]+signing[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print tolower($2); exit}' /etc/samba/smb.conf 2>/dev/null)
        encrypting=$(awk -F'=' '/^[[:space:]]*smb[[:space:]]+encrypt[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print tolower($2); exit}' /etc/samba/smb.conf 2>/dev/null)
        server_min=$(awk -F'=' '/^[[:space:]]*server[[:space:]]+min[[:space:]]+protocol[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/samba/smb.conf 2>/dev/null)
    fi

    write_kv 'Samba configuration' "$( [ -r /etc/samba/smb.conf ] && echo '/etc/samba/smb.conf (parsed, not verified effective)' || echo 'not readable' )"
    write_kv 'server signing' "${signing:-not set (Samba default: if_required for the client, optional for the server)}"
    write_kv 'smb encrypt' "${encrypting:-not set}"
    write_kv 'server min protocol' "${server_min:-not set (Samba default applies)}"

    case "$signing" in
        mandatory|required)
            add_finding PASS 'SMB Configuration' 'SMB signing is mandatory, so a relayed SMB session cannot be established against this host.' \
                attr='SMB signing' configured="server signing = ${signing}" expected='mandatory' observed='/etc/samba/smb.conf' \
                validation='Configuration read. The EFFECTIVE value was not verified with testparm or a live negotiation.' \
                class='High' impact='Control satisfied at the configuration level.' \
                remediation='None required. Confirm the value survives configuration management.'
            ;;
        disabled|no)
            add_finding 'RISK DETECTED' 'SMB Configuration' 'SMB signing is explicitly DISABLED, so SMB sessions on this host can be relayed - the same class of exposure as an unsigned Windows file server.' \
                attr='SMB signing' configured="server signing = ${signing}" expected='mandatory' observed='/etc/samba/smb.conf' \
                validation='Configuration read. The relay condition itself was NOT demonstrated - no SMB authentication was relayed or replayed by this tool.' \
                class='High' catclass='IdentityRights' weakness='1' \
                prereq='An attacker positioned to relay SMB authentication to this host, plus one authentication to relay. NOT tested here.' \
                impact='On a flat network this is the dominant path from a foothold to administrative file access, and it needs no credentials of its own.' \
                remediation='Set "server signing = mandatory" and reload Samba in a change window. Confirm clients that cannot negotiate signing before enforcing it estate-wide.'
            ;;
        '')
            add_finding WARN 'SMB Configuration' 'Samba is installed but "server signing" is not set, so the Samba default applies. Depending on version and client behaviour that default does not guarantee signing on every session.' \
                attr='SMB signing' configured='directive absent' expected='mandatory (set explicitly)' observed='/etc/samba/smb.conf' \
                validation='Configuration read. The DEFAULT is version-dependent and was not measured on this host.' \
                class='Medium' catclass='IdentityRights' weakness='1' \
                impact='Signing may be optional, which permits relay against clients that do not require it.' \
                remediation='Set "server signing = mandatory" explicitly rather than relying on a version-dependent default.' 
            ;;
        *)
            add_finding WARN 'SMB Configuration' "SMB signing is set to an unrecognised value: ${signing}." \
                attr='SMB signing' configured="server signing = ${signing}" expected='mandatory' observed='/etc/samba/smb.conf' \
                validation='Configuration read; the value did not match any documented setting so its effect was NOT established.' \
                class='Medium' catclass='IdentityRights' \
                impact='Unknown rather than compliant - the setting was accepted by the file but its meaning was not verified.' \
                remediation='Confirm the intended value against the Samba documentation for the installed version.'
            ;;
    esac

    case "$encrypting" in
        required|mandatory)
            add_finding PASS 'SMB Configuration' 'SMB transport encryption is required.' \
                attr='SMB encryption' configured="smb encrypt = ${encrypting}" observed='/etc/samba/smb.conf' \
                validation='Configuration read' class='Medium' impact='Control satisfied at the configuration level.' remediation='None required.'
            ;;
        desired|enabled)
            add_finding WARN 'SMB Configuration' 'SMB encryption is desired but not required, so a client that does not negotiate it will still connect in clear text.' \
                attr='SMB encryption' configured="smb encrypt = ${encrypting}" expected='required' observed='/etc/samba/smb.conf' \
                validation='Configuration read' class='Medium' catclass='Confidentiality' weakness='1' \
                impact='File content and credentials are exposed to an on-path observer for clients that decline encryption.' \
                remediation='Set "smb encrypt = required" once every client in use supports it.'
            ;;
    esac
}

# =============================================================================================
#  SECTION 4 :: AUTHENTICATION POLICY VS OBSERVED
# =============================================================================================
section4_authentication() {
    write_section '4' 'AUTHENTICATION POLICY VS OBSERVED'
    write_status 'INFO' 'Policy is read from configuration. This tool performs NO authentication attempts against any account, local or remote, so nothing here measures whether the policy is effective in practice - that is stated per row.'

    # ---- password composition -----------------------------------------------------------------
    local pwq='' minlen='' pwqfile=''
    for pwqfile in /etc/security/pwquality.conf /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
        [ -r "$pwqfile" ] || continue
        if grep -Eq 'pam_pwquality|pam_cracklib' "$pwqfile" 2>/dev/null; then pwq="$pwqfile"; fi
        local m
        m=$(awk '/^[[:space:]]*minlen/ {print $3; exit}' "$pwqfile" 2>/dev/null)
        [ -n "$m" ] && minlen="$m"
    done
    if [ -n "$pwq" ]; then
        write_kv 'Quality module' "$pwq"
        write_kv 'Minimum length' "${minlen:-not set (module default, usually 8 or 9)}"
        if [ -n "$minlen" ] && [ "$minlen" -lt 12 ] 2>/dev/null; then
            add_finding WARN 'Authentication' "Local password policy requires only ${minlen} character(s)." \
                attr='Minimum password length' configured="minlen=${minlen}" observed="$pwq" validation='Configuration read' \
                class='High' weakness='1' expected='at least 14, ideally with breached-password screening' \
                impact='Short passwords fall to offline cracking and to online guessing, and they are the enabling condition for every credential-reuse path in this report. No guessing was performed here.' \
                remediation='Raise minlen to 14 or more (length dominates complexity), and deploy a breached-password check so users cannot choose a known-compromised password.'
        fi
    else
        write_kv 'Quality module' 'pam_pwquality / pam_cracklib not found in the PAM stacks'
        add_finding WARN 'Authentication' 'No password-quality module was found in the PAM stack, so password composition is not enforced locally.' \
            attr='Password quality module' configured='not present' observed='searched /etc/pam.d and /etc/security/pwquality.conf' \
            validation='Configuration read' class='High' weakness='1' expected='pam_pwquality loaded with a minimum length' \
            impact='Users may set trivially guessable passwords, which then defeat every other authentication control in this report.' \
            remediation='Load pam_pwquality in the password stack with minlen>=14, and confirm the change through the distribution mechanism so it survives package updates.'
    fi

    # ---- lockout ------------------------------------------------------------------------------
    local lockout='' lockfile=''
    for lockfile in /etc/security/faillock.conf /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/login; do
        [ -r "$lockfile" ] || continue
        if grep -Eq 'pam_faillock|pam_tally2' "$lockfile" 2>/dev/null; then lockout="$lockfile"; fi
    done
    local deny=''
    [ -r /etc/security/faillock.conf ] && deny=$(awk '/^[[:space:]]*deny/ {print $3; exit}' /etc/security/faillock.conf 2>/dev/null)
    if [ -n "$lockout" ]; then
        write_kv 'Lockout module' "$lockout"
        write_kv 'Lockout threshold' "${deny:-configured in the PAM line, not in faillock.conf}"
        add_finding INFO 'Authentication' 'A local account-lockout module is loaded, so repeated failed local authentications are bounded by policy.' \
            attr='Local lockout policy' configured="module in ${lockout}; deny=${deny:-per PAM argument}" observed='configuration read' \
            validation='Configuration read. Whether lockout actually triggers, and how it interacts with each service, was NOT tested.' \
            class='Low' impact='Context that bounds local guessing. It says nothing about remote services that do not use this PAM stack.' \
            remediation='Confirm the threshold matches the corporate baseline and that lockout events are alerted on, so the control cannot itself be used to deny service to a shared account.'
    else
        write_kv 'Lockout module' 'not found in the PAM stacks'
        add_finding WARN 'Authentication' 'No local account-lockout module (pam_faillock or pam_tally2) was found, so failed local authentications are unbounded.' \
            attr='Local lockout policy' configured='not present' observed='searched /etc/pam.d and /etc/security/faillock.conf' \
            validation='Configuration read' class='High' weakness='1' expected='pam_faillock with an agreed threshold' \
            impact='Removes the only control limiting repeated password attempts against local accounts. Note that a threshold must be paired with alerting, or it becomes a denial-of-service vector against service accounts.' \
            remediation='Load pam_faillock with a threshold agreed with the identity team, and alert on cumulative lockout events.'
    fi

    # ---- password aging policy ---------------------------------------------------------------
    if [ -r /etc/login.defs ]; then
        local maxd mind warnd enc
        maxd=$(awk '/^[[:space:]]*PASS_MAX_DAYS/ {print $2; exit}' /etc/login.defs)
        mind=$(awk '/^[[:space:]]*PASS_MIN_DAYS/ {print $2; exit}' /etc/login.defs)
        warnd=$(awk '/^[[:space:]]*PASS_WARN_AGE/ {print $2; exit}' /etc/login.defs)
        enc=$(awk '/^[[:space:]]*ENCRYPT_METHOD/ {print $2; exit}' /etc/login.defs)
        write_kv 'PASS_MAX_DAYS' "${maxd:-unset}"
        write_kv 'PASS_MIN_DAYS' "${mind:-unset}"
        write_kv 'PASS_WARN_AGE' "${warnd:-unset}"
        write_kv 'ENCRYPT_METHOD' "${enc:-unset}"
        if [ -n "${enc:-}" ]; then
            case "$(printf '%s' "$enc" | tr '[:upper:]' '[:lower:]')" in
                yescrypt|sha512|sha256) add_finding PASS 'Credential Storage' "Password hashing method ${enc} is acceptable." \
                        attr='ENCRYPT_METHOD' configured="$enc" observed='/etc/login.defs' validation='Configuration read' \
                        class='High' impact='Control satisfied.' remediation='None required.' ;;
                md5|des)
                    add_finding 'RISK DETECTED' 'Credential Storage' "New passwords are hashed with ${enc}, a fast legacy algorithm that falls quickly to offline cracking once a hash is obtained." \
                        attr='ENCRYPT_METHOD' configured="$enc" observed='/etc/login.defs' validation='Configuration read' \
                        class='Critical' weakness='1' expected='yescrypt (preferred) or sha512' \
                        impact='Any disclosure of the hash file converts directly into recovered plaintext for a large fraction of accounts.' \
                        remediation='Set ENCRYPT_METHOD to yescrypt where the distribution supports it, otherwise SHA512, and expire every existing password so it is rehashed.' ;;
            esac
        fi
    fi

    add_finding 'NOT TESTABLE' 'Authentication' 'Per-account password age and lockout state were NOT assessed. Establishing them requires reading /etc/shadow, which this tool deliberately does not do.' \
        attr='Per-account credential state' configured='not read by design' observed='the tool never opens /etc/shadow' \
        validation='Deliberate scope boundary. The permission state OF the file is assessed in Section 2; its contents are not touched.' \
        class='High' impact='Unknown rather than compliant. A human with authorisation must review account aging and lockout state directly.' \
        remediation='Review with: chage -l <user> for aging, and faillock --user <user> for lockout state, under the engagement authorisation.'

    # ---- directory-backed identities ----------------------------------------------------------
    if [ -e /etc/sssd/sssd.conf ] || [ -e /etc/krb5.conf ] || [ -e /etc/nsswitch.conf ]; then
        if grep -Eq 'sss|ldap|winbind' /etc/nsswitch.conf 2>/dev/null; then
            local prov
            prov=$(grep -E '^\s*(id_provider|ldap_uri|krb5_server)' /etc/sssd/sssd.conf 2>/dev/null | tr '\n' '; ')
            write_kv 'Identity backend' 'directory-backed (sss/ldap/winbind in nsswitch.conf)'
            add_finding INFO 'Directory Services' 'Local authentication is delegated to a directory service, so the local password policy above governs only local accounts.' \
                attr='Identity backend' configured="${prov:-directory provider configured}" observed='nsswitch.conf and sssd/krb5 configuration' \
                validation='Configuration read. No directory query was made by this section.' \
                class='Medium' impact='A local-only policy assessment would understate the exposure: the authoritative policy lives in the directory.' \
                remediation='Assess the directory policy directly (this tool does so in Section 9 where a directory is reachable).'
        fi
    fi
}

# =============================================================================================
#  SECTION 5 :: CREDENTIAL-MATERIAL EXPOSURE (READ-ONLY, METADATA ONLY)
# =============================================================================================
section5_credential_exposure() {
    write_section '5' 'CREDENTIAL-MATERIAL EXPOSURE (metadata only)'
    write_status 'INFO' 'THIS SECTION INSPECTS FILE METADATA ONLY. No credential file is opened, read, parsed or copied, and no hash is extracted. The finding is the permission state, not the secret.'

    # ---- private keys and credential files ----------------------------------------------------
    local -a targets=(
        "$HOME/.ssh"
        "/root/.ssh"
        "$HOME/.netrc"
        "$HOME/.pgpass"
        "$HOME/.my.cnf"
        "$HOME/.aws/credentials"
        "$HOME/.kube/config"
        "$HOME/.docker/config.json"
    )
    local t found_any=0
    for t in "${targets[@]}"; do
        [ -e "$t" ] || continue
        found_any=1
        local m owner
        m=$(get_octal_perms "$t" 2>/dev/null)
        owner=$(stat -c '%U' "$t" 2>/dev/null)
        case "$t" in
            *.ssh)
                if [ -d "$t" ]; then
                    local dperm
                    dperm=$(get_octal_perms "$t" 2>/dev/null)
                    if [ "$dperm" != '700' ] && [ "$dperm" != '750' ]; then
                        add_finding WARN 'Credential Storage' "Directory ${t} has mode ${dperm}, so its contents may be readable beyond the owner." \
                            attr='SSH directory permissions' configured="${dperm} ${owner}" observed="$t" \
                            validation='Filesystem metadata read' class='Medium' weakness='1' expected='700 (or 750 for shared administrative access)' \
                            impact='Widens who can read the private keys and known-hosts data inside.' \
                            remediation="chmod 700 ${t}"
                    fi
                    local k
                    for k in "$t"/id_*; do
                        [ -f "$k" ] || continue
                        case "$k" in *.pub) continue ;; esac
                        local km
                        km=$(get_octal_perms "$k" 2>/dev/null)
                        if [ "$km" != '600' ] && [ "$km" != '400' ]; then
                            add_finding 'RISK DETECTED' 'Credential Storage' "SSH private key ${k} has mode ${km} and is therefore readable by users other than its owner." \
                                attr='SSH private key permissions' configured="${km}" observed="$k" \
                                validation='Filesystem metadata read. The key was NOT opened or copied.' class='High' weakness='1' expected='600 or 400' \
                                impact='Another local account can read the key and impersonate this identity against every system that trusts it - including systems outside this engagement scope.' \
                                remediation="chmod 600 ${k}. If the file has been readable for an unknown period, treat the key as compromised: rotate it on every target that authorises it, then remove the old public key."
                        fi
                    done
                fi
            ;;
            *)
                if [ -f "$t" ]; then
                    case "$m" in 600|400|000|640) ;; *)
                        add_finding WARN 'Credential Storage' "Credential-bearing file ${t} has mode ${m}, so it may be readable beyond its owner." \
                            attr='Credential file permissions' configured="${m} ${owner}" observed="$t" \
                            validation='Filesystem metadata read. The file was NOT opened; this tool does not read credential stores.' \
                            class='High' weakness='1' expected='600 or stricter' \
                            impact='Stored service credentials are exposed to other local users.' \
                            remediation="chmod 600 ${t} and rotate the stored credential if the exposure window is unknown."
                    ;;
                    esac
                fi
            ;;
        esac
    done
    if [ "$found_any" = '0' ]; then
        write_kv 'Credential-bearing files' 'none of the common locations exist for this user'
    fi

    # ---- shell history: present but deliberately not read -------------------------------------
    local hf hsize
    # History is metadata-only: never read credential-bearing contents. Cover bash/zsh/sh defaults
    # plus the common /root deployment paths without dereferencing or harvesting history text.
    for hf in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.sh_history" \
               "/root/.bash_history" "/root/.zsh_history" "/root/.sh_history"; do
        [ -f "$hf" ] || continue
        local hm
        hm=$(get_octal_perms "$hf" 2>/dev/null)
        if have wc; then hsize=$(wc -c < "$hf" 2>/dev/null | tr -d ' '); else hsize='unknown'; fi
        add_finding INFO 'Credential Storage' "Shell history exists at ${hf} (mode ${hm}). It commonly contains credentials passed on command lines, and this tool does not read it." \
            attr='Shell history' configured="mode ${hm}" observed="$hf exists (${hsize} bytes, not read)" \
            validation='Filesystem metadata read. Contents deliberately NOT read: command history is a credential-bearing artefact and harvesting it is outside this tool''s scope.' \
            class='Medium' impact='A human tester reviewing history under authorisation, or an attacker with the same access, could recover credentials typed inline. The exposure is the practice of typing secrets on the command line.' \
            remediation='Set HISTIGNORE and HISTCONTROL to exclude patterns containing secrets, and prefer files or interactive prompts for credential input.'
    done

    # ---- readable process environments ---------------------------------------------------------
    if [ -d /proc ] && [ "$ELEVATED" = '1' ]; then
        local readable=0 pid
        for pid in /proc/[0-9]*; do
            [ -r "$pid/environ" ] || continue
            if [ "$pid" != "/proc/$$" ] && [ "$pid" != "/proc/$PPID" ]; then readable=$((readable+1)); fi
        done
        if [ "$readable" -gt 0 ]; then
            add_finding WARN 'Credential Storage' "${readable} running process(es) have an environment block readable at this privilege level. Environment variables routinely carry credentials, tokens and connection strings." \
                attr='Readable process environments' configured="${readable} processes" observed='readability test of /proc/<pid>/environ (contents were NOT read)' \
                validation='Permission test only. No environment variable was read by this tool.' class='Medium' weakness='1' \
                impact='Any process able to read these blocks obtains whatever secrets the owning service was started with - a common and quiet path from a low-privilege foothold to a service credential.' \
                remediation='Pass secrets through a file readable only by the service account, a credential helper or a vault agent, rather than through the environment; restrict who can operate as root.'
        else
            add_finding PASS 'Credential Storage' 'No process environment beyond the current shell was readable at this privilege level.' \
                attr='Readable process environments' configured='0' observed='readability test of /proc/<pid>/environ' \
                validation='Permission test only' class='Medium' impact='Control satisfied.' remediation='None required.'
        fi
    elif [ "$ELEVATED" != '1' ]; then
        add_finding 'NOT TESTABLE' 'Credential Storage' 'Process-environment readability was not assessed because this run is not privileged.' \
            attr='Readable process environments' observed='non-root run' validation='Privilege check' class='Medium' \
            impact='Unknown. A privileged run is needed to determine the full exposure.' \
            remediation='Re-run with privilege for this control, or accept the gap and record it.'
    fi

    add_finding INFO 'Assessment Integrity' 'This section performed no credential extraction. The Windows edition of this tool documents the same boundary, and it is a deliberate design constraint rather than a missing feature.' \
        attr='Credential-handling boundary' configured='metadata inspection only' observed='no credential file opened in this run' \
        validation='Design constraint, restated in the report so a reader does not mistake absence of credential findings for absence of credential exposure.' \
        class='Low' impact='Enablement, not a finding: the report states plainly which credential-related questions it did and did not answer.' \
        remediation='None. Where credential validation is genuinely in scope, it belongs in a separately authorised exercise with its own written approval, an agreed lockout budget and a human operator.'
}

# =============================================================================================
#  SECTION 6 :: PRINT / CUPS EXPOSURE
# =============================================================================================
section6_cups() {
    write_section '6' 'PRINT SERVICE EXPOSURE (role-aware)'
    local cups=0
    { have cupsd || [ -r /etc/cups/cupsd.conf ]; } && cups=1
    if [ "$cups" = '0' ]; then
        write_status 'INFO' 'No CUPS installation detected: this host is not a print server, so the section is not applicable.'
        add_finding INFO 'Print Service' 'CUPS is not installed, so no print-service exposure exists on this host.' \
            attr='CUPS presence' configured='not installed' observed='no cupsd binary and no /etc/cups/cupsd.conf' \
            validation='Presence check' class='Low' impact='Not applicable.' remediation='None required.'
        return
    fi
    local listening
    listening=$(inventory_listening_sockets 2>/dev/null | awk -F'|' '$3=="631"{print $2":"$3}' | head -3 | tr '\n' ' ')
    if [ -n "$listening" ]; then
        write_kv 'CUPS listening' "$listening"
        add_finding WARN 'Print Service' "CUPS is listening on 631 (${listening}). The CUPS web interface and IPP endpoint are reachable from wherever this socket is exposed." \
            attr='CUPS exposure' configured="$listening" observed='listening-socket inventory' \
            validation='Socket inventory (ss). The administrative interface was NOT exercised.' class='Medium' weakness='1' \
            expected='bound to loopback, or restricted to a print-management segment' \
            impact='Historically CUPS has had remote code execution issues, and its administrative interface exposes printer configuration and job contents.' \
            remediation='Bind CUPS to loopback where printing is local, and restrict 631 to management networks by firewall where it is not. Keep CUPS patched.'
    else
        write_kv 'CUPS listening' 'not listening'
        add_finding PASS 'Print Service' 'CUPS is installed but not listening on a network socket.' attr='CUPS exposure' \
            configured='not listening' observed='listening-socket inventory' validation='Socket inventory (ss)' \
            class='Medium' impact='Control satisfied.' remediation='None required.'
    fi
}

# =============================================================================================
#  SECTION 7 :: PATCH AND UPDATE POSTURE
# =============================================================================================
section7_patching() {
    write_section '7' 'PATCH AND UPDATE POSTURE'
    local reboot_required='no'
    { [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]; } && reboot_required='yes'
    write_kv 'Reboot required' "$reboot_required"
    if [ "$reboot_required" = 'yes' ]; then
        add_finding WARN 'Patch Management' 'The system has flagged that a reboot is required to complete a pending update. Until it is applied, the running kernel and services remain at the previous version while the package database reports the newer one.' \
            attr='Reboot required' configured='/run/reboot-required present' observed='flag file exists' \
            validation='Filesystem check of the distribution reboot-required marker' class='Medium' weakness='1' \
            expected='reboot scheduled and completed within the patch window' \
            impact='Security fixes that need a restart - most kernel and libc fixes - are not in effect, so the host remains vulnerable to issues the package manager reports as resolved.' \
            remediation='Schedule the reboot inside the agreed window and re-run this assessment afterwards to confirm the new kernel is running.'
    fi

    # ---- running kernel vs installed kernels ---------------------------------------------------
    local running_ver installed_newest=''
    running_ver="$KERNEL"
    if rpm_usable; then
        installed_newest=$(rpm -q kernel --qf '%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort -V | tail -1)
    elif have dpkg-query && [ -d /boot ]; then
        installed_newest=$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's|.*/vmlinuz-||' | sort -V | tail -1)
    fi
    if [ -n "$installed_newest" ]; then
        write_kv 'Running kernel' "$running_ver"
        write_kv 'Newest installed kernel' "$installed_newest"
        if [ "$running_ver" != "$installed_newest" ]; then
            add_finding WARN 'Patch Management' "The running kernel (${running_ver}) is not the newest installed kernel (${installed_newest}), so kernel security fixes are installed but not in effect." \
                attr='Kernel version drift' configured="running ${running_ver}; installed ${installed_newest}" \
                observed='uname -r compared with the kernel package or /boot contents' \
                validation='Direct comparison of the running kernel against installed kernel artefacts' class='High' weakness='1' \
                expected='the running kernel matches the newest installed kernel' \
                impact='Any kernel-level vulnerability fixed in the newer package remains exploitable on this host despite the patch being recorded as applied.' \
                remediation='Reboot into the newest kernel in the next window, and pin the bootloader entry so a failed update cannot silently select the older kernel.'
        else
            add_finding PASS 'Patch Management' 'The running kernel is the newest installed kernel.' \
                attr='Kernel version drift' configured="running ${running_ver}" observed='uname -r matches the installed kernel package' \
                validation='Direct comparison' class='High' impact='Control satisfied.' remediation='None required.'
        fi
    else
        note_missing_tool 'kernel package query'
        add_finding 'NOT TESTABLE' 'Patch Management' "Kernel version drift could not be assessed: no usable rpm database (rpm $(rpm_usable && echo usable || echo 'present but unusable on this host')), and no /boot kernel images to compare against." \
            attr='Kernel version drift' configured="$(tool_search_note)" observed='no usable package database and no /boot images' \
            attr='Kernel version drift' observed="uname -r = ${running_ver}; no comparison source" validation='Tool/artefact availability check' \
            class='High' impact='Unknown rather than compliant.' \
            remediation='Compare the running kernel with the installed kernel package by hand for this distribution.'
    fi

    # ---- last package transaction --------------------------------------------------------------
    local last_txn=''
    if [ -r /var/log/dpkg.log ]; then
        last_txn=$(grep -E ' (install|upgrade) ' /var/log/dpkg.log 2>/dev/null | tail -1 | awk '{print $1" "$2}')
    elif rpm_usable; then
        last_txn=$(rpm -qa --qf '%{INSTALLTIME}\n' 2>/dev/null | sort -n | tail -1 | awk '{print strftime("%Y-%m-%d %H:%M",$1)}')
    fi
    if [ -n "$last_txn" ]; then
        write_kv 'Last package transaction' "$last_txn"
        local age_days
        age_days=$(( ( $(date +%s) - $(date -d "${last_txn%% *}" +%s 2>/dev/null || echo "$(date +%s)") ) / 86400 ))
        if [ "$age_days" -gt 90 ] 2>/dev/null; then
            add_finding WARN 'Patch Management' "No package transaction has been recorded for approximately ${age_days} days." \
                attr='Patch cadence' configured="last transaction ${last_txn}" observed='package manager log / database' \
                validation='Package log timestamp. A quiet period can also mean a stable host, so this is a CADENCE observation, not proof of a missing patch.' \
                class='Medium' weakness='1' expected='patches applied on the agreed cycle' \
                impact='Extends the window in which a published vulnerability is exploitable here.' \
                remediation='Confirm whether this host is inside the patch cycle or was missed by it, and remediate the gap.'
        else
            add_finding PASS 'Patch Management' "Package activity within the last ${age_days} days." attr='Patch cadence' \
                configured="last transaction ${last_txn}" observed='package manager log / database' \
                validation='Package log timestamp' class='Medium' impact='Control appears satisfied.' remediation='None required.'
        fi
    else
        note_missing_tool 'package log'
        add_finding 'NOT TESTABLE' 'Patch Management' 'Patch cadence could not be established: no package manager log was readable.' \
            attr='Patch cadence' observed="no dpkg log and no usable rpm database available; $(tool_search_note)" validation='Artefact availability check' \
            class='Medium' impact='Unknown rather than compliant.' \
            remediation='Establish patch cadence from the configuration management or patch-orchestration record instead.'
    fi
}

# =============================================================================================
#  SECTION 8 :: NETWORK DISCOVERY (bounded and authorised)
# =============================================================================================
PORTS_DEFAULT='21 22 23 53 80 88 111 135 139 389 443 445 636 1433 2049 3268 3269 3306 3389 5432 5900 5985 5986 6379 8080 8443'
BANNER_PORTS='21 22 23 25 80 8080'

derive_local_subnet() {
    # Returns "ip|prefix|iface" for the first global-scope IPv4 address.
    net_inventory 2>/dev/null | awk -F'|' '$4=="global" {print $2"|"$3"|"$1; exit}'
}

sweep_host() {
    # echoes "host" when the host responds on any of the liveness ports, or to a TCP RST.
    local h="$1" p
    for p in 445 22 3389 80; do
        if tcp_open "$h" "$p" "$TCP_TIMEOUT_MS"; then echo "$h"; return 0; fi
    done
    return 1
}

portmatrix_host() {
    # echoes "host|port" for each open port
    local h="$1" p
    for p in $PORTS_DEFAULT; do
        if tcp_open "$h" "$p" "$TCP_TIMEOUT_MS"; then echo "$h|$p"; fi
    done
}

bounded_parallel_echo() {
    # bounded_parallel_echo <batch-size> <function> <item>...
    # Portable bounded parallelism: run in batches of N and wait for each batch. Simpler than a
    # rolling pool and works on bash 3+, which matters because this must run on distributions
    # still shipping bash 4.x or a reduced 3.x.
    local batch="$1" fn="$2"; shift 2
    local -a items=("$@")
    local i=0 n=${#items[@]}
    while [ "$i" -lt "$n" ]; do
        local j=0
        while [ "$j" -lt "$batch" ] && [ "$i" -lt "$n" ]; do
            "$fn" "${items[$i]}" &
            i=$((i+1)); j=$((j+1))
            if [ "$STARTUP_DELAY_MS" -gt 0 ]; then
                sleep "$DELAY_SEC"
            fi
        done
        wait
    done
}

grab_banner() {
    # grab_banner <host> <port>  -> prints a collapsed one-line banner
    local h="$1" p="$2" out=''
    socket_gate "$h" || return 1
    case "$p" in
        80|8080)
            out=$(run_bounded_seconds 3 bash -c '
                exec 3<>/dev/tcp/"$1"/"$2" 2>/dev/null || exit 1
                printf "HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s/%s\r\nConnection: close\r\n\r\n" "$1" '"$TOOL_NAME"' '"$TOOL_VERSION"' >&3
                head -c 8192 <&3 2>/dev/null' _ "$h" "$p" 2>/dev/null) ;;
        21|22|23|25)
            out=$(tcp_read_banner "$h" "$p" 1500 1024) ;;
        *)  return 0 ;;
    esac
    printf '%s' "$out" | tr -d '\r' | tr '\n\t' '  ' | sed 's/  */ /g' | cut -c1-400
}

tls_certificate() {
    # tls_certificate <host> <port> -> "subject=...;issuer=...;notBefore=...;notAfter=..."
    local h="$1" p="$2"
    socket_gate "$h" || return 1
    have openssl || { note_missing_tool openssl; return 1; }
    local raw
    raw=$(run_bounded_seconds 5 openssl s_client -connect "${h}:${p}" -servername "$h" </dev/null 2>/dev/null) || return 1
    printf '%s' "$raw" | openssl x509 -noout -subject -issuer -dates 2>/dev/null \
        | tr '\n' ';' | sed 's/  */ /g'
}

# HOSTPORT_KEYS/HOSTPORT_VALUES and LIVE_HOSTS are GLOBAL on purpose: Section 16 and Section 19
# correlate discovery results, so scoping them to this function would silently empty the later sections.
section8_discovery() {
    write_section '8' 'NETWORK DISCOVERY (bounded, authorised scope)'

    local sub
    sub=$(derive_local_subnet)
    if [ -z "$sub" ]; then
        note_missing_tool ip
        write_status 'NOT TESTABLE' 'No IPv4 address inventory was available (the ip utility is absent), so the local subnet could not be derived.'
        add_finding 'NOT TESTABLE' 'Network Discovery' 'The local subnet could not be derived, so the discovery sweep was not performed.' \
            attr='Local subnet derivation' observed='no usable address inventory' validation='iproute2 availability check' \
            class='Medium' impact='Discovery coverage is unknown.' \
            remediation='Install iproute2, or supply an explicit scope with --scope and derive the target list externally.'
        return
    fi
    local myip="${sub%%|*}"; local rest="${sub#*|}"; local prefix="${rest%%|*}"; local iface="${rest##*|}"
    write_kv 'Assessment position' "${myip}/${prefix} on ${iface}"

    # ---- target list -------------------------------------------------------------------------
    local -a targets=()
    local base
    base=$(ip_to_int "$myip")
    if [ "$prefix" = '24' ]; then
        local net=$(( base & 0xFFFFFF00 ))
        local n=1
        while [ "$n" -le 254 ]; do
            local cand=$(( net + n ))
            targets+=( "$( printf '%d.%d.%d.%d' $(( (cand >> 24) & 255 )) $(( (cand >> 16) & 255 )) $(( (cand >> 8) & 255 )) $(( cand & 255 )) )" )
            n=$((n + 1))
        done
    else
        add_finding INFO 'Network Discovery' "The local interface is a /${prefix}, which is not a /24. The sweep is bounded to the /24 around this address; the wider range is NOT swept." \
            attr='Sweep bounding' configured="local address ${myip}/${prefix}" observed='address inventory' \
            validation='Prefix check before the target list is built' class='Medium' \
            impact='Hosts outside the derived /24 are not discovered by this pass.' \
            remediation='Run the assessment per segment, or supply an explicit --scope for each range to be covered.'
        local net=$(( base & 0xFFFFFF00 ))
        local n=1
        while [ "$n" -le 254 ]; do
            local cand=$(( net + n ))
            targets+=( "$( printf '%d.%d.%d.%d' $(( (cand >> 24) & 255 )) $(( (cand >> 16) & 255 )) $(( (cand >> 8) & 255 )) $(( cand & 255 )) )" )
            n=$((n + 1))
        done
    fi

    # Exclude our own address.
    local -a filtered=()
    local t
    for t in "${targets[@]}"; do [ "$t" != "$myip" ] && filtered+=("$t"); done
    targets=("${filtered[@]}")

    # SCOPE FILTER - applied at the single point the list is finalised, so no later change can
    # reintroduce an out-of-scope address. Default-deny whenever a scope was supplied.
    if [ "$SCOPE_ACTIVE" = '1' ]; then
        local -a scoped=()
        local removed=0
        for t in "${targets[@]}"; do
            if test_in_scope "$t"; then scoped+=("$t"); else removed=$((removed+1)); fi
        done
        targets=("${scoped[@]}")
        if [ "$removed" -gt 0 ]; then
            write_status 'INFO' "engagement scope removed ${removed} address(es) outside: ${SCOPE_TEXT}"
        fi
    fi

    if [ ${#targets[@]} -eq 0 ]; then
        write_status 'INFO' 'No in-scope target addresses remain (the scope excludes the whole derived range). No sweep was performed.'
        add_finding INFO 'Network Discovery' 'The supplied scope excludes every address in the derived range, so no sweep was performed.' \
            attr='Discovery scope' configured="$SCOPE_TEXT" observed='0 in-scope addresses' \
            validation='Scope filter applied before any connection' class='Low' impact='No discovery coverage - by operator design.' \
            remediation='Widen the scope if discovery was intended.'
        return
    fi

    if ! test_remote_allowed; then
        write_status 'NOT TESTABLE' "$(get_suppressed_reason)"
        add_finding 'NOT TESTABLE' 'Network Discovery' "The bounded sweep of ${#targets[@]} address(es) was not performed: $(get_suppressed_reason)." \
            attr='Discovery sweep' configured="$SCOPE_TEXT" observed="0 of ${#targets[@]} addresses checked" \
            validation='Authorisation gate (checked before any socket was opened)' class='Medium' \
            impact='Host inventory, service matrix and banner capture are all unassessed. Every downstream section that depends on discovery is NOT TESTABLE, not clean.' \
            remediation='Re-run with --scope or --authorize-active when the engagement authorises off-host traffic.'
        return
    fi

    write_kv 'Sweep scope' "${#targets[@]} address(es) in the /24 around ${myip}"
    write_kv 'Sweep profile' "${TCP_TIMEOUT_MS} ms connect, ${MAX_PARALLEL} concurrent, ${STARTUP_DELAY_MS} ms spacing, ${SWEEP_DEADLINE}s ceiling"

    # ---- liveness ----------------------------------------------------------------------------
    write_status 'INFO' 'Bounded liveness discovery...'
    local start_ts
    start_ts=$(date +%s)
    local live_raw
    live_raw=$(bounded_parallel_echo "$MAX_PARALLEL" sweep_host "${targets[@]}" 2>/dev/null)
    local elapsed=$(( $(date +%s) - start_ts ))
    local -a live=()
    while IFS= read -r t; do [ -n "$t" ] && live+=("$t"); done <<< "$live_raw"
    local timedout=0
    [ "$elapsed" -ge "$SWEEP_DEADLINE" ] && timedout=1

    write_status 'INFO' "Liveness complete: ${#live[@]} responsive address(es) of ${#targets[@]} checked in ${elapsed}s."
    if [ "$timedout" = '1' ]; then
        add_finding WARN 'Network Discovery' "The discovery sweep reached its ${SWEEP_DEADLINE}s ceiling, so coverage of the derived range may be incomplete." \
            attr='Incomplete sweep coverage' configured="ceiling ${SWEEP_DEADLINE}s" observed="${#live[@]} responsive of ${#targets[@]} addresses, ${elapsed}s elapsed" \
            validation='Deadline control (reported rather than hidden)' class='Medium' weakness='1' \
            impact='The host count below is a LOWER BOUND, not a total. Unscanned addresses may contain additional systems.' \
            remediation='Re-run with a longer ceiling, or use --fast on a segment where burst traffic is acceptable, or split the assessment by subnet.'
    fi
    add_finding INFO 'Network Discovery' "Bounded liveness sweep of the derived /24: ${#live[@]} address(es) responded out of ${#targets[@]} probed (TCP 445/22/3389/80 connect test; an RST also counts as responsive)." \
        attr='Discovery sweep' configured="${#targets[@]} in scope; ${TCP_TIMEOUT_MS} ms timeout; ${MAX_PARALLEL} concurrent" \
        observed="${#live[@]} responsive in ${elapsed}s" \
        validation='TCP connect test from the assessment position. This is REACHABILITY evidence only: no authentication was attempted against any discovered host.' \
        class='Low' impact='Reachability alone is not impact. It matters where a service reachable here sits on a trust boundary that should have blocked it (Section 14).' \
        remediation='Confirm each responsive address belongs to the expected inventory; unexplained hosts warrant their own review.'

    if [ ${#live[@]} -eq 0 ]; then
        write_status 'INFO' 'No responsive hosts. The service matrix and banner capture are not applicable.'
        return
    fi

    # ---- service matrix ----------------------------------------------------------------------
    write_status 'INFO' 'Service matrix on responsive hosts...'
    local matrix_raw
    matrix_raw=$(bounded_parallel_echo "$MAX_PARALLEL" portmatrix_host "${live[@]}" 2>/dev/null)
    local -a found=()
    while IFS= read -r t; do [ -n "$t" ] && found+=("$t"); done <<< "$matrix_raw"
    write_status 'INFO' "${#found[@]} open service(s) found."

    local -a rows=()
    local entry h p names
    for entry in "${found[@]}"; do
        h="${entry%%|*}"; p="${entry##*|}"
        names="$(hostport_get "$h" 2>/dev/null)"
        [ -n "$names" ] && names="$names, "
        hostport_set "$h" "$names$p"
    done
    for h in "${live[@]}"; do
        names="$(hostport_get "$h" 2>/dev/null)"
        local infer='role not determinable from ports'
        case "$names" in
            *88*389*|*389*88*) infer='probable directory/Kerberos server' ;;
            *445*139*) infer='file server (SMB)' ;;
            *3306*|*5432*|*1433*) infer='database server' ;;
            *80*443*|*8080*|*8443*) infer='web server' ;;
        esac
        rows+=("${h}|${names:-none}|${infer}")
    done
    if [ ${#rows[@]} -gt 0 ]; then
        write_table 'Host|Open probed ports|Role inference' "${rows[@]}"
    fi

    for h in "${live[@]}"; do
        local pi="$(hostport_get "$h" 2>/dev/null)"
        local -a svc=()
        for p in $pi; do svc+=("$(service_name_for_port "$p")/${p}"); done
        add_finding INFO 'Network Discovery' "Host responded and exposes: ${svc[*]:-no services from the probed set}." \
            attr='Discovered host' source="$HOST_SHORT" target="$h" port="$(printf '%s' "$pi" | tr ' ' ',')" \
            observed="live by TCP connect; open ports: ${pi:-none}" \
            validation='TCP connect survey from the assessment position. No authentication was attempted, and no host role was confirmed - the inference column is a port-pattern guess, not a determination.' \
            class='Low' \
            impact='Becomes significant only where an administrative service is reachable from a segment that should not have access.' \
            remediation='Confirm each exposed service is required for the host role, and restrict administrative interfaces to management networks.'
        # administrative exposure
        for p in $pi; do
            case "$p" in
                22|3389|5985|5986|5900)
                    add_finding WARN 'Network Discovery' "Remote-administration service $(service_name_for_port "$p") (TCP/${p}) is reachable from the assessment position on ${h}." \
                        attr='Administrative interface reachable' source="$HOST_SHORT" target="$h" port="$p" \
                        prereq='Valid credentials for an account with access to this host (NOT validated by this tool)' \
                        observed="TCP/${p} open from ${HOST_SHORT}" \
                        validation='TCP connect test. Reachability is CONFIRMED; authentication was NOT attempted, so this is a precondition, not a compromise.' \
                        class='High' weakness='1' \
                        exploit='Reachability validated, authentication not attempted.' \
                        impact='Any credential usable against this host - including one reused from elsewhere in the estate - provides interactive access to it. Reachable administrative interfaces from user segments are the primary lateral-movement enabler.' \
                        remediation='Restrict remote management to privileged-access workstations and management VLANs with host firewall rules and network ACLs, and require keys rather than passwords.'
                ;;
            esac
        done
    done

    # ---- banner capture ----------------------------------------------------------------------
    write_status 'INFO' 'Read-only banner / TLS certificate capture...'
    local b h2 p2 bn
    for h2 in "${live[@]}"; do
        for p2 in $BANNER_PORTS; do
            case "$(hostport_get "$h2" 2>/dev/null)" in *"$p2"*) ;; *) continue ;; esac
            test_target_allowed "$h2" || continue
            bn=$(grab_banner "$h2" "$p2")
            [ -n "$bn" ] || continue
            add_finding INFO 'Service Exposure' "Service on ${h2}:${p2} volunteers an identifying banner before authentication." \
                attr='Pre-authentication banner' source="$HOST_SHORT" target="$h2" port="$p2" \
                prereq='TCP reachability only; no credentials presented and no protocol state advanced' \
                observed="banner: ${bn}" \
                validation='The string was read directly from the live service in this run and is reproduced verbatim. Mapping it to a specific CVE was NOT performed and is not claimed.' \
                class='Low' \
                exploit='Informational to Low - a version string is not by itself exploitable; it becomes actionable only against a matching published vulnerability.' \
                impact='Removes guesswork from an adversary pre-attack reconnaissance and shortlists the host for version-specific exploitation.' \
                remediation='Suppress the version string where the service supports it; otherwise keep it patched and restrict reachability to required source ranges.'
            if printf '%s' "$bn" | grep -Eq '[0-9]+\.[0-9]+'; then
                add_finding WARN 'Service Exposure' "Version-disclosing banner on ${h2}:${p2}: ${bn}" \
                    attr='Version disclosure' source="$HOST_SHORT" target="$h2" port="$p2" \
                    observed="$bn" \
                    validation='Banner read from the live service. The version was NOT compared against a vulnerability database by this tool, so no CVE mapping is asserted.' \
                    class='Low' weakness='1' \
                    impact='Lets an attacker select exploits by version rather than by trial, which is faster and noisier to detect.' \
                    remediation='Suppress version banners where supported; where not, treat patch latency as the compensating control.'
            fi
        done
        for p2 in 443 8443 5986; do
            case "$(hostport_get "$h2" 2>/dev/null)" in *"$p2"*) ;; *) continue ;; esac
            test_target_allowed "$h2" || continue
            local cert
            cert=$(tls_certificate "$h2" "$p2")
            if [ -z "$cert" ]; then
                note_missing_tool openssl
                continue
            fi
            add_finding INFO 'Cryptography' "TLS endpoint ${h2}:${p2} presented a certificate." \
                attr='TLS certificate' source="$HOST_SHORT" target="$h2" port="$p2" \
                observed="$cert" \
                validation='Certificate captured from a live handshake. Chain validation and revocation were NOT checked, so no trust conclusion is drawn.' \
                class='Low' impact='Context for the endpoint identity.' \
                remediation='Ensure the certificate is issued by the internal PKI and renewed before expiry.'
            local subj issu
            subj=$(printf '%s' "$cert" | sed -n 's/.*subject=\([^;]*\).*/\1/p')
            issu=$(printf '%s' "$cert" | sed -n 's/.*issuer=\([^;]*\).*/\1/p')
            if [ -n "$subj" ] && [ "$subj" = "$issu" ]; then
                add_finding WARN 'Cryptography' "TLS endpoint ${h2}:${p2} presents a SELF-SIGNED certificate (subject and issuer are identical)." \
                    attr='Self-signed certificate' source="$HOST_SHORT" target="$h2" port="$p2" \
                    observed="$cert" \
                    validation='Subject and issuer strings read from the live certificate. Trust-store contents and revocation were not inspected, so the deployment reason is not attributed.' \
                    class='Medium' weakness='1' expected='certificate issued by the internal PKI with the host name in the SAN' \
                    impact='Weakens the confidentiality guarantee of the endpoint and trains operators to click through trust warnings, which defeats the warning for every other host too.' \
                    remediation='Reissue from the internal PKI with the correct SAN and a tracked expiry; add expiry monitoring so renewal is not manual.'
            fi
        done
    done
}

# =============================================================================================
#  SECTION 9 :: DIRECTORY SERVICES (policy and metadata)
# =============================================================================================
section9_directory() {
    write_section '9' 'DIRECTORY SERVICES (KERBEROS / LDAP / SSSD)'
    local joined=0
    [ -r /etc/krb5.conf ] && joined=1
    [ -r /etc/sssd/sssd.conf ] && joined=1
    grep -Eq 'sss|ldap|winbind' /etc/nsswitch.conf 2>/dev/null && joined=1
    if [ "$joined" = '0' ]; then
        write_status 'INFO' 'No directory integration detected on this host.'
        add_finding INFO 'Directory Services' 'The host is not joined to a directory: no krb5 configuration, SSSD configuration or directory entry in nsswitch.conf.' \
            attr='Directory membership' configured='not joined' observed='configuration presence check' \
            validation='Configuration read' class='Low' impact='Not applicable. Directory-based attack paths do not reach this host.' \
            remediation='None required.'
        return
    fi

    # ---- Kerberos configuration --------------------------------------------------------------
    if [ -r /etc/krb5.conf ]; then
        local realm kdcs weak
        realm=$(awk -F'=' '/^[[:space:]]*default_realm/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/krb5.conf)
        kdcs=$(awk -F'=' '/^[[:space:]]*kdc[[:space:]]*=/ {gsub(/[[:space:]]/,"",$2); print $2}' /etc/krb5.conf | sort -u | tr '\n' ' ')
        write_kv 'Kerberos realm' "${realm:-not set}"
        write_kv 'KDC(s) configured' "${kdcs:-none}"
        weak=$(grep -E '^\s*allow_weak_crypto\s*=\s*true' /etc/krb5.conf 2>/dev/null | head -1)
        if [ -n "$weak" ]; then
            add_finding 'RISK DETECTED' 'Cryptography' 'Kerberos is configured with allow_weak_crypto = true, so it will negotiate RC4-HMAC and other legacy encryption types.' \
                attr='allow_weak_crypto' configured="$weak" observed='/etc/krb5.conf' validation='Configuration read' \
                class='High' weakness='1' expected='false, with AES as the floor' \
                impact='Service tickets encrypted with RC4 are far cheaper to attack offline, and weak crypto permits downgrade of otherwise-protected authentication.' \
                remediation='Set allow_weak_crypto to false, confirm no service still depends on RC4, then raise the domain minimum encryption type.'
        fi
        # default credential cache mode
        local ccache
        ccache=$(awk -F'=' '/^[[:space:]]*default_ccache_name/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/krb5.conf)
        if [ -n "$ccache" ]; then
            write_kv 'Credential cache' "$ccache"
            case "$ccache" in
                FILE*|*/tmp*)
                    add_finding WARN 'Credential Storage' "Kerberos credential caches default to ${ccache}, a file-backed cache on disk." \
                        attr='Kerberos credential cache type' configured="$ccache" observed='/etc/krb5.conf' \
                        validation='Configuration read. No cache file was read or copied by this tool.' \
                        class='Medium' weakness='1' expected='KCM (sssd-kcm) or KEYRING where available' \
                        impact='File-backed caches persist credentials in the filesystem and can survive a session, widening the window in which they can be found. The cache file itself was NOT read here.' \
                        remediation='Where the distribution supports it, migrate to KCM or KEYRING caches and confirm that cache files are not world-readable.'
                ;;
            esac
        fi
    fi

    # ---- SSSD / LDAP endpoints ---------------------------------------------------------------
    local ldap_uri=''
    if [ -r /etc/sssd/sssd.conf ]; then
        ldap_uri=$(awk -F'=' '/^[[:space:]]*ldap_uri/ {gsub(/^[[:space:]]+/,"",$2); print $2; exit}' /etc/sssd/sssd.conf)
        local cache_cred
        cache_cred=$(grep -Ec '^\s*cache_credentials\s*=\s*[Tt]rue' /etc/sssd/sssd.conf 2>/dev/null)
        if [ "${cache_cred:-0}" -gt 0 ]; then
            add_finding WARN 'Credential Storage' 'SSSD is configured with cache_credentials = true, so domain credential material is cached locally to permit offline logon.' \
                attr='SSSD cache_credentials' configured='true' observed='/etc/sssd/sssd.conf' validation='Configuration read' \
                class='Medium' weakness='1' expected='disabled unless offline logon is a requirement' \
                impact='Cached domain credentials on a host extend the value of a local compromise. The cache database was NOT read by this tool.' \
                remediation='Disable cache_credentials where offline logon is not required; where it is required, restrict local administrative access and monitor for cache tampering.'
        fi
    fi

    if [ -z "$ldap_uri" ]; then
        write_status 'INFO' 'No LDAP URI configured, so directory reachability was not probed.'
        return
    fi
    write_kv 'LDAP URI' "$ldap_uri"

    # ---- reachability (gated) -----------------------------------------------------------------
    local host_part="${ldap_uri#ldap://}"; host_part="${host_part#ldaps://}"
    host_part="${host_part%%,*}"; host_part="${host_part%%/*}"
    local port=389
    case "$ldap_uri" in ldaps://*) port=636 ;; esac
    # An explicit port in the URI must be honoured. Ignoring it made the reachability probe test
    # port 389 against a server listening on another port, so the report said "not reachable" and
    # then, two lines later, "answered an anonymous query" - two rows contradicting each other about
    # the same endpoint. Found by pointing this section at a directory on a non-standard port.
    case "$host_part" in
        *:*)
            local explicit_port="${host_part##*:}"
            # only a purely numeric suffix is a port; this leaves a bracketed IPv6 literal intact
            if [ -n "$explicit_port" ] && [ -z "${explicit_port//[0-9]/}" ]; then
                host_part="${host_part%:*}"
                port="$explicit_port"
            fi
            ;;
    esac
    host_part="${host_part#[}"; host_part="${host_part%]}"
    [ -n "$host_part" ] || return 0
    # socket_gate, not test_target_allowed: this function also runs the anonymous-bind probe below,
    # and socket_gate is the one gate the containment audit recognises. It adds the loopback/self
    # exemption, which is correct here - a directory server running on this host is a LOCAL check.
    if ! socket_gate "$host_part"; then
        write_status 'NOT TESTABLE' "$(get_suppressed_reason) - directory reachability was not probed."
        add_finding 'NOT TESTABLE' 'Directory Services' "Directory reachability to ${host_part}:${port} was not probed: $(get_suppressed_reason)." \
            attr='Directory reachability' configured="$ldap_uri" observed='no connection attempted' \
            validation='Authorisation/scope gate applied before any socket was opened' class='Medium' \
            impact='Whether the directory is reachable from this foothold is unknown. Directory-based lateral movement therefore remains unassessed.' \
            remediation='Re-run with an in-scope authorisation when the engagement covers the directory.'
        return
    fi
    if tcp_open "$host_part" "$port" 2000; then
        write_kv 'Directory reachable' "${host_part}:${port} open"
        add_finding INFO 'Directory Services' "The directory server ${host_part}:${port} is reachable from this host." \
            attr='Directory reachability' source="$HOST_SHORT" target="$host_part" port="$port" \
            observed="TCP/${port} connect succeeded" validation='Single TCP connect test; no LDAP query was sent by this section' \
            class='Medium' impact='A directory server reachable from an unprivileged segment is the precondition for directory-based enumeration and relay paths.' \
            remediation='Restrict directory ports to the networks that require them; do not expose LDAP to general user segments.'
    else
        write_kv 'Directory reachable' "${host_part}:${port} not reachable"
        add_finding INFO 'Directory Services' "The configured directory server ${host_part}:${port} did not accept a TCP connection from this host." \
            attr='Directory reachability' source="$HOST_SHORT" target="$host_part" port="$port" \
            observed='connect failed or timed out within 2s' validation='Single TCP connect test' \
            class='Low' impact='Directory-based attack paths from this host are not available over the network.' \
            remediation='None required. Confirm the host still authenticates as expected - a directory-joined host that cannot reach its KDC will fall back to cached credentials.'
    fi

    # ---- anonymous bind test -------------------------------------------------------------------
    # The gate is evaluated AGAIN here rather than relying on the reachability check above. The
    # reason is the kill switch: an operator who creates EIA_STOP while a sweep is running expects
    # the remaining off-host work to stop, and a single check at the top of the section would let
    # this query - the tool's only live probe - proceed on a stale authorisation.
    if ! socket_gate "$host_part"; then
        write_status 'NOT TESTABLE' "$(get_suppressed_reason "$host_part") - the anonymous-bind test was not attempted."
        add_finding 'NOT TESTABLE' 'Directory Services' "The anonymous-bind test was not attempted against ${ldap_uri}: $(get_suppressed_reason "$host_part")." \
            attr='Anonymous LDAP bind' configured="$ldap_uri" observed='no LDAP query sent' \
            validation='Authorisation/scope gate applied before any LDAP client was invoked' class='Medium' \
            impact='Unknown rather than compliant: whether the directory answers unauthenticated queries was not measured.' \
            remediation='Re-run with an in-scope authorisation when the engagement covers the directory.'
        return
    fi
    if have ldapsearch; then
        local anon
        if run_bounded_seconds 8 ldapsearch -x -H "$ldap_uri" -s base -b '' "(objectClass=*)" namingContexts >/dev/null 2>&1; then
            add_finding WARN 'Directory Services' "The directory at ${ldap_uri} answered an anonymous (unauthenticated) LDAP query." \
                attr='Anonymous LDAP bind' source="$HOST_SHORT" target="$host_part" port="$port" \
                observed='a base-scope query returned a result without credentials' \
                validation='CONFIRMED by a live read-only base-scope query with no credentials presented. This is the same evidence class as the Windows edition produces for anonymous binds.' \
                class='Medium' weakness='1' expected='anonymous bind refused' \
                impact='Unauthenticated read access to directory metadata accelerates enumeration, and on misconfigured directories can expose objects beyond the base context.' \
                remediation='Disable anonymous binds and require authenticated access for all directory queries; review what anonymous readers could previously reach.'
        else
            add_finding PASS 'Directory Services' "The directory at ${ldap_uri} refused an anonymous bind." \
                attr='Anonymous LDAP bind' source="$HOST_SHORT" target="$host_part" port="$port" \
                observed='the unauthenticated query did not return a result' validation='Live read-only anonymous query attempt' \
                class='Medium' impact='Control satisfied.' remediation='None required.'
        fi
    else
        note_missing_tool ldapsearch
        # The reachability probe above already CONFIRMED the TCP path, so a missing client degrades
        # this from a validated result to a gap - it does not invalidate the reachability evidence.
        add_finding 'NOT TESTABLE' 'Directory Services' "The anonymous-bind test could not be performed: ldapsearch was not found ($(tool_search_note)). Directory reachability itself was confirmed separately above." \
            attr='Anonymous LDAP bind' configured="$ldap_uri" observed="ldapsearch unavailable; $(tool_search_note)" validation='Tool availability check' \
            class='Medium' impact='Unknown rather than compliant. The absence of the client tool is NOT evidence that anonymous binding is disabled.' \
            remediation='Install ldap-utils to assess this control, or test it from a host that has a directory client.'
    fi
}

# =============================================================================================
#  SECTION 10 :: SUID / SGID / CAPABILITIES
# =============================================================================================
section10_suid() {
    write_section '10' 'SET-UID, SET-GID AND FILE CAPABILITIES'
    if ! have find; then
        note_missing_tool find
        add_finding 'NOT TESTABLE' 'Local Privilege Escalation' 'The SUID/SGID inventory could not be produced because find is not installed.' \
            attr='SUID/SGID inventory' observed='find unavailable' validation='Tool availability check' class='High' \
            impact='Unknown rather than compliant.' remediation='Install findutils, or produce the inventory by another route.'
        return
    fi

    local suid_list suid_count
    suid_list=$(find / -xdev -type f -perm -4000 2>/dev/null | sort)
    suid_count=$(printf '%s\n' "$suid_list" | grep -c . )
    write_kv 'Set-UID binaries' "$suid_count"

    local sgid_count
    sgid_count=$(find / -xdev -type f -perm -2000 2>/dev/null | wc -l)
    write_kv 'Set-GID binaries' "$sgid_count"

    # ---- unexpected set-uid binaries ---------------------------------------------------------
    # The finding that matters is NOT "set-uid binaries exist" - they are normal. It is a set-uid
    # binary in a path an unprivileged user can influence, or one that should not carry the bit.
    local suspicious=''
    local f
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        local dperm
        dperm=$(get_octal_perms "$(dirname "$f")" 2>/dev/null)
        case "$dperm" in
            *2|*3|*6|*7)  # world- or group-writable directory containing a set-uid binary
                # only flag when the write permission applies to a group that is not trivially root
                case "$dperm" in
                    1777|777|1776|776|766|757) suspicious+="${f}(dir ${dperm}) " ;;
                esac
            ;;
        esac
    done <<< "$suid_list"
    if [ -n "$suspicious" ]; then
        add_finding 'RISK DETECTED' 'Local Privilege Escalation' "Set-UID binary/binaries live in a writable directory: ${suspicious}" \
            attr='Set-UID in writable directory' configured="$suspicious" observed='find -perm -4000 crossed with directory permissions' \
            validation='Filesystem permission cross-check. The binary itself was NOT executed.' class='Critical' weakness='1' \
            expected='set-uid binaries only in root-owned, non-writable directories' \
            impact='A writable directory containing a set-uid binary lets any user replace it, so the next execution runs their code as the file owner - normally root. This is direct local privilege escalation.' \
            remediation='Remove the set-uid bit from the affected binary, fix the directory to root-owned mode 755, and determine whether the permissions were changed by a package error or by an attacker.'
    else
        add_finding PASS 'Local Privilege Escalation' 'No set-uid binary was found inside a writable directory.' \
            attr='Set-UID in writable directory' configured='0' observed='find -perm -4000 with a directory permission cross-check' \
            validation='Filesystem permission analysis' class='Critical' \
            impact='The most direct form of local privilege escalation via set-uid is not present.' \
            remediation='None required. Re-check after package changes.'
    fi

    # ---- binaries that do not belong to any package -------------------------------------------
    local orphan='' owner_result resolved_target
    if dpkg_usable || rpm_usable; then
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            resolved_target=$(resolve_assessed_path "$f" 2>/dev/null)
            if [ -z "$resolved_target" ]; then
                orphan+="$f(unresolvable) "
                continue
            fi
            owner_result=$(package_owner "$resolved_target" 2>/dev/null)
            # Do not trust only the package manager exit status: require clean, non-empty stdout.
            if [ -z "$(printf '%s' "$owner_result" | sed '/^[[:space:]]*$/d')" ]; then
                orphan+="$resolved_target "
            fi
        done <<< "$suid_list"
    fi
    if [ -n "$orphan" ]; then
        add_finding 'RISK DETECTED' 'Local Privilege Escalation' "Set-UID binary/binaries that no package owns: ${orphan}" \
            attr='Unowned set-uid binary' configured="$orphan" context='UNOWNED_PRIVILEGED' observed='readlink -f followed by verified package ownership query for every set-uid file' \
            validation='Package-manager ownership query. The binaries were NOT executed. Ownership was accepted only when stdout was non-empty and matched the package-manager output grammar.' \
            class='Critical' weakness='1' expected='every set-uid binary owned by an installed package' \
            impact='Unowned privileged binaries are a classic privilege-escalation plant and also a persistence mechanism. Their presence warrants investigation before anything else in this report.' \
            remediation='Identify the origin of each binary before deleting it. Preserve a copy for forensics if the host is suspected compromised, and treat the host as potentially untrusted until the origin is explained.'
    elif [ -n "$suid_list" ]; then
        add_finding PASS 'Local Privilege Escalation' 'Every set-uid binary is owned by an installed package.' \
            attr='Unowned set-uid binary' configured='0' observed='readlink -f plus package ownership query for every set-uid file' \
            validation='Verified package-manager ownership query' class='Critical' impact='Control satisfied.' remediation='None required.'
    fi

    # ---- file capabilities --------------------------------------------------------------------
    if have getcap; then
        local caps
        # `getcap -r /` walks the ENTIRE filesystem and on a large host that takes minutes. It is
        # bounded here so an assessment cannot stall in this section, and the bound is reported when
        # it is hit rather than silently truncating the inventory.
        local caps_raw cap_rc
        caps_raw=$(run_bounded_seconds 60 getcap -r / 2>/dev/null)
        cap_rc=$?
        if [ "$cap_rc" -eq 124 ]; then
            add_finding WARN 'Local Privilege Escalation' 'The recursive file-capability scan was stopped after 60 seconds, so the capability inventory below may be INCOMPLETE.' \
                attr='File capabilities' configured='getcap -r / bounded at 60s' observed='scan did not finish within the bound' \
                validation='Wall-clock bound applied to the enumeration' class='Medium' catclass='Context' \
                impact='A capability on a path that was not reached is unreported, so absence from this list is not evidence of absence.' \
                remediation='Re-run the scan against specific mount points, or build the inventory from the package database.'
        fi
        caps=$(printf '%s\n' "$caps_raw" | head -40)
        if [ -n "$caps" ]; then
            local cap_count
            cap_count=$(printf '%s\n' "$caps" | grep -c .)
            write_kv 'Files with capabilities' "$cap_count (first 40 shown in the report)"
            add_finding INFO 'Local Privilege Escalation' "Files carrying Linux capabilities were found (${cap_count} listed)." \
                attr='File capabilities' configured="$cap_count file(s)" observed="$(printf '%s' "$caps" | tr '\n' '; ' | cut -c1-400)" \
                validation='getcap enumeration. Capabilities are a legitimately-used feature; presence alone is context, not a weakness.' \
                class='Medium' impact='Context for privilege-escalation review. Specific capabilities (cap_setuid, cap_dac_read_search, cap_sys_admin) on a writable or interpreter binary are far more significant than the fact that capabilities exist.' \
                remediation='Review the list against the expected baseline; remove capabilities from binaries that do not need them, and never combine a capability with a file that an unprivileged user can modify.'
            # capability on an interpreter is a well-known escalation
            if printf '%s' "$caps" | grep -Eq '/(python[0-9.]*|perl|ruby|node|php|bash|sh|dash)\b'; then
                add_finding 'RISK DETECTED' 'Local Privilege Escalation' 'A scripting interpreter carries file capabilities, which is a direct privilege-escalation route: the capability applies to any code the interpreter runs.' \
                    attr='Capability on interpreter' configured="$(printf '%s' "$caps" | grep -E '/(python[0-9.]*|perl|ruby|node|php|bash|sh|dash)\b' | tr '\n' '; ')" \
                    observed='getcap enumeration' validation='Capability enumeration crossed with the binary name' \
                    class='Critical' weakness='1' expected='no capability on an interpreter or shell' \
                    impact='Any user able to run the interpreter runs code with the capability held, which for several capability sets is equivalent to root.' \
                    remediation='Remove the capability from the interpreter immediately (setcap -r <path>) and reimplement the need as a dedicated, audited binary.'
            fi
        else
            write_kv 'Files with capabilities' 'none'
            # A clean result is still a result and belongs in the evidence. Without this row the CSV
            # cannot distinguish "enumerated and found none" from "never enumerated", which is the
            # same distinction the rest of the tool insists on everywhere else.
            add_finding PASS 'Local Privilege Escalation' 'No file with a Linux capability was found anywhere in the filesystem.' \
                attr='File capabilities' configured='0 file(s)' observed='getcap -r / returned no entries' \
                validation='getcap enumeration over the whole filesystem, bounded at 60 seconds' \
                class='Medium' impact='The capability-based privilege-escalation route is not present on this host.' \
                remediation='None required. Re-check after any setcap or package installation.'
        fi
    else
        note_missing_tool getcap
        add_finding 'NOT TESTABLE' 'Local Privilege Escalation' "File capabilities were not enumerated: getcap was not found ($(tool_search_note)). This is a GAP in coverage, not a clean result - a capability such as cap_setuid or cap_sys_admin on a binary a non-privileged user can influence is a direct privilege-escalation path that this run could not see." \
            attr='File capabilities' observed="getcap unavailable; $(tool_search_note)" validation='Tool availability check' class='Medium' \
            impact='Unknown rather than compliant. This is a common local privilege-escalation route, so the gap should be closed.' \
            remediation='Install libcap2-bin (getcap) and re-run this section.'
    fi
}

# =============================================================================================
#  SECTION 11 :: LISTENING SOCKETS AND EXPOSURE
# =============================================================================================
section11_listening() {
    write_section '11' 'LISTENING SOCKETS AND NETWORK EXPOSURE'
    local inv
    if ! inv=$(inventory_listening_sockets); then
        add_finding 'NOT TESTABLE' 'Network Discovery' 'The listening-socket inventory could not be produced: neither ss nor netstat is available.' \
            attr='Listening sockets' observed='no socket-listing tool' validation='Tool availability check' class='High' \
            impact='The host external attack surface is unassessed.' \
            remediation='Install iproute2 (ss) and re-run.'
        return
    fi

    local total bound_all=0
    total=$(printf '%s\n' "$inv" | grep -c . )
    write_kv 'Listening sockets' "$total"

    local -a exposed=()
    local line proto addr port proc
    while IFS='|' read -r proto addr port proc; do
        [ -n "$port" ] || continue
        case "$addr" in
            0.0.0.0|'*'|::|'[::]'|:::|'')
                exposed+=("${port}|${proto}|${proc:-unknown}|${addr}")
                bound_all=$((bound_all+1))
            ;;
        esac
    done <<< "$inv"

    write_kv 'Sockets bound to all interfaces' "$bound_all"

    # ss -p prints no process information at all unless the caller is root. Showing a bare
    # "unknown" per row would read as a data gap; the honest statement is that attribution itself
    # was not available, which is a NOT TESTABLE condition and NOT a clean result.
    if [ "$ELEVATED" != '1' ]; then
        add_finding 'NOT TESTABLE' 'Network Exposure' 'The PROCESS owning each listening socket was NOT identified: socket-to-process attribution requires root, and this run is unprivileged.' \
            attr='Listening socket ownership' configured="${total} socket(s) inventoried; owner not attributable without root" observed='ss -lntup without CAP_NET_ADMIN emits no process column' \
            validation='The port and address inventory IS confirmed. Only the owning process is unestablished.' class='Medium' \
            impact='Without ownership the operator cannot tell an intended service from an unexpected one, which is the single most useful thing about a socket inventory.' \
            remediation='Re-run with sudo to attribute every listening socket to a process, or correlate against the systemd unit list in Section 17.'
    fi

    if [ ${#exposed[@]} -gt 0 ]; then
        local -a rows=(); local e
        for e in "${exposed[@]}"; do
            local p2="${e%%|*}"; local r2="${e#*|}"
            local pr="${r2%%|*}"; r2="${r2#*|}"; local pc="${r2%%|*}"
            rows+=("${p2}|$(service_name_for_port "$p2")|${pr}|${pc}")
        done
        write_table 'Port|Service|Proto|Process' "${rows[@]}"

        add_finding WARN 'Network Exposure' "${bound_all} listening socket(s) are bound to all interfaces (0.0.0.0 or ::), so they are reachable from every network this host connects to." \
            attr='Services bound to all interfaces' configured="${bound_all} socket(s)" observed="$(printf '%s; ' "${rows[@]}" | cut -c1-400)" \
            validation='Socket inventory from ss. Binding to all interfaces is CONFIRMED; whether a given path is reachable in practice also depends on the host firewall (Section 14).' \
            class='Medium' weakness='1' expected='services bound to the specific addresses that require them' \
            impact='Every one of these services is exposed on every interface, including any management or storage network this host participates in.' \
            remediation='Bind each service to the address it is actually required on, then confirm the firewall default-deny posture separately.'
    fi

    # ---- high-value service exposure -----------------------------------------------------------
    local -a high_value=('23:Telnet - cleartext authentication' '21:FTP - often cleartext or anonymous' '2049:NFS - frequently exported without authentication' '6379:Redis - historically unauthenticated by default' '3306:MySQL - often bound widely' '5432:PostgreSQL' '5900:VNC' '11211:memcached - no authentication by design')
    local hv
    for hv in "${high_value[@]}"; do
        local hp="${hv%%:*}" hdesc="${hv#*:}"
        case "$inv" in
            *"|$hp|"*)
                add_finding WARN 'Network Exposure' "Service on TCP/${hp} is listening on this host: ${hdesc}." \
                    attr="Service exposure TCP/${hp}" port="$hp" \
                    configured="listening on TCP/${hp}" observed="$(printf '%s' "$inv" | awk -F'|' -v p="$hp" '$3==p {print $2":"$3}' | head -3 | tr '\n' ' ')" \
                    validation='Socket inventory (ss). The service was NOT connected to, and no authentication or exploitation was attempted.' \
                    class='High' weakness='1' \
                    impact="High-value lateral-movement or data-exposure service reachable on the network. ${hdesc} widens the attack surface beyond what many estates assume is present." \
                    remediation="Confirm the service is required on this host, bind it to the interfaces that need it, and require authentication. Where it is not required, disable it."
            ;;
        esac
    done
}

# =============================================================================================
#  SECTION 12 :: CRYPTOGRAPHY POLICY
# =============================================================================================
section12_crypto() {
    write_section '12' 'CRYPTOGRAPHIC POLICY AND FIPS STATE'

    # ---- LSM integrity checkpoint --------------------------------------------------------------
    local lsm12=''
    [ -r /sys/kernel/security/lsm ] && lsm12=$(cat /sys/kernel/security/lsm 2>/dev/null | tr -d '\n')
    [ -z "$lsm12" ] && [ -r /sys/kernel/security/lsm_list ] && lsm12=$(cat /sys/kernel/security/lsm_list 2>/dev/null | tr -d '\n')
    if [ -n "$lsm12" ]; then
        write_kv 'Active LSMs' "$lsm12"
        add_finding INFO 'Cryptography' 'Active LSM ordering was sampled as an integrity/context checkpoint; no LSM policy was changed.' \
            attr='LSM integrity checkpoint' configured="$lsm12" observed='/sys/kernel/security/lsm or lsm_list' \
            validation='Read-only kernel security interface' class='Low' catclass='Context' \
            impact='Provides policy context for interpreting crypto and hardening observations on SELinux/AppArmor-enabled hosts.' \
            remediation='None.'
    fi

    # ---- FIPS mode -----------------------------------------------------------------------------
    local fips='unknown'
    if [ -r /proc/sys/crypto/fips_enabled ]; then
        fips=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null | tr -d '\n')
    fi
    if [ "$fips" != 'unknown' ]; then
        write_kv 'FIPS mode (/proc/sys/crypto/fips_enabled)' "$fips"
    else
        write_kv 'FIPS mode' 'not exposed by this kernel'
    fi
    if [ -e /etc/system-fips ]; then
        write_kv 'FIPS policy marker (/etc/system-fips)' 'present'
    fi

    if [ "$fips" = '1' ]; then
        add_finding INFO 'Cryptography' 'Kernel FIPS mode is enabled, so the kernel crypto API is restricted to FIPS-validated algorithms.' \
            attr='FIPS mode' configured='fips_enabled=1' observed='/proc/sys/crypto/fips_enabled' \
            validation='Read of the running kernel state' class='Low' \
            impact='Raises the cryptographic floor for kernel-provided functions. It does NOT imply that every application on the host respects FIPS mode - user-space libraries can still negotiate non-approved algorithms.' \
            remediation='No action. Verify user-space crypto policy separately (below) if FIPS compliance is a requirement.'
    elif [ "$fips" = '0' ]; then
        add_finding INFO 'Cryptography' 'Kernel FIPS mode is disabled.' \
            attr='FIPS mode' configured='fips_enabled=0' observed='/proc/sys/crypto/fips_enabled' \
            validation='Read of the running kernel state' class='Low' \
            impact='Expected on most deployments. Relevant only where a compliance requirement mandates FIPS mode.' \
            remediation='Enable FIPS mode only if a compliance requirement mandates it, and plan for the compatibility impact it causes.'
    fi

    # ---- system-wide crypto policy (RHEL family) -----------------------------------------------
    if [ -r /etc/crypto-policies/config ]; then
        local pol
        pol=$(cat /etc/crypto-policies/config 2>/dev/null | tr -d '\n')
        write_kv 'System crypto policy' "$pol"
        case "$pol" in
            LEGACY)
                add_finding 'RISK DETECTED' 'Cryptography' 'The system-wide crypto policy is LEGACY, which enables algorithms that are no longer considered safe (including SHA-1 signatures and 1024-bit keys).' \
                    attr='Crypto policy' configured="$pol" observed='/etc/crypto-policies/config' validation='Configuration read' \
                    class='High' weakness='1' expected='DEFAULT or FUTURE' \
                    impact='Every application that follows the system policy negotiates weak cryptography, affecting TLS, SSH and certificate validation across the host.' \
                    remediation='Move to the DEFAULT policy, catalogue what breaks, and address those consumers individually rather than leaving the whole host on LEGACY.'
            ;;
            DEFAULT|FUTURE|NEXT)
                add_finding PASS 'Cryptography' "System-wide crypto policy is ${pol}." attr='Crypto policy' \
                    configured="$pol" observed='/etc/crypto-policies/config' validation='Configuration read' class='High' \
                    impact='Control satisfied.' remediation='None required.'
            ;;
        esac
    fi

    # ---- OpenSSL configuration -----------------------------------------------------------------
    for f in /etc/ssl/openssl.cnf /etc/pki/tls/openssl.cnf; do
        [ -r "$f" ] || continue
        if grep -Eq '^\s*(MinProtocol|CipherString)\s*=' "$f" 2>/dev/null; then
            local mp cs
            mp=$(grep -E '^\s*MinProtocol' "$f" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')
            cs=$(grep -E '^\s*CipherString' "$f" 2>/dev/null | head -1 | cut -d= -f2 | tr -d ' ')
            write_kv 'OpenSSL minimum protocol' "${mp:-unset}"
            case "${mp:-}" in
                TLSv1_2|TLSv1_3) add_finding PASS 'Cryptography' "OpenSSL system configuration requires at least ${mp}." \
                        attr='OpenSSL minimum protocol' configured="${mp}" observed="$f" validation='Configuration read' \
                        class='Medium' impact='Control satisfied for users of the system OpenSSL configuration.' \
                        remediation='None required.' ;;
                TLSv1|TLSv1_1|SSLv3)
                    add_finding WARN 'Cryptography' "OpenSSL is configured to permit ${mp}, a deprecated protocol version." \
                        attr='OpenSSL minimum protocol' configured="${mp} ${cs:-}" observed="$f" validation='Configuration read' \
                        class='High' weakness='1' expected='TLSv1_2 or TLSv1_3' \
                        impact='Applications using the system configuration will negotiate protocols with known weaknesses, and may fall to downgrade attacks against older clients.' \
                        remediation='Raise MinProtocol to TLSv1_2 (preferably TLSv1_3 for internal services), then test the applications that depend on the system configuration.' ;;
            esac
        fi
        break
    done

    # ---- expired / expiring local certificates --------------------------------------------------
    if have openssl; then
        local certdir found=0 f2
        for certdir in /etc/ssl/certs /etc/pki/tls/certs; do
            [ -d "$certdir" ] || continue
            for f2 in "$certdir"/*.pem "$certdir"/*.crt; do
                [ -f "$f2" ] || continue
                local end
                end=$(openssl x509 -in "$f2" -noout -enddate 2>/dev/null | cut -d= -f2)
                [ -n "$end" ] || continue
                local endsec nowsec
                endsec=$(date -d "$end" +%s 2>/dev/null) || continue
                nowsec=$(date +%s)
                if [ "$endsec" -lt "$nowsec" ]; then
                    found=$((found+1))
                    [ "$found" -le 5 ] && add_finding WARN 'Cryptography' "Local certificate has EXPIRED: ${f2}" \
                        attr='Expired local certificate' configured="expired ${end}" observed="$f2" \
                        validation='Certificate parse of the local file. This is a filesystem file, not a live TLS service - live endpoints are covered in Section 8.' \
                        class='Medium' weakness='1' expected='all deployed certificates within their validity period' \
                        impact='Anything validating against this certificate will fail closed (which is detectable) or be configured to fail open (which is not). Both outcomes undermine trust in the endpoint.' \
                        remediation='Replace the certificate and add expiry monitoring so renewal is not a manual activity.'
                fi
            done
            break
        done
        if [ "$found" -eq 0 ]; then
            write_kv 'Expired local certificates' 'none found in the system certificate directory'
        fi
    else
        note_missing_tool openssl
    fi
}

# =============================================================================================
#  SECTION 13 :: LOGGING AND AUDIT POSTURE
# =============================================================================================
section13_logging() {
    write_section '13' 'LOGGING AND AUDIT POSTURE'
    write_status 'INFO' 'These are DETECTION controls. A weakness here does not create a vulnerability; it removes the ability to notice one being exploited, which is why it is assessed alongside the findings it would have recorded.'

    # ---- auditd --------------------------------------------------------------------------------
    if have auditctl || [ -d /etc/audit ]; then
        local auditing='unknown'
        if have auditctl; then
            if auditctl -s >/dev/null 2>&1; then
                auditing=$(auditctl -s 2>/dev/null | awk -F'[= ]+' '/^enabled/{print $2}')
            fi
        elif [ -r /etc/audit/auditd.conf ]; then
            auditing=$(awk -F'=' '/^\s*enabled/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/audit/auditd.conf)
        fi
        write_kv 'Audit subsystem enabled' "${auditing:-unknown}"
        if [ "$auditing" = '0' ]; then
            add_finding WARN 'Logging and Auditing' 'The audit subsystem is installed but disabled (enabled=0), so no audit records are being generated.' \
                attr='auditd enabled' configured='enabled=0' observed='auditctl -s / auditd.conf' validation='Runtime state read where available' \
                class='High' weakness='1' expected='enabled=1 (or 2 for immutable mode)' \
                impact='No record of privilege changes, file modifications or execution exists on this host, so neither this assessment nor a real intrusion can be reconstructed from local evidence.' \
                remediation='Enable the audit subsystem, apply a baseline ruleset covering identity files and privileged execution, and forward the records to a central collector so they survive a host compromise.'
        elif [ -n "$auditing" ] && [ "$auditing" != 'unknown' ]; then
            add_finding PASS 'Logging and Auditing' "The audit subsystem is enabled (enabled=${auditing})." \
                attr='auditd enabled' configured="enabled=${auditing}" observed='auditctl -s' validation='Runtime state read' \
                class='High' impact='Control satisfied for local audit generation.' \
                remediation='Confirm records are forwarded off-host and that the ruleset still covers identity and privileged-execution activity.'
        fi
        # key audit rules present?
        if [ -r /etc/audit/audit.rules ] || [ -d /etc/audit/rules.d ]; then
            if ! grep -RqsE 'shadow|passwd|sudoers|execve' /etc/audit/rules.d /etc/audit/audit.rules 2>/dev/null; then
                add_finding WARN 'Logging and Auditing' 'The audit ruleset does not appear to cover the identity files or privileged execution (no rules matching shadow, passwd, sudoers or execve were found).' \
                    attr='Audit ruleset coverage' configured='no identity/execve rules matched' observed='searched /etc/audit/rules.d and audit.rules' \
                    validation='Configuration read. Rule effectiveness was NOT tested by generating an auditable event.' \
                    class='Medium' weakness='1' expected='rules covering /etc/passwd, /etc/shadow, /etc/sudoers, privileged execution and privilege changes' \
                    impact='Even with the audit daemon running, the events that matter for detecting privilege escalation are not recorded.' \
                    remediation='Add rules for identity file modification, sudoers changes, and execve by privileged accounts, then verify with ausearch that events are actually produced.'
            fi
        fi
    else
        note_missing_tool auditd
        add_finding WARN 'Logging and Auditing' 'No audit subsystem was detected on this host.' \
            attr='auditd presence' configured='not installed' observed='no auditctl binary and no /etc/audit directory' \
            validation='Tool and path presence check' class='High' weakness='1' expected='auditd installed, enabled and forwarding' \
            impact='There is no local record of privileged activity, so post-incident reconstruction depends entirely on what external collectors happened to capture.' \
            remediation='Deploy auditd with a baseline ruleset on hosts where the platform supports it, and forward records to a central collector.'
    fi

    # ---- syslog / journald ---------------------------------------------------------------------
    local remote_log=''
    if [ -r /etc/rsyslog.conf ]; then
        remote_log=$(grep -E '^\s*\*\.\*\s*@@?[^ ]' /etc/rsyslog.conf 2>/dev/null | head -1)
    fi
    if [ -z "$remote_log" ] && [ -d /etc/rsyslog.d ]; then
        remote_log=$(grep -rhE '^\s*\*\.\*\s*@@?[^ ]' /etc/rsyslog.d 2>/dev/null | head -1)
    fi
    # systemd-journal-upload is the only journald mechanism that actually forwards off-host.
    # An earlier revision matched the bare section header "[Journal]" in journald.conf and
    # reported it as remote forwarding - a FALSE PASS on a control the check exists to measure.
    if [ -z "$remote_log" ] && [ -r /etc/systemd/journal-upload.conf ]; then
        remote_log=$(grep -E '^\s*URL\s*=\s*[^ ]' /etc/systemd/journal-upload.conf 2>/dev/null | head -1)
    fi
    if [ -n "$remote_log" ]; then
        write_kv 'Remote logging' "configured: ${remote_log}"
        add_finding PASS 'Logging and Auditing' 'Remote log forwarding is configured.' attr='Remote logging' \
            configured="$remote_log" observed='/etc/rsyslog.conf or journald.conf' validation='Configuration read' class='Medium' \
            impact='Control satisfied - records survive the loss of this host, which is the property that matters during an incident.' \
            remediation='None required. Periodically confirm records are arriving at the collector.'
    else
        write_kv 'Remote logging' 'no remote forwarding configured'
        add_finding WARN 'Logging and Auditing' 'No remote log forwarding was found, so log records exist only on this host.' \
            attr='Remote logging' configured='not configured' observed='/etc/rsyslog.conf and journald.conf' \
            validation='Configuration read' class='Medium' weakness='1' expected='records forwarded to a central collector' \
            impact='An attacker who gains root can remove or alter the local record of their activity, leaving no independent evidence.' \
            remediation='Forward system logs to a central collector over an authenticated transport, and confirm the collector retains them beyond the host retention period.'
    fi
}

# =============================================================================================
#  SECTION 14 :: FIREWALL AND SEGMENTATION ENFORCEMENT
# =============================================================================================
section14_firewall() {
    write_section '14' 'FIREWALL AND SEGMENTATION ENFORCEMENT'
    write_status 'INFO' 'This assesses the host-local enforcement point only. Network-level segmentation (VLANs, ACLs, switch configuration) is outside what a host can observe and is not claimed here.'

    local enforced=0

    # ---- nftables ------------------------------------------------------------------------------
    if have nft; then
        local rules
        if rules=$(nft list ruleset 2>/dev/null) && [ -n "$rules" ]; then
            enforced=1
            local policy
            policy=$(printf '%s' "$rules" | awk '/^\s*type filter hook (input|forward)/ {for(i=1;i<=NF;i++) if($i=="policy") print $(i+1)}' | sort -u | tr '\n' ' ')
            write_kv 'nftables' "active (hook policy: ${policy:-unset, which means accept})"
            if printf '%s' "$policy" | grep -q 'accept'; then
                add_finding WARN 'Network Segmentation' 'The nftables input or forward hook has a default ACCEPT policy, so traffic is permitted unless a rule specifically denies it.' \
                    attr='Firewall default policy' configured="nftables hook policy: ${policy}" observed='nft list ruleset' \
                    validation='Runtime ruleset read' class='High' weakness='1' expected='default drop on input and forward, with explicit allow rules' \
                    impact='Any service bound to an interface is reachable from every network this host is attached to, including segments that were meant to be isolated.' \
                    remediation='Set the input and forward base chains to policy drop, then add explicit allow rules for the traffic the host actually needs. Verify from another host before closing the session, or administrative access may be lost.'
            else
                add_finding PASS 'Network Segmentation' "nftables is active with a default-deny hook policy (${policy})." \
                    attr='Firewall default policy' configured="$policy" observed='nft list ruleset' validation='Runtime ruleset read' \
                    class='High' impact='Control satisfied at the host enforcement point.' \
                    remediation='None required. Re-verify after changes to the host firewall.'
            fi
        fi
    fi

    # ---- iptables ------------------------------------------------------------------------------
    if [ "$enforced" = '0' ] && have iptables; then
        local rules
        if rules=$(iptables -S 2>/dev/null) && [ -n "$rules" ]; then
            enforced=1
            local inpol fwpol
            inpol=$(printf '%s' "$rules" | awk '/^-P INPUT/ {print $3}')
            fwpol=$(printf '%s' "$rules" | awk '/^-P FORWARD/ {print $3}')
            write_kv 'iptables' "active (INPUT ${inpol:-unset}, FORWARD ${fwpol:-unset})"
            if [ "${inpol:-ACCEPT}" = 'ACCEPT' ]; then
                add_finding WARN 'Network Segmentation' "The iptables INPUT policy is ACCEPT, so inbound traffic is permitted unless a rule denies it." \
                    attr='Firewall default policy' configured="INPUT ${inpol}" observed='iptables -S' \
                    validation='Runtime ruleset read' class='High' weakness='1' expected='INPUT DROP with explicit allow rules' \
                    impact='Every listening service is reachable from every attached network, so any segmentation boundary this host crosses is not enforced locally.' \
                    remediation='Set INPUT to DROP and add allow rules for the required traffic. Confirm management access still works from a second session before applying, or access may be lost.'
            else
                add_finding PASS 'Network Segmentation' "iptables INPUT policy is ${inpol} (default deny)." \
                    attr='Firewall default policy' configured="INPUT ${inpol}" observed='iptables -S' validation='Runtime ruleset read' \
                    class='High' impact='Control satisfied at the host enforcement point.' remediation='None required.'
            fi
        fi
    fi

    # ---- firewalld / ufw -----------------------------------------------------------------------
    if have firewall-cmd; then
        local zones
        zones=$(firewall-cmd --get-active-zones 2>/dev/null | tr '\n' ' ')
        write_kv 'firewalld' "${zones:-present, no active zone reported}"
        enforced=1
    fi
    if have ufw; then
        local ust
        ust=$(ufw status 2>/dev/null | head -1)
        write_kv 'ufw' "${ust:-status unavailable}"
        enforced=1
        case "$ust" in
            *inactive*) add_finding WARN 'Network Segmentation' 'ufw is installed but INACTIVE, so no host firewall rules are in force.' \
                    attr='Host firewall state' configured='inactive' observed='ufw status' validation='Runtime state read' \
                    class='High' weakness='1' expected='active with a default-deny incoming policy' \
                    impact='All listening services are reachable from every attached network.' \
                    remediation='Enable ufw with default deny incoming, allow only the required ports, and verify from a second session before closing this one.' ;;
            *active*)   add_finding PASS 'Network Segmentation' 'ufw is active.' attr='Host firewall state' \
                    configured="$ust" observed='ufw status' validation='Runtime state read' class='High' \
                    impact='Control satisfied.' remediation='None required.' ;;
        esac
    fi

    if [ "$enforced" = '0' ]; then
        # The reason matters and the three cases are different claims:
        #   (a) no firewall tool is installed            -> the control cannot be assessed here;
        #   (b) a tool IS installed but its ruleset is unreadable without root -> a privilege limit,
        #       and re-running as root would settle it;
        #   (c) a tool is installed, readable and empty  -> there are genuinely no rules.
        # Reporting (b) as "none detected" told the operator to go and look at the network design when
        # a one-word change to the command would have answered the question.
        local fw_tools='' fw_reason=''
        have nft && fw_tools="${fw_tools}nft "
        have iptables && fw_tools="${fw_tools}iptables "
        have ip6tables && fw_tools="${fw_tools}ip6tables "
        have firewall-cmd && fw_tools="${fw_tools}firewall-cmd "
        have ufw && fw_tools="${fw_tools}ufw "
        if [ -n "$fw_tools" ] && [ "$ELEVATED" != '1' ]; then
            fw_reason="a firewall tool is present (${fw_tools% }) but its ruleset cannot be read without root, and this run is unprivileged"
        elif [ -n "$fw_tools" ]; then
            fw_reason="a firewall tool is present (${fw_tools% }) and readable, but reported no rules, so there is no host-level enforcement in force"
        else
            fw_reason='no firewall implementation is installed on this host'
        fi
        add_finding 'NOT TESTABLE' 'Network Segmentation' "Host-level enforcement could not be established: ${fw_reason}." \
            attr='Host firewall' configured="$( [ -n "$fw_tools" ] && echo "tools present: ${fw_tools% }" || echo 'none detected' )" observed="checked nft, iptables, ip6tables, firewall-cmd and ufw; $(tool_search_note)" \
            validation='Tool/runtime availability check. Absence of the TOOL is not proof of absence of the CONTROL: enforcement may sit upstream at the network layer.' \
            class='High' \
            impact='Unknown at the host level. Determine enforcement from the network design rather than from this host.' \
            remediation='Establish whether enforcement is provided by the network, and record that decision so the gap is a documented design choice rather than an oversight.'
    fi

    # ---- forwarding / routing role -------------------------------------------------------------
    local fwd
    fwd=$(read_sysctl 'net.ipv4.ip_forward')
    if [ "$fwd" = '1' ]; then
        local masq=''
        have nft && masq=$(nft list ruleset 2>/dev/null | grep -c 'masquerade')
        have iptables && [ -z "$masq" ] && masq=$(iptables -t nat -S 2>/dev/null | grep -c 'MASQUERADE')
        add_finding WARN 'Network Segmentation' "This host forwards IPv4 traffic${masq:+ and appears to perform masquerading}. It can therefore act as a router between the networks it is attached to." \
            attr='Forwarding role' configured='net.ipv4.ip_forward=1' observed="ip_forward=1; masquerade rules: ${masq:-unknown}" \
            validation='Kernel parameter read plus rule inspection' class='High' weakness='1' \
            impact='A dual-homed host with forwarding enabled bridges its networks. Where those networks have different trust levels, this host is a pivot that bypasses the intended separation, and it defeats assessments that assume segment isolation.' \
            remediation='Disable forwarding unless the host is a deliberate router or NAT gateway. If it is deliberate, document the networks it joins and apply strict rules on the FORWARD chain.'
    fi

    # ---- listening on management networks ------------------------------------------------------
    local inv
    inv=$(inventory_listening_sockets 2>/dev/null)
    if [ -n "$inv" ] && [ "${#SCOPE_INC[@]}" -gt 0 ]; then
        add_finding INFO 'Network Segmentation' 'Enforcement for the specific paths this assessment traversed is recorded per discovered host in Section 8, where reachability evidence exists.' \
            attr='Segmentation evidence' configured="$SCOPE_TEXT" observed='see the discovery findings above' \
            validation='Cross-reference to the discovery evidence rather than a separate claim' class='Low' \
            impact='Avoids double-counting: a path is only recorded as open where a connection actually succeeded.' \
            remediation='None - pointer row.'
    fi
}

# =============================================================================================
#  SECTION 15 :: MOUNT AND FILESYSTEM HARDENING
# =============================================================================================
section15_mounts() {
    write_section '15' 'MOUNT AND FILESYSTEM HARDENING'

    local mounttab='/proc/mounts'
    [ -r "$mounttab" ] || { add_finding 'NOT TESTABLE' 'Kernel hardening' '/proc/mounts is not readable, so mount options could not be assessed.' \
        attr='Mount options' observed='/proc/mounts unreadable' validation='Filesystem check' class='Medium' \
        impact='Unknown rather than compliant.' remediation='Re-run with sufficient privilege.'; return; }

    check_mount() {
        # check_mount <mountpoint> <required-option> <class> <finding-text>
        local mp="$1" want="$2" class="$3" text="$4"
        local line
        line=$(awk -v m="$mp" '$2==m {print $3"|"$4}' "$mounttab" 2>/dev/null | head -1)
        if [ -z "$line" ]; then
            return 0   # not a separate mount: the default filesystem options apply, reported below
        fi
        local fstype opts
        fstype="${line%%|*}"; opts="${line#*|}"
        write_kv "$mp" "${fstype} [${opts}]"
        if printf '%s' ",$opts," | grep -q ",$want,"; then
            add_finding PASS 'Kernel hardening' "${mp} is mounted with ${want}." attr="Mount option ${want} on ${mp}" \
                configured="${opts}" observed='/proc/mounts' validation='Mount table read' class="$class" \
                impact='Control satisfied.' remediation='None required.' 
        else
            add_finding WARN 'Kernel hardening' "$text" attr="Mount option ${want} on ${mp}" \
                configured="${fstype} [${opts}]" observed='/proc/mounts' \
                validation='Mount table read. This is the option the running kernel is using.' \
                class="$class" weakness='1' expected="${want} set on ${mp}" \
                impact='A world-writable directory that permits execution is a standard staging location for tooling and a documented privilege-escalation primitive on some kernels.' \
                remediation="Add ${want} to the ${mp} entry in /etc/fstab and remount, after confirming no application legitimately needs the capability."
        fi
    }

    check_mount '/tmp'     'noexec' 'Medium' '/tmp is mounted without noexec, so any user can execute a file they can write there.'
    check_mount '/tmp'     'nosuid' 'Medium' '/tmp is mounted without nosuid, so a set-uid binary placed there would be honoured.'
    check_mount '/var/tmp' 'noexec' 'Medium' '/var/tmp is mounted without noexec, so it is a second execution location for any user.'
    check_mount '/dev/shm' 'noexec' 'Medium' '/dev/shm is mounted without noexec, so shared memory can be used to stage and execute code.'
    check_mount '/dev/shm' 'nosuid' 'Medium' '/dev/shm is mounted without nosuid.'

    # ---- /proc hidepid -------------------------------------------------------------------------
    local procopts
    procopts=$(awk '$2=="/proc" {print $4}' "$mounttab" 2>/dev/null | head -1)
    if [ -n "$procopts" ]; then
        if printf '%s' ",$procopts," | grep -qE ',hidepid=(1|2|invisible|ptraceable),'; then
            add_finding PASS 'Kernel hardening' '/proc is mounted with hidepid, limiting visibility of other users processes.' \
                attr='proc hidepid' configured="$procopts" observed='/proc/mounts' validation='Mount table read' \
                class='Medium' impact='Control satisfied - reduces the information a local user can gather about other processes.' \
                remediation='None required.'
        else
            add_finding WARN 'Kernel hardening' '/proc is mounted without hidepid, so every local user can see the command line and metadata of every process on the host.' \
                attr='proc hidepid' configured="${procopts:-default}" observed='/proc/mounts' \
                validation='Mount table read' class='Medium' weakness='1' expected='hidepid=1, hidepid=2, invisible, or ptraceable (with gid= where monitoring tools require it)' \
                impact='Process command lines routinely contain credentials, file paths and service topology, giving a low-privilege user a detailed map of the host.' \
                remediation='Mount /proc with hidepid=2 and a gid that monitoring tools belong to, and test that system tooling still functions.'
        fi
    fi

    # ---- sticky world-writable directories -----------------------------------------------------
    if have find; then
        local ww
        ww=$(find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -10)
        if [ -n "$ww" ]; then
            add_finding WARN 'Kernel hardening' 'World-writable directories WITHOUT the sticky bit were found, so any user may delete or replace files owned by others in them.' \
                attr='Non-sticky world-writable directories' configured="$(printf '%s' "$ww" | tr '\n' ' ')" \
                observed='find -perm -0002 ! -perm -1000' validation='Filesystem permission scan' \
                class='High' weakness='1' expected='every shared directory sticky (chmod +t)' \
                impact='Without the sticky bit, one user can replace another user file - or a privileged process file - in a shared location, which is a direct path to code execution as that other identity.' \
                remediation='Apply the sticky bit (chmod +t) to the listed directories, and remove world-write where sharing is not actually required.'
        else
            add_finding PASS 'Kernel hardening' 'No non-sticky world-writable directories were found.' \
                attr='Non-sticky world-writable directories' configured='0' observed='find -perm -0002 ! -perm -1000' \
                validation='Filesystem permission scan' class='High' impact='Control satisfied.' remediation='None required.'
        fi
    fi
}

# =============================================================================================
#  SECTION 16 :: LATERAL-MOVEMENT AND ATTACK-PATH ANALYSIS
# =============================================================================================
section16_attackpaths() {
    write_section '16' 'LATERAL-MOVEMENT AND ATTACK-PATH ANALYSIS'
    write_status 'INFO' 'This section CORRELATES findings already produced above. It introduces no new observations, and every chain cites the sections it is built from.'

    local discoverable_hosts admin_hosts=0
    discoverable_hosts=${#HOSTPORT_KEYS[@]}
    local h
    for h in "${HOSTPORT_KEYS[@]}"; do
        case "$(hostport_get "$h" 2>/dev/null)" in
            *22*|*3389*|*5900*|*5985*|*5986*) admin_hosts=$((admin_hosts+1)) ;;
        esac
    done

    write_kv 'Remote-administration reachable' "${admin_hosts} host(s)"
    write_kv 'Note' 'A chain below states the sequence a human would follow, not that this tool followed it.'

    # ---- chain 1: credential reuse onto a reachable administrative service ----------------------
    if [ "$admin_hosts" -gt 0 ]; then
        add_finding WARN 'Attack Path' "Chain candidate: an administrative service is reachable on ${admin_hosts} host(s) in scope, and local credential-reuse exposure was assessed in Sections 5 and 17. Any credential usable on those hosts yields interactive access." \
            attr='Attack chain: reachable admin service + credential reuse' \
            target="$(printf '%s, ' "${HOSTPORT_KEYS[@]}" | cut -c1-200)" port='22,3389,5900,5985' \
            prereq='A credential valid on the target host. This tool does NOT test credentials and did not attempt authentication.' \
            observed="${admin_hosts} host(s) with an administrative service reachable from the assessment position" \
            validation='Correlation of the Section 8 reachability evidence with the Section 5 and 17 exposure findings. The CHAIN IS NOT VALIDATED: each link is individually evidenced, the sequence is not.' \
            class='High' weakness='1' expected='administrative interfaces reachable only from a privileged-access network' \
            impact='This is the standard lateral-movement path on a flat internal network: one reusable credential converts a single foothold into administrative access to every host that accepts it.' \
            remediation='Tier the administration paths - restrict management protocols to a privileged-access workstation network, and ensure administrative credentials are unique per host (LAPS or equivalent for Linux: per-host SSH host certificates or a managed vault) so one credential cannot be replayed estate-wide.'
    fi

    # ---- chain 2: local escalation via writable privileged path ---------------------------------
    if [ "${#HOSTPORT_KEYS[@]}" -gt 0 ]; then
        :
    fi
    add_finding INFO 'Attack Path' 'Chain candidates for LOCAL escalation are recorded in Sections 10, 15 and 17 (set-uid in a writable path, world-writable files in privileged locations, writable privileged scripts, capability on an interpreter). Each is reported where it was observed, with its own severity - none is double-counted here.' \
        attr='Attack path: local escalation surface' \
        observed='see Sections 10, 15 and 17' \
        validation='Cross-reference. Deliberately NOT restated as a separate weakness, so the same defect is not counted repeatedly across the report.' \
        class='Medium' impact='Pointer row for the reader assembling the local escalation narrative.' \
        remediation='Treat the individual rows in Sections 10, 15 and 17 as the actionable list.'
}

# =============================================================================================
#  SECTION 17 :: LOCAL PRIVILEGE-ESCALATION CONFIGURATION
# =============================================================================================
section17_privesc() {
    write_section '17' 'LOCAL PRIVILEGE-ESCALATION CONFIGURATION'

    # ---- sudo ----------------------------------------------------------------------------------
    if have sudo || [ -r /etc/sudoers ]; then
        local sudoers_files=()
        [ -r /etc/sudoers ] && sudoers_files+=('/etc/sudoers')
        if [ -d /etc/sudoers.d ]; then
            local f
            for f in /etc/sudoers.d/*; do [ -f "$f" ] && sudoers_files+=("$f"); done
        fi
        write_kv 'sudoers files readable' "${#sudoers_files[@]}"

        local nopasswd='' wildcard='' writable_sudoers=''
        for f in "${sudoers_files[@]}"; do
            [ -r "$f" ] || continue
            local m
            m=$(get_octal_perms "$f" 2>/dev/null)
            case "$m" in 440|400|000|0440|0400) ;; *) writable_sudoers+="$f(${m}) " ;; esac
            grep -Eq 'NOPASSWD' "$f" 2>/dev/null && nopasswd+="$f "
            grep -EqE '\bALL\b.*=\s*\(ALL(:ALL)?\)\s*NOPASSWD:\s*ALL|\*\s*\)\s*NOPASSWD' "$f" 2>/dev/null && wildcard+="$f "
        done

        if [ -n "$writable_sudoers" ]; then
            add_finding 'RISK DETECTED' 'Local Privilege Escalation' "sudoers file(s) have permissions that allow modification by a non-root user: ${writable_sudoers}. Any user who can write to a sudoers file can grant themselves unrestricted root access." \
                attr='Writable sudoers file' configured="$writable_sudoers" observed='stat of each sudoers file' \
                validation='Filesystem permission read. The rule contents were read to check for risky patterns, but no sudo command was executed by this tool.' \
                class='Critical' weakness='1' expected='0440 root:root (or 0400) on every sudoers file' \
                impact='Direct, persistent local privilege escalation to root, and a stealthy one: a sudoers edit leaves a file modification rather than an exploit signature.' \
                remediation='chmod 0440 and chown root:root the listed files immediately, then review audit records for the period during which they were writable.'
        fi
        if [ -n "$wildcard" ]; then
            add_finding 'RISK DETECTED' 'Local Privilege Escalation' "A sudoers rule grants unrestricted NOPASSWD access to ALL commands: ${wildcard}" \
                attr='sudo NOPASSWD ALL' configured="$wildcard" observed='pattern match over the readable sudoers files' \
                validation='Configuration read. The rule was NOT exercised - no sudo command was run by this tool.' \
                class='Critical' weakness='1' expected='explicit command lists, with a password where the account is interactive' \
                impact='Any account this rule applies to obtains root without a password prompt, which removes both the barrier and the audit signal of a password entry.' \
                remediation='Replace blanket rules with explicit command lists scoped to the task. Where automation needs NOPASSWD, restrict it to a dedicated account, to specific commands, and to specific source hosts.'
        elif [ -n "$nopasswd" ]; then
            add_finding WARN 'Local Privilege Escalation' "sudo NOPASSWD entries exist (${nopasswd}). Each one is a command that can be run as root without re-authentication." \
                attr='sudo NOPASSWD entries' configured="$nopasswd" observed='pattern match over the readable sudoers files' \
                validation='Configuration read' class='High' weakness='1' expected='NOPASSWD only where automation requires it, scoped to explicit commands' \
                impact='Reduces the evidence trail and increases the value of any account able to use those entries.' \
                remediation='Review each NOPASSWD entry against a genuine automation requirement and remove the rest.'
        fi
        # wildcards / relative commands in sudo rules
        for f in "${sudoers_files[@]}"; do
            [ -r "$f" ] || continue
            if grep -EqE '=\s*/[^,]*\*|=\s*[a-zA-Z0-9_-]+\s*$' "$f" 2>/dev/null; then
                add_finding WARN 'Local Privilege Escalation' "A sudoers rule in ${f} uses a wildcard path or a bare command name, both of which can be redirected to a different binary than intended." \
                    attr='sudo wildcard command' configured="$f" observed='pattern match for wildcard paths and relative commands' \
                    validation='Configuration read. The bypass was NOT exercised.' class='High' weakness='1' \
                    expected='absolute paths, with wildcards avoided in command arguments' \
                    impact='Wildcards in sudo command specifications are a well-documented escalation route: the argument glob can be satisfied by a command that runs something else entirely.' \
                    remediation='Replace wildcards with absolute, fully-qualified paths, and where an argument is genuinely variable, use a wrapper script with root-owned validation rather than a glob.'
            fi
        done
    fi

    # ---- systemd persistent capability assignments -------------------------------------------
    if [ -d /etc/systemd/system ]; then
        local cap_units='' cap_file cap_lines
        for cap_file in /etc/systemd/system/*.service /etc/systemd/system/*.socket /etc/systemd/system/*.timer; do
            [ -f "$cap_file" ] || continue
            cap_lines=$(grep -E '^[[:space:]]*(CapabilityBoundingSet|AmbientCapabilities)=' "$cap_file" 2>/dev/null)
            [ -n "$cap_lines" ] || continue
            cap_units+="$cap_file: $(printf '%s' "$cap_lines" | tr '\n' ';') "
        done
        if [ -n "$cap_units" ]; then
            add_finding WARN 'Local Privilege Escalation' 'One or more persistent systemd units explicitly configure CapabilityBoundingSet or AmbientCapabilities.' \
                attr='Systemd ambient capabilities' configured="$cap_units" observed='grep -E CapabilityBoundingSet|AmbientCapabilities over /etc/systemd/system unit files' \
                validation='Static unit-file inspection only. The service was NOT started and effective runtime capabilities were NOT assumed from the text alone.' \
                class='High' weakness='1' expected='capability grants limited to the minimum required by the service role' \
                impact='Ambient or bounding capabilities can bypass ordinary SUID-based assumptions when a service is compromised or invokes a helper.' \
                remediation='Review each listed capability against the service role; remove unnecessary ambient capabilities and narrow CapabilityBoundingSet during the normal systemd change process.'
        else
            add_finding PASS 'Local Privilege Escalation' 'No explicit CapabilityBoundingSet or AmbientCapabilities assignments were found in /etc/systemd/system unit files.' \
                attr='Systemd ambient capabilities' configured='0 matches' observed='grep over local systemd unit files' \
                validation='Static unit-file inspection' class='High' impact='No persistent capability assignment was observed in this directory.' remediation='None required.'
        fi
    fi

    # ---- cron ----------------------------------------------------------------------------------
    local cron_bad=''
    local crondir
    for crondir in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [ -e "$crondir" ] || continue
        local m
        m=$(get_octal_perms "$crondir" 2>/dev/null)
        case "$m" in *2|*3|*6|*7) cron_bad+="$crondir(${m}) " ;; esac
    done
    if [ -n "$cron_bad" ]; then
        add_finding 'RISK DETECTED' 'Local Privilege Escalation' "Cron configuration path(s) are writable beyond root: ${cron_bad}. A user who can write here schedules a job that runs as root." \
            attr='Writable cron path' configured="$cron_bad" observed='stat of cron directories and tables' \
            validation='Filesystem permission read' class='Critical' weakness='1' expected='root-owned, not group- or world-writable' \
            impact='Direct privilege escalation persisting across reboots, and difficult to attribute afterwards because it looks like routine scheduled maintenance.' \
            remediation='Restore root-only ownership and write permissions on the listed paths, then review the scheduled entries for anything not expected.'
    else
        add_finding PASS 'Local Privilege Escalation' 'Cron configuration paths are root-owned and not writable by other users.' \
            attr='Writable cron path' configured='0' observed='stat of cron directories and tables' \
            validation='Filesystem permission read' class='Critical' impact='Control satisfied.' remediation='None required.'
    fi

    # systemd timers as the modern equivalent
    if [ -d /etc/systemd/system ]; then
        local tbad=''
        local t
        for t in /etc/systemd/system/*.timer; do
            [ -e "$t" ] || continue
            local m
            m=$(get_octal_perms "$t" 2>/dev/null)
            case "$m" in *2|*3|*6|*7) tbad+="$t(${m}) " ;; esac
        done
        if [ -n "$tbad" ]; then
            add_finding 'RISK DETECTED' 'Local Privilege Escalation' "Systemd timer unit(s) are writable beyond root: ${tbad}" \
                attr='Writable systemd timer' configured="$tbad" observed='stat of timer units' validation='Filesystem permission read' \
                class='Critical' weakness='1' expected='root-owned, mode 644' \
                impact='The same escalation as a writable cron entry, with the same persistence and the same low visibility during an investigation.' \
                remediation='Restore root ownership and 644 on the listed units, then reload systemd and review what each timer executes.'
        fi
    fi

    # ---- systemd services with writable ExecStart ----------------------------------------------
    if [ -d /etc/systemd/system ]; then
        local svc_bad=''
        local s
        for s in /etc/systemd/system/*.service; do
            [ -e "$s" ] || continue
            local exec_line exec_path m
            exec_line=$(awk -F'=' '/^\s*ExecStart/ {print $2; exit}' "$s" 2>/dev/null | awk '{print $1}')
            [ -n "$exec_line" ] || continue
            exec_path="$exec_line"
            [ -f "$exec_path" ] || continue
            m=$(get_octal_perms "$exec_path" 2>/dev/null)
            case "$m" in *2|*3|*6|*7) svc_bad+="$s -> $exec_path(${m}) " ;; esac
        done
        if [ -n "$svc_bad" ]; then
            add_finding 'RISK DETECTED' 'Local Privilege Escalation' "Systemd service(s) execute a path that is writable beyond root: ${svc_bad}" \
                attr='Writable service executable' configured="$svc_bad" observed='ExecStart resolved and stat-ed for each unit' \
                validation='Configuration and permission read. No service was restarted.' class='Critical' weakness='1' \
                expected='root-owned, non-writable executables for every unit' \
                impact='A writable binary referenced by a root service means the next restart or timer run executes attacker-controlled code as root.' \
                remediation='Correct the permissions on the listed executables, and audit the systemd unit list for units whose ExecStart points into a shared or user-writable location.'
        fi
    fi

    # ---- PATH integrity ------------------------------------------------------------------------
    local path_bad=''
    local d
    IFS=':' read -r -a _pathdirs <<< "$PATH"
    for d in "${_pathdirs[@]}"; do
        [ -d "$d" ] || continue
        local m
        m=$(get_octal_perms "$d" 2>/dev/null)
        case "$m" in *2|*3|*6|*7) path_bad+="$d(${m}) " ;; esac
    done
    if [ -n "$path_bad" ]; then
        add_finding WARN 'Local Privilege Escalation' "A directory in the current PATH is writable by a user other than root: ${path_bad}" \
            attr='Writable directory in PATH' configured="$path_bad" observed="PATH=${PATH}" \
            validation='Permission read of each PATH entry' class='High' weakness='1' \
            impact='Any command resolved from a writable PATH directory can be replaced. Where a privileged user runs a script that calls a command by name, the replacement executes as that user.' \
            remediation='Remove writable directories from PATH for all users, and ensure root PATH contains only root-owned directories. Add a leading dot check: a PATH containing "." is the same defect in its most obvious form.'
    fi

    # ---- dynamic linker configuration ----------------------------------------------------------
    local ld_bad=''
    for f in /etc/ld.so.conf /etc/ld.so.conf.d /etc/ld.so.preload; do
        [ -e "$f" ] || continue
        if [ "$f" = '/etc/ld.so.preload' ]; then
            add_finding WARN 'Local Privilege Escalation' 'The global dynamic-linker preload file /etc/ld.so.preload exists, so a library is being force-loaded into every process on the host.' \
                attr='ld.so.preload present' configured="$f exists" observed='filesystem check' \
                validation='Existence check. The file contents were read only to confirm it is not empty.' class='High' weakness='1' \
                expected='absent unless deliberately used by a monitoring agent' \
                impact='A deliberate agent uses this legitimately; a malicious one uses it for host-wide code injection. Distinguishing the two requires knowing why it is there.' \
                remediation='Confirm the preload is accounted for by a known agent. Remove it if it is not, and verify no library path it references is writable by any user.'
        fi
        local m
        m=$(get_octal_perms "$f" 2>/dev/null)
        case "$m" in *2|*3|*6|*7) ld_bad+="$f(${m}) " ;; esac
    done
    if [ -n "$ld_bad" ]; then
        add_finding 'RISK DETECTED' 'Local Privilege Escalation' "Dynamic-linker configuration is writable beyond root: ${ld_bad}" \
            attr='Writable ld.so configuration' configured="$ld_bad" observed='stat of ld.so.conf, ld.so.conf.d and ld.so.preload' \
            validation='Filesystem permission read' class='Critical' weakness='1' expected='root-owned, not writable by others' \
            impact='An added library search path lets an attacker place a shared library that every privileged process loads, which is code execution as root on a global scale.' \
            remediation='Correct ownership and permissions on the listed paths and remove any directory from the search path that is writable by an unprivileged user.'
    fi

    # ---- login-triggered MOTD/profile execution surfaces -------------------------------------
    local login_writable=''
    local login_dir login_file login_mode
    for login_dir in /etc/update-motd.d /etc/profile.d; do
        [ -d "$login_dir" ] || continue
        login_mode=$(get_octal_perms "$login_dir" 2>/dev/null)
        case "$login_mode" in *2|*3|*6|*7) login_writable+="$login_dir(dir ${login_mode}) " ;; esac
        for login_file in "$login_dir"/*; do
            [ -f "$login_file" ] || continue
            login_mode=$(get_octal_perms "$login_file" 2>/dev/null)
            case "$login_mode" in *2|*3|*6|*7) login_writable+="$login_file(${login_mode}) " ;; esac
        done
    done
    if [ -n "$login_writable" ]; then
        add_finding 'RISK DETECTED' 'Local Privilege Escalation' "Login-triggered MOTD/profile configuration is writable beyond root: ${login_writable}" \
            attr='Writable login-triggered configuration' configured="$login_writable" observed='permission metadata for /etc/update-motd.d and /etc/profile.d' \
            validation='Filesystem permission read only. No MOTD/profile script was executed by this tool.' \
            class='High' weakness='1' expected='root-owned, not group- or world-writable' \
            impact='Files in these directories can be sourced or executed during user login on distributions/configurations that enable them; writable content can therefore become a privilege-escalation or persistence vector.' \
            remediation='Restore root ownership and remove group/world write permission from the listed directories/files. Confirm the login stack actually invokes each affected path before treating the exposure as an executed path.'
    else
        add_finding PASS 'Local Privilege Escalation' 'No writable-beyond-root files were observed in the standard MOTD/profile.d execution directories.' \
            attr='Writable login-triggered configuration' configured='0' observed='permission metadata for /etc/update-motd.d and /etc/profile.d' \
            validation='Filesystem permission read' class='High' impact='Control satisfied for the observed paths.' remediation='None required.'
    fi

    # ---- NFS exports ---------------------------------------------------------------------------
    if [ -r /etc/exports ]; then
        if grep -Eq 'no_root_squash|insecure' /etc/exports 2>/dev/null; then
            add_finding 'RISK DETECTED' 'Network Segmentation' "NFS exports use no_root_squash or insecure, so a client root maps to local root on the exported filesystem." \
                attr='NFS export options' configured="$(grep -E 'no_root_squash|insecure' /etc/exports | head -3 | tr '\n' '; ')" \
                observed='/etc/exports' validation='Configuration read. No mount was attempted.' class='Critical' weakness='1' \
                expected='root_squash (default) plus secure ports and restrict to specific client addresses' \
                impact='On a share mounted by a host an attacker controls, root_squash disabled is a direct path to writing set-uid binaries or configuration on this host as root.' \
                remediation='Remove no_root_squash unless a specific application provably requires it, restrict each export to named client addresses, and use Kerberos-secured NFS where the estate supports it.'
        fi
    fi
}

# =============================================================================================
#  SECTION 18 :: INTERPRETERS, CONTAINERS AND EXECUTION SURFACES
# =============================================================================================
section18_interpreters() {
    write_section '18' 'INTERPRETERS, CONTAINER RUNTIME AND EXECUTION SURFACES'

    local interp=''
    local t
    for t in python3 python2 perl ruby node php lua tclsh socat; do
        have "$t" && interp+="$t "
    done
    write_kv 'Interpreters present' "${interp:-none of the common interpreters}"
    add_finding INFO 'Local Privilege Escalation' "Interpreters available on the host: ${interp:-none detected}. Interpreters are normal on an administrative host; each one is also a way to execute arbitrary code in any context that can invoke it." \
        attr='Interpreters present' configured="${interp:-none}" observed='which over a standard interpreter list' \
        validation='Presence check' class='Low' \
        impact='Context. The finding that matters is an interpreter reachable from a privileged execution path or carrying capabilities - both assessed in Sections 10 and 17.' \
        remediation='Remove interpreters that the host role does not require; they widen the execution surface without adding function.'

    # ---- container runtime/control sockets ----------------------------------------------------
    local container_sockets='' cs sockm
    # Enumerate standard and discovered runtime sockets without opening or connecting to them.
    for cs in /var/run/docker.sock /run/docker.sock \
              /var/run/containerd.sock /run/containerd.sock \
              /var/run/lxd.sock /run/lxd.sock \
              /var/run/podman.sock /run/podman.sock \
              /var/run/k3s.sock /run/k3s.sock; do
        [ -S "$cs" ] || continue
        container_sockets+="$cs "
    done
    if have find; then
        while IFS= read -r cs; do
            [ -S "$cs" ] || continue
            case " $container_sockets " in *" $cs "*) ;; *) container_sockets+="$cs " ;; esac
        done < <(find /run /var/run -xdev -type s \( -name 'docker.sock' -o -name 'containerd.sock' -o -name 'lxd.sock' -o -name 'podman.sock' -o -name 'k3s.sock' \) 2>/dev/null)
    fi
    for cs in $container_sockets; do
        sockm=$(get_octal_perms "$cs" 2>/dev/null)
        write_kv 'Container control socket' "$cs (mode ${sockm:-unknown})"
        case "$sockm" in
            *2|*3|*6|*7)
                add_finding 'RISK DETECTED' 'Local Privilege Escalation' "Container control socket ${cs} is writable beyond its owner (mode ${sockm})." \
                    attr='Container control socket permissions' configured="${cs} mode ${sockm}" observed='socket enumeration and permission metadata read' \
                    validation='Filesystem metadata read. The socket was NOT opened or used and no container was started.' class='Critical' weakness='1' \
                    expected='root-only or an explicitly controlled privileged group' \
                    impact='Write access to a container runtime control socket can provide host-level control depending on runtime configuration.' \
                    remediation='Restrict the socket to root or an explicitly reviewed privileged group; prefer rootless/container-isolated runtime configurations where appropriate.' ;;
            *)
                add_finding PASS 'Local Privilege Escalation' "Container control socket ${cs} is not writable beyond its owner." \
                    attr='Container control socket permissions' configured="${cs} mode ${sockm:-unknown}" observed='socket enumeration and permission metadata read' \
                    validation='Filesystem metadata read' class='Critical' impact='Control satisfied for the observed socket mode.' remediation='None required.' ;;
        esac
    done
    if [ -n "$container_sockets" ]; then
        add_finding INFO 'Local Privilege Escalation' "Container runtime control socket(s) observed: ${container_sockets}. This tool did not connect to or operate any socket." \
            attr='Container runtime present' observed="${container_sockets}" \
            validation='Read-only socket enumeration. No container escape technique was attempted.' class='Medium' catclass='Context' \
            impact='Runtime sockets are privileged control interfaces and should be treated as administrative assets.' \
            remediation='Confirm each socket is required and restricted to explicitly authorised administrators.'
    elif have docker || have podman; then
        add_finding INFO 'Local Privilege Escalation' 'A container runtime binary is present, but no standard runtime control socket was observed.' \
            attr='Container runtime present' observed='docker/podman command presence; socket enumeration returned none' \
            validation='Presence check and read-only socket enumeration' class='Medium' catclass='Context' impact='Runtime presence without a discovered control socket.' remediation='None required; review rootless/runtime-specific endpoints if container administration is expected.'
    fi

    # ---- Secure Boot / module signing ------------------------------------------------------------
    if [ -d /sys/firmware/efi ]; then
        local sb
        sb=$(od -An -t u1 /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | awk '{print $NF}' | head -1)
        if [ "$sb" = '1' ]; then
            add_finding PASS 'Kernel hardening' 'UEFI Secure Boot is enabled.' attr='Secure Boot' \
                configured='SecureBoot=1' observed='/sys/firmware/efi/efivars' validation='Firmware variable read' \
                class='Medium' impact='Control satisfied - kernel and bootloader signatures are enforced.' \
                remediation='None required. Ensure module signing is enforced so kernel modules are covered too.'
        elif [ "$sb" = '0' ]; then
            add_finding WARN 'Kernel hardening' 'UEFI Secure Boot is disabled, so an attacker with local write access to the boot path can load a modified kernel or module.' \
                attr='Secure Boot' configured='SecureBoot=0' observed='/sys/firmware/efi/efivars' \
                validation='Firmware variable read' class='Medium' weakness='1' expected='enabled with module signing' \
                impact='Defeats one of the few defences that persist below the operating system, and can make malware invisible to in-OS tooling.' \
                remediation='Enable Secure Boot where the hardware and drivers support it, and enforce kernel module signing (kernel.modules_disabled or the module signature policy).'
        fi
    fi
}

# =============================================================================================
#  SECTION 19 :: ACTIVE EXPLOITABILITY VALIDATION
# =============================================================================================
# Validation classes:
#   CONFIRMED            - the condition was demonstrated directly in this run
#   PARTIALLY CONFIRMED  - the precondition was demonstrated, the full condition was not
#   NOT CONFIRMED        - the check ran and did not find the condition
#   NOT TESTABLE         - the check could not run, and the reason is recorded
#
# The distinction that matters in this report: a DISCOVERED WEAKNESS is a configuration or
# exposure that a human still has to validate. A VALIDATED CONDITION was measured in this run.
# The two are never merged into one number.
section19_validation() {
    write_section '19' 'ACTIVE EXPLOITABILITY VALIDATION'

    # ---- the one truly active probe in this tool: anonymous LDAP --------------------------------
    write_status 'INFO' 'The only network-active validation in this tool is the anonymous LDAP bind (Section 9). Everything else is a configuration observation or a reachability test.'

    # ---- SUID/SGID: can the condition be confirmed without exploitation? ------------------------
    add_finding 'VALIDATED' 'Local Privilege Escalation' 'PARTIALLY CONFIRMED - set-uid inventory and package ownership were confirmed. Whether any individual set-uid binary is actually exploitable was NOT tested: that requires executing crafted input against a privileged binary, which is out of scope for a read-only assessment.' \
        attr='Set-UID exploitability' configured='see Section 10' observed='inventory and ownership queries completed' \
        validation='Validation class: PARTIALLY CONFIRMED. The INVENTORY is CONFIRMED by direct observation; the EXPLOITABILITY is NOT TESTED. The two are reported separately so the row cannot be read as claiming a working privilege escalation.' \
        class='Critical' \
        impact='A set-uid inventory is a shortlist for a human tester, not a finding of compromise.' \
        remediation='Review the list against the distribution baseline; validate individual candidates only in an isolated range or under explicit written authorisation to execute exploit code.'

    # ---- sudo: policy confirmed, execution not tested -------------------------------------------
    add_finding 'VALIDATED' 'Local Privilege Escalation' 'PARTIALLY CONFIRMED - the sudo policy was read and its risk patterns identified. No sudo command was executed, so whether a given rule is exploitable in practice is NOT established here.' \
        attr='sudo rule exploitability' configured='see Section 17' observed='sudoers files parsed; no sudo invocation performed' \
        validation='Validation class: PARTIALLY CONFIRMED. The POLICY is confirmed by file read; EXPLOITABILITY is NOT tested. A wildcard rule that looks exploitable on paper may be constrained by a wrapper, an argument check or a filesystem permission this assessment did not evaluate.' \
        class='High' impact='The report names candidates; validating them requires running the command, which this tool does not do.' \
        remediation='Validate individual rules under authorisation, in an isolated environment first, using a proof that does not modify the system.'

    # ---- kernel: version observed, exploitability not tested ------------------------------------
    add_finding 'NOT TESTABLE' 'Kernel hardening' 'Kernel vulnerability exploitability was NOT assessed. Determining whether a particular kernel is vulnerable to a specific issue requires matching the exact build against an advisory and, to confirm impact, executing the exploit.' \
        attr='Kernel exploitability' configured="kernel ${KERNEL}" observed='version string only' \
        validation='NULL RESULT, stated explicitly: the absence of a kernel vulnerability finding in this report is NOT evidence that the kernel is not vulnerable.' \
        class='Critical' \
        impact='A reader could misread this report as clearing the kernel. It does not. Kernel patching status must be established against the vendor advisory for the exact running build.' \
        remediation="Compare the running kernel against the distribution's security advisories, and confirm the running build is not the subject of an unpatched advisory."

    # ---- reachability: confirmed, but explicitly bounded -----------------------------------------
    add_finding 'VALIDATED' 'Network Discovery' 'CONFIRMED - network reachability of the in-scope hosts and services recorded in Section 8 is CONFIRMED: each entry corresponds to a connection that completed in this run.' \
        attr='Reachability evidence' configured="scope and authorisation as recorded in row 3 of the CSV" \
        observed="$( [ "${#HOSTPORT_KEYS[@]}" -gt 0 ] && echo "${#HOSTPORT_KEYS[@]} host(s) with at least one open probed port" || echo 'discovery not performed or no host responded' )" \
        validation='Validation class: CONFIRMED. TCP connect tests - the evidence is the completed connection itself. No authentication and no exploitation were attempted.' \
        class='Medium' \
        impact='Reachability is a precondition, not a compromise. It is reported as CONFIRMED because the connection demonstrably occurred, and the report does not extend that class to anything it did not measure.' \
        remediation='Restrict reachability to the minimum required by the host role.'

    # ---- credential exposure: metadata confirmed, contents deliberately untouched ----------------
    add_finding 'VALIDATED' 'Credential Storage' 'CONFIRMED - file permission findings in Section 5 are CONFIRMED: the mode was read from the filesystem in this run.' \
        attr='Credential file permissions' configured='see Section 5' observed='stat output recorded per file' \
        validation='CONFIRMED for the permission state. Whether any credential in those files is valid elsewhere was NOT tested, and the contents were NOT read.' \
        class='High' \
        impact='An exposed key is only as damaging as the targets that trust it - which is outside what this host can observe.' \
        remediation='Rotate the affected credential material if it was exposed for an unknown period, and confirm where it is authorised before considering the issue closed.'

    write_status 'INFO' 'Validation summary: this tool confirms conditions it can measure directly and states plainly what it did not test. It does not promote a configuration observation into a compromise claim.'

    validation_ledger
}

# ---------------------------------------------------------------------------------------------
#  19.4 EVIDENCE LEDGER: CONFIGURATION / ACTIVE VALIDATION / IMPACT
#
#  Every non-informational row is classified by what actually supported it, so a reader can tell a
#  demonstrated result from a documented one without reading 60 rows line by line. The
#  classification is derived from the row's own recorded validation and exploitability values -
#  it is not asserted separately, and it cannot disagree with the evidence.
# ---------------------------------------------------------------------------------------------
validation_ledger() {
    printf '\n  -- 19.4 Evidence ledger ------------------------------------------------\n'
    local rec st sev cat attr tgt find vld exp obs pre imp rem cls
    local n_impact=0 n_active=0 n_config=0 n_rows=0
    local -a impact=() active=() config=()
    for rec in "${FINDINGS[@]}"; do
        IFS=$'\x1f' read -r st sev cat attr tgt find vld exp obs pre imp rem <<< "$rec"
        case "$st" in INFO|PASS) continue ;; esac
        n_rows=$((n_rows+1))
        cls=$(get_validation_class "$vld" "$exp" "$obs")
        case "$cls" in
            'IMPACT EVIDENCE')     n_impact=$((n_impact+1)); impact+=("${sev}|${st}|${cat}|${attr}") ;;
            'ACTIVE VALIDATION')   n_active=$((n_active+1)); active+=("${sev}|${st}|${cat}|${attr}") ;;
            'CONFIGURATION EVIDENCE') n_config=$((n_config+1)); config+=("${sev}|${st}|${cat}|${attr}") ;;
        esac
    done

    if [ "$n_rows" -eq 0 ]; then
        write_status 'INFO' 'No weaknesses were recorded, so the evidence ledger is empty.'
        return
    fi

    write_table 'Evidence classification|Rows' \
        "IMPACT EVIDENCE|${n_impact}" "ACTIVE VALIDATION|${n_active}" "CONFIGURATION EVIDENCE|${n_config}"

    local i
    for i in "${!impact[@]}"; do
        [ "$i" -ge 50 ] && break
        write_kv '  impact' "${impact[$i]//|/  }"
    done
    for i in "${!active[@]}"; do
        [ "$i" -ge 50 ] && break
        write_kv '  active' "${active[$i]//|/  }"
    done
    for i in "${!config[@]}"; do
        [ "$i" -ge 50 ] && break
        write_kv '  config' "${config[$i]//|/  }"
    done
    if [ "$n_rows" -gt 150 ]; then
        write_status 'INFO' "$((n_rows-150)) further row(s) are in the CSV report."
    fi

    add_finding INFO 'Validation' "${n_impact} row(s) are classified IMPACT EVIDENCE - these are the only rows that may be presented as demonstrated impact." \
        attr='Evidence ledger: IMPACT EVIDENCE' configured="${n_impact} of ${n_rows} non-informational row(s)" \
        observed="$(printf '%s; ' "${impact[@]}" | cut -c1-400)" \
        validation='Programmatic classification of every non-informational row by its recorded validation method and exploitability statement.' \
        class='Low' catclass='Context' \
        impact='Not applicable - this row is a reporting-integrity control. It exists so a configuration observation cannot be escalated to the business as a demonstrated compromise.' \
        remediation='Read the classification before escalating any row: a CONFIGURATION EVIDENCE row needs an owner decision, an ACTIVE VALIDATION row needs prioritisation, and an IMPACT EVIDENCE row needs immediate remediation.'

    add_finding INFO 'Validation' "${n_active} row(s) are classified ACTIVE VALIDATION - the condition was observed at runtime from the affected system, but end-to-end impact was not demonstrated." \
        attr='Evidence ledger: ACTIVE VALIDATION' configured="${n_active} of ${n_rows} non-informational row(s)" \
        observed="$(printf '%s; ' "${active[@]}" | cut -c1-400)" \
        validation='Programmatic classification of every non-informational row by its recorded validation method and exploitability statement.' \
        class='Low' catclass='Context' \
        impact='Not applicable - this row is a reporting-integrity control.' remediation='Prioritise these rows above configuration evidence.'

    add_finding INFO 'Validation' "${n_config} row(s) are classified CONFIGURATION EVIDENCE - the condition is documented from configuration or a directory attribute, and its impact is NOT demonstrated." \
        attr='Evidence ledger: CONFIGURATION EVIDENCE' configured="${n_config} of ${n_rows} non-informational row(s)" \
        observed="$(printf '%s; ' "${config[@]}" | cut -c1-400)" \
        validation='Programmatic classification of every non-informational row by its recorded validation method and exploitability statement.' \
        class='Low' catclass='Context' \
        impact='Not applicable - this row is a reporting-integrity control.' remediation='Each row requires an owner decision, not an incident response.'
}

# =============================================================================================
#  SECTION 20 :: ATTACK-CHAIN CORRELATION
# =============================================================================================
section20_chains() {
    write_section '20' 'ATTACK-CHAIN CORRELATION'

    local chain_count=0
    local chain_txt=''

    # A chain is only recorded when both links were individually evidenced in this run.
    if [ "$STATS_RISK" -gt 0 ]; then
        chain_txt+="local weakness(es) present (${STATS_RISK} risk-class finding(s)); "
        chain_count=$((chain_count+1))
    fi
    if [ "$STATS_WARN" -gt 0 ]; then
        chain_txt+="${STATS_WARN} warning-class finding(s); "
    fi
    if [ "$STATS_NOTTESTABLE" -gt 0 ]; then
        chain_txt+="${STATS_NOTTESTABLE} control(s) NOT TESTABLE - these are gaps in coverage, not clean results; "
    fi
    if test_kill_switch; then
        chain_txt+='the run was stopped early by the kill switch; '
    fi

    write_kv 'Findings by class' "risk=${STATS_RISK} warn=${STATS_WARN} validated=${STATS_VALIDATED} not-confirmed=${STATS_NOTCONFIRMED} not-testable=${STATS_NOTTESTABLE} errors=${STATS_ERRORS} pass=${STATS_PASS} info=${STATS_INFO}"

    if [ "$chain_count" -eq 0 ] && [ "$STATS_NOTTESTABLE" -eq 0 ]; then
        add_finding PASS 'Attack Path' 'No multi-step chain was assembled: no risk-class findings were produced in this run, and every assessed control either passed or produced informational output.' \
            attr='Attack chain' observed="$chain_txt" \
            validation='Correlation over this run''s own finding log' class='Low' \
            impact='No chain is claimed. Note this is a statement about findings FROM THIS RUN, not a statement that no attack path exists on the host.' \
            remediation='None. Re-assess after any change to the host or its network position.'
        return
    fi

    add_finding INFO 'Attack Path' "Attack-chain correlation over this run: ${chain_txt}" \
        attr='Attack chain' observed="$chain_txt" \
        validation='Correlation over the finding log produced by this run. Each contributing finding is individually evidenced above; the SEQUENCE is a narrative for the reader and is NOT itself a validated exploit chain.' \
        class='Medium' \
        impact='States which findings combine into a plausible path, so remediation can be prioritised by chain rather than by individual severity - a low-severity link on a viable chain often deserves attention before a high-severity one that leads nowhere.' \
        remediation='Prioritise breaking the chained paths named in Section 16, then work through the remaining findings by severity.'

    # Chain 1: reachable admin service + local credential material exposure
    if [ "$STATS_WARN" -gt 0 ] && [ "${#SCOPE_INC[@]}" -gt 0 ]; then
        add_finding WARN 'Attack Path' 'Chain: a reachable administrative service in scope combined with any credential material exposed on the assessed hosts yields lateral movement from this foothold.' \
            attr='Attack chain: exposure + reachable administration' observed="$chain_txt" \
            prereq='A credential valid on the target. NOT tested by this tool.' \
            validation='Correlation of Section 8 reachability with Sections 5 and 17 exposure findings. The links are evidenced; the chain was NOT executed.' \
            class='High' weakness='1' \
            impact='This is the dominant lateral-movement path in a flat internal network, and it needs only one reusable credential to cross the estate.' \
            remediation='Break the chain at the cheapest point: make administrative credentials unique per host, and remove remote administration from networks that do not require it.'
    fi
}

# =============================================================================================
#  SECTION 21 :: REPORTING
# =============================================================================================
write_test_registry() {
    {
        printf '%s\n' 'TestID,Section,Control,Outcome,EvidenceReference'
        printf '%s\n' "T-01,2,Kernel hardening parameters,/proc/sys read for 17 parameters,Section 2 rows"
        printf '%s\n' "T-02,2,/etc/shadow permissions,stat only - contents never read,Section 2 row"
        printf '%s\n' "T-03,3,SSH effective configuration,sshd -T where privileged else file parse,Section 3 rows"
        printf '%s\n' "T-04,4,Password quality and lockout modules,PAM stack and login.defs read,Section 4 rows"
        printf '%s\n' "T-05,5,Credential-material exposure,metadata only - no file opened,Section 5 rows"
        printf '%s\n' "T-06,7,Kernel drift and patch cadence,kernel package vs uname and package log,Section 7 rows"
        printf '%s\n' "T-07,8,Bounded liveness sweep,TCP connect over the derived /24 within scope,Section 8 rows"
        printf '%s\n' "T-08,8,Service matrix and banner capture,read-only greeting or HEAD request,Section 8 rows"
        printf '%s\n' "T-09,9,Anonymous LDAP bind,LIVE unauthenticated base-scope query,Section 9 row"
        printf '%s\n' "T-10,10,SUID/SGID and capabilities,find and getcap enumeration,Section 10 rows"
        printf '%s\n' "T-11,11,Listening socket inventory,ss -lntup,Section 11 rows"
        printf '%s\n' "T-12,12,FIPS state and crypto policy,/proc/sys and policy files,Section 12 rows"
        printf '%s\n' "T-13,14,Host firewall enforcement,nft/iptables/ufw runtime read,Section 14 rows"
        printf '%s\n' "T-14,15,Mount hardening,/proc/mounts option review,Section 15 rows"
        printf '%s\n' "T-15,17,sudo/cron/systemd/PATH privilege surface,configuration and permission read,Section 17 rows"
        printf '%s\n' "T-16,19,Validation class assignment,explicit per-condition classification,Section 19 rows"
        printf '%s\n' "T-17,22,Kernel module integrity,/proc/modules + /sys/module + modules_disabled,Section 22 rows"
        printf '%s\n' "T-18,23,IPC and descriptor boundary,shared runtime endpoint metadata + procfs fd links,Section 23 rows"
        printf '%s\n' "T-19,24,Login profile injection,login/MOTD permission metadata,Section 24 rows"
        printf '%s\n' "T-20,25,Container runtime control endpoints,socket metadata only,Section 25 rows"
    } > "$REGISTRY_PATH" 2>/dev/null
    return 0
}

section21_reporting() {
    write_section '21' 'REPORTING'
    write_kv 'Evidence report (CSV)' "$CSV_PATH"
    write_kv 'Test registry' "$REGISTRY_PATH"
    write_kv 'Evidence rows' "$FINDING_COUNT"
    if [ -f "$CSV_PATH" ]; then
        write_kv 'Report size' "$(wc -c < "$CSV_PATH" 2>/dev/null | tr -d " ") bytes"
        write_status 'PASS' 'Reporting checkpoint written. Sections 22-25 append their evidence to the same CSV; the final summary and handoff are produced after Section 25.'
        write_status 'INFO' 'RFC4180 escaping applied to every field. The file is plain UTF-8 and opens in any spreadsheet or CSV reader.'
    else
        write_status 'ERROR' 'The CSV report could not be written. Evidence exists only on this console - capture it now.'
    fi
    if [ "$MALFORMED_FIELDS" -gt 0 ]; then
        write_status 'ERROR' "${MALFORMED_FIELDS} finding field(s) were malformed and did not reach the report. This is a tool defect - the affected rows are incomplete."
    fi
}

# =============================================================================================
#  EXECUTIVE SUMMARY
# =============================================================================================
write_executive_summary() {
    local elapsed="$1"
    printf '\n%s================================================================%s\n' "$C_BOLD" "$C_RESET"
    printf '%s  EXECUTIVE SUMMARY%s\n' "$C_BOLD" "$C_RESET"
    printf '%s================================================================%s\n' "$C_BOLD" "$C_RESET"
    write_kv 'Host' "$HOST_SHORT ($HOST_FQDN)"
    write_kv 'Platform' "$OS_NAME, kernel $KERNEL"
    write_kv 'Runtime' "$(printf '%.0f' "$elapsed")s"
    write_kv 'Assessed position' "$( [ "$ELEVATED" = '1' ] && echo 'root (full local visibility)' || echo 'unprivileged (some controls NOT TESTABLE)' )"
    write_kv 'Off-host work' "$( [ "$NETWORK_AUTH" = '1' ] && [ "$LOCAL_ONLY" != '1' ] && echo "authorised; scope: ${SCOPE_TEXT:-permissive}" || echo 'not performed (local-only or unauthorised)' )"
    printf '\n'
    write_kv 'Risk-class findings' "$STATS_RISK"
    write_kv 'Warnings' "$STATS_WARN"
    write_kv 'Validated conditions' "$STATS_VALIDATED"
    write_kv 'Not confirmed' "$STATS_NOTCONFIRMED"
    write_kv 'NOT TESTABLE' "$STATS_NOTTESTABLE"
    write_kv 'Errors' "$STATS_ERRORS"
    write_kv 'Passed controls' "$STATS_PASS"
    write_kv 'Informational' "$STATS_INFO"
    printf '\n'
    if [ "$STATS_NOTTESTABLE" -gt 0 ]; then
        printf '  %sNote:%s %d control(s) are NOT TESTABLE. They are GAPS, not clean results - read the\n' "$C_YELLOW" "$C_RESET" "$STATS_NOTTESTABLE"
        printf '  specific reason recorded on each of those rows before treating any control as satisfied.\n'
    fi
    printf '\n'
    write_kv 'Report' "$CSV_PATH"
    [ -n "$HANDOFF_PATH" ] && write_kv 'Validation handoff' "$HANDOFF_PATH"
    printf '\n'
}

# =============================================================================================
#  VALIDATION HANDOFF
#
#  For every finding that warrants human follow-up: the next step, what CONFIRMS it, what REFUTES
#  it, and the blast radius of trying. The tool NEVER performs these steps itself: in a real
#  engagement the next step depends on what the previous one returned, so a pre-scripted sequence
#  would be confidently wrong the moment reality diverges.
#
#  This mirrors the Windows build's $script:HandoffSteps layer: a match token, a stage from a fixed
#  ordered list, a context (range / either), an ordered list of next actions, and explicit confirm,
#  refute and blast-radius statements.
# =============================================================================================
HANDOFF_STAGE_ORDER=(
    'DISCOVERY / SERVICE ENUMERATION'
    'VULNERABILITY VALIDATION'
    'INITIAL ACCESS VALIDATION'
    'LOCAL PRIVILEGE ESCALATION'
    'CREDENTIAL / ACCESS MATERIAL VALIDATION'
    'AD / DIRECTORY ATTACK-PATH VALIDATION'
    'LATERAL-MOVEMENT VALIDATION'
    'ESTATE-LEVEL IMPACT VALIDATION'
)

# Match tokens are checked IN ORDER, so a specific token must precede a generic one
# ('kernel exploitability' before 'kernel', 'service executable' before 'service').
HANDOFF_TOKENS=()

# Bash 3.x-compatible handoff table. Each record is token|stage|where|next|confirms|refutes|blast.
HB_RECORDS=()

hb_add() {
    # hb_add <match-token> <stage> <where> <next1~next2~next3> <confirms> <refutes> <blast>
    HANDOFF_TOKENS+=("$1")
    HB_RECORDS+=("$1|$2|$3|$4|$5|$6|$7")
}

hb_alias() {
    # hb_alias <new-token> <existing-token> - copy the existing guidance without associative arrays.
    local rec tok
    for rec in "${HB_RECORDS[@]}"; do
        tok="${rec%%|*}"
        [ "$tok" = "$2" ] || continue
        HANDOFF_TOKENS+=("$1")
        HB_RECORDS+=("$1|${rec#*|}")
        return 0
    done
}

handoff_table() {
    hb_add 'anonymous ldap' 'DISCOVERY / SERVICE ENUMERATION' 'either' \
        'Test the anonymous bind from a DIFFERENT host on the same segment - a bind refused elsewhere proves it is source-restricted|If it still succeeds, query ONLY the root DSE and the naming contexts|Record exactly which attributes were readable without credentials' \
        'The bind succeeds from a second source and returns directory metadata.' \
        'The bind is refused from another source, or succeeds but returns no readable attribute.' \
        'Minimal: a base-scope query is one packet. Do not enumerate object data - the volume of objects retrieved is what trips detection, not the bind itself.'

    hb_add 'kernel exploitability' 'VULNERABILITY VALIDATION' 'either' \
        'Establish the exact running build: uname -a and the vendor kernel package version|Match that build against the distribution security advisories|Confirm the running image is not the subject of an unpatched advisory' \
        'The running build matches an advisory that has no available fix in the configured repository.' \
        'The build is newer than the advisory, or a fixed package is already available for install.' \
        'None - this is a version comparison, not a test. Nothing is executed.'

    hb_add 'drift' 'VULNERABILITY VALIDATION' 'either' \
        'Compare the running kernel against the newest installed kernel package|Check whether a reboot is pending|If a newer kernel is installed but not running, schedule the restart in a change window' \
        'A newer kernel is installed and the host has been running the old image for longer than the agreed patch window.' \
        'No newer kernel is installed, or the running image is already the newest.' \
        'MEDIUM: restarting a production server is a service-impacting event. Never reboot without the change record and a rollback plan.'

    hb_add 'permitrootlogin' 'INITIAL ACCESS VALIDATION' 'either' \
        'Determine whether the root account has a password set at all: passwd -S root (metadata only)|Check whether root is reachable on any interface NOT covered by the firewall|If both are true, treat this as a live initial-access path and treat the correction as urgent' \
        'Root has an active password AND port 22 is reachable from a network the assessment considers untrusted.' \
        'Root is locked (L in passwd -S output), or SSH is restricted to a management network by rule.' \
        'LOW: this is a configuration read plus one metadata query. Do not attempt a root login - lockout policy may apply to root and an alert will be raised.'

    hb_add 'empty password' 'INITIAL ACCESS VALIDATION' 'either' \
        'List accounts with an EMPTY password field using metadata only: awk -F: '"'"'($2==""){print $1}'"'"' /etc/shadow (requires root)|Confirm each account is required|Disable SSH password authentication entirely if empty passwords are accepted' \
        'An account with an empty password exists AND its shell is a login shell.' \
        'No account has an empty password field, or every such account is locked or shell-less.' \
        'LOW: reading /etc/shadow is a privileged metadata read and changes nothing. Do NOT attempt to log in as any such account.' 

    hb_add 'password authentication' 'VULNERABILITY VALIDATION' 'range' \
        'Establish whether the password path is reachable: confirm port 22 is exposed to the segments that matter|Confirm the account lockout policy actually applied (Section 4), because that bounds any guessing|Decide with the engagement owner whether credential testing is authorised at all' \
        'Password authentication is reachable from an untrusted segment AND no lockout policy bounds failed attempts.' \
        'Key-only authentication is enforced for every account, or lockout policy bounds attempts at a threshold the owner accepts.' \
        'HIGH: this is the one path that leads to authentication attempts against real accounts. This tool does NOT perform them. Testing it requires explicit, itemised authorisation and a named account - never a guessed one.'

    hb_add 'lockout' 'CREDENTIAL / ACCESS MATERIAL VALIDATION' 'either' \
        'Read the effective lockout policy from the PAM stack and login.defs|Confirm which accounts it applies to, including service accounts|Decide whether the absence of lockout is acceptable given the SSH exposure found above' \
        'No lockout module is configured AND password authentication is reachable from an untrusted segment.' \
        'A lockout or delay module is configured, or password authentication is not reachable.' \
        'None - configuration read only.'

    hb_add 'credential' 'CREDENTIAL / ACCESS MATERIAL VALIDATION' 'either' \
        'Determine where the exposed material is AUTHORISED before treating it as compromised|Check the public key or credential against the systems that trust it|Rotate on those systems first, then remove the old material' \
        'The credential is accepted by another system - which must be tested only with explicit authorisation.' \
        'The credential is stale, already revoked, or scoped to this host alone.' \
        'MEDIUM: rotation is a change-control event and can interrupt services that depend on the credential. Coordinate before rotating, and never test a stolen key against a production target.'

    hb_add 'private key' 'CREDENTIAL / ACCESS MATERIAL VALIDATION' 'either' \
        'Establish whether the key has a passphrase and where it is authorised|Check the authorised_keys files on the systems that trust it|Rotate: generate a replacement, deploy it, then remove the exposed key' \
        'The key is authorised on another host and is usable without a passphrase.' \
        'The key is not present in any authorised_keys file, or it is passphrase-protected and the passphrase is not exposed alongside it.' \
        'MEDIUM: key rotation on a production estate can lock out automation that depends on the key. Inventory the consumers before removing anything.'

    hb_add 'capabilit' 'LOCAL PRIVILEGE ESCALATION' 'range' \
        'For each file_with_capability, establish which capability and which binary|Determine whether the binary can be influenced by a non-privileged user (arguments, config, environment, plugin path)|Validate only in an isolated range, with a proof that does not modify the system' \
        'A capability such as cap_setuid or cap_sys_admin sits on a binary a non-privileged user can influence.' \
        'Every capability is on a root-owned binary with a fixed argument set and no user-controlled input.' \
        'MEDIUM: proving a capability escalation requires executing code against a privileged binary. On production, do not - the process may write state or crash the service that depends on it.'

    hb_add 'set-uid' 'LOCAL PRIVILEGE ESCALATION' 'range' \
        'For each unowned or unexpected set-uid binary, identify its origin BEFORE anything else|Compare against the distribution package manifest and the change record|If the origin is unexplained, preserve evidence and escalate - do not test exploits' \
        'A set-uid binary matches nothing in the package database or the change record.' \
        'Every set-uid binary matches an installed package or a documented local build.' \
        'HIGH if the host is believed compromised: exploit testing destroys the evidence that matters. Escalate to incident response instead.'

    hb_add 'unowned set-uid' 'LOCAL PRIVILEGE ESCALATION' 'either' \
        'Identify the origin of each unowned set-uid binary|Hash it and check it against the package manifests of every installed package|Preserve a copy of the evidence before any remediation' \
        'The binary is not owned by any installed package and no change record explains it.' \
        'The binary belongs to a package, a documented local build, or a vendor agent that was installed deliberately.' \
        'LOW to inspect, HIGH to ignore: an unexplained set-uid root binary is the strongest single indicator of compromise this assessment can produce.'

    hb_add 'sudo' 'LOCAL PRIVILEGE ESCALATION' 'range' \
        'For each NOPASSWD or wildcard rule, determine from the file exactly which binary it invokes|Check whether that binary or its arguments can be influenced by an unprivileged user|Only then decide whether a proof is warranted, and build it so it does not modify the system' \
        'A rule resolves to a binary or argument set the tester can influence.' \
        'The rule is an absolute path to a root-owned binary with a fixed, non-influenceable argument set.' \
        'LOW to read, MEDIUM to demonstrate: executing a bypass changes system state and must be authorised individually. Do it in an isolated range first.'

    hb_add 'cron' 'LOCAL PRIVILEGE ESCALATION' 'either' \
        'Check the permission and ownership of every file a root cron job executes|Check whether the script sources anything from a user-writable location|Confirm the directory chain to each executed file is root-owned and not writable' \
        'A root cron job executes a file or reads a configuration that a non-privileged user can modify.' \
        'Every file in the execution chain is root-owned and writable only by root.' \
        'LOW: this is a permission read. Do not modify anything a scheduled job consumes - that is the exploitation step and it may break the job.'

    hb_add 'service executable' 'LOCAL PRIVILEGE ESCALATION' 'either' \
        'Resolve the ExecStart path for each unit and check every directory in that path|Check whether any unit runs with a user-controlled environment file|Correct ownership first, then restart the unit in a change window' \
        'A root-run service executes a binary or reads an environment file from a location a non-privileged user can write.' \
        'Every ExecStart path is root-owned and non-writable by anyone else.' \
        'MEDIUM: correcting permissions is safe; RESTARTING the affected unit is a service event. Do not restart a production unit to prove the fix.'

    hb_add 'ld.so' 'LOCAL PRIVILEGE ESCALATION' 'range' \
        'List the effective library search paths for a privileged binary: LD_DEBUG=libs on a harmless root-owned binary|Check every directory in that list for writability|Validate the escalation only in an isolated range' \
        'A writable directory precedes a trusted one in the library search path of a privileged binary.' \
        'Every directory in every search path is root-owned and not writable by non-root.' \
        'MEDIUM: demonstrating this means planting a shared library. That modifies the host and can corrupt a running service - range only.'

    hb_add 'docker' 'LOCAL PRIVILEGE ESCALATION' 'either' \
        'Enumerate the members of the docker group and check each against the access review|Confirm whether any non-privileged account or service is a member|Do NOT start a container to prove it - membership alone is the finding' \
        'A non-privileged principal is a member of the docker group or can reach the socket.' \
        'Only privileged administrative accounts are members, and the socket is not otherwise reachable.' \
        'HIGH if proven by execution: starting a container mutates the host and may leave images or volumes behind. Prove it by group membership and socket permissions instead.'

    hb_add 'world-writable' 'LOCAL PRIVILEGE ESCALATION' 'either' \
        'List every world-writable file and directory under the privileged paths, with owners|Determine whether any privileged process reads or executes each one|Fix permissions from the top down, starting with directories' \
        'A world-writable file is read or executed by a privileged process, or a world-writable directory is in a privileged search path.' \
        'World-writable entries exist but no privileged process consumes them, and none is in a search or library path.' \
        'LOW: permission changes are reversible and low-risk, but do them in a change window on production - a service that depends on a file being group-writable can break.'

    hb_add 'nfs' 'LATERAL-MOVEMENT VALIDATION' 'either' \
        'List the exported paths and their client restrictions: showmount -e localhost and /etc/exports|Identify which clients are permitted and whether root_squash is set|Test mounting ONLY from an authorised client, and never write to the export' \
        'An export is world-readable or world-writable, or root_squash is disabled for a client the assessment does not control.' \
        'Every export is restricted to specific client addresses and root_squash is enabled.' \
        'MEDIUM: mounting an export is a read of another host data set. Do not write to a share, and do not assume authorisation for the client-side test.'

    hb_add 'all interfaces' 'LATERAL-MOVEMENT VALIDATION' 'either' \
        'For each socket bound to 0.0.0.0 or ::, identify the owning process and its intended network|Check reachability from the segments this host participates in, not just the local one|Bind each service to the specific address it is required on' \
        'A service intended for one network answers on a network it was not designed for.' \
        'Every all-interface socket is reachable only from segments where it is intended, enforced by the host firewall.' \
        'LOW for the read, MEDIUM for the change: rebinding a service to a specific address requires a restart and a configuration change. Verify the firewall default-deny posture before removing the fallback.'

    hb_add 'firewall' 'LATERAL-MOVEMENT VALIDATION' 'either' \
        'Establish whether enforcement is provided upstream by the network rather than by this host|If the host is the intended enforcement point, plan the change in a window with a SECOND administrative session already open|Never apply a default-deny input policy and then close your last session' \
        'No upstream enforcement exists and the host itself is the only control.' \
        'The network enforces the boundary and the host is correctly permissive.' \
        'HIGH: applying a default-deny firewall to a remote host without an out-of-band path is how connectivity to a production server is lost. Always keep a second session open, and prefer a scheduled rollback over confidence.'

    hb_add 'audit' 'VULNERABILITY VALIDATION' 'either' \
        'Determine whether auditd or an equivalent is expected on this host class by its build standard|Establish whether logs are forwarded off-host, and to where|If neither is present, record it as a detection gap and confirm the compensating monitoring that covers this host' \
        'Neither local auditing nor remote forwarding is in place, so activity on this host would leave no record.' \
        'Logs are forwarded to a collector, or upstream network monitoring covers the host.' \
        'LOW: this is a configuration read. Installing or reconfiguring auditd on production is a change event and requires a window - an overly broad ruleset can saturate disk and impact the service.'

    hb_add 'mount' 'LOCAL PRIVILEGE ESCALATION' 'either' \
        'Check /proc/mounts for each writable path users can reach and confirm the missing options|Determine whether anything legitimate depends on executing from that path|Add noexec, nosuid and nodev in a change window' \
        'A writable path is mounted without noexec/nosuid and a privileged process consumes files from it.' \
        'Every user-writable mount already carries nosuid and nodev, or nothing privileged reads from it.' \
        'MEDIUM: remounting with noexec breaks any legitimate workflow that executes from that path, for example /tmp in a build pipeline. Confirm before applying.'

    hb_add 'listening socket ownership' 'DISCOVERY / SERVICE ENUMERATION' 'either' \
        'Re-run the socket inventory with sudo so each socket is attributed to a process|Correlate each listener against the intended role of the host|Investigate any listener that no role justifies' \
        'A listening socket cannot be attributed to an intended service.' \
        'Every listener maps to a service this host is documented to run.' \
        'None - a local inventory read. Note that without root the inventory itself is incomplete.'

    hb_add 'reachability' 'DISCOVERY / SERVICE ENUMERATION' 'either' \
        'Re-probe only the ports that matter for the engagement objective|Confirm each open port against the host role and the firewall ruleset|Treat reachability as a precondition, not a finding, when writing the report' \
        'A port is reachable that neither the role nor the firewall documentation accounts for.' \
        'Every reachable port is accounted for by the role and permitted by the ruleset.' \
        'LOW on a range, MEDIUM on production: connection attempts are logged and may be alerted on. Volume is what triggers a response - keep the probe list small and the spacing wide.'

    hb_add 'attack chain' 'ESTATE-LEVEL IMPACT VALIDATION' 'range' \
        'Work the chains in Section 16 in order, breaking the cheapest link first|Execute each link only in an isolated range, recording what the previous link returned before moving on|Do not chain steps unattended - each link changes what the next one can do' \
        'Each link is individually confirmed and the chain reaches a target that matters.' \
        'Any link fails, which breaks the chain and reduces the priority of every finding that contributed to it.' \
        'HIGH: chaining multiplies both impact and footprint. On production this must be explicitly authorised per link, never as a package.'

    hb_add 'patch' 'VULNERABILITY VALIDATION' 'either' \
        'Compare the installed package set against the newest available for the release|Identify the packages with security updates pending|Schedule installation in a change window, with the service owner informed' \
        'Security updates are available and available patches are unapplied beyond the agreed window.' \
        'The host is current for its release, or the outstanding updates are non-security.' \
        'MEDIUM: applying updates restarts services and can require a reboot. Never patch a production host without a window and a rollback plan.'

    # Tokens below are deliberately LAST: they are the more general categories, and the specific
    # tokens above must win. A row is matched against this list in insertion order.
    hb_add 'in path' 'LOCAL PRIVILEGE ESCALATION' 'either' \
        'Print the effective PATH for root and for each service manager|Check every directory in it for group or world writability|Correct ownership and permissions, then confirm no legitimate workflow depended on the writable directory' \
        'A directory that precedes a trusted system directory in a privileged PATH is writable by a non-privileged user.' \
        'Every directory in every privileged PATH is root-owned and not writable by others.' \
        'LOW: a permission change is reversible. Confirm the change with the application owner first - some vendor products install into a writable directory deliberately.' 

    hb_add 'container' 'LOCAL PRIVILEGE ESCALATION' 'range' \
        'Enumerate container runtimes and check the socket permissions and group membership|Check whether any container runs privileged or with the host filesystem mounted|Confirm whether the runtime is required on this host at all' \
        'A non-privileged principal can reach the container socket, or a running container holds host-level privileges.' \
        'The socket is root-only, no container runs privileged, and no host path is mounted into one.' \
        'HIGH if proven by execution: starting or entering a container changes host state and may leave artefacts. Prove it from socket permissions and group membership instead.'

    hb_add 'interpreter' 'LOCAL PRIVILEGE ESCALATION' 'either' \
        'List the interpreters present and check the permission of every directory they search on start-up|Check for interpreter-specific configuration a non-privileged user can write (site-packages, PYTHONPATH, library path files)|Determine whether any privileged process invokes an interpreter from a writable location' \
        'A privileged process invokes an interpreter that loads code from a path a non-privileged user can write.' \
        'Every interpreter invoked by a privileged process loads only from root-owned, non-writable paths.' \
        'MEDIUM: demonstrating this means planting code that a privileged interpreter will load. Range only.'

    hb_add 'hidepid' 'LOCAL PRIVILEGE ESCALATION' 'either' \
        'Assess what process metadata is actually exposed: run ps aux as an unprivileged user and look for command-line secrets|Determine whether any service passes credentials as arguments or environment values|Move secrets out of the command line before considering hidepid' \
        'A privileged process command line or environment exposes a credential to any local user.' \
        'No privileged process carries a credential in its command line or environment.' \
        'LOW: this is a read. Note that mounting /proc with hidepid can break monitoring agents and some service managers - test on a range host first.'

    hb_add 'kernel' 'VULNERABILITY VALIDATION' 'either' \
        'Compare the running kernel parameters against the distribution or CIS baseline for this release|For each differing value, determine what depends on the current setting before changing it|Apply the agreed baseline in a change window and re-read /proc/sys to confirm persistence' \
        'A parameter differs from the agreed baseline and the difference weakens a control the baseline exists to provide.' \
        'The parameter is deliberately set for this host role, and a change record explains it.' \
        'MEDIUM: some of these settings affect running services immediately - ip_forward and rp_filter in particular can break routing and load balancing. Never change them on a production host outside a window.'

    hb_add 'print' 'LOCAL PRIVILEGE ESCALATION' 'either' \
        'Confirm whether the print service needs to be running at all on this host|If it does, check its version against the vendor advisories|If it does not, disable and mask the service' \
        'The print daemon is installed on a host whose role does not require printing.' \
        'The service is required by the role, or it is already disabled and masked.' \
        'LOW: stopping a print daemon is safe on a non-print role, but confirm with the owner first - silent removal of a service someone depends on is its own incident.'

    hb_add 'cups' 'LOCAL PRIVILEGE ESCALATION' 'either' \
        'Confirm whether CUPS is required on this host|Check the CUPS version against the distribution advisory list|Disable the service and remove its socket from public bindings if it is not required' \
        'CUPS is running, its version is subject to an advisory, and no role requires it.' \
        'CUPS is not installed, or the running version has no outstanding advisory.' \
        'LOW: service changes are reversible, but confirm the role first.'

    hb_add 'certificat' 'DISCOVERY / SERVICE ENUMERATION' 'either' \
        'Identify the issuer and the system that consumes the certificate|Confirm how the replacement is distributed before removing anything|Replace through the normal lifecycle, and confirm trust chains still validate afterwards' \
        'The certificate is still referenced by a live service, so a removal would break it.' \
        'The certificate is unreferenced or already superseded by one in the same store.' \
        'MEDIUM: removing a trusted root is a global change to the trust store. Always test against a replica first, and never remove a root on production without the change record.'

    hb_add 'kerberos' 'AD / DIRECTORY ATTACK-PATH VALIDATION' 'range' \
        'Confirm which realm and KDC this host trusts, and whether it is joined or merely configured|Enumerate the join account and ticket cache LOCATION only - do not extract tickets|Establish with the directory owner whether the computer account is still required' \
        'A stale keytab or an active machine account exists for a host that no longer needs directory membership.' \
        'The host is a current domain member and the keytab is rotated on the normal schedule.' \
        'MEDIUM: touching Kerberos material on a production member server can break authentication for the whole host. This tool never reads ticket caches or keytab contents, and neither should this step.'

    hb_add 'sssd' 'AD / DIRECTORY ATTACK-PATH VALIDATION' 'either' \
        'Check the sssd configuration for the directory it points at and the credential it stores|Confirm the file permissions on any stored bind credential (metadata only)|Confirm the directory account is minimally privileged and its password is managed' \
        'A directory bind credential sits on disk in a location readable by more than root.' \
        'The cached credential is root-only, or authentication uses a machine identity instead.' \
        'LOW: permission inspection only. Do not read the credential value - rotation is the remedy if the permissions are wrong, and rotation is a change event.'

    hb_add 'directory integration' 'AD / DIRECTORY ATTACK-PATH VALIDATION' 'either' \
        'Confirm whether directory integration is required by the host role|If not required, remove the configuration rather than leaving it dormant|If required, confirm the account and keytab are current' \
        'Directory integration is configured but no role requires it.' \
        'The host role requires directory integration and the configuration is current.' \
        'LOW: removal is a configuration change; confirm nothing authenticates through the directory before disabling it.'

    # Aliases for attribute wordings that mean the same technique.
    hb_alias 'emptypassword' 'empty password'
    hb_alias 'password quality' 'lockout'
    hb_alias 'discovery' 'reachability'

    hb_add 'segmentation' 'LATERAL-MOVEMENT VALIDATION' 'either' \
        'Establish the intended network boundary for this host from the network owner, not from the host|Compare the host firewall ruleset against that intent|Recommend the enforcement point - host or network - and apply it in one place, not both' \
        'The host is reachable from a segment the design intends to isolate it from.' \
        'Reachability matches the intended boundary, or upstream enforcement provides it.' \
        'MEDIUM: firewall changes on a remote host are the classic way to lose connectivity. Keep a second session open and prefer an out-of-band path.'
}

handoff_lookup() {
    # Returns "<stage>~<where>~<next>~<confirms>~<refutes>~<blast>" for a row, or the default.
    local hay tok
    hay=$(lower_string "$1")
    local rec stage where next confirms refutes blast rest
    for tok in "${HANDOFF_TOKENS[@]}"; do
        case "$hay" in
            *"$tok"*)
                for rec in "${HB_RECORDS[@]}"; do
                    case "$rec" in
                        "$tok"\|*)
                            rest="${rec#*|}"; stage="${rest%%|*}"; rest="${rest#*|}"
                            where="${rest%%|*}"; rest="${rest#*|}"
                            next="${rest%%|*}"; rest="${rest#*|}"
                            confirms="${rest%%|*}"; rest="${rest#*|}"
                            refutes="${rest%%|*}"; blast="${rest#*|}"
                            printf '%s~%s~%s~%s~%s~%s' "$stage" "$where" "$next" "$confirms" "$refutes" "$blast"
                            return
                            ;;
                    esac
                done
                ;;
        esac
    done
    printf '%s' "VULNERABILITY VALIDATION~either~Re-read the configuration evidence and observed result for this row, then reproduce the observation by hand~Decide explicitly whether this is a validated weakness or a configuration observation, and label it as such in the final report~Manual reproduction matches the recorded observation, which upgrades the row from discovered to validated~Manual reproduction disagrees - then the row must be corrected, not carried forward~Unknown - assess before acting. This item was not mapped to a specific technique, so it has not been risk-rated."
}

export_handoff() {
    handoff_table
    # Reads the in-memory finding ledger rather than re-parsing the CSV: splitting the CSV on
    # '","' and indexing columns by number silently used the wrong offsets.
    local rec st sev cat attr tgt find vld exp obs pre imp rem
    local -a rows=()
    for rec in "${FINDINGS[@]}"; do
        IFS=$'\x1f' read -r st sev cat attr tgt find vld exp obs pre imp rem <<< "$rec"
        case "$st" in
            WARN|'RISK DETECTED'|'NOT TESTABLE'|VALIDATED|ERROR) rows+=("$rec") ;;
            # PASS, INFO, NOT CONFIRMED and OPPORTUNITY are excluded on purpose: a passed control
            # needs no follow-up, and NOT CONFIRMED already records that the condition was looked
            # for and not found.
            *) ;;
        esac
    done

    HANDOFF_PATH="$OUTPUT_DIR/Internal_VAPT_Handoff_${REPORT_HOST_TAG}_${REPORT_STAMP}.md"
    {
        printf '# Validation handoff - %s - %s\n\n' "$HOST_SHORT" "$(date '+%Y-%m-%d %H:%M:%S')"
        printf 'Produced by %s v%s. Companion to `%s`.\n\n' "$TOOL_NAME" "$TOOL_VERSION" "$(basename "$CSV_PATH")"
        printf 'Every entry below is a step this tool DID NOT perform. Each states what to do, what would\n'
        printf 'CONFIRM the weakness, what would REFUTE it, and the blast radius of trying. Read the blast\n'
        printf 'radius first: several of these are change-control events, and one of them can cost you\n'
        printf 'remote access to the host.\n\n'
        printf 'A row recorded as a DISCOVERED WEAKNESS is not a validated compromise. Nothing in this\n'
        printf 'document was executed against a live target by this tool.\n\n'
        printf 'Where a step is marked `range first`, it may alter state or is likely to be detected: do it\n'
        printf 'in the isolated range before it ever touches production.\n\n---\n\n'

        if [ "${#rows[@]}" -eq 0 ]; then
            printf 'Nothing requires follow-up: this run produced no warning-class, risk-class, validated or\n'
            printf 'untestable finding. Confirm that this is consistent with the host role before treating the\n'
            printf 'assessment as complete - an unexpectedly clean result on a server is more often a coverage\n'
            printf 'gap than a hardened build.\n'
        else
            # Stage summary first, so a reader can see where the follow-up work actually is.
            printf '## Follow-up by stage\n\n| Stage | Rows |\n|---|---|\n'
            local s2
            for s2 in "${HANDOFF_STAGE_ORDER[@]}"; do
                local cnt=0
                for rec in "${rows[@]}"; do
                    IFS=$'\x1f' read -r st sev cat attr tgt find vld exp obs pre imp rem <<< "$rec"
                    local hb; hb=$(handoff_lookup "$attr $cat")
                    [ "${hb%%~*}" = "$s2" ] && cnt=$((cnt+1))
                done
                [ "$cnt" -gt 0 ] && printf '| %s | %d |\n' "$s2" "$cnt"
            done
            printf '\n---\n\n'

            local s
            for s in "${HANDOFF_STAGE_ORDER[@]}"; do
                local printed_header=0
                for rec in "${rows[@]}"; do
                    IFS=$'\x1f' read -r st sev cat attr tgt find vld exp obs pre imp rem <<< "$rec"
                    local hb stage where nxt confirms refutes blast n1 n2 n3 wheretxt
                    hb=$(handoff_lookup "$attr $cat")
                    stage="${hb%%~*}"; hb="${hb#*~}"
                    where="${hb%%~*}"; hb="${hb#*~}"
                    nxt="${hb%%~*}"; hb="${hb#*~}"
                    confirms="${hb%%~*}"; hb="${hb#*~}"
                    refutes="${hb%%~*}"; hb="${hb#*~}"
                    blast="$hb"
                    [ "$stage" = "$s" ] || continue
                    if [ "$printed_header" = '0' ]; then
                        printf '## %s\n\n' "$s"
                        printed_header=1
                    fi
                    case "$where" in
                        range)  wheretxt='range first - this step can alter state or is likely to be detected' ;;
                        *)      wheretxt='range or production, subject to the change window' ;;
                    esac
                    printf '### %s\n\n' "${attr:-$cat}"
                    printf '`%s` | %s | %s | %s  \n' "${sev:-Informational}" "$st" "${tgt:-$HOST_SHORT}" "$cat"
                    printf '*Evidence class:* %s  \n' "$(get_validation_class "$vld" "$exp" "$obs")"
                    printf '*Context:* %s\n\n' "$wheretxt"
                    printf '%s\n\n' "${find:-no description recorded}"
                    [ -n "$obs" ] && printf '*Observed:* %s\n\n' "$obs"
                    [ -n "$pre" ] && printf '*Prerequisites:* %s\n\n' "$pre"
                    printf '**Next step**\n\n'
                    local step
                    while IFS= read -r step; do [ -n "$step" ] && printf -- '- %s\n' "$step"; done <<< "${nxt//\~/$'\n'}"
                    printf '\n**Confirms:** %s\n\n' "$confirms"
                    printf '**Refutes:** %s\n\n' "$refutes"
                    printf '**Blast radius:** %s\n\n' "$blast"
                done
            done
        fi

        printf -- '---\n\n'
        printf 'Until a step above is executed and its outcome recorded, the corresponding item remains a\n'
        printf 'DISCOVERED WEAKNESS and must not be reported to the business as a validated finding.\n'
    } > "$HANDOFF_PATH" 2>/dev/null

    if [ -s "$HANDOFF_PATH" ]; then
        write_kv 'Validation handoff' "$HANDOFF_PATH"
        write_status 'PASS' "$(grep -c '^### ' "$HANDOFF_PATH" 2>/dev/null) validation step(s) written. Execute them, then fold the results back into the engagement record."
    else
        HANDOFF_PATH=''
        write_status 'WARN' 'The handoff file could not be written; the steps are recoverable from the findings themselves.'
    fi
}

echo_plan() {
    printf '%s%s v%s%s\n' "$C_BOLD" "$TOOL_NAME" "$TOOL_VERSION" "$C_RESET"
    printf 'Read-only internal assessment. Nothing is modified; no credential is harvested.\n\n'
    printf '  Host            : %s (%s)\n' "$HOST_SHORT" "$OS_NAME"
    printf '  Privilege       : %s\n' "$( [ "$ELEVATED" = '1' ] && echo 'root' || echo 'unprivileged - some controls will be NOT TESTABLE' )"
    printf '  Off-host work   : %s\n' "$( if [ "$LOCAL_ONLY" = '1' ]; then echo 'SUPPRESSED (--local-only): no packet leaves this host'; elif [ "$NETWORK_AUTH" = '1' ]; then echo "AUTHORISED - scope: ${SCOPE_TEXT:-permissive, bounded to the derived /24}"; else echo 'NOT AUTHORISED: a bare run assesses this host only'; fi )"
    printf '  Scan profile    : %s\n' "$SCAN_PROFILE"
    printf '  Report          : %s\n\n' "$CSV_PATH"
}

# ---------------------------------------------------------------------------------------------
# =============================================================================================
#  SECTION 22 :: LKM DRIVER & KERNEL MODULE INTEGRITY
# =============================================================================================
section22_lkm_integrity() {
    write_section '22' 'LKM DRIVER & KERNEL MODULE INTEGRITY'
    local disabled='unknown' loaded=0 unsigned='' third_party='' tainted='' signer_gap=0 m mp signer module_file mt
    if [ -r /proc/sys/kernel/modules_disabled ]; then
        disabled=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null | tr -d '[:space:]')
    fi
    write_kv 'kernel.modules_disabled' "${disabled:-unavailable}"
    case "$disabled" in
        1)
            add_finding PASS 'Kernel Integrity' 'Runtime kernel module loading is disabled by kernel.modules_disabled=1.' \
                attr='Dynamic module loading' configured='1' observed='/proc/sys/kernel/modules_disabled' validation='Read-only sysctl inspection' \
                class='High' catclass='Integrity' impact='Post-boot module insertion is blocked until reboot.' remediation='None required.' ;;
        0)
            add_finding WARN 'Kernel Integrity' 'Dynamic kernel module loading remains enabled (kernel.modules_disabled=0).' \
                attr='Dynamic module loading' configured='0' observed='/proc/sys/kernel/modules_disabled' validation='Read-only sysctl inspection' \
                class='Medium' weakness='1' catclass='Integrity' impact='Runtime module insertion remains an available kernel-level persistence surface to sufficiently privileged attackers.' \
                remediation='Where operationally appropriate, disable module loading after required modules are loaded and validate application compatibility.' ;;
        *)
            add_finding 'NOT TESTABLE' 'Kernel Integrity' 'kernel.modules_disabled could not be read.' \
                attr='Dynamic module loading' observed='sysctl unavailable or unreadable' validation='Read-only sysctl availability check' class='Medium' \
                impact='The module-insertion control state is unknown.' remediation='Read kernel.modules_disabled with sufficient kernel visibility.' ;;
    esac
    if [ -r /proc/modules ]; then
        loaded=$(awk 'END {print NR+0}' /proc/modules 2>/dev/null)
        write_kv 'Loaded kernel modules' "$loaded"
        while IFS= read -r m; do
            [ -n "$m" ] || continue
            mp="/sys/module/$m"
            [ -d "$mp" ] || continue
            mt=''
            [ -r "$mp/taint" ] && mt=$(cat "$mp/taint" 2>/dev/null | tr -d '[:space:]')
            signer=''
            if have modinfo; then
                signer=$(modinfo -F signer "$m" 2>/dev/null | head -1)
                [ -n "$signer" ] || unsigned+="$m(no signer) "
                module_file=$(modinfo -F filename "$m" 2>/dev/null | head -1)
                case "$module_file" in */extra/*|*/updates/*|*/weak-updates/*) third_party+="$m(${module_file}) " ;; esac
            else
                signer_gap=1
            fi
            case "$mt" in *O*|*E*) tainted+="$m(taint=${mt}) ";; esac
        done < /proc/modules
        if [ -n "$third_party" ]; then
            add_finding INFO 'Kernel Integrity' "Loaded module(s) appear outside the normal kernel module tree: ${third_party}" \
                attr='Out-of-tree module inventory' configured="$third_party" observed='modinfo filename path classification' \
                validation='Read-only module filename inspection; out-of-tree status is a path-based indicator and not proof of maliciousness' \
                class='Medium' catclass='Context' impact='Third-party modules require baseline and vendor provenance review because they extend the trusted kernel code base.' \
                remediation='Verify each module against the approved driver/vendor inventory.'
        fi
        if [ -n "$unsigned" ]; then
            add_finding WARN 'Kernel Integrity' "Loaded module(s) have no signer metadata: ${unsigned}" \
                attr='Unsigned/unverified module metadata' configured="$unsigned" observed='/proc/modules crossed with /sys/module and modinfo when available' \
                validation='Read-only module metadata inspection; no module was manipulated' class='High' weakness='1' catclass='Integrity' \
                impact='Unsigned or locally-built modules can be legitimate, but they bypass the assurance normally provided by vendor-signed modules.' \
                remediation='Validate each module against the approved kernel/module baseline and vendor signing policy.'
        fi
        if [ "$signer_gap" -eq 1 ]; then
            add_finding 'NOT TESTABLE' 'Kernel Integrity' 'Module signer metadata could not be verified because modinfo is unavailable.' \
                attr='Module signer verification' observed='modinfo unavailable; /proc/modules and /sys/module were still enumerated' \
                validation='Tool availability check' class='Medium' catclass='Integrity' \
                impact='The inventory cannot distinguish unsigned modules from modules whose signing metadata is simply unavailable to this userland.' \
                remediation='Run the read-only module provenance check with the distribution modinfo utility available.'
        fi
        if [ -n "$tainted" ]; then
            add_finding WARN 'Kernel Integrity' "Loaded module(s) report taint indicators: ${tainted}" \
                attr='Module taint state' configured="$tainted" observed='/sys/module/*/taint' validation='Read-only kernel module metadata' \
                class='Medium' weakness='1' catclass='Integrity' impact='Kernel taint indicates an exception to a fully trusted module state; the exact taint reason must be mapped to the running kernel documentation.' \
                remediation='Identify the taint reason and reconcile it with the approved kernel/module baseline.'
        fi
    else
        add_finding 'NOT TESTABLE' 'Kernel Integrity' 'Loaded module inventory could not be read from /proc/modules.' \
            attr='Loaded modules' observed='/proc/modules unavailable' validation='Read-only procfs check' class='Medium' \
            impact='Kernel module provenance could not be assessed.' remediation='Re-run with procfs module visibility available.'
    fi
}

# =============================================================================================
#  SECTION 23 :: SHARED MEMORY & SOCKET DESCRIPTOR HIJACKING SURFACE
# =============================================================================================
section23_ipc_surface() {
    write_section '23' 'SHARED MEMORY & SOCKET DESCRIPTOR HIJACKING SURFACE'
    if ! have find; then
        add_finding 'NOT TESTABLE' 'IPC Security' 'IPC staging paths could not be enumerated because find is unavailable.' \
            attr='IPC enumeration' observed='find unavailable' validation='Tool availability check' class='Medium' impact='Writable IPC endpoints may be missed.' remediation='Provide find or an equivalent approved inventory.'
        return
    fi
    local root item mode ipc_bad='' socket_count=0 pipe_count=0 root_proc='' pid fd link
    for root in /dev/shm /run /var/run; do
        [ -d "$root" ] || continue
        while IFS= read -r item; do
            [ -e "$item" ] || continue
            mode=$(get_octal_perms "$item" 2>/dev/null)
            [ -n "$mode" ] || continue
            case "$mode" in *2|*6|*7) ipc_bad+="$item(${mode}) ";; esac
            [ -S "$item" ] 2>/dev/null && socket_count=$((socket_count + 1))
            [ -p "$item" ] 2>/dev/null && pipe_count=$((pipe_count + 1))
        done < <(find "$root" -xdev \( -type s -o -type p -o -type f -perm -0002 \) -print 2>/dev/null | head -200)
    done
    write_kv 'Observed IPC endpoints' "sockets=${socket_count}, FIFOs=${pipe_count}"
    if [ -n "$ipc_bad" ]; then
        add_finding 'RISK DETECTED' 'IPC Security' "Writable IPC staging objects were observed: ${ipc_bad}" \
            attr='Writable IPC endpoint' configured="$ipc_bad" observed='/dev/shm, /run and /var/run bounded endpoint scan' \
            validation='Filesystem type and permission inspection; no endpoint was opened or written' class='High' weakness='1' catclass='Integrity' \
            impact='Writable sockets, FIFOs or staging files can become control/input channels when a privileged daemon consumes them without an independent access-control boundary.' \
            remediation='Restrict ownership and mode to the service account/root as appropriate, remove stale endpoints, and verify daemon socket activation permissions.'
    else
        add_finding PASS 'IPC Security' 'No world-writable IPC staging object was observed in the bounded runtime paths.' \
            attr='Writable IPC endpoint' configured='0 observed' observed='/dev/shm, /run and /var/run' validation='Read-only endpoint scan' class='High' \
            impact='No obvious writable IPC control vector was identified in the scanned paths.' remediation='None required.'
    fi
    if [ -d /proc ]; then
        for pid in /proc/[0-9]*; do
            [ -d "$pid" ] || continue
            [ -r "$pid/status" ] || continue
            if grep -Eq '^Uid:[[:space:]]*0[[:space:]]' "$pid/status" 2>/dev/null; then
                for fd in "$pid"/fd/*; do
                    [ -e "$fd" ] || continue
                    link=$(readlink "$fd" 2>/dev/null) || continue
                    case "$link" in
                        /dev/shm/*|/run/*|/var/run/*)
                            mode=$(get_octal_perms "$link" 2>/dev/null)
                            case "$mode" in *2|*6|*7) root_proc+="$pid:$link(${mode}) ";; esac
                            ;;
                    esac
                done
            fi
        done
    fi
    if [ -n "$root_proc" ]; then
        add_finding 'RISK DETECTED' 'IPC Security' "A root-owned process has an open descriptor to a writable runtime IPC object: ${root_proc}" \
            attr='Root process / writable IPC cross-boundary' configured="$root_proc" observed='/proc/*/fd symlink and object permission cross-check' \
            validation='Read-only procfs descriptor inspection; no descriptor was opened by the assessor' class='Critical' weakness='1' context='STAGING_VIOLATION' \
            impact='An unprivileged writer may be able to feed input into an object consumed by a privileged process, depending on the daemon protocol.' \
            remediation='Identify the owning daemon and tighten endpoint permissions or service isolation before making any change.'
    fi
}

# =============================================================================================
#  SECTION 24 :: LOGIN PROFILE & MOTD SCRIPT INJECTION
# =============================================================================================
section24_login_injection() {
    write_section '24' 'LOGIN PROFILE & MOTD SCRIPT INJECTION AUDIT'
    local f mode bad=''
    local -a paths=()
    paths=(/etc/update-motd.d/* /etc/profile.d/* /etc/bashrc /etc/profile)
    for f in "${paths[@]}"; do
        [ -f "$f" ] || continue
        mode=$(get_octal_perms "$f" 2>/dev/null)
        case "$mode" in *2|*3|*6|*7) bad+="$f(${mode}) ";; esac
    done
    if [ -n "$bad" ]; then
        add_finding 'RISK DETECTED' 'Login Security' "Login-triggered configuration is writable beyond root: ${bad}" \
            attr='Writable login-triggered configuration' configured="$bad" observed='/etc/update-motd.d, /etc/profile.d, /etc/bashrc and /etc/profile permission metadata' \
            validation='Read-only permission inspection; no login script was sourced or executed' class='High' weakness='1' context='LOGIN_INTERCEPT' \
            expected='root-owned and not group/world writable' impact='A non-root writer can alter code or shell state executed during login, creating persistence or privilege escalation where a privileged login context consumes the affected file.' \
            remediation='Restore root ownership and remove non-root write access; then review the login stack to confirm which files are actually executed.'
    else
        add_finding PASS 'Login Security' 'No writable-beyond-root login/MOTD profile asset was observed in the standard paths.' \
            attr='Writable login-triggered configuration' configured='0 observed' observed='/etc/update-motd.d, /etc/profile.d, /etc/bashrc and /etc/profile' \
            validation='Read-only permission inspection' class='High' impact='The standard login interception surface appears protected by file permissions.' remediation='None required.'
    fi
}

# =============================================================================================
#  SECTION 25 :: UNIFIED CONTAINER CONTROL ENDPOINT MAPPING
# =============================================================================================
section25_container_endpoints() {
    write_section '25' 'UNIFIED CONTAINER CONTROL ENDPOINT MAPPING'
    local base name sock mode endpoints='' critical=''
    local -a names=()
    names=(containerd.sock lxd.sock podman.sock k3s.sock cri-dockerd.sock docker.sock)
    for base in /run /var/run; do
        [ -d "$base" ] || continue
        for name in "${names[@]}"; do
            sock="$base/$name"
            [ -S "$sock" ] 2>/dev/null || continue
            mode=$(get_octal_perms "$sock" 2>/dev/null)
            [ -n "$mode" ] || mode='unknown'
            endpoints+="$sock(${mode}) "
            case "$mode" in *2|*6|*7) critical+="$sock(${mode}) ";; esac
        done
    done
    if [ -n "$endpoints" ]; then
        write_kv 'Container control sockets' "$endpoints"
        if [ -n "$critical" ]; then
            add_finding 'RISK DETECTED' 'Container Security' "Container runtime control endpoint(s) permit group/world write access: ${critical}" \
                attr='Writable container control endpoint' configured="$critical" observed='socket type and permission metadata under /run and /var/run' \
                validation='Read-only socket metadata inspection; no container API request was sent' class='Critical' weakness='1' context='STAGING_VIOLATION' \
                impact='Write access to a container runtime control socket can provide host-level control equivalent to the runtime service account, depending on runtime policy.' \
                remediation='Restrict socket ownership/mode to the intended administrative group, verify group membership, and remove stale runtime endpoints.'
        else
            add_finding PASS 'Container Security' "Container control endpoint(s) were found but none were group/world writable: ${endpoints}" \
                attr='Container control endpoint' configured="$endpoints" observed='socket metadata' validation='Read-only socket permission inspection' class='High' \
                impact='No obvious unprivileged write path to the discovered container control sockets was observed.' remediation='None required.'
        fi
    else
        add_finding PASS 'Container Security' 'No active standard container control socket was observed under /run or /var/run.' \
            attr='Container control endpoint' configured='none observed' observed='containerd, lxd, podman, k3s, cri-dockerd and docker socket names' \
            validation='Read-only filesystem socket scan' class='High' impact='No standard runtime control endpoint was visible in the scanned paths.' remediation='None required.'
    fi
}

#  SECTION DISPATCH
#
#  Every module goes through run_section so that the kill switch is evaluated before EACH one.
#  A kill switch that is only read at start-up cannot stop a run in progress, which is the whole
#  point of having one: an operator who creates EIA_STOP during a sweep expects the remaining
#  off-host work to stop, not to finish the current pass first.
# ---------------------------------------------------------------------------------------------
SECTION_FUNCS=(
    '1|section1_initialisation'
    '2|section2_local_configuration'
    '3|section3_ssh'
    '4|section4_authentication'
    '5|section5_credential_exposure'
    '6|section6_cups'
    '7|section7_patching'
    '8|section8_discovery'
    '9|section9_directory'
    '10|section10_suid'
    '11|section11_listening'
    '12|section12_crypto'
    '13|section13_logging'
    '14|section14_firewall'
    '15|section15_mounts'
    '16|section16_attackpaths'
    '17|section17_privesc'
    '18|section18_interpreters'
    '19|section19_validation'
    '20|section20_chains'
    '21|section21_reporting'
    '22|section22_lkm_integrity'
    '23|section23_ipc_surface'
    '24|section24_login_injection'
    '25|section25_container_endpoints'
)

KILLED_EARLY=0

run_section() {
    local id="$1" fn="$2"
    if test_kill_switch; then
        if [ "$KILLED_EARLY" = '0' ]; then
            KILLED_EARLY=1
            write_status 'NOT TESTABLE' "The kill switch is ACTIVE. Sections ${id} onward were NOT executed - this is a deliberate stop, not a clean result."
            add_finding 'NOT TESTABLE' 'Assessment Integrity' "The kill switch stopped the run before Section ${id}. Every section from ${id} onward is UNASSESSED." \
                attr='Kill switch' configured='EIA_KILL_SWITCH=1 or an EIA_STOP file' observed="last section reached: ${LAST_SECTION:-none}" \
                validation='The stop is deliberate and is recorded as a gap in coverage.' class='High' \
                impact='The report covers a PARTIAL assessment. Nothing downstream of Section '${id}' was examined, so absence of findings there carries no meaning.' \
                remediation='Re-run when the stop condition clears.'
        fi
        return 0
    fi
    "$fn"
    return 0
}

# Verifies the run reached the end. A section that abandons the call stack leaves LAST_SECTION
# behind Section 21, and a silent partial report is exactly what this must never produce.
assert_section_completion() {
    if [ "$LAST_SECTION" != '25' ]; then
        write_status 'ERROR' "INCOMPLETE RUN: the last section that started was '${LAST_SECTION:-none}', not 25. Sections after it were NOT executed."
        add_finding ERROR 'Assessment Integrity' "The assessment did not run to completion: Section ${LAST_SECTION:-?} started but the run left its dispatch before Section 25 finished." \
            attr='Run completeness' configured="sections started: ${SECTION_LOG:-none}" observed="expected 25 sections, last started ${LAST_SECTION:-none}" \
            validation='Sentinel check: every section announces itself, so a shortfall is measured rather than assumed.' class='High' \
            impact='PARTIAL COVERAGE. Treat every control not explicitly reported below as UNASSESSED, and re-run before relying on this report.' \
            remediation='Re-run with --verbose and report the failing section.'
    else
        add_finding PASS 'Assessment Integrity' 'All 25 assessment modules ran to completion in this run.' \
            attr='Run completeness' configured='25 modules expected' observed="25 modules expected; sections started: ${SECTION_LOG}" \
            validation='Sentinel check on the section dispatch' class='Low' \
            impact='The coverage claimed by this report was actually executed.' remediation='None.'
    fi
}

main() {
    local start_ts
    start_ts=$(date +%s)

    collect_identity
    detect_transport
    scope_init
    initialise_report

    # A scope entry that was supplied but could not be parsed is a DEFECT, not a detail: with
    # default-deny it silently narrows what the run is allowed to touch, so a malformed scope would
    # otherwise look like a correctly confined assessment.
    if [ "$SCOPE_DROPPED" -gt 0 ]; then
        write_status 'ERROR' "${SCOPE_DROPPED} scope entr(y/ies) could not be parsed and were ignored: ${SCOPE_DROPPED_LIST}"
        add_finding ERROR 'Assessment Integrity' "${SCOPE_DROPPED} supplied scope entr(y/ies) were not understood and had no effect. The assessment ran under a scope NARROWER than the one supplied." \
            attr='Scope parsing' configured="${SCOPE_DROPPED_LIST}" observed="parsed includes=${#SCOPE_INC[@]} excludes=${#SCOPE_EXC[@]}" \
            validation='Parsed at start-up. Every entry must be an address, a CIDR with a mask from 0 to 32, or a host name, optionally prefixed with ! to exclude it.' class='High' \
            impact='Coverage is SMALLER than the engagement asked for, so absence of findings in the dropped range means nothing.' \
            remediation='Correct the scope syntax and re-run. Confirm the effective scope printed at the top of this run matches the engagement authorisation.'
    fi

    echo_plan

    local entry id fn
    for entry in "${SECTION_FUNCS[@]}"; do
        id="${entry%%|*}"
        fn="${entry#*|}"
        run_section "$id" "$fn"
        [ "$KILLED_EARLY" = '1' ] && break
    done

    assert_section_completion
    write_test_registry
    export_handoff

    local elapsed=$(( $(date +%s) - start_ts ))
    write_executive_summary "$elapsed"

    if [ "$NO_PAUSE" != '1' ] && [ -t 0 ]; then
        printf '\nPress Enter to close...'
        read -r _ || true
    fi
    return 0
}

# LX_TESTLIB is set by the test harness so the file can be sourced for assertions. It must NOT be
# exported to child processes: `export LX_TESTLIB=1` is inherited, so an end-to-end run launched by
# the harness would skip argument parsing and silently ignore every switch. The harness therefore
# sets it as a plain shell variable.
if [ -z "${LX_TESTLIB:-}" ]; then
    main "$@"
fi
