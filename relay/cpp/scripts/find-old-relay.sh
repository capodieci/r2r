#!/usr/bin/env bash
# Finds the previous R2R relay on this host and reports exactly what to remove:
# which runtime it was, where its application file lives, and where its data
# directory is.
#
#   ./find-old-relay.sh                    report only (default, changes nothing)
#   ./find-old-relay.sh --purge --yes      stop it and remove app + data
#   ./find-old-relay.sh --purge --yes --no-archive
#
# All four old installs share one unit name -- /etc/systemd/system/r2r-relay.service --
# which is also the name the new relay uses. They are told apart by ExecStart:
#
#   /usr/bin/php    %h/relay-server.php   -> PHP
#   /usr/bin/python3 %h/relay-server.py   -> Python
#   /usr/bin/node   %h/relay-server.js    -> Node
#   %h/r2r-relay                          -> old compiled binary
#   %h/r2r                                -> old compiled binary, other name
#   /usr/local/bin/r2r-relay              -> the NEW relay; never touched
#
# Some hosts run the old binary under a unit with a different name, or from
# cron or rc.local, and the unit scan alone misses those. So whatever holds
# port 8787 is inspected directly: its executable, working directory and the
# systemd unit (or parent process) that started it. If that is not the new
# relay, it is the old one, and its supervisor goes into the removal plan --
# otherwise the old relay respawns the moment install.sh stops it.
#
# The data directory holds users' stored messages, voice notes and video. By
# default --purge archives it to a tarball before removing anything; that is
# the difference between a migration and losing everyone's history.
set -uo pipefail

PURGE=0; ASSUME_YES=0; ARCHIVE=1
ARCHIVE_DIR="/var/backups/r2r"
UNIT_PATH="/etc/systemd/system/r2r-relay.service"

while [ $# -gt 0 ]; do
    case "$1" in
        --purge) PURGE=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --no-archive) ARCHIVE=0 ;;
        --archive-dir) ARCHIVE_DIR="${2:-$ARCHIVE_DIR}"; shift ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

say()  { printf '%s\n' "$*"; }
head1() { printf '\n== %s ==\n' "$*"; }

FOUND_KIND=""; FOUND_APP=""; FOUND_DATA=""; FOUND_USER=""; FOUND_UNIT=""

# --- 1. the systemd unit ----------------------------------------------------
head1 "systemd unit"

inspect_unit() {
    local unit="$1"
    [ -r "$unit" ] || return 1

    local exec_start work_dir svc_user data_env port_env
    exec_start="$(grep -m1 -E '^\s*ExecStart=' "$unit" | sed 's/^\s*ExecStart=//')"
    work_dir="$(grep -m1  -E '^\s*WorkingDirectory=' "$unit" | sed 's/^\s*WorkingDirectory=//')"
    svc_user="$(grep -m1  -E '^\s*User=' "$unit" | sed 's/^\s*User=//')"
    data_env="$(grep -m1  -E '^\s*Environment=DATA_DIR=' "$unit" | sed 's/.*DATA_DIR=//')"
    port_env="$(grep -m1  -E '^\s*Environment=PORT=' "$unit" | sed 's/.*PORT=//')"

    say "unit:           $unit"
    say "ExecStart:      ${exec_start:-<none>}"
    say "User:           ${svc_user:-<default: root>}"
    say "WorkingDirectory: ${work_dir:-<none>}"
    [ -n "$port_env" ] && say "PORT:           $port_env"

    # %h in a system unit is the home of User=.
    local home=""
    if [ -n "$svc_user" ]; then
        home="$(getent passwd "$svc_user" 2>/dev/null | cut -d: -f6)"
    fi
    [ -z "$home" ] && home="/root"
    local resolved_wd="${work_dir//\%h/$home}"
    [ -z "$resolved_wd" ] && resolved_wd="$home"

    case "$exec_start" in
        */php\ *)      FOUND_KIND="PHP" ;;
        */python3\ *|*/python\ *) FOUND_KIND="Python" ;;
        */node\ *)     FOUND_KIND="Node.js" ;;
        /usr/local/bin/r2r-relay*) FOUND_KIND="NEW" ;;
        *r2r-relay*)   FOUND_KIND="old compiled binary" ;;
        */r2r|*/r2r\ *) FOUND_KIND="old compiled binary" ;;
        *)             FOUND_KIND="unrecognised" ;;
    esac

    if [ "$FOUND_KIND" = "NEW" ]; then
        say "verdict:        this is the NEW C++ relay -- nothing to remove here"
        return 0
    fi

    # The application file is the last whitespace-separated token that looks
    # like a path (the script for interpreted variants, the binary otherwise).
    local app
    app="$(printf '%s\n' "$exec_start" | awk '{print $NF}')"
    app="${app//\%h/$home}"
    case "$app" in
        /*) ;;
        *)  app="${resolved_wd%/}/${app#./}" ;;
    esac

    local data="${data_env:-./r2r-relay-data}"
    data="${data//\%h/$home}"
    case "$data" in
        /*) ;;
        *)  data="${resolved_wd%/}/${data#./}" ;;
    esac

    say ""
    say "runtime:        $FOUND_KIND"
    say "application:    $app $( [ -f "$app" ] && echo "(present, $(du -sh "$app" 2>/dev/null | cut -f1))" || echo '(MISSING)' )"
    say "data directory: $data $( [ -d "$data" ] && echo "(present, $(du -sh "$data" 2>/dev/null | cut -f1), $(find "$data" -type f 2>/dev/null | wc -l) files)" || echo '(MISSING)' )"

    FOUND_APP="$app"; FOUND_DATA="$data"; FOUND_USER="$svc_user"; FOUND_UNIT="$unit"
    return 0
}

if [ -r "$UNIT_PATH" ]; then
    inspect_unit "$UNIT_PATH"
else
    say "no unit at $UNIT_PATH"
fi

# Any other unit that runs a relay-server script.
for u in /etc/systemd/system/*.service /lib/systemd/system/*.service; do
    [ -r "$u" ] || continue
    [ "$u" = "$UNIT_PATH" ] && continue
    if grep -qE 'ExecStart=.*(relay-server\.(php|py|js)|/r2r-relay|/r2r( |$))' "$u" 2>/dev/null; then
        say ""
        say "additional relay unit found:"
        inspect_unit "$u"
    fi
done

# --- 2. filesystem sweep ----------------------------------------------------
# The unit may already have been overwritten by a new install, which would take
# the record of where the old data lived with it. Look for the artefacts too.
head1 "filesystem sweep"
sweep_hits=0
for base in /root /home/*; do
    [ -d "$base" ] || continue
    for f in "$base"/relay-server.php "$base"/relay-server.py "$base"/relay-server.js "$base"/r2r-relay "$base"/r2r; do
        # Regular files only. A checkout of the new relay's source sits at
        # ~/r2r-relay as a *directory*, and matching that would point the purge
        # at the wrong thing entirely.
        [ -f "$f" ] || continue
        say "app:  $f  ($(du -sh "$f" 2>/dev/null | cut -f1), modified $(date -r "$f" '+%Y-%m-%d %H:%M' 2>/dev/null))"
        sweep_hits=$((sweep_hits+1))
    done
    if [ -d "$base/r2r-relay-data" ]; then
        say "data: $base/r2r-relay-data  ($(du -sh "$base/r2r-relay-data" 2>/dev/null | cut -f1), $(find "$base/r2r-relay-data" -type f 2>/dev/null | wc -l) files)"
        sweep_hits=$((sweep_hits+1))
    fi
done
[ "$sweep_hits" -eq 0 ] && say "nothing found in /root or /home/*"

# --- 3. who holds the ports -------------------------------------------------
# The process on 8787 is the ground truth. Whatever unit scan and sweep say,
# if something other than /usr/local/bin/r2r-relay is listening there, that
# is the old relay, and the thing that started it has to be stopped too.
head1 "ports"
HOLDER_PIDS=(); HOLDER_UNITS=()

port_pids() { { ss -lntpH "sport = :$1" 2>/dev/null || true; } | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u; }
unit_of_pid() { sed -n 's|.*/\([^/]*\.service\)$|\1|p' "/proc/$1/cgroup" 2>/dev/null | head -1; }

for port in 8787 8788; do
    pids="$(port_pids "$port")"
    [ -n "$pids" ] || { say "  $port: free"; continue; }
    for pid in $pids; do
        # Never act on init, a process group (0) or this script.
        { [ "$pid" -gt 1 ] 2>/dev/null && [ "$pid" != "$$" ]; } || continue
        cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | sed 's/ $//')"
        exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null)"
        [ -n "$exe" ] || exe="$(printf '%s' "$cmd" | awk '{print $1}')"
        cwd="$(readlink -f "/proc/$pid/cwd" 2>/dev/null)"
        puser="$(stat -c %U "/proc/$pid" 2>/dev/null)"
        unit="$(unit_of_pid "$pid")"
        ppid="$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')"
        pcomm="$(ps -o comm= -p "${ppid:-0}" 2>/dev/null)"
        say "  $port: PID $pid (${puser:-?}): ${cmd:-?}"
        say "        executable $exe"
        [ -n "$cwd" ] && say "        working dir $cwd"
        if [ -n "$unit" ]; then
            say "        started by systemd unit $unit"
        else
            say "        parent process ${pcomm:-?} (PID ${ppid:-?}) -- not systemd: look in crontab and /etc/rc.local"
        fi
        case "$exe" in
            /usr/local/bin/r2r-relay) say "        this is the NEW relay"; continue ;;
        esac
        say "        => this is the OLD relay"
        HOLDER_PIDS+=("$pid")
        [ -n "$unit" ] && HOLDER_UNITS+=("$unit")

        # Where its application and data are, when the unit scan did not say.
        app="$exe"
        case "$(basename "$exe")" in
            node|php|php[0-9]*|python|python3|python3.*)
                app="$(printf '%s\n' "$cmd" | tr ' ' '\n' | grep -m1 -E 'relay-server\.(php|py|js)$')"
                case "$app" in ""|/*) ;; *) app="${cwd%/}/${app#./}" ;; esac ;;
        esac
        if [ -z "$FOUND_APP" ] && [ -n "$app" ] && [ -f "$app" ]; then
            FOUND_APP="$app"; FOUND_KIND="running process"; FOUND_USER="$puser"
            say "        application $app"
        fi
        if [ -z "$FOUND_DATA" ]; then
            for d in "$cwd/r2r-relay-data" "$(dirname "$app")/r2r-relay-data"; do
                [ -d "$d" ] || continue
                FOUND_DATA="$d"
                say "        data directory $d ($(du -sh "$d" 2>/dev/null | cut -f1), $(find "$d" -type f 2>/dev/null | wc -l) files)"
                break
            done
        fi
        # The unit that started it, if the scan above did not already show it.
        if [ -n "$unit" ] && [ "$unit" != "r2r-relay.service" ] && [ "$FOUND_UNIT" != "$unit" ]; then
            frag="$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null)"
            [ -n "$frag" ] && say "        unit file $frag"
        fi
    done
done

# Anything that would relaunch the application after it is removed.
RELAUNCH_NOTES=()
if [ -n "$FOUND_APP" ]; then
    for u in root ${FOUND_USER:-}; do
        if crontab -l -u "$u" 2>/dev/null | grep -qF "$FOUND_APP"; then
            RELAUNCH_NOTES+=("crontab of $u references $FOUND_APP")
        fi
    done
    if [ -f /etc/rc.local ] && grep -qF "$FOUND_APP" /etc/rc.local; then
        RELAUNCH_NOTES+=("/etc/rc.local references $FOUND_APP")
    fi
fi

# --- 4. plan / purge --------------------------------------------------------
head1 "removal plan"
if [ -z "$FOUND_APP" ] && [ "$sweep_hits" -eq 0 ] && [ ${#HOLDER_PIDS[@]} -eq 0 ]; then
    say "No previous relay found on this host. Nothing to remove."
    exit 0
fi

# Units to stop: the shared name, plus whatever the port holder runs under.
UNITS_TO_STOP=()
if systemctl list-unit-files 2>/dev/null | grep -q '^r2r-relay\.service'; then
    UNITS_TO_STOP+=("r2r-relay.service")
fi
for u in "${HOLDER_UNITS[@]}"; do
    case " ${UNITS_TO_STOP[*]} " in *" $u "*) ;; *) UNITS_TO_STOP+=("$u") ;; esac
done

step=1
for u in "${UNITS_TO_STOP[@]}"; do
    say "$step. systemctl stop $u && systemctl disable $u"; step=$((step+1))
done
[ ${#HOLDER_PIDS[@]} -gt 0 ] && { say "$step. stop PID(s) ${HOLDER_PIDS[*]} if still running"; step=$((step+1)); }
for n in "${RELAUNCH_NOTES[@]}"; do say "$step. remove the relaunch line: $n"; step=$((step+1)); done
[ -n "$FOUND_DATA" ] && { say "$step. archive $FOUND_DATA  (users' stored messages, voice and video live here)"; step=$((step+1)); }
[ -n "$FOUND_APP" ]  && { say "$step. rm $FOUND_APP"; step=$((step+1)); }
[ -n "$FOUND_DATA" ] && { say "$step. rm -rf $FOUND_DATA"; step=$((step+1)); }
say "$step. install the new relay (scripts/install.sh), which writes its own unit"

if [ "$PURGE" -ne 1 ]; then
    say ""
    say "Report only. Re-run with --purge --yes to carry this out."
    exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
    say ""
    say "--purge needs --yes as well. Refusing to delete user data on a bare --purge."
    exit 2
fi

[ "$(id -u)" -eq 0 ] || { say "purge needs root"; exit 1; }

head1 "purging"
for u in "${UNITS_TO_STOP[@]}"; do
    systemctl stop "$u" 2>/dev/null || true
    systemctl disable "$u" 2>/dev/null || true
    say "stopped and disabled $u"
    # A unit with another name is not overwritten by install.sh, so its file
    # would linger; remove it when it is ours to remove (under /etc) and it is
    # the old relay's, never the new relay's unit.
    if [ "$u" != "r2r-relay.service" ]; then
        frag="$(systemctl show -p FragmentPath --value "$u" 2>/dev/null)"
        case "$frag" in
            /etc/systemd/system/*)
                if ! grep -q '/usr/local/bin/r2r-relay' "$frag" 2>/dev/null; then
                    rm -f "$frag" && say "removed $frag"
                fi ;;
        esac
    fi
done
for pid in "${HOLDER_PIDS[@]}"; do
    { [ "$pid" -gt 1 ] 2>/dev/null && [ "$pid" != "$$" ]; } || continue
    kill -0 "$pid" 2>/dev/null || continue
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
    if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; say "killed PID $pid"; else say "stopped PID $pid"; fi
done
if [ -n "$FOUND_APP" ]; then
    for u in root ${FOUND_USER:-}; do
        if crontab -l -u "$u" 2>/dev/null | grep -qF "$FOUND_APP"; then
            crontab -l -u "$u" 2>/dev/null | grep -vF "$FOUND_APP" | crontab -u "$u" - \
                && say "removed the crontab line(s) of $u that referenced $FOUND_APP"
        fi
    done
    if [ -f /etc/rc.local ] && grep -qF "$FOUND_APP" /etc/rc.local; then
        say "NOTE: /etc/rc.local still references $FOUND_APP -- edit it by hand"
    fi
fi

if [ -n "$FOUND_DATA" ] && [ -d "$FOUND_DATA" ] && [ "$ARCHIVE" -eq 1 ]; then
    mkdir -p "$ARCHIVE_DIR"
    stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
    archive="${ARCHIVE_DIR}/r2r-old-data-${stamp}.tar.gz"
    if tar -czf "$archive" -C "$(dirname "$FOUND_DATA")" "$(basename "$FOUND_DATA")" 2>/dev/null; then
        chmod 0600 "$archive"
        say "archived data to $archive ($(du -h "$archive" | cut -f1))"
    else
        say "ARCHIVE FAILED -- refusing to delete the data directory"
        exit 1
    fi
fi

if [ -n "$FOUND_APP" ] && [ -e "$FOUND_APP" ]; then
    case "$FOUND_APP" in
        /usr/local/bin/*) say "refusing to delete $FOUND_APP (that is the new relay)" ;;
        /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*|/lib/*|/lib64/*|/usr/lib/*|/usr/lib64/*)
            # An interpreter or a system tool, never the relay's own file.
            say "refusing to delete $FOUND_APP (system path)" ;;
        *) rm -f "$FOUND_APP" && say "removed $FOUND_APP" ;;
    esac
fi
if [ -n "$FOUND_DATA" ] && [ -d "$FOUND_DATA" ]; then
    rm -rf "$FOUND_DATA" && say "removed $FOUND_DATA"
fi

systemctl daemon-reload 2>/dev/null || true
say ""
say "Done. Install the new relay with: sudo ./scripts/install.sh <public-ip>:8787"
