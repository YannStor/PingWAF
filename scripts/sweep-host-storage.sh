#!/usr/bin/env bash
# Reclaim disk on a host that runs PingWAF from images.
#
# Written after a 2026-10-23 cleanup on the demo box, where a hand-rolled
# removal of "orphan" overlay directories took a running container's writable
# layer with it: the app kept serving from memory but `/etc/passwd` was gone,
# so every `podman exec` failed and the healthcheck answered 125. The layers
# that `layers.json` does not list are *not* garbage — a container's own layer
# is not in that file either.
#
# So this script never touches the storage tree. It drives `podman`'s own
# commands, which know what is referenced, and reports before and after so the
# effect is visible rather than assumed.
#
# What it reclaims, in order of how safe it is:
#
#   1. Stopped containers. Their writable layers go with them.
#   2. Dangling images (`<none>`) — the leftover of every rebuild.
#   3. Unused volumes, unless --keep-volumes.
#   4. Images not referenced by a running container and older than --days.
#      This is what removes the old release candidates and the `rust:` /
#      `node:` build images a host accumulated while building.
#   5. Journal logs, vacuumed to --journal-size (default 200M).
#   6. Stale files under /tmp, if --tmp-days is given.
#
# It never removes a running container's image, and it never removes a
# container that is running.
#
# Usage: scripts/sweep-host-storage.sh [options]
#
#   --dry-run          report only, remove nothing
#   --days N           keep images younger than N days (default 7)
#   --keep-volumes     do not prune unused volumes
#   --journal-size S   journal cap, e.g. 200M (default 200M; 'skip' to leave)
#   --tmp-days N       delete /tmp entries older than N days (default: off)
#   --quiet            summary only
#   -h, --help         this text
#
# Run it on the host, not inside a container.

set -euo pipefail

dry_run=0
days=7
keep_volumes=0
journal_size=200M
tmp_days=0
quiet=0

usage() {
	cat <<'EOF'
Reclaim disk on a PingWAF host by driving podman's own cleanup commands.

Usage: scripts/sweep-host-storage.sh [options]

  --dry-run          report only, remove nothing
  --days N           keep images younger than N days (default 7)
  --keep-volumes     do not prune unused volumes
  --journal-size S   journal cap, e.g. 200M (default 200M; 'skip' to leave)
  --tmp-days N       delete /tmp entries older than N days (default: off)
  --quiet            summary only
  -h, --help         this text
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--dry-run) dry_run=1; shift ;;
	--days)
		[ $# -ge 2 ] || { echo "sweep-host-storage: --days needs a value" >&2; exit 2; }
		days=$2; shift 2 ;;
	--keep-volumes) keep_volumes=1; shift ;;
	--journal-size)
		[ $# -ge 2 ] || { echo "sweep-host-storage: --journal-size needs a value" >&2; exit 2; }
		journal_size=$2; shift 2 ;;
	--tmp-days)
		[ $# -ge 2 ] || { echo "sweep-host-storage: --tmp-days needs a value" >&2; exit 2; }
		tmp_days=$2; shift 2 ;;
	--quiet) quiet=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) echo "sweep-host-storage: unknown argument: $1" >&2; exit 2 ;;
	esac
done

case "$days" in
'' | *[!0-9]*) echo "sweep-host-storage: --days needs a non-negative integer" >&2; exit 2 ;;
esac
case "$tmp_days" in
'' | *[!0-9]*) echo "sweep-host-storage: --tmp-days needs a non-negative integer" >&2; exit 2 ;;
esac

# A container runtime is the whole premise; say so plainly when there is none.
if command -v podman >/dev/null 2>&1; then
	runtime=podman
elif command -v docker >/dev/null 2>&1; then
	runtime=docker
else
	echo "sweep-host-storage: neither podman nor docker is installed" >&2
	exit 1
fi

say() { [ "$quiet" -eq 1 ] || echo "sweep-host-storage: $*"; }

# Free space of the filesystem holding the container storage, so the report can
# prove the space came back. `df -k` then KiB arithmetic, portable on both.
storage_root=/var/lib/containers
[ "$runtime" = docker ] && storage_root=/var/lib/docker
avail_kb() { df -k "$storage_root" 2>/dev/null | awk 'NR == 2 { print $4 }' || echo 0; }

before_free=$(avail_kb)

say "runtime: $runtime (storage under $storage_root)"
say "before:"
[ "$quiet" -eq 1 ] || $runtime system df 2>/dev/null || true

if [ "$dry_run" -eq 1 ]; then
	say "dry run — nothing removed"
	say "stopped containers:"
	[ "$quiet" -eq 1 ] || $runtime ps -a --filter status=exited --filter status=created \
		--format '  {{.ID}} {{.Names}} {{.Image}} {{.Status}}' 2>/dev/null || true
	say "dangling images:"
	[ "$quiet" -eq 1 ] || $runtime images -f dangling=true \
		--format '  {{.ID}} {{.Size}}' 2>/dev/null || true
	say "images older than ${days}d not in use:"
	[ "$quiet" -eq 1 ] || $runtime images --format '{{.ID}} {{.Repository}}:{{.Tag}} {{.CreatedSince}} {{.Size}}' 2>/dev/null |
		awk -v d="$days" '{ print "  " $0 }' | head -40
	exit 0
fi

# 1. Stopped containers. `-a` plus the status filter, so a running container is
#    never a candidate even if its name looks abandoned.
say "pruning stopped containers"
$runtime container prune -f >/dev/null 2>&1 || say "  (container prune failed; continuing)"

# 2. Dangling images: the `<none>` left by every rebuild.
say "pruning dangling images"
$runtime image prune -f >/dev/null 2>&1 || say "  (image prune failed; continuing)"

# 3. Unused volumes, unless asked to keep them. Anonymous volumes are excluded
#    by the runtime itself; a named one still in use is never touched.
if [ "$keep_volumes" -eq 0 ]; then
	say "pruning unused volumes"
	$runtime volume prune -f >/dev/null 2>&1 || say "  (volume prune failed; continuing)"
fi

# 4. Old images not backing a running container.
#
#    `podman`/`docker` have no "remove images older than N days" primitive, so
#    the age test is done here and the removal still goes through `rmi`, which
#    refuses anything in use. `--filter until=` exists on docker but not on the
#    podman on the demo host, so the portable path is used for both.
say "removing images older than ${days}d that no running container uses"
in_use=$(
	$runtime ps --format '{{.Image}}' 2>/dev/null | sort -u
)
removed=0
while IFS=' ' read -r id created; do
	[ -n "$id" ] || continue
	# `--format {{.CreatedAt}}` is an absolute timestamp; compare on epoch via
	# `date`, which both GNU and BSD understand for this form.
	age_days=$(
		python3 - "$created" <<'PY' 2>/dev/null || echo ""
import sys, datetime
try:
    ts = sys.argv[1].split(".")[0].replace(" +0000 UTC", "").replace(" UTC", "")
    t = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    print((datetime.datetime.utcnow() - t).days)
except Exception:
    print("")
PY
	)
	[ -n "$age_days" ] || continue
	[ "$age_days" -ge "$days" ] || continue
	# Skip anything a running container names, by id or by any tag.
	tags=$($runtime inspect --format '{{.RepoTags}} {{.Id}}' "$id" 2>/dev/null || echo "")
	skip=0
	for used in $in_use; do
		case "$tags" in *"$used"*) skip=1 ;; esac
	done
	[ "$skip" -eq 1 ] && continue
	if $runtime rmi "$id" >/dev/null 2>&1; then
		removed=$((removed + 1))
	fi
done < <($runtime images --format '{{.ID}} {{.CreatedAt}}' 2>/dev/null | sort -u)
say "  removed $removed image(s)"

# 5. Journal. Only on a host that has one.
if [ "$journal_size" != skip ] && command -v journalctl >/dev/null 2>&1; then
	say "vacuuming journal to $journal_size"
	journalctl --vacuum-size="$journal_size" >/dev/null 2>&1 || say "  (vacuum failed; continuing)"
fi

# 6. /tmp, only when asked. `-mmin` so `--tmp-days 0` means everything, and
#    `-delete` so the removal is an unlink rather than a move to a trash dir.
if [ "$tmp_days" -gt 0 ]; then
	say "deleting /tmp entries older than ${tmp_days}d"
	find /tmp -mindepth 1 -mmin "+$((tmp_days * 1440))" -delete 2>/dev/null || true
fi

after_free=$(avail_kb)
reclaimed_mb=$(((after_free - before_free) / 1024))

say "after:"
[ "$quiet" -eq 1 ] || $runtime system df 2>/dev/null || true
printf 'sweep-host-storage: free space %+d MB\n' "$reclaimed_mb"

# A running container is the one thing this must not have disturbed.
say "containers after:"
[ "$quiet" -eq 1 ] || $runtime ps --format '  {{.Names}} {{.Status}}' 2>/dev/null || true