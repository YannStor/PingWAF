#!/usr/bin/env bash
# Prune the disposable half of target/.
#
# Cargo keeps one copy of every artifact per (crate, feature set, profile) and
# never garbage-collects them, so a checkout that has been built with
# `--features=full`, `--no-default-features --features=tls-rustls,full` and
# `-p pingap-plugin --features=geo` carries several ~195 MB `pingwaf-server`
# rlibs at once. A sweep of this repo in October 2026 found 47 GB of target/
# holding 2055 rlibs for only 583 distinct crates - `pingap_core` alone had 41
# copies - plus 21000 object files. None of that was incremental cache: it was
# feature-set duplication.
#
# Two things are removed:
#
#   1. target/*/incremental - the fastest growing and cheapest part to lose.
#   2. The intermediate artifacts under target/*/deps (`*.rlib`, `*.rmeta`,
#      `*.o`, `*.d`) older than --days.
#
# The linked executables in deps/ are deliberately left alone, because
# target/<profile>/<bin> is a hard link to one of them. Anything deleted here is
# simply rebuilt by the next cargo invocation that needs it, so this trades disk
# for time and can never produce a stale or wrong build.
#
# Deletion goes through `find -delete`, not `xargs rm -f`, on purpose: under
# WorkBuddy's brokered shell `rm` on a *file* moves it to ~/.Trash instead of
# unlinking it, so file-by-file rm reports success while freeing nothing. The
# script therefore also compares free space before and after and says so out
# loud when the two disagree - the failure mode it exists to avoid.
#
# Usage: scripts/sweep-target.sh [--days N] [--dry-run] [--quiet]
#
#   --days N    only touch artifacts older than N days (default 3; 0 = all)
#   --dry-run   report what would be removed, delete nothing
#   --quiet     print only the one-line summary
#   -h, --help  this text

set -euo pipefail

days=3
dry_run=0
quiet=0

usage() {
	cat <<'EOF'
Prune the disposable half of target/: the incremental caches and the
intermediate artifacts (`*.rlib`, `*.rmeta`, `*.o`, `*.d`) that other feature
sets left behind in target/*/deps. Linked executables are never touched.

Usage: scripts/sweep-target.sh [--days N] [--dry-run] [--quiet]

  --days N    only touch artifacts older than N days (default 3; 0 = all)
  --dry-run   report what would be removed, delete nothing
  --quiet     print only the one-line summary
  -h, --help  this text
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--days)
		[ $# -ge 2 ] || { echo "sweep-target: --days needs a value" >&2; exit 2; }
		days=$2
		shift 2
		;;
	--dry-run)
		dry_run=1
		shift
		;;
	--quiet)
		quiet=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "sweep-target: unknown argument: $1" >&2
		exit 2
		;;
	esac
done

case "$days" in
'' | *[!0-9]*)
	echo "sweep-target: --days needs a non-negative integer, got '$days'" >&2
	exit 2
	;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

if [ ! -d target ]; then
	echo "sweep-target: no target/ in $root, nothing to do"
	exit 0
fi

# `du -k` and `df -k` are KiB, `du -sm` is MiB; only the KiB sums are converted.
kb_to_mb() { awk -v k="$1" 'BEGIN { printf "%.1f", k / 1024 }'; }

# Free space of the volume holding target/, so the report can prove the space
# actually came back rather than merely leaving the paths.
avail_kb() { df -k "$root" | awk 'NR == 2 { print $4 }'; }

say() { [ "$quiet" -eq 1 ] || echo "sweep-target: $*"; }

# The stale set, as a predicate so it can be used both to list and to delete.
stale() {
	dir=$1
	shift
	find "$dir" -maxdepth 1 -type f \
		\( -name '*.rlib' -o -name '*.rmeta' -o -name '*.o' -o -name '*.d' \) \
		-mmin "+$((days * 1440))" "$@"
}

deps_dirs() {
	for dir in target/*/deps; do
		[ -d "$dir" ] || continue
		echo "$dir"
	done
}

before_mb=$(du -sm target | cut -f1)
before_free=$(avail_kb)

# 1. Incremental caches. A loop rather than a bare glob so a profile that has
# none costs nothing. `rm -rf <dir>` does unlink for real, even brokered.
for dir in target/*/incremental; do
	[ -d "$dir" ] || continue
	rm -rf "$dir"
done

# 2. Intermediates left behind by the feature sets we are not building now.
#    `-mmin` rather than `-mtime` so --days 0 really means "everything".
list=$(mktemp)
trap 'rm -f "$list"' EXIT

deps_dirs | while IFS= read -r dir; do
	stale "$dir" >>"$list"
done

count=$(wc -l <"$list" | tr -d ' ')

if [ "$count" -eq 0 ]; then
	after_mb=$(du -sm target | cut -f1)
	printf 'sweep-target: nothing older than %sd; target/ %s MB -> %s MB\n' \
		"$days" "$before_mb" "$after_mb"
	exit 0
fi

# `du -k` in batches rather than `stat`: portable (BSD and GNU disagree on the
# size flag) and it reports disk blocks, which is what we are trying to free.
# No `-c`, or every batch would add its own `total` line and double-count.
listed_kb=$(xargs -n 200 du -k <"$list" | awk '{ s += $1 } END { print s + 0 }')

if [ "$dry_run" -eq 1 ]; then
	say "would remove $count artifacts ($(kb_to_mb "$listed_kb") MB)"
	say "largest, by size:"
	xargs -n 200 du -k <"$list" | sort -rn | head -10 |
		awk '{ printf "sweep-target:   %7.1f MB  %s\n", $1 / 1024, $2 }'
	printf 'sweep-target: dry run, target/ %s MB unchanged\n' "$before_mb"
	exit 0
fi

# `-delete` is silent under BSD/GNU find but WorkBuddy's brokered find echoes
# every path it removes, so pin the output rather than let it vary by host.
deps_dirs | while IFS= read -r dir; do
	stale "$dir" -delete >/dev/null
done

after_mb=$(du -sm target | cut -f1)
after_free=$(avail_kb)
freed_mb=$((before_mb - after_mb))
reclaimed_mb=$(((after_free - before_free) / 1024))

say "removed $count artifacts ($(kb_to_mb "$listed_kb") MB)"
printf 'sweep-target: target/ %s MB -> %s MB; free space %+d MB\n' \
	"$before_mb" "$after_mb" "$reclaimed_mb"

# Honest failure: if bytes left the tree but the volume did not grow, they were
# moved somewhere else (a trash directory) rather than deleted. Do not let that
# pass as a successful cleanup - it is exactly how this repo lost 24 GB to
# ~/.Trash in October 2026 while everyone believed target/ had been cleaned.
if [ "$freed_mb" -ge 8 ] && [ "$reclaimed_mb" -lt $((freed_mb / 2)) ]; then
	echo "sweep-target: WARNING: $freed_mb MB left target/ but only $reclaimed_mb MB came back." >&2
	echo "sweep-target:   The deletions were routed to a trash directory, not unlinked." >&2
	echo "sweep-target:   Empty the Trash (Finder > Empty Trash), or run 'cargo clean'." >&2
	exit 1
fi
