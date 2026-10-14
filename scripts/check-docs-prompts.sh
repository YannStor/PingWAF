#!/usr/bin/env bash
# Static consistency checks for project docs and agent prompts.
#
#   ./scripts/check-docs-prompts.sh          # check everything
#   ./scripts/check-docs-prompts.sh <file>…  # check only these markdown files
#
# Covers (all offline, no toolchain or network deps):
#   1. Agent frontmatter: name/description/model/tools present, name matches
#      the filename, model is one of the declared routing targets.
#   2. Rule files (.codebuddy/rules/*/RULE.mdc): description/enabled present,
#      agent files referenced in the multi-agent roster exist, model names in
#      the roster are valid.
#   3. Cross references: files mentioned inside .codebuddy/**/*.md exist
#      (backticked paths under .codebuddy/ or repo-root docs/scripts).
#   4. Markdown relative links: `](path)` targets resolve to local files for
#      the checked scope. Anchors (#section) and external URLs are NOT
#      verified — see "Known limitations".
#
# Known limitations (documented, not hidden): anchor targets, code-block link
# text, and reference-style links are not validated; docs/zh translation
# coverage is not checked here.
set -uo pipefail

ALLOWED_MODELS="deepseek-v4.1-flash glm-5.3-flash glm-5.3-flashx inherit"
errors=0

fail() { echo "FAIL: $*"; errors=$((errors + 1)); }

# Markdown files to link-check by default. docs/** is the user-facing tree;
# .codebuddy/** keeps prompts and rules consistent.
default_scope() {
  printf '%s\n' \
    CLAUDE.md CODEBUDDY.md README.md README_zh.md UPSTREAM.md CONTRIBUTING.md \
    examples/README.md \
    $(find .codebuddy docs -name '*.md' 2>/dev/null | sort)
}

# Resolve a link target; prints "ok" or "missing".
link_ok() { # $1 = md file, $2 = raw link target
  local target="$1" link="$2"
  link="${link%%#*}"   # drop anchor
  link="${link%%\?*}"  # drop query
  [ -z "$link" ] && { echo ok; return; }          # pure anchor: unchecked
  [[ "$link" == *"://"* || "$link" == "mailto:"* ]] && { echo ok; return; }
  local dir dirfile
  dir=$(dirname "$target")
  if [ -e "$dir/$link" ]; then echo ok; else echo missing; fi
}

# 1 ─ Agent frontmatter ------------------------------------------------------
check_agent() { # $1 = agent file
  local file="$1" stem
  stem=$(basename "$file" .md)
  local fm
  fm=$(sed -n '1,/^---$/p' "$file" | sed '1d;$d')
  if [ "$(head -c 3 "$file")" != "---" ]; then
    fail "$file: missing frontmatter block"
    return
  fi
  local name desc model tools
  name=$(grep -m1 '^name:' <<<"$fm" | cut -d: -f2- | xargs)
  desc=$(grep -m1 '^description:' <<<"$fm" | cut -d: -f2- | xargs)
  model=$(grep -m1 '^model:' <<<"$fm" | cut -d: -f2- | xargs)
  tools=$(grep -m1 '^tools:' <<<"$fm" | cut -d: -f2- | xargs)
  [ "$name" = "$stem" ] || fail "$file: frontmatter name '$name' != filename stem '$stem'"
  [ -n "$desc" ] || fail "$file: missing description"
  [ -n "$tools" ] || fail "$file: missing tools line"
  if [ -z "$model" ]; then
    fail "$file: missing model"
  elif ! grep -qw "$model" <<<"$ALLOWED_MODELS"; then
    fail "$file: model '$model' not in declared routing targets ($ALLOWED_MODELS)"
  fi
}

# 2 ─ Rule files -------------------------------------------------------------
check_rules() {
  local rule
  for rule in .codebuddy/rules/*/RULE.mdc; do
    [ -e "$rule" ] || continue
    grep -q '^description:' "$rule" || fail "$rule: missing description"
    grep -q '^enabled:' "$rule" || fail "$rule: missing enabled flag"
    if [ "$(basename "$(dirname "$rule")")" = "pingwaf-multi-agent" ]; then
      # Roster rows reference agent files and model names.
      local ref model
      while read -r ref; do
        [ -e ".codebuddy/agents/$ref" ] || fail "$rule: roster references missing agent file '$ref'"
      done < <(grep -o '`pingwaf-[a-z-]*\.md`' "$rule" | tr -d '`' | sort -u)
      while read -r model; do
        grep -qw "$model" <<<"$ALLOWED_MODELS" || fail "$rule: roster model '$model' not in ($ALLOWED_MODELS)"
      done < <(grep -Eo '(DeepSeek-V4\.1-Flash|GLM-5\.3-FlashX|GLM-5\.3-Flash)' "$rule" | sort -u)
    fi
  done
}

# 3+4 ─ Cross references and markdown links ----------------------------------
check_links() { # $@ = markdown files
  local file line target
  for file in "$@"; do
    [ -f "$file" ] || { fail "scope file not found: $file"; continue; }
    # Link targets in inline links only: ](target). Inline code spans are
    # stripped first — `parent['eval'](...)` inside backticks is code, not a
    # link. Line numbers survive: sed works line by line.
    while IFS=$'\t' read -r line target; do
      [ -n "$target" ] || continue
      if [ "$(link_ok "$file" "$target")" = missing ]; then
        fail "$file:$line: broken relative link '$target'"
      fi
    done < <(sed 's/`[^`]*`//g' "$file" \
             | grep -noE '\]\(([^)#?]+)(#[^)]*)?\)' \
             | sed -E 's/^([0-9]+):.*\]\(([^)]*)\)$/\1\t\2/')
    # Backticked .codebuddy paths inside .codebuddy/**/*.md must exist.
    if [[ "$file" == .codebuddy/* ]]; then
      local ref
      while IFS=$'\t' read -r line ref; do
        [ -e "$ref" ] || fail "$file:$line: referenced path does not exist: '$ref'"
      done < <(grep -noE '`(\.codebuddy/[A-Za-z0-9_./-]+)`' "$file" 2>/dev/null \
               | sed -E 's/^([0-9]+):.*`([^`]+)`$/\1\t\2/')
    fi
  done
}

cd "$(dirname "$0")/.." || exit 1

echo "== example/config TOML =="
# Syntax validation only (tomllib); semantic consistency with the Rust config
# structs is not checked here. Skipped with a notice when tomllib (py3.11+) is
# unavailable — a missing validator must not be reported as a pass.
if command -v python3 >/dev/null 2>&1 && python3 -c "import tomllib" 2>/dev/null; then
  for f in $(find examples conf -name '*.toml' 2>/dev/null | sort) pingwaf.toml; do
    [ -f "$f" ] || continue
    python3 -c "import tomllib; tomllib.load(open('$f','rb'))" 2>/dev/null \
      || fail "$f: invalid TOML"
  done
else
  echo "skip: python3 with tomllib (3.11+) unavailable"
fi

echo "== agent frontmatter =="
for f in .codebuddy/agents/pingwaf-*.md; do
  [ -e "$f" ] && check_agent "$f"
done
echo "== rules =="
check_rules
echo "== links & cross references =="
scope=()
while IFS= read -r f; do scope+=("$f"); done < <(default_scope | sort -u)
if [ "$#" -gt 0 ]; then
  check_links "$@"
else
  check_links "${scope[@]}"
fi

echo "== done: $errors error(s) =="
[ "$errors" -eq 0 ]
