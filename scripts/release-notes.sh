#!/usr/bin/env bash
# Print the body of the GitHub release for a tag: an install line, the
# CHANGELOG.md section for exactly that tag, and a link to the changes since
# the previous v* tag.
#
#   scripts/release-notes.sh v1.0.0-beta.3 > release-notes.md
#
# Fails when CHANGELOG.md has no section for the tag. A tag without a
# changelog entry is a mistake, and the release should stop on it.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <tag>" >&2
  exit 2
fi

tag="$1"
repo="HoneyBBQ/teamspeak-go"
module="github.com/honeybbq/teamspeak-go"
cd "$(dirname "$0")/.."
changelog="CHANGELOG.md"

# The section: from the "## <tag>" heading, which may be followed by a date in
# parentheses, up to the next "## " heading. The heading line itself is left out.
section="$(awk -v tag="$tag" '
  /^## / {
    if (found) exit
    title = substr($0, 4)
    if (title == tag || index(title, tag " ") == 1) { found = 1; next }
  }
  found { print }
' "$changelog")"

# Blank lines around the section do not belong in the release body.
section="$(printf '%s\n' "$section" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')"

if [ -z "$section" ]; then
  echo "release-notes: $changelog has no section for $tag (or it is empty); add a \"## $tag (date)\" heading" >&2
  exit 1
fi

# The release page is not CHANGELOG.md, so a link that is an anchor or a
# relative path there would point nowhere. Make both absolute, at the tag.
base="https://github.com/$repo/blob/$tag"
section="$(printf '%s\n' "$section" | sed -E \
  -e "s|\]\(#([^)]*)\)|](${base}/${changelog}#\1)|g" \
  -e "s|\]\((\./)?([^):/#][^):]*)\)|](${base}/\2)|g")"

# CHANGELOG.md is wrapped at 80 columns, but a release page turns every line
# break into a hard one. Join the lines of each paragraph and list item; code
# blocks, headings, table rows and blank lines stay as they are.
section="$(printf '%s\n' "$section" | awk '
  function flush() { if (buf != "") print buf; buf = "" }
  /^[ \t]*```/ { flush(); print; code = !code; next }
  code { print; next }
  /^[ \t]*$/ { flush(); print; next }
  /^[ \t]*([-*+] |[0-9]+\. )/ || /^#/ || /^[ \t]*\|/ || /^>/ { flush(); buf = $0; next }
  buf == "" { buf = $0; next }
  { sub(/^[ \t]+/, ""); buf = buf " " $0 }
  END { flush() }
')"

# The previous tag by version order, with prereleases before their release.
previous="$(git -c versionsort.suffix=- tag --list 'v*' --sort=-v:refname |
  awk -v tag="$tag" 'found { print; exit } $0 == tag { found = 1 }')"

# shellcheck disable=SC2016 # the backticks are markdown, not a command substitution
printf 'Install:\n\n```sh\ngo get %s@%s\n```\n\n' "$module" "$tag"
printf '%s\n' "$section"
if [ -n "$previous" ]; then
  printf '\n**Full changelog**: https://github.com/%s/compare/%s...%s\n' "$repo" "$previous" "$tag"
fi
