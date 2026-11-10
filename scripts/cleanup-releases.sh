#!/usr/bin/env bash
# SingCtl GitHub Releases, Orphan Tags & Actions History Cleanup Script
# Keeps only the latest N releases (default: 3), deletes older releases + orphan v* tags,
# and trims old completed GitHub Actions workflow runs.

set -euo pipefail

KEEP_RELEASES="${1:-${KEEP_RELEASES:-3}}"
KEEP_RUNS="${KEEP_RUNS:-15}"

if ! [[ "$KEEP_RELEASES" =~ ^[0-9]+$ ]] || [ "$KEEP_RELEASES" -lt 1 ]; then
  echo "Error: KEEP_RELEASES must be an integer >= 1 (got: $KEEP_RELEASES)" >&2
  exit 1
fi

echo "==> [1/3] Cleaning up GitHub Releases (keeping latest ${KEEP_RELEASES})..."

# Fetch all release tags sorted by version descending (v1.14.97, v1.14.96, ...)
ALL_RELEASE_TAGS=$(gh release list --limit 500 --json tagName -q '.[].tagName' | sort -V -r)

KEPT_TAGS=()
DELETE_RELEASE_TAGS=()
idx=0

for tag in $ALL_RELEASE_TAGS; do
  [ -z "$tag" ] && continue
  idx=$((idx + 1))
  if [ "$idx" -le "$KEEP_RELEASES" ]; then
    KEPT_TAGS+=("$tag")
  else
    DELETE_RELEASE_TAGS+=("$tag")
  fi
done

echo "    Kept releases (${#KEPT_TAGS[@]}): ${KEPT_TAGS[*]:-none}"

if [ "${#DELETE_RELEASE_TAGS[@]}" -gt 0 ]; then
  echo "    Deleting ${#DELETE_RELEASE_TAGS[@]} old releases and their tags..."
  for tag in "${DELETE_RELEASE_TAGS[@]}"; do
    echo "      - Deleting release & tag: $tag"
    gh release delete "$tag" --cleanup-tag --yes || true
  done
else
  echo "    No old releases to delete."
fi

echo "==> [2/3] Cleaning up orphan remote v* Git tags..."
REPO_SLUG=$(gh repo view --json nameWithOwner -q '.nameWithOwner')
REMOTE_TAGS=$(gh api --paginate "repos/${REPO_SLUG}/tags" -q '.[].name' | grep -E '^v[0-9]+\.' || true)

is_kept_tag() {
  local target="$1"
  local k
  for k in "${KEPT_TAGS[@]:-}"; do
    if [ "$k" = "$target" ]; then
      return 0
    fi
  done
  return 1
}

ORPHAN_COUNT=0
for rtag in $REMOTE_TAGS; do
  [ -z "$rtag" ] && continue
  if ! is_kept_tag "$rtag"; then
    echo "      - Deleting orphan tag: $rtag"
    gh api -X DELETE "repos/${REPO_SLUG}/git/refs/tags/${rtag}" >/dev/null 2>&1 || true
    ORPHAN_COUNT=$((ORPHAN_COUNT + 1))
  fi
done
echo "    Deleted ${ORPHAN_COUNT} orphan tags."

if [ "${KEEP_RUNS}" -gt 0 ]; then
  echo "==> [3/3] Trimming completed GitHub Actions workflow runs (keeping latest ${KEEP_RUNS})..."
  OLD_RUN_IDS=$(gh run list --limit 200 --json databaseId,status -q ".[] | select(.status == \"completed\") | .databaseId" | tail -n +"$((KEEP_RUNS + 1))" || true)
  RUN_DEL_COUNT=0
  for run_id in $OLD_RUN_IDS; do
    [ -z "$run_id" ] && continue
    gh api -X DELETE "repos/${REPO_SLUG}/actions/runs/${run_id}" >/dev/null 2>&1 || true
    RUN_DEL_COUNT=$((RUN_DEL_COUNT + 1))
  done
  echo "    Deleted ${RUN_DEL_COUNT} old workflow runs."
fi

echo "==> Cleanup complete!"
