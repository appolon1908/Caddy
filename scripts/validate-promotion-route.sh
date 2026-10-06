#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'PROMOTION_GUARD=FAIL:%s\n' "$1" >&2
  exit 2
}

EVENT_NAME="${EVENT_NAME:-}"
BASE_BRANCH="${BASE_BRANCH:-}"
HEAD_BRANCH="${HEAD_BRANCH:-}"
HEAD_SHA="${HEAD_SHA:-}"
BASE_SHA="${BASE_SHA:-}"

if [[ "$EVENT_NAME" != "pull_request" ]]; then
  echo PROMOTION_GUARD=PASS
  exit 0
fi

[[ -n "$BASE_BRANCH" && -n "$HEAD_BRANCH" ]] || fail missing_branch_context

validate_tree_identical_reconciliation() {
  local source_branch="$1" destination_branch="$2"
  local route_regex head_tree source_tree

  route_regex="^reconcile/${source_branch}-to-${destination_branch}-[0-9]{8}([.-][A-Za-z0-9._-]+)?$"
  [[ "$HEAD_BRANCH" =~ $route_regex ]] || return 1

  [[ "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]] || fail invalid_head_sha
  [[ "$BASE_SHA" =~ ^[0-9a-f]{40}$ ]] || fail invalid_base_sha
  command -v git >/dev/null 2>&1 || fail git_missing
  [[ "$(git rev-parse HEAD)" == "$HEAD_SHA" ]] || fail checkout_identity

  # promotion-guard checks out with fetch-depth: 0 before credentials are
  # removed. Reconciliation must use only those already-materialized refs;
  # never make governance depend on a post-checkout authenticated refetch.
  git rev-parse --verify --quiet "refs/remotes/origin/${source_branch}" >/dev/null \
    || fail "${source_branch}_ref_missing"
  git rev-parse --verify --quiet "refs/remotes/origin/${destination_branch}" >/dev/null \
    || fail "${destination_branch}_ref_missing"

  [[ "$(git rev-parse "origin/${destination_branch}")" == "$BASE_SHA" ]] \
    || fail "stale_${destination_branch}_base"

  read -r -a commit_line <<<"$(git rev-list --parents -n 1 "$HEAD_SHA")"
  [[ "${#commit_line[@]}" -eq 2 ]] || fail reconciliation_must_be_single_parent
  [[ "${commit_line[1]}" == "$BASE_SHA" ]] \
    || fail "reconciliation_parent_not_${destination_branch}"

  head_tree="$(git rev-parse "$HEAD_SHA^{tree}")"
  source_tree="$(git rev-parse "origin/${source_branch}^{tree}")"
  [[ "$head_tree" == "$source_tree" ]] || fail "${source_branch}_tree_mismatch"
  git diff --quiet "$HEAD_SHA" "origin/${source_branch}" -- . \
    || fail "${source_branch}_content_mismatch"

  printf 'PROMOTION_RECONCILIATION=PASS destination_parent=%s source_branch=%s source_tree=%s\n' \
    "$BASE_SHA" "$source_branch" "$source_tree"
  return 0
}

require_direct_or_reconciliation() {
  local source_branch="$1" destination_branch="$2" invalid_reason="$3"
  if [[ "$HEAD_BRANCH" == "$source_branch" ]]; then
    return 0
  fi
  if validate_tree_identical_reconciliation "$source_branch" "$destination_branch"; then
    return 0
  fi
  fail "$invalid_reason"
}

case "$BASE_BRANCH" in
  development)
    [[ "$HEAD_BRANCH" =~ ^(feat|fix|chore|docs|refactor|ci)/ ]] || fail invalid_development_source
    ;;
  test)
    require_direct_or_reconciliation development test invalid_test_source
    ;;
  staging)
    require_direct_or_reconciliation test staging invalid_staging_source
    ;;
  production)
    require_direct_or_reconciliation staging production invalid_production_source
    ;;
  main)
    require_direct_or_reconciliation production main invalid_main_source
    ;;
  *)
    fail invalid_base
    ;;
esac

printf 'PROMOTION_GUARD=PASS route=%s->%s\n' "$HEAD_BRANCH" "$BASE_BRANCH"
