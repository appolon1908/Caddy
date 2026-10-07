#!/usr/bin/env bash
#
# Apply the canonical protection for the Caddy promotion chain:
#
#   subsection/* -> section/* -> development -> testing -> staging -> production
#
# Run through .github/workflows/apply-branch-protection.yml, which supplies a
# repository-administration token and archives the read-back as evidence.
#
# Three earlier defects are called out so they are not reintroduced:
#
#   1. required_approving_review_count was 0 on every branch, including main.
#      That is weaker than config/github/main-ruleset.json, which requires one
#      approval, and it left `production` -- the approved release source -- as
#      the least protected branch in the repository.
#
#   2. The required contexts "exact-head-validation" and
#      "merge-result-validation" are reported by no workflow. The jobs in
#      validate.yml are named "validate-source" and "validate-merge-result".
#      Requiring a context that never reports leaves a branch permanently
#      unmergeable rather than protected.
#
#   3. The payload sent dismissal_restrictions and bypass_pull_request_allowances.
#      GitHub rejects both on a user-owned repository with
#      "Only organization repositories can have users and team restrictions"
#      (HTTP 422), so the script could not have succeeded here at all.
#
# Every context below was observed reporting on real pull requests into the
# branch it is required for.
set -Eeuo pipefail

repository="${1:-ingtrader21-spec/Caddy}"
owner="${repository%%/*}"
repo="${repository#*/}"

# Reported by validate.yml on every pull request, whatever the base branch.
readonly base_contexts='"validate-source","validate"'
# Reported by the promotion and release gates carried on the promotion chain.
readonly promotion_contexts='"promotion-guard","immutable-release-gate"'

contexts_for() {
  case "$1" in
    main)
      # Mirrors config/github/main-ruleset.json, which
      # scripts/validate_observability_exposure.py asserts independently.
      printf '["validate-source","validate-merge-result"]' ;;
    production)
      printf '[%s,%s,"staging-certification"]' "$base_contexts" "$promotion_contexts" ;;
    *)
      printf '[%s,%s]' "$base_contexts" "$promotion_contexts" ;;
  esac
}

# main and production are the branches where the last pusher must not also be
# the approver. development and testing stay workable by a single maintainer.
last_push_approval_for() {
  case "$1" in
    main|production) printf 'true' ;;
    *) printf 'false' ;;
  esac
}

apply() {
  local branch="$1"
  local contexts last_push
  contexts="$(contexts_for "$branch")"
  last_push="$(last_push_approval_for "$branch")"

  jq -n \
    --argjson contexts "$contexts" \
    --argjson last_push "$last_push" '{
    required_status_checks:{strict:true,contexts:$contexts},
    enforce_admins:true,
    required_pull_request_reviews:{
      dismiss_stale_reviews:true,
      require_code_owner_reviews:false,
      required_approving_review_count:1,
      require_last_push_approval:$last_push
    },
    restrictions:null,
    required_linear_history:true,
    allow_force_pushes:false,
    allow_deletions:false,
    block_creations:false,
    required_conversation_resolution:true,
    lock_branch:false,
    allow_fork_syncing:false
  }' | gh api --method PUT \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "/repos/${owner}/${repo}/branches/${branch}/protection" --input - >/dev/null

  gh api "/repos/${owner}/${repo}/branches/${branch}" --jq \
    '{name,protected,
      required_checks:.protection.required_status_checks.contexts,
      approvals:.protection.required_pull_request_reviews.required_approving_review_count}'
}

for branch in development testing staging production main; do
  apply "$branch"
done
