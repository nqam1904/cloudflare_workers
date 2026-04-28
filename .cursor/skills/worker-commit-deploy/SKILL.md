---
name: worker-commit-deploy
description: Commit, push, and deploy Cloudflare Worker changes. Use when working in cloudflare_workers and the user asks to commit, push, deploy, accept code, or finish Worker changes.
---

# Worker Commit Deploy

## Instructions

When the user accepts code or asks to commit/push Worker changes in `cloudflare_workers`:

1. Review `git status --short` and `git diff` so only intended Worker changes are committed.
2. Run `npx tsc --noEmit`.
3. If type-check passes, commit with a concise message.
4. Push the commit to the tracked remote branch.
5. After push succeeds, run `npm run deploy` to deploy with Wrangler.
6. Report the commit hash, push result, deploy result, and any remaining working tree changes.

## Safety Rules

- Do not run `npm run deploy` if type-check, commit, or push fails.
- Do not deploy unrelated uncommitted changes unless the user explicitly includes them.
- Do not use `--no-verify`, force push, or destructive git commands unless explicitly requested.
- If Wrangler requires authentication or deployment confirmation, stop and ask the user to complete/approve it.
