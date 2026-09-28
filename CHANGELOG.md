# Upgrade notes

These notes cover the upgrade to 1.9.41. Run the steps in this order. Run mongosh commands in-pod against the application database, and Python and bash snippets in a backend pod, from the working directory where `app` is importable.

Before the rollout, resolve each gate before the first new pod starts:

1. Build the findings index.
2. Check partial restores made by a pre-release 1.9.41 build.
3. Resolve email addresses that differ only in case, then add the case-insensitive unique index.
4. Check what each team-syncing GitLab token can see, and decide per instance.
5. Check SMTP in the database settings.
6. Set the base URL of GitHub Enterprise Server instances that have none.
7. Review synced team members and active accounts that are not verified (a review, not a gate).

Deploy blocker, also before the rollout: fill the allowlists of the github.com and gitlab.com instances, or switch their auto-create off.

Last, right before the rollout starts: rotate `SECRET_KEY` (recommended), or end every session. Either way, snapshot the accounts.

After the rollout, once the last pod on the previous image has terminated:

1. End every session, and review what was created during the rollout if needed. Mandatory on every installation.
2. Remove TruffleHog plaintext secrets from `analysis_results`.
3. Rewrite archive bundles that still hold TruffleHog plaintext.
4. Backfill `first_seen_at`.
5. Purge leaked chat tool results, then rotate the exposed secrets.
6. Rotate GitHub Enterprise tokens that reached github.com.
7. Review GitLab bindings set through the old unchecked path.
8. Review the retention of projects created in the dialog.

Once 1.9.41 is confirmed stable, drop the old findings index. Four optional checks look for abuse of the fixed gaps from before the upgrade. The behaviour changes that users and operators will notice are listed at the end.

## Before the rollout (gate): build the findings index

The `(project_id, component, type)` findings index grows into a covering index for the first-detection lookup. Startup's `create_index` would build it in-line on the large findings collection and block pod start until the build finishes. Build it in-pod with mongosh before rolling out the new image, with the exact key, so startup finds it and does nothing. The old image does not read it, so building it early is harmless.

```js
db.findings.createIndex({ project_id: 1, component: 1, type: 1, finding_id: 1, version: 1, first_seen_at: 1, scan_created_at: 1 })
```

## Before the rollout (gate): check partial restores made by a pre-release 1.9.41 build

A restore now marks its scan `restore_in_progress` until its last write and only then sets `restored_at`. Housekeeping drops the archive metadata, and with it the bundle, only of a scan without the flag whose `restored_at` is later than its archiving. Restores made by 1.9.40 carry no `restored_at`, so 1.9.41 keeps their metadata and they need nothing. Only an installation that ran a pre-release 1.9.41 build can hold a partial restore with `restored_at` and no flag. It looks complete, and the next housekeeping pass would drop its metadata and orphan its bundle. On every other installation the query below returns nothing.

Run this right before the rollout, in a window with no restore running, and at the latest before the first housekeeping pass on the new image. A restore still running on a pre-release build can show the same low counts. The query lists restored scans whose archive metadata still exists, with the expected and found counts:

```js
db.archive_metadata.aggregate([
  {$lookup: {from: "scans", localField: "scan_id", foreignField: "_id", as: "scan"}},
  {$unwind: "$scan"},
  {$match: {"scan.restored_at": {$ne: null}, "scan.restore_in_progress": {$ne: true},
            $expr: {$gt: ["$scan.restored_at", "$archived_at"]}}},
  {$lookup: {from: "dependencies", localField: "scan_id", foreignField: "scan_id", pipeline: [{$count: "n"}], as: "deps"}},
  {$lookup: {from: "findings", localField: "scan_id", foreignField: "scan_id", pipeline: [{$count: "n"}], as: "fnd"}},
  {$project: {scan_id: 1, archived_at: 1, restored_at: "$scan.restored_at",
              dependencies_expected: "$dependencies_count", dependencies_found: {$ifNull: [{$first: "$deps.n"}, 0]},
              findings_expected: "$findings_count", findings_found: {$ifNull: [{$first: "$fnd.n"}, 0]}}}
])
```

For every row where a found count is below its expected count, mark the scan unfinished. Housekeeping then keeps its metadata and bundle, and the next restore of the scan rolls back the leftovers and restores it again:

```js
db.scans.updateOne({_id: "<scan_id>"}, {$set: {restore_in_progress: true}, $unset: {restored_at: ""}})
```

Marking is safe before the rollout: every build that writes `restored_at` keeps the metadata of a scan without it, and retention skips the scan because a restore pins it. Rows whose counts match are completed restores whose metadata cleanup failed; leave them to housekeeping. An empty result means there is nothing to do.

## Before the rollout (gate): resolve email addresses that differ only in case

Email lookups are now case-insensitive: login by email, forgot and reset password, verification, the OIDC callback, team and project member add, the CI initial member and team sync. Take a local `Alice@x` and an OIDC `alice@x`: the OIDC login can resolve to the local account and be refused, and so can the password login the other way round. List the pairs. The result must be empty before the rollout:

```js
db.users.aggregate([
  { $group: { _id: { $toLower: "$email" }, n: { $sum: 1 },
      accounts: { $push: { id: "$_id", username: "$username", email: "$email",
        auth_provider: "$auth_provider", is_verified: "$is_verified", is_active: "$is_active" } } } },
  { $match: { n: { $gt: 1 } } }
])
```

A person decides each pair: which account keeps the address, and whether to merge or delete the other. There is no automatic fix. Once the query returns nothing, add the case-insensitive unique index next to the exact `email_1` that startup creates. MongoDB allows a second index on the same key when its collation differs:

```js
db.users.createIndex({ email: 1 }, { unique: true, name: "email_ci_unique", collation: { locale: "en", strength: 2 } })
```

Optional and cosmetic, at any time after the pairs are resolved: lowercase the stored legacy addresses. All lookups ignore case, so correctness does not depend on it.

```js
db.users.updateMany({ email: { $regex: "[A-Z]" } }, [{ $set: { email: { $toLower: "$email" } } }])
```

## Before the rollout (gate): check what each team-syncing GitLab token can see

Team sync now matches a member only by an email GitLab vouches for, and only against verified DC accounts. With an administrator's token that is the address in the members listing. With any other token the listing carries no emails, so each member costs one `GET /users/:id` lookup of the public profile email. GitLab rate-limits that lookup per token user, to 300 per 10 minutes by default. Synced teams then shrink to the members whose public email matches a verified account, and where the limit is hit they freeze, for good once a token needs more lookups than its daily budget. Users lose the project access those teams gave them.

Run this script in a backend pod before the rollout. It reads each instance's stored token and pages through every group bound to a team. A group the token cannot read is reported and skipped, not counted:

```bash
python - <<'PY'
import asyncio, httpx
from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

async def members_of(c, gid):
    """Return (rows, None) or (None, reason) when the token cannot read the group."""
    rows, page = [], "1"
    while page:
        try:
            r = await c.get(f"/groups/{gid}/members/all", params={"per_page": 100, "page": page})
        except httpx.HTTPError as exc:
            return None, f"request failed: {exc!r}"
        if r.status_code != 200:
            return None, f"HTTP {r.status_code}"
        try:
            chunk = r.json()
        except ValueError:
            return None, "answer is not JSON"
        if not isinstance(chunk, list):
            return None, f"answer is not a list: {str(chunk)[:120]}"
        rows += chunk
        page = r.headers.get("x-next-page")
    return rows, None

async def main():
    db = AsyncIOMotorClient(settings.MONGODB_URL)[settings.DATABASE_NAME]
    async for inst in db.gitlab_instances.find({"sync_teams": True, "is_active": {"$ne": False}}):
        iid, base = str(inst["_id"]), inst["url"].rstrip("/")
        if not inst.get("access_token"):
            print(f"{inst['name']}: no access token stored; team sync cannot read any group")
            continue
        async with httpx.AsyncClient(base_url=base + "/api/v4", timeout=30,
                                     headers={"PRIVATE-TOKEN": inst["access_token"]}) as c:
            try:
                r = await c.get("/user")
            except httpx.HTTPError as exc:
                print(f"{inst['name']}: GET /user failed: {exc!r}; instance skipped")
                continue
            if r.status_code != 200:
                print(f"{inst['name']}: GET /user answered HTTP {r.status_code}; token invalid, instance skipped")
                continue
            me = r.json()
            with_email, without_email, unreadable = set(), set(), []
            async for team in db.teams.find({"bindings.instance_id": iid}, {"name": 1, "bindings": 1}):
                for b in team["bindings"]:
                    if b["instance_id"] != iid:
                        continue
                    rows, reason = await members_of(c, b["external_id"])
                    if rows is None:
                        unreadable.append((team.get("name"), b["external_id"], reason))
                        continue
                    for m in rows:
                        if isinstance(m, dict) and "id" in m:
                            (with_email if m.get("email") else without_email).add(m["id"])
            without_email -= with_email
            print(f"{inst['name']}: token user={me.get('username')} is_admin={bool(me.get('is_admin'))} "
                  f"members with listed email={len(with_email)}, needing GET /users/:id={len(without_email)}")
            for team_name, gid, reason in unreadable:
                print(f"  UNREADABLE group {gid} (team {team_name!r}): {reason}; not counted above")
            s = await c.get("/application/settings")
            if s.status_code == 200:
                js = s.json()
                print(f"  users_get_by_id_limit={js.get('users_get_by_id_limit')} "
                      f"excluded users={js.get('users_get_by_id_limit_allowlist_raw')!r}")
            elif without_email:
                print(f"  token cannot read the limit; a GitLab administrator runs: curl -sH "
                      f"'PRIVATE-TOKEN: <admin token>' {base}/api/v4/application/settings | jq "
                      f"'{{users_get_by_id_limit, users_get_by_id_limit_allowlist_raw}}'")

asyncio.run(main())
PY
```

Read the output per instance:

- `needing GET /users/:id=0`: the listing carries the emails, so the token reads as an administrator. No lookups, no limit.
- Any other count: the token is not an effective administrator and `users_get_by_id_limit` applies, 300 per 10 minutes by default, about 43,200 a day. Get the limit and the "Excluded users" list with the printed curl, or in Admin > Settings > Network > Users API rate limits. The token user is unlimited when the limit is 0 or when the printed username is in "Excluded users". For a group access token that username is its `group_<id>_bot_...` user.
- If neither applies, the instance works only while the "needing" count times the jobs that sync the same group concurrently stays well below the daily budget, `users_get_by_id_limit` x 144. Concurrent jobs read the same members and split the budget. Above it, cached answers expire before the rest are filled, and the affected groups stay frozen for good. Below it, a group of M members that need a lookup still stays frozen for about M / limit x 10 minutes of ingests, longer with concurrent jobs, when its entries are first filled and again when they are refilled a day later.
- Admin Mode: where GitLab's Admin Mode is on, an administrator's token acts as an administrator only with the `admin_mode` scope. `is_admin=True` alone does not show that; the "needing" count does.
- `UNREADABLE group ...`: the token cannot read that bound group, and team sync cannot either. Fix the token's access or the binding before the rollout.
- `no access token stored` or `GET /user answered HTTP 401`: team sync on that instance cannot work at all. Fix the token first.
- Independent of the limit, a non-admin token keeps only the members whose public GitLab email matches a verified DC account.
- On gitlab.com neither remedy exists: customers get no administrator tokens and cannot change the limit. There the listing carries emails only for enterprise users, and only when the token user may read them.

Decide per instance before the rollout: switch to an administrator's token, have a GitLab administrator add the token user to "Excluded users", or accept the shrink. Accept it only where the needing count times the concurrent jobs stays well below the daily budget; above it, groups stay frozen for good.

## Before the rollout (gate): check SMTP in the database settings

Admin password reset (`POST /users/{id}/reset-password`) now only sends mail. It no longer returns a manual link, and it answers 501 "Email server not configured" when `system_settings` has no `smtp_host`. Self-service email changes need the same setting. Accounts verify their email through the mailed link, and adding a member by email now needs a verified account. The environment variable `SMTP_HOST` does not count. Check:

```js
db.system_settings.findOne({ _id: "current" }, { smtp_host: 1 })
```

If it is empty and admins reset passwords, configure SMTP in System Settings before the rollout.

## Before the rollout (gate): set the base URL of GitHub Enterprise Server instances

After the rollout, a GitHub instance with an empty base URL (`github_url`) and an issuer other than GitHub Actions makes no GitHub API calls at all: no team sync, PR decoration, branch listing or pickers. The old image already sends API calls to `<github_url>/api/v3` when the URL is set, so setting it before the rollout is safe. List the instances without it, then set each one's URL:

```js
db.github_instances.find(
  { github_url: { $in: [null, ""] }, url: { $not: /^https:\/\/token\.actions\.githubusercontent\.com(\/|$)/ } },
  { name: 1, url: 1, is_active: 1, sync_teams: 1 })
db.github_instances.updateOne({ _id: "<id>" }, { $set: { github_url: "https://<ghes-host>" } })
```

Running the find again returns nothing once every instance is set.

## Before the rollout (review): synced members and accounts that are not verified

Identity matching now uses verified accounts only. These read-only reviews show who is affected; they do not block the rollout.

Synced team members whose account is unverified drop out at the next sync, and with them the project roles the team gave them:

```js
db.teams.aggregate([
  {$unwind: "$members"},
  {$match: {"members.source": {$regex: "^(gitlab|github)"}}},
  {$lookup: {from: "users", localField: "members.user_id", foreignField: "_id", as: "u"}},
  {$unwind: "$u"},
  {$match: {"u.is_verified": {$ne: true}}},
  {$project: {team: "$name", user: "$u.username", email: "$u.email", source: "$members.source"}}
])
```

Members matched by username so far, with a verified account whose provider email differs from the DC email, drop out too. Mongo cannot show them; the next sync logs them at DEBUG.

Active unverified accounts are no longer found by team member add, project invite by email, CI auto-create or team sync. They verify through the mailed link if SMTP is configured. Mark an account verified only after checking it by hand, never in bulk, because a squatted address would then become trusted:

```js
db.users.find({is_active: {$ne: false}, is_verified: {$ne: true}}, {username: 1, email: 1, auth_provider: 1})
```

## Deploy blocker: fill the allowlists of the github.com and gitlab.com instances

Every repository on github.com and every project on gitlab.com can mint a token for the shared issuers `https://token.actions.githubusercontent.com` and `https://gitlab.com`. From 1.9.41, an instance on a shared issuer with auto-create on and an empty allowlist stops auto-creating: a token for an unknown repository gets 403. Tokens of projects already bound keep ingesting. Every edit of that instance (`PUT`) answers 400 until the list is filled or auto-create is switched off. Before the rollout, fill `allowed_owner_ids` (GitHub) or `allowed_namespaces` (GitLab) for these instances, or switch their auto-create off in Settings > CI/CD Instances.

The old image ignores the unknown field, so setting it before the rollout is safe. The ids must be strings: `allowed_owner_ids: [123]` fails `GitHubInstance` validation, and every ingest on that instance would answer 500.

Find the owners in use (replace `<GH_INSTANCE_ID>`):

```js
db.projects.aggregate([
  { $match: { github_instance_id: "<GH_INSTANCE_ID>" } },
  { $group: { _id: { $arrayElemAt: [{ $split: ["$github_repository_path", "/"] }, 0] }, projects: { $sum: 1 } } },
  { $sort: { projects: -1 } }
])
```

Look up each legitimate owner's numeric id; for a user account, replace `orgs/<org>` with `users/<login>`:

```bash
curl -s https://api.github.com/orgs/<org> | jq .id
```

Then set the list:

```js
db.github_instances.updateOne(
  { _id: "<GH_INSTANCE_ID>", url: "https://token.actions.githubusercontent.com" },
  { $set: { allowed_owner_ids: ["<ORG_ID_1>", "<ORG_ID_2>"], last_modified_at: new Date() } }
)
```

For a gitlab.com instance, set its top-level groups:

```js
db.gitlab_instances.updateOne({ url: "https://gitlab.com" }, { $set: { allowed_namespaces: ["<top-level-group>"], last_modified_at: new Date() } })
```

Both updates must report `matchedCount: 1`; 0 means the filter did not match the stored `_id` or `url`, for example a URL stored with a trailing slash. Once a list is set, tokens from other owners or namespaces get 403 even for projects already bound, and so does a GitHub token without the `repository_owner_id` claim. Projects the aggregation shows under owners that are not yours were created by outsiders: review and delete them. After the rollout both lists can also be edited in Settings > CI/CD Instances.

## Right before the rollout (gate): rotate `SECRET_KEY`, or end every session

Tokens now name the user id as their subject, and `/login/refresh-token` resolves it by id. Before 1.9.41, self-service username changes let any user obtain a refresh token that names another account's id. It stays valid for 7 days, and from the first new pod on it resolves to that account. Until the token is refused, its holder can do three things that outlive any session reset: create a `dck_` API key, change a local account's email through the confirmation link and then reset its password, or set a password on an SSO account (`POST /users/me/migrate`). The backend rolls out pod by pod, and old pods hand out such tokens until the last one terminates. A session reset after the rollout alone leaves that window open.

Recommended: rotate `SECRET_KEY` with the deploy. Only this closes the window. Each pod keeps the key it started with, so new pods refuse every token an old pod mints. Right before `helm upgrade`, write a new key into `<fullname>-secrets`, the Secret the backend's `SECRET_KEY` reads. The chart keeps an existing Secret's key and ignores `backend.secrets.secretKey`, so patch the Secret itself:

```bash
kubectl -n <namespace> patch secret <fullname>-secrets --type merge \
  -p "{\"stringData\":{\"secret-key\":\"$(openssl rand -hex 32)\"}}"
```

With `secrets.provider: external-secrets`, change `backendSecretKey` in the store and wait until the Secret shows the new value. The key signs only tokens and links: everyone logs in again, a user may have to log in more than once while requests alternate between old and new pods, and open email-verification and password-reset links stop working. An old-image container that starts after the key change, after a crash or a scale-up during the rollout, reads the new key and reopens the window. The review after the rollout covers that case.

Otherwise, end every session right before the rollout. 1.9.40 honours `last_logout_at` too, so this refuses every token obtained before it. A token obtained on an old pod during the rollout stays valid until the reset after the rollout, so the review after the rollout is then mandatory:

```js
db.users.updateMany({}, { $set: { last_logout_at: new Date() } })
```

In both cases, at the moment of the key change or the reset, snapshot the accounts and note the printed time:

```js
print(new Date().toISOString())
db.users.aggregate([{ $project: { email: 1, pending_email: 1, auth_provider: 1 } }, { $out: "tmp_account_snapshot" }])
```

## After the rollout (mandatory): end every session and review the rollout window

Run this on every installation, once the last pod on the previous image has terminated. An old pod that still serves keeps minting tokens by username, hence after the last old pod:

```js
db.users.updateMany({}, { $set: { last_logout_at: new Date() } })
```

Afterwards every earlier token has an `iat` before every account's `last_logout_at` and is refused (bearer 401, refresh 403), and everyone logs in again. Current usernames show no trace of the rename, so this step cannot depend on a collision check.

The reset does not revoke API keys, emails or passwords set during the window. Review them if you ended sessions before the rollout instead of rotating `SECRET_KEY`, or if an old-image container started after the key change: `kubectl -n <namespace> get pods` shows restarts and ages. Replace `<T0>` with the time printed before the rollout.

API keys created since then, with their owners:

```js
db.api_keys.aggregate([
  { $match: { created_at: { $gte: ISODate("<T0>") }, revoked_at: null } },
  { $lookup: { from: "users", localField: "user_id", foreignField: "_id", as: "u" } },
  { $project: { name: 1, prefix: 1, surfaces: 1, created_at: 1, user: { $first: "$u.username" } } }
])
```

Accounts whose email, pending email or auth provider changed since the snapshot. Accounts created since then show up too, without a `before`:

```js
db.users.aggregate([
  { $lookup: { from: "tmp_account_snapshot", localField: "_id", foreignField: "_id", as: "before" } },
  { $set: { before: { $first: "$before" } } },
  { $match: { $expr: { $or: [
      { $ne: [{ $ifNull: ["$email", null] }, { $ifNull: ["$before.email", null] }] },
      { $ne: [{ $ifNull: ["$pending_email", null] }, { $ifNull: ["$before.pending_email", null] }] },
      { $ne: [{ $ifNull: ["$auth_provider", null] }, { $ifNull: ["$before.auth_provider", null] }] } ] } } },
  { $project: { username: 1, email: 1, pending_email: 1, auth_provider: 1, before: 1 } }
])
```

Ask each listed owner whether the change was theirs. For each change that was not:

- API key: revoke it with `db.api_keys.updateOne({ _id: "<id>" }, { $set: { revoked_at: new Date() } })`.
- Pending email: unset `pending_email`, which voids its confirmation link.
- Changed email: set the snapshot's address back first, then send the owner a password reset, since the new address could have reset the password.
- Auth provider changed to local: set `auth_provider` back to the snapshot value and unset `hashed_password`.

Changes made through the account's roles persist too, such as team or project members and webhooks it added; when the review applies, check those from the same period. Drop the snapshot after the review, or right away when no review is needed:

```js
db.tmp_account_snapshot.drop()
```

## After the rollout: remove TruffleHog plaintext secrets

TruffleHog findings no longer store or serve the plaintext secret (`Raw`). They keep only the first 8 hex characters of its md5 digest (`RawHash`), the part the finding id is built from. Existing `analysis_results` rows still carry `Raw`.

Run this migration **after the rollout has finished**, meaning every backend and worker pod is on the new image. Old pods read only `Raw`. If an old pod aggregates a row after pass 2, it gets `SECRET-<detector>-nohash`, which orphans the waivers. Run it in a backend pod with `kubectl exec ... -- python`, from the working directory where `app` is importable.

The rollout itself has the same window: a TruffleHog upload ingested on a new pod stores only `RawHash`, and if an old pod aggregates that scan, its secrets get `SECRET-<detector>-nohash` ids. Finish the rollout before new TruffleHog uploads are aggregated, or afterwards rescan the scans ingested during the rollout with `POST /api/v1/projects/<project_id>/scans/<scan_id>/rescan`, which aggregates their results again. A scan without SBOMs, such as one from a secrets-only pipeline, refuses the rescan with 400; retry its CI job instead, which uploads to the same scan id and aggregates it again.

Pass 1 writes the digest prefix next to `Raw`. Pass 2 removes `Raw` only from documents in which every finding already has `RawHash`. Carry-over copies made between the deploy and the migration are ordinary `analysis_results` rows, so the same passes clean them. Start with the count line as a dry run.

```python
import hashlib
from pymongo import MongoClient, UpdateOne
from app.core.config import settings
from app.services.aggregation import ResultAggregator

coll = MongoClient(settings.MONGODB_URL)[settings.DATABASE_NAME].analysis_results
q = {"analyzer_name": "trufflehog", "result.findings.Raw": {"$exists": True}}
print("docs with Raw:", coll.count_documents(q))

def ids(doc):
    agg = ResultAggregator()
    agg.aggregate("trufflehog", doc["result"])
    return sorted(f.id for f in agg.get_findings())

sample = {d["_id"]: ids(d) for d in coll.find(q, {"result": 1}).limit(50)}

# Pass 1: persist the digest prefix the finding_id is built from.
ops = []
for doc in coll.find(q, {"result.findings": 1}):
    sets = {}
    for i, f in enumerate(doc["result"].get("findings") or []):
        if "Raw" in f and "RawHash" not in f:
            raw = f["Raw"]
            sets[f"result.findings.{i}.RawHash"] = hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()[:8] if raw else None
    if sets:
        ops.append(UpdateOne({"_id": doc["_id"]}, {"$set": sets}))
    if len(ops) >= 500:
        coll.bulk_write(ops, ordered=False)
        ops = []
if ops:
    coll.bulk_write(ops, ordered=False)

# Pass 2: drop Raw only where every finding carries its digest prefix.
unset_q = {**q, "result.findings": {"$not": {"$elemMatch": {"RawHash": {"$exists": False}}}}}
print("pass 2 modified:", coll.update_many(unset_q, {"$unset": {"result.findings.$[].Raw": ""}}).modified_count)
print("remaining docs with Raw:", coll.count_documents(q))  # expect 0
print("sampled ids changed:", [i for i, before in sample.items() if ids(coll.find_one({"_id": i}, {"result": 1})) != before])  # expect []
```

The last line recomputes the ids of up to 50 sampled documents with the deployed normalizer and compares them with the ids from before pass 1. An empty list shows that pass 1 hashed exactly the way the model does.

Archive bundles already in S3 still hold `Raw`, and no Mongo migration can reach them; the bundle rewrite in the next section removes it. A restore passes TruffleHog results through the same model, so a restored scan gets `RawHash` without `Raw` and identical finding ids, and nothing needs re-running after a restore.

## After the rollout: rewrite archive bundles that still hold TruffleHog plaintext

From 1.9.41, downloads and new bundles carry no `Raw`, but bundles archived before still hold it at rest in S3. This one-off rewrite replaces each affected bundle with a copy whose TruffleHog findings carry `RawHash` instead. Run it after the rollout, in a backend pod (`kubectl exec -it <backend-pod> -- python`), in a window with no restore running. Start with `DRY_RUN = True`, which only lists the affected bundles:

```python
import asyncio, time
from app.core.encryption import is_encryption_enabled
from app.core.s3 import delete_object, upload_stream
from app.db.mongodb import connect_to_mongo, get_database
from app.models.archive import ArchiveMetadata
from app.services.archive import _encrypt_stream, _open_bundle_stream, stream_bundle_for_download
from app.services.archive_bundle import read_bundle_frames

DRY_RUN = True

async def has_plaintext(meta):
    async for e in read_bundle_frames(_open_bundle_stream(meta)):
        d = e.get("data") or {}
        if e["type"] == "doc" and e["collection"] == "analysis_results" and d.get("analyzer_name") == "trufflehog":
            if any("Raw" in f for f in (d.get("result") or {}).get("findings") or []):
                return True
    return False

async def main():
    await connect_to_mongo()
    db = await get_database()
    async for doc in db.archive_metadata.find({}):
        meta = ArchiveMetadata.model_validate(doc)
        if not await has_plaintext(meta):
            continue
        print("plaintext:", meta.scan_id, meta.s3_bucket, meta.s3_key)
        if DRY_RUN:
            continue
        payload, ctype = stream_bundle_for_download(meta), "application/gzip"
        if is_encryption_enabled():
            payload, ctype = _encrypt_stream(payload), "application/octet-stream"
        new_key = f"{meta.project_id}/{meta.scan_id}-{int(time.time())}.bundle"
        size = await upload_stream(new_key, payload, content_type=ctype, bucket=meta.s3_bucket)
        res = await db.archive_metadata.update_one(
            {"scan_id": meta.scan_id, "s3_key": meta.s3_key},
            {"$set": {"s3_key": new_key, "compressed_size_bytes": size}},
        )
        if res.modified_count == 1:
            await delete_object(meta.s3_key, bucket=meta.s3_bucket)
        print("rewritten:", meta.scan_id, "->", new_key, size)
    await asyncio.sleep(1)  # let the S3 reads left open after each footer close before shutdown

asyncio.run(main())
```

- A second dry run afterwards lists nothing once every bundle is clean. The snippet has only run against the test fakes, not against real S3 and MongoDB, so compare the dry-run list with the rewritten lines.
- It uploads the new object and swaps the metadata before it deletes the old object, so a crash midway leaves the old bundle referenced. The orphan reaper removes an unreferenced new object after `ARCHIVE_ORPHAN_MIN_AGE_HOURS`.
- New bundles are encrypted with the live key, the same rule as archiving.
- `delete_object` removes only the live object. Object versioning and GCS soft delete keep the old plaintext; check the bucket before the rewrite and purge the old versions after it, as described below. Backups and replicas of the bucket hold the plaintext too.

### Purge the old plaintext versions

Before the first run with `DRY_RUN = False`, check each bucket the dry run printed. On GCS:

```bash
gcloud storage buckets describe gs://<bucket> --format="default(versioning_enabled,soft_delete_policy)"
```

- `versioning_enabled: true`: each deleted old bundle stays as a noncurrent version.
- `soft_delete_policy` with `retentionDurationSeconds` above 0 (7 days by default): every deleted object and version stays restorable for that long, and nothing removes it earlier. Clearing soft delete does not shorten it for objects already deleted. To remove the plaintext at once, clear soft delete before the rewrite and set the previous duration back after the purge. Objects deleted in between cannot be restored:

```bash
gcloud storage buckets update gs://<bucket> --clear-soft-delete
gcloud storage buckets update gs://<bucket> --soft-delete-duration=<previous duration, e.g. 7d>
```

On S3, `"Status": "Enabled"` or `"Suspended"` means old versions can exist, and an empty answer means versioning was never on. Add `--endpoint-url` for S3-compatible storage:

```bash
aws s3api get-bucket-versioning --bucket <bucket>
```

After the rewrite, take each old key from a `plaintext:` line and make sure no metadata references it any more. A failed metadata swap leaves the old key live:

```js
db.archive_metadata.countDocuments({ s3_key: "<old s3_key>" })  // must be 0
```

Then list its remaining versions and delete each one; use the exact old key, never a prefix that also matches the new bundle. On GCS, run `rm` once per listed `#<generation>`:

```bash
gcloud storage ls --all-versions gs://<bucket>/<old s3_key>
gcloud storage rm gs://<bucket>/<old s3_key>#<generation>
```

On S3, run `delete-object` once per listed version id:

```bash
aws s3api list-object-versions --bucket <bucket> --prefix "<old s3_key>" --query 'Versions[].[Key,VersionId]' --output text
aws s3api delete-object --bucket <bucket> --key "<old s3_key>" --version-id <VersionId>
```

The purge is complete when the listing matches nothing for every old key and, on GCS with soft delete left on, `gcloud storage ls --soft-deleted gs://<bucket>/<old s3_key>` matches nothing after the retention has passed.

## After the rollout: backfill `first_seen_at`

The CVE remediation SLA now measures a finding's age from `first_seen_at`, which is stored when a scan's findings are persisted and carried forward from the project's earlier findings, so retention no longer resets it. Existing findings do not have the field and keep passing the SLA until this backfill has run.

Run the backfill off-peak, because step 2 groups the whole findings collection. It sets `first_seen_at` to the earliest `scan_created_at` of each `(project_id, type, component, version, finding_id)`, using `first_seen_at` where a copy already has one, which matches the application's rule. It only touches documents whose field is missing or later than that minimum, so it is idempotent and safe to re-run. Step 3's filter is served by the new index. In-pod mongosh against the application database:

```js
// 1. Dry run: how many findings lack the field
db.findings.countDocuments({ first_seen_at: { $exists: false } })

// 2. Earliest detection per identity into a scratch collection
db.findings.aggregate([
  { $group: {
      _id: { project_id: "$project_id", type: "$type", component: "$component",
             version: "$version", finding_id: "$finding_id" },
      first_seen_at: { $min: { $ifNull: ["$first_seen_at", "$scan_created_at"] } } } },
  { $match: { first_seen_at: { $ne: null } } },
  { $out: "tmp_first_seen_backfill" }
], { allowDiskUse: true })

// 3. Stamp every copy of each identity (served by the new 7-field findings index)
let ops = [], modified = 0;
const flush = () => { if (ops.length) { modified += db.findings.bulkWrite(ops, { ordered: false }).modifiedCount; ops = []; } };
db.tmp_first_seen_backfill.find().forEach(r => {
  const k = r._id;
  ops.push({ updateMany: {
    filter: { project_id: k.project_id ?? null, type: k.type ?? null, component: k.component ?? null,
              version: k.version ?? null, finding_id: k.finding_id ?? null,
              $or: [{ first_seen_at: { $exists: false } }, { first_seen_at: null },
                    { first_seen_at: { $gt: r.first_seen_at } }] },
    update: { $set: { first_seen_at: r.first_seen_at } } } });
  if (ops.length === 1000) flush();
});
flush();
print(`modified ${modified}`);

// 4. Verify (0 expected, except findings that also lack scan_created_at), then clean up
db.findings.countDocuments({ first_seen_at: { $exists: false } })
db.tmp_first_seen_backfill.drop()
```

`?? null` is deliberate. `$group` omits a missing key from `_id`, and `{version: null}` matches both a null and a missing `version`.

Scans restored from archives written before this release come back without `first_seen_at`. Re-running steps 2 to 4 after such a restore stamps them.

## After the rollout: purge leaked chat tool results, then rotate the exposed secrets

Before 1.9.41 the chat and MCP tools `list_project_webhooks`, `get_system_settings` and `get_project_details` returned webhook secrets and headers, system integration secrets and the project API key hash. Chat history still holds those results in `chat_messages.tool_calls[].result`. Run this after the rollout, because old pods keep writing them:

```js
const leaky = ["list_project_webhooks", "get_system_settings", "get_project_details"];
db.chat_messages.updateMany(
  { "tool_calls.tool_name": { $in: leaky } },
  { $set: { "tool_calls.$[t].result": { error: "Result redacted: it contained credentials" } } },
  { arrayFilters: [ { "t.tool_name": { $in: leaky } } ] })
```

Then rotate every project webhook `secret` and any credential in webhook `headers`. If an admin used `get_system_settings` through chat or an external MCP client, rotate the system integration tokens as well: GitHub and GitLab tokens, the OIDC client secret, the SMTP password, the Slack and Mattermost tokens, and the OSM API key. Running the update again reports `modifiedCount: 0`. Assistant replies (`chat_messages.content`) may repeat a secret in prose; the update does not reach them.

## After the rollout: rotate GitHub Enterprise tokens that reached github.com

Before 1.9.41, GHSA enrichment sent an instance token to api.github.com whenever `system_settings.github_token` was empty. A GHES instance's PAT went too when that instance was the one picked. Every GHES instance without a base URL also sent its PAT there with its own API calls. Rotate those PATs after the rollout; before it, a new PAT would leak the same way. List the candidates, and check the settings token: if it is empty, or was empty at any time, the instance fallback was in use:

```js
db.github_instances.find({ is_active: true, access_token: { $nin: [null, ""] } }, { name: 1, url: 1, github_url: 1, created_at: 1 })
db.system_settings.findOne({ _id: "current" }, { github_token: 1 })
```

## After the rollout: review GitLab bindings set through the old unchecked path

Before 1.9.41 any project admin could bind their project to any GitLab project through `PUT /api/v1/projects/{id}`. 1.9.41 stops new bindings of that kind, but bindings carry no provenance, so an existing one set that way cannot be told apart from one set by OIDC ingest. These read-only reviews list the candidates.

Bindings to an instance that does not exist, possible only through the old unchecked path:

```js
db.projects.aggregate([
  {$match: {gitlab_instance_id: {$type: "string"}}},
  {$lookup: {from: "gitlab_instances", localField: "gitlab_instance_id", foreignField: "_id", as: "inst"}},
  {$match: {inst: {$size: 0}}},
  {$project: {name: 1, gitlab_instance_id: 1, gitlab_project_id: 1, gitlab_project_path: 1}}
])
```

Bound projects whose name no longer matches the bound path. Ingest keeps name and path equal for the projects it creates, so review who administers these:

```js
db.projects.find(
  {gitlab_instance_id: {$type: "string"}, $expr: {$ne: ["$name", "$gitlab_project_path"]}},
  {name: 1, gitlab_instance_id: 1, gitlab_project_id: 1, gitlab_project_path: 1, "members.user_id": 1, "members.role": 1}
)
```

Only if a binding is confirmed as illegitimate, unbind it:

```js
db.projects.updateOne({_id: "<id>"}, {$set: {gitlab_instance_id: null, gitlab_project_id: null, gitlab_project_path: null}})
```

## After the rollout: review the retention of projects created in the dialog

Since 1.4.61 (2026-03-03) the create-project dialog has offered Archive and None as the retention action, but until 1.9.41 every project it created was stored with `retention_action: "delete"`. The upgrade does not correct these projects. While the system retention mode is `project`, housekeeping keeps deleting their expired scans until someone corrects the setting. The choice was never stored, so no migration can restore it.

List the candidates read-only with in-pod mongosh, then ask each owner to confirm the Retention setting in the project's Settings tab. Do not bulk-rewrite them: the list also holds projects whose owners did choose Delete, and the stored documents cannot tell them apart.

```js
db.projects.find(
  { retention_action: "delete", retention_days: { $gt: 0 },
    created_at: { $gte: ISODate("2026-03-03T00:00:00Z"), $lt: ISODate("<time the 1.9.41 rollout finished>") } },
  { _id: 1, name: 1, team_ids: 1, retention_days: 1, created_at: 1 }
).sort({ created_at: -1 })
```

## Once 1.9.41 is confirmed stable: drop the old findings index

The new findings index starts with the old `(project_id, component, type)` key, so the old index only costs writes now. Drop it only once a rollback is no longer expected: 1.9.40 recreates it at startup, in-line on the large findings collection, and pods do not start until that build finishes.

```js
db.findings.dropIndex("project_id_1_component_1_type_1")
```

## Optional after the rollout: look for abuse from before the fix

The fixes stop four abuses but do not undo what happened before the upgrade. The queries are read-only. Run them with in-pod mongosh.

Before 1.9.41 a `team:read_all` holder could add team members and make themselves team admin. This lists team admins who hold `team:read_all` but neither `team:update` nor `system:manage`. Team membership does not record who added a member, so the rows are candidates to review with the team, not proof.

```js
const ids = db.users.find({ permissions: { $in: ["team:read_all"], $nin: ["team:update", "system:manage"] } }, { _id: 1 })
  .toArray().map(u => String(u._id));
db.teams.find(
  { members: { $elemMatch: { role: "admin", user_id: { $in: ids } } } },
  { name: 1, admins: { $filter: { input: "$members",
      cond: { $and: [{ $eq: ["$$this.role", "admin"] }, { $in: ["$$this.user_id", ids] }] } } } }
)
```

The query finds only holders who promoted themselves to team admin. Before 1.9.41 a `team:read_all` holder could also add or re-role other members, delete teams and write team webhooks, and nothing records who did that. Review each team's members and webhooks with the team; `db.webhooks.find({ team_id: { $ne: null } }, { team_id: 1, url: 1, events: 1, created_at: 1 })` lists the team webhooks. A self-made team admin was also admin of the team's projects, so check those projects' policy audit for crypto and license policy changes by the listed users.

Before 1.9.41 a `project:read_all` holder with `webhook:create`, `webhook:update` or `webhook:delete` could create, change, delete and test-fire the webhooks of any project, for example to send its events to an outside URL. Webhooks do not record who created them, so review the listed URLs with each project's owners:

```js
db.webhooks.find({ project_id: { $ne: null } }, { project_id: 1, url: 1, events: 1, created_at: 1 }).sort({ created_at: -1 })
```

Before 1.9.41 a callgraph upload could name a `scan_id` of another project and overwrite that scan's reachability verdicts. This lists callgraphs stored under a scan of a different project:

```js
db.callgraphs.aggregate([
  { $match: { scan_id: { $type: "string" } } },
  { $lookup: { from: "scans", localField: "scan_id", foreignField: "_id", as: "scan" } },
  { $unwind: "$scan" },
  { $match: { $expr: { $ne: ["$scan.project_id", "$project_id"] } } },
  { $project: { project_id: 1, scan_id: 1, language: 1, created_at: 1, updated_at: 1, scan_project_id: "$scan.project_id" } }
])
```

If it returns rows, review them, then delete them with `db.callgraphs.deleteMany({ _id: { $in: [<ids from the query>] } })`. The affected scans keep the injected verdicts until a callgraph is uploaded again for the same pipeline; a rescan replaces the run with one whose reachability stays pending until its callgraph arrives. To replace each affected run now, call `POST /api/v1/projects/<scan_project_id>/scans/<scan_id>/rescan`.

Before 1.9.41 a chat or MCP tool call could pass an object, such as a MongoDB query operator, where an id was declared, for example to read another team's details. MCP arguments are not stored, but chat tool calls are. This lists stored chat tool calls that carried an object-valued argument:

```js
db.chat_messages.aggregate([
  {$unwind: "$tool_calls"},
  {$project: {conversation_id: 1, created_at: 1, tool: "$tool_calls.tool_name",
    args: {$objectToArray: {$cond: [{$eq: [{$type: "$tool_calls.arguments"}, "object"]}, "$tool_calls.arguments", {}]}}}},
  {$match: {args: {$elemMatch: {v: {$type: "object"}}}}}
])
```

## Behaviour changes

### Sign-in, sessions and accounts

- Bearer authentication accepts only access tokens. A refresh token, or a token without a `type` claim, sent as `Authorization: Bearer` now gets 401. A bearer token blacklisted at logout still gets 401, now with the detail "Could not validate credentials" instead of "Token has been revoked".
- `/login/refresh-token` answers every refused token with 403 "Could not validate credentials". A wrongly typed, subject-less or logout-revoked token used to get the detail "Invalid token type", "Invalid token" or "Token revoked".
- Everyone must log in again after the rollout. Tokens now carry the user id as their subject, and the mandatory session step above refuses every earlier token. With a rotated `SECRET_KEY`, users may also have to log in more than once during the rollout. Afterwards, renaming a user no longer logs them out.
- Usernames can no longer be changed in self-service. `PATCH /users/me` answers 422 when the body contains `username`, `email` or any unknown field, and `PUT /users/{own id}` with either answers 403, for administrators too. The profile shows both read-only.
- Local accounts change their email through a confirmation link. `POST /api/v1/users/me/email` stores `pending_email` and mails a link to the new address; `POST /api/v1/confirm-email-change` (frontend route `/confirm-email`) swaps it in and marks it verified. It needs SMTP in the database settings (501 without it). User responses carry `pending_email`.
- An admin can no longer change the email of an account from an identity provider (400). On a local account the new address is stored lowercased and marks the account unverified; with `enforce_email_verification` on, the user must verify again. A blank username and a null username or email answer 422.
- Email lookups ignore case everywhere, and uniqueness checks refuse every case variant of a registered address. New signups and admin-created users are stored lowercased.
- An OIDC login whose `email_verified` claim is false in any case or padding, or `"0"` or `0`, is refused with 400 "The identity provider has not verified this email address". An absent claim still logs in.
- Admin password reset (`POST /users/{id}/reset-password`) never returns a link. It sends the mail and answers `{"message": "Password reset email sent"}`, or 501 "Email server not configured" without SMTP in the database settings. The user dialog no longer shows a manual link.
- User management (`PUT /users/{id}` on another user, `POST /users/{id}/migrate`, `/reset-password`, `/2fa/disable`, `DELETE /users/{id}`) answers 403 "Cannot manage a user who holds permissions you don't hold" when the target holds a permission the caller lacks, unless the caller holds `system:manage`. A permission edit can no longer revoke a permission the caller lacks, and no longer fails because the target keeps one.

### Teams, projects and permissions

- `team:read_all` is read-only. It still reads every team, but adding or changing members, deleting a team and writing team webhooks now need membership with the role the action requires, or the global permission for it such as `team:update` or `team:delete`. The frontend no longer offers team admin actions to users whose only team grant is `team:read_all`.
- `project:read_all` no longer writes project webhooks. Creating, updating, deleting and test-firing a project's webhooks with `webhook:create`, `webhook:update` or `webhook:delete` now also needs membership of the project, direct or through an owning team, or `project:update` or `project:delete`. Accounts that combine `project:read_all` with a webhook permission, such as automation or auditor accounts, now get 403 on projects they are not a member of, and the frontend no longer offers them the webhook controls there. `project:read_all` with `webhook:read` still lists and reads every project's webhooks.
- `GET /api/v1/analytics/projects/{project_id}/dependency-tree` answers 404 "No scan found for this project" for a `scan_id` of another project, which it used to serve, and 404 "Project not found" instead of 403 for an unknown project.
- New projects keep the retention action and analyzer settings chosen at creation. They used to be stored with `retention_action: "delete"` and no analyzer settings. When the system retention mode is `global`, the global retention settings still apply. Projects created before 1.9.41 with Archive or None are still stored as Delete, and housekeeping keeps deleting their scans until an owner corrects the setting. See "review the retention of projects created in the dialog" above.
- Team member add and project invite by email find only accounts with a verified email, in any case, and otherwise answer 404 "No user has verified this email address". Accounts created by an admin, or by a signup whose link was never clicked, are not verified.
- GitLab binding changes need an admin. Setting or changing `gitlab_instance_id` or `gitlab_project_id` through `PUT /api/v1/projects/{id}` needs `system:manage`, `project:update` or `project:delete`; project admins get 403. Clearing both stays open to project admins, and resending the stored values is unaffected. A half binding answers 400, an unknown instance 404, and a GitLab project bound to another project 409 instead of 500. When the instance answers, the stored path is GitLab's `path_with_namespace`.
- Project settings show other users a bound project's GitLab link read-only, with a "Remove GitLab link" action. Choosing "None" as the GitLab instance clears the project id and path too.

### CI integrations

- Allowlists gate OIDC auto-create. A github.com or gitlab.com instance with auto-create on and an empty `allowed_owner_ids` or `allowed_namespaces` no longer auto-creates (403). Once a list is set on any instance, tokens from other owners or namespaces get 403 even for projects already bound, and so does a GitHub token without `repository_owner_id`. Each refusal logs a warning with the repository path and owner id.
- The instance admin API answers 422 on create and 400 on update for a shared issuer with auto-create on and an empty list. It refuses an explicit `null` list, non-numeric owner ids and namespaces with a `/`. Settings > CI/CD Instances has the new inputs.
- CI auto-create makes the GitLab job's `user_email` project admin only if a verified account holds it, and the GitHub `actor` only if its public GitHub email belongs to a verified account. That costs one GitHub API read per auto-created project.
- Team sync (GitLab and GitHub) matches members only by their provider email against verified accounts, never by username. Members matched by username so far drop out at the next sync, with the project roles the team gave them. GitHub sync reads `GET /users/{login}` for every member (cached 5 minutes).
- GitLab team sync with a non-admin token looks up each member's public email with `GET /users/:id`, which GitLab rate-limits. On 429 the group's stored members stay as they are until the next window, logged as WARNING "GitLab API GET /users/<id> answered 429". Answers are cached for 24 hours, so a member who sets or changes a public email is matched up to a day later. Jobs that read the same group concurrently split the budget. When the distinct members of one token's synced groups, times the jobs reading them concurrently, exceed the daily budget (about 43,200 at the default limit), cached answers expire before the rest are filled and the affected groups stay frozen for good; the 429 WARNING is the only signal. A group where no member resolves freezes, logged as WARNING "Resolved 0 of N members of GitLab group ...".
- GitHub tokens are sent only to github.com, so a GHES token never reaches api.github.com. Without `system_settings.github_token`, GHSA enrichment takes the token of the oldest active github.com instance, and an installation with only GHES instances runs GHSA unauthenticated (60 requests per hour). Removing or deactivating a token takes effect on the next scan.
- A GHES instance without a base URL makes no GitHub API calls: team sync, PR decoration, branch listing and pickers get no answer, as with no token. The settings field is now "GitHub Base URL".

### Archives

- A restore marks its scan `restore_in_progress` until its last write, then sets `restored_at`. Restoring a scan that an earlier restore left unfinished rolls back the leftovers and restores it again; it used to answer 409. Housekeeping keeps the metadata and bundle of an unfinished restore.
- A second restore of the same scan answers 409 for as long as the first runs, which renews its lock every 200 s. A restore that lost its lock stops without rolling back and counts `archive_failures_total{operation="restore",reason="lock_held"}`.
- Archive downloads are re-emitted, not byte-identical to the stored object. TruffleHog findings carry `RawHash` instead of `Raw`, their lines are re-encoded, the footer digest is recomputed and the stream is compressed again; other lines and markers pass through as stored. A download holds about twice the largest line in memory.
- Download decryption follows the bundle: a plaintext bundle downloads after encryption was switched on, and an encrypted bundle fails once the key is removed. A bundle that fails its digest check, is truncated or has an unknown header version aborts the download mid-stream.
- New bundles never contain TruffleHog `Raw`. A TruffleHog row that fails validation fails the archive of its scan, and the scan's data stays in MongoDB.

### Analysis and uploads

- Callgraph uploads ignore a `scan_id` in the request body. The scan is always derived from the project in the path together with `pipeline_id` and the commit. Clients that still send `scan_id` keep working, and the field is dropped.
- New ad-hoc and callgraph size limits answer 413 before any parsing. Ad-hoc `/api/v1/analyze` refuses more than 50 000 callgraph entries and more than 250 000 SBOM dependency-graph entries, and SPDX `externalRefs` now count against the 20 000 component-evidence budget.
- A callgraph upload's 200 000-entry limit now also counts symbols, madge dependencies and analyzed modules, and an oversized upload with a bad format gets 413 instead of 400. A `callee_function` that is a JSON object or array fails the parse (400 on upload).
- OSV malicious-package (MAL-) matches now produce a CRITICAL malware finding; they used to be dropped. Expect new malware findings, and the notifications they trigger, on the next scan of affected projects; a rescan surfaces them sooner. OSV findings now carry `published` and `modified`.

### Webhooks, notifications and chat

- Webhook response bodies are capped and bound by a deadline. A delivery attempt or `POST /webhooks/{id}/test` fails as a timeout when the attempt as a whole takes longer than `WEBHOOK_TIMEOUT_SECONDS` (default 30 s). On 2xx the body is not read; on other statuses at most 64 KiB is read, decoded as UTF-8. Requests send `Accept-Encoding: identity`. The test's `response_time_ms` and the webhook duration histogram measure time to response headers.
- Deactivated users get no project notifications on any channel, whether they are direct or team members. Enforced notification settings come from the first active admin member with preferences.
- Chat and MCP tool arguments are type-checked. A wrong JSON type answers `{"error": "Argument '<name>' must be of type <type>"}` (`isError: true` over MCP), arguments that are not a JSON object answer "Tool arguments must be a JSON object", and undeclared keys are dropped.
- Chat and MCP tool results follow the REST response schemas. `get_system_settings` returns `*_configured` booleans instead of secrets, `get_project_details` no longer returns `api_key_hash`, and `list_project_webhooks` no longer returns `secret`, `headers` or the delivery counters. Members without `webhook:read` who are not project admins are refused the webhook tools, as in REST, and `get_webhook_deliveries` answers "Webhook not found or access denied" to every refusal.

### Monitoring

- The `endpoint` label of `http_requests_total`, `http_request_duration_seconds`, `http_request_size_bytes` and `http_response_size_bytes` now carries the matched route template, for example `/api/v1/projects/{project_id}`, instead of the raw path with ids masked as `{id}`. Unmatched requests share the label `<unmatched>`, and `http_requests_in_progress` is labelled by `method` only. Dashboards and alerts that filter on raw paths need updating. The bundled Grafana dashboard only groups by `endpoint` and needs no change.



# Release 1.9.40

## 📦 Build & CI

- chore: release 1.9.40 — GitLab parity, the permission gate, and the tests that pinned nothing (#0)



# Release 1.9.40



# Release 1.9.39



# Release 1.9.38



# Release 1.9.37



# Release 1.9.36

## 📦 Build & CI

- chore: bump VERSION to 1.9.35 (#0)



# Release 1.9.35



# Release 1.9.34

## 📦 Build & CI

- chore: release 1.9.32 - GitHub adopts the team it would have duplicated (#0)



# Release 1.9.32

## 📦 Build & CI

- chore: release 1.9.31 - GitHub creates the teams it does not know yet (#0)



# Release 1.9.31

## 📦 Build & CI

- chore: release 1.9.30 - the team dropdown is back in the settings form (#0)



# Release 1.9.30

## 📦 Build & CI

- chore: release 1.9.29 - owning teams in a plain multi-select dropdown (#0)



# Release 1.9.29

## 📦 Build & CI

- chore: release 1.9.28 — pick several owning teams in one go (#0)



# Release 1.9.28

## 📦 Build & CI

- chore: release 1.9.27 — projects owned by several teams (#0)



# Release 1.9.27

## 📦 Build & CI

- chore: release 1.9.25 — GitHub team resolution without repository admin (#0)
- chore: release 1.9.26 — bind a team to a GitHub team (#0)



# Release 1.9.26

## 🐛 Fixes

- fix(api): file CBOM ingest under the ingest tag with its siblings (#0)

## 📦 Build & CI

- chore: release 1.9.24 — retire the legacy API key systems (#0)



# Release 1.9.24

## 🚀 Features

- feat(projects): carry team_ids and per-team team_sources (#0)
- feat(scripts): expand project team_id into team_ids (#0)
- feat(scripts): expand project team_id into team_ids (#0)
- feat(scripts): expand project team_id into team_ids (#0)
- feat(db): index projects on team_ids (#0)
- feat(api-keys): one repository for keys that name their surfaces (#0)
- feat(db): index the unified api_keys collection (#0)
- feat(api-keys): request and response schemas for unified keys (#0)
- feat(api-keys): one dependency for any key-guarded surface (#0)
- feat(api-keys): mint, list and revoke unified keys (#0)
- feat(api-keys): analyze accepts unified and legacy keys (#0)
- feat(ui): client and hooks for unified API keys (#0)
- feat(ui): one card for keys that name their surfaces (#0)
- feat(ui): offer the unified key card on the profile page (#0)

## 🐛 Fixes

- fix(api-keys): mode=after for request validation, comprehensive tests, docstring cleanup (#0)
- fix: add created_at nullability split and real refetch tests (#0)

## 🧪 Tests

- test: add regression tests for team_ids derivation in constructor and unassigned state (#0)
- test(mcp): pin the MCP key auth contract (#0)
- test(mcp): detect a widened permission gate and stray key writes (#0)
- test(mcp): pin the MCP key repository and endpoints (#0)
- test(api-keys): pin the primary read, the scope of a usage stamp and the expiry floor (#0)
- test(api-keys): pin the fail-closed surface default and the header-free 401 (#0)

## 📦 Build & CI

- chore: release 1.9.23 — unified API keys, multi-team groundwork, ad-hoc hardening (#0)



# Upgrade notes for 1.9.27 — a project can belong to several teams

**This release changes what per-team numbers mean.** A project now belongs to a list of teams rather than
one, and it counts **fully at every** owning team. Per-team figures are therefore no longer additive:
adding up the teams will exceed the estate total. That is correct, not a bug.

- `team_id` on a project is replaced by `team_ids`, and each owner records who established it —
  a GitLab sync, a GitHub sync, or a person. A sync only ever replaces the owners **it** set, so a team
  someone added by hand is never removed by CI, and a repository that moves loses the team it left.
- The project list and the API now report `teams: [{id, name}]` where they used to report a single
  `team_name`. A project with no owner reports `[]`.
- Ownership moved out of the project settings form into its own card: add and remove owners individually.
  Removing an owner a provider established only lasts until the next sync re-establishes it, and the UI
  says so. A project cannot be left with no team able to administer it, and 16 owners is the cap.
- Everyone in **any** owning team reaches the project, with the strongest role any of those teams grants —
  so gaining a co-owner can never take access away from anyone who already had it.

**Metabase dashboards are not adjusted by this release.** Cards that read `projects.team_id` will
undercount every co-owned project, and cards that group on the team without unwinding will bucket by the
whole owner list. They need fixing separately.

# Upgrade notes for 1.9.24 — the legacy API key systems are gone

**Both older key systems have been removed.** `dca_` keys (ad-hoc analysis) and `mcp_` keys (MCP) no
longer exist, along with the two cards that managed them and the endpoints behind them:

- `GET|POST|DELETE /api/v1/analyze-keys/...` — removed
- `GET|POST|DELETE /api/v1/mcp-keys/...` — removed

Mint one key under **Profile → API keys** instead and tick the surfaces it should open. A single
`dck_` key can serve both `/api/v1/analyze` and `/api/v1/mcp`.

`/api/v1/analyze` and `/api/v1/mcp` are otherwise unchanged: same request shapes, same status codes,
same messages. Only the accepted token prefix narrowed to `dck_`. Everything a unified key could do
before this release, it still does.

Nothing else about a key changed — listing and revoking still need only ownership, so a key you own
stays visible and revocable even if you lose the permission that let you mint it; `/analyze` still
records no usage stamp, so an ad-hoc-only key's last-used column still reads *not recorded*.

# Upgrade notes for 1.9.23

## 🔑 API keys

- The profile page now offers **one card for API keys**. A key minted there names the surfaces it may
  enter — MCP, ad-hoc analysis, or both — so a single `dck_` key replaces the two you previously had to
  mint separately. You are offered only the surfaces you hold the permission to mint for.
- Your existing `dca_` and `mcp_` keys keep working, and the two older cards stay on the page so you can
  still see and revoke them. Mint a replacement at your convenience; nothing expires early.
- A key you own stays listed and revokable even if you lose the permission that let you mint it.
  Previously such a key was invisible to its owner and could not be killed.
- Where a key is used only for ad-hoc analysis, its last-used column reads *not recorded* rather than
  *never used*: `/analyze` deliberately writes nothing when it authenticates, so there is no stamp to
  show — the key may be in constant use.

- `POST /api/v1/analyze` now accepts a unified `dck_` key naming the `adhoc` surface as well as the
  `dca_` ad-hoc key it has always taken. Existing `dca_` keys keep working unchanged; mint a
  replacement under `/api/v1/api-keys` at your convenience.
- Three response details on that endpoint changed with it:
  - the 401 for an unusable token now reads `Invalid, revoked, or expired API key` (was
    `Invalid, revoked, or expired ad-hoc API key`), so the answer no longer says which key system
    was consulted;
  - the 403 for an owner who lost the permission now reads `Token owner no longer has adhoc access`
    (was `Token owner no longer has ad-hoc analysis access`);
  - the `WWW-Authenticate` challenge sent when the `Authorization` header is missing is now
    `Bearer realm="adhoc"` (was `realm="analyze"`).
- `POST /api/v1/mcp` now accepts a unified `dck_` key naming the `mcp` surface as well as the `mcp_`
  key it has always taken. Existing `mcp_` keys keep working unchanged, last-used stamp included;
  mint a replacement under `/api/v1/api-keys` at your convenience.
- Three response details on that endpoint changed with it:
  - the 401 for an unusable token now reads `Invalid, revoked, or expired API key` (was
    `Invalid, revoked, or expired MCP API key`), so the answer no longer says which key system was
    consulted;
  - the 403 for an owner who lost the permission now reads `Token owner no longer has mcp access`
    (was `Token owner no longer has MCP access`);
  - a unified key that does not name the `mcp` surface is answered 403
    `API key does not grant the mcp surface`.
- `GET /api/v1/api-keys/` no longer fails the whole page when one stored key document is damaged.
  Such a key is now listed with placeholders for the fields it lost — `""` for `name` and `prefix`,
  `[]` for `surfaces`, `null` for a timestamp — so it stays visible, and the keys beside it stay
  listed. `created_at` and `expires_at` are therefore nullable in the listing; on the mint response
  they stay required, because that renders a document the server has just written.
- `DELETE /api/v1/api-keys/{key_id}` now also accepts the id of a key whose stored `_id` is an
  `ObjectId` rather than a string. Such a key was listed but answered 404 on revoke, so it could be
  seen and not killed. Keys minted through this API are unaffected.
- A damaged key document is now logged once per listing at `WARNING`, naming the key id and the
  fields that fell back to placeholders.

## 🛡️ Ad-hoc analysis

- **A crafted SBOM can no longer stall `/api/v1/analyze`.** Every SPDX licence pattern opened with a
  repeated whitespace class, so the engine restarted from each position inside a whitespace run and
  backtracked the whole run each time. One component licensed `MIT` + 50k spaces + `Apache-2.0` cost
  around 10 s of CPU in a stage the endpoint reaches synchronously, where its 180 s deadline cannot
  interrupt it — an 80 KB request killed a uvicorn worker outright and reset the connection. Worst case
  at 80k characters is now 6 ms, and every shape scales linearly. Licence results are unchanged.
- **`analyzers.notes` now names every stage that puts your posted data on the wire.** It promised this
  and carried only `osv` and `epss_kev`, so a caller who requested `deps_dev`, `outdated_packages`,
  `end_of_life`, `hash_verification`, `maintainer_risk` or `os_malware` was told nothing while their
  package coordinates went to `api.deps.dev`, `endoflife.date`, `pypi.org`, `registry.npmjs.org`,
  `api.github.com` or `api.opensourcemalware.com`. `typosquatting` is now named too, saying the
  opposite: it downloads a list and matches locally, sending nothing.
- **A crypto finding's id is now stable across runs.** It was a fresh UUID per run, so the same CBOM
  posted twice returned the same findings under different ids and a waiver written against
  `finding_id` could never match a later scan. The id is now `CRYPTO-{type}-{bom_ref}`. Nothing stored
  has to move — this installation holds no crypto assets or findings yet.

## 👥 Teams

- A project now also carries `team_ids` and per-team `team_sources` alongside its existing `team_id`,
  and project access derives from **every** owning team rather than only the first. The scalar stays
  authoritative and remains the field every writer sets; nothing about team assignment changes yet.



# Release 1.9.22



# Release 1.9.21



# Release 1.9.20



# Release 1.9.19



# Release 1.9.18

## 📦 Build & CI

- chore: bump to 1.9.17 (#0)



# Release 1.9.17

## 📦 Build & CI

- chore: bump to 1.9.16 (#0)



# Release 1.9.16

## 📦 Build & CI

- chore: bump to 1.9.15 (#0)



# Release 1.9.15

## 📦 Build & CI

- chore: bump to 1.9.14 (#0)



# Release 1.9.14

## 📦 Build & CI

- chore: bump to 1.9.13 (#0)



# Release 1.9.13

## 📦 Build & CI

- chore: bump to 1.9.12 (#0)



# Release 1.9.12

## 📦 Build & CI

- chore: bump to 1.9.11 (#0)



# Release 1.9.11

## 📦 Build & CI

- chore: bump to 1.9.10 (#0)



# Release 1.9.10

## 📦 Build & CI

- chore: bump to 1.9.9 (#0)



# Release 1.9.9

## 📦 Build & CI

- chore: bump to 1.9.8 (#0)



# Release 1.9.8

## 📦 Build & CI

- chore: bump to 1.9.7 (#0)



# Release 1.9.7

## 📦 Build & CI

- chore: bump to 1.9.6 (#0)



# Release 1.9.6



# Release 1.9.5



# Release 1.9.4



# Release 1.9.3

## 📦 Build & CI

- chore: bump version to 1.9.1 (#0)



# Release 1.9.1

## 📦 Build & CI

- chore: bump version to 1.9.0 (#0)



# Release 1.9.0

## 📦 Build & CI

- chore: bump version to 1.8.5 (#0)



# Release 1.8.5

## 🐛 Fixes

- fix: surface configured state for stored secrets in system settings UI (#102) (#0)

## 📦 Build & CI

- chore: bump version to 1.8.4 (#0)



# Release 1.8.4

## 🐛 Fixes

- fix: read outdated latest version from fixed_version and align inventory card headers (#101) (#0)

## 📦 Build & CI

- chore: bump version to 1.8.3 (#0)



# Release 1.8.3

## 📦 Build & CI

- chore: bump version to 1.8.2 (#0)



# Release 1.8.2



# Release 1.8.1

## 🚀 Features

- feat(secrets): capture git origin commit and current-tree status (#0)
- feat(secrets): score secrets by verified + current-tree status (#0)
- feat(stats): add SecretPrioritizedCounts model (#0)
- feat(stats): compute secret_priority per scan (#0)
- feat(types): add secret git-context and priority fields (#0)
- feat(findings-table): show tree-status badge for secret findings (#0)
- feat(finding-details): show origin commit and tree status for secrets (#0)
- feat(project-overview): add secret priority dashboard card (#0)

## 🐛 Fixes

- fix(finding-details): format commit timestamp with formatDate (#0)



# Release 1.8.0

## 🐛 Fixes

- fix(scan): align the findings filter to the right of the tab bar (#0)



# Release 1.7.8



# Release 1.7.7

## 🐛 Fixes

- fix(sbom): direct-dep fallback returns root children, not roots, when SBOM bom-ref mismatches dependency graph (#0)
- fix(analysis): read SBOM from primary GridFS with bounded retry; mark scan failed (not silently completed) when no SBOM can be loaded (#0)

## 📦 Build & CI

- chore(frontend): remove dead exports (legacy permission re-exports, QUERY_STALE_TIMES, finding-utils SEVERITY_ORDER) (#0)



# Release 1.7.6

## 🚀 Features

- feat(waivers): recompute MatchSignature from a raw finding doc (self-heal input) (#0)
- feat(waivers): record dormant (no-candidate) waivers in WaiverApplication (#0)
- feat(waivers): log per-recalc waiver outcomes + dormant detail (rule_key/file_key/group size) (#0)
- feat(waivers): add rule_keys set + effective_rule_keys to MatchSignature (#0)
- feat(waivers): populate rule_keys set in signature derivation (#0)
- feat(waivers): group by file_key + rule-key-set intersection (scanner-flip robustness) (#0)
- feat(waivers): add last_eval_scan_id + last_match_count to Waiver (#0)
- feat(waivers): record per-waiver match outcome in recalc (orphaned visibility) (#0)
- feat(api): expose waiver eval outcome + orphaned list filter (#0)
- feat(ui): thread orphaned filter + eval-outcome fields through waiver types/api/hooks (#0)
- feat(ui): orphaned-waiver badge + 'only orphaned' filter in waiver tables (#0)

## 🐛 Fixes

- fix(waivers): self-heal missing finding signature in recalc so re-anchoring isn't silently dropped (#0)
- fix(chat): get_waiver_status no longer reports waived=true on mere waiver existence (#0)
- fix(ui): waiver table overflow + a11y + error states, lapsed-badge condition/label, re-waive scope prefill (#0)
- fix(api): orphaned waiver filter also excludes expired waivers (mirror is_active badge) (#0)
- fix(ui): team members dialog scrolls instead of overflowing the screen with many members (#0)
- fix(gitlab): team sync resolves existing users only, never creates GitLab bot/service accounts (#0)
- fix(ui): truncate username + break long user_id in team members dialog (no horizontal scroll) (#0)
- fix(gitlab): resolve team members by case-insensitive email so a real user is not silently dropped on case mismatch (#0)

## 🧪 Tests

- test(waivers): assert Finding and raw-doc signature paths are equivalent (#0)



# Release 1.7.5

## 🚀 Features

- feat(iac): persist KICS similarity_id in finding details for waiver anchoring (#0)
- feat(models): add MatchSignature and finding/waiver match + lapsed fields (#0)
- feat(waivers): add compute_match_signature for location-based findings (#0)
- feat(aggregation): attach MatchSignature to every finding in get_findings (#0)
- feat(waivers): add Pass-1 strong-exact waiver match predicate (#0)
- feat(waivers): add two-pass waiver-to-finding orchestrator with re-anchoring (#0)
- feat(waivers): lazy back-fill MatchSignature for legacy finding-scope waivers (#0)
- feat(waivers): snapshot finding MatchSignature into waiver at creation (#0)
- feat(waivers): strong-exact signature match in ingest + engine apply paths (#0)
- feat(api): add GET /waivers/{id} endpoint for single waiver lookup (#0)
- feat(ui): show lapsed-waiver badge and re-waive (prefill) for shifted findings (#0)
- feat(permissions): add chat + mcp to USER preset (analytics stays own-projects-only) (#0)

## 🐛 Fixes

- fix(ingest): keep OpenGrep extra.fingerprint and extra.lines through validation (#0)
- fix(waivers): route untyped non-location waivers to legacy path (avoid silent drop) (#0)
- fix(waivers): keep file/rule-scope waivers on legacy path (signature path is finding-scope only) (#0)
- fix(chat): get_waiver_status reads authoritative finding waived/lapsed flags (#0)



# Release 1.7.4



# Release 1.7.3



# Release 1.7.2

## 🚀 Features

- feat(archive): bump bundle/encryption versions, add streaming constants (#0)
- feat(archive): add reason-labeled failure metric (#0)
- feat(archive): replace single-block AES-GCM with chunked streaming format (#0)
- feat(archive): add streaming multipart upload/download for S3 (#0)
- feat(archive): add NDJSON bundle v2 reader/writer (#0)
- feat(housekeeping): add orphan S3 object reaper (#0)
- feat(archive): pre-deploy guard against v1 bundle data (#0)
- feat(scan-delta): add unified response schemas (#0)
- feat(scan-delta): add findings identity-key helper (#0)
- feat(scan-delta): compute findings delta with filters and pagination (#0)
- feat(scan-delta): add components identity-key helper (#0)
- feat(scan-delta): compute components delta with version+license diff (#0)
- feat(scan-delta): add crypto delta envelope adapter (#0)
- feat(scan-delta): orchestrator with category dispatch and validation (#0)
- feat(scan-delta): unified REST endpoint with auth and cross-project guard (#0)
- feat(scan-delta): frontend API client for unified scan delta (#0)
- feat(scan-delta): shared list/pagination/badge components (#0)
- feat(scan-delta): crypto delta tab (migrated from ScanDeltaView) (#0)
- feat(scan-delta): findings delta tab with severity/type/change filters (#0)
- feat(scan-delta): components delta tab with added/removed/version/license (#0)
- feat(scan-delta): multi-tab modal with lazy-loaded tabs and badge counts (#0)
- feat(scan-delta): wire ScanDeltaModal in ProjectScans, remove old crypto view (#0)
- feat(mcp): advertise new params + envelope shape in compare_scans/get_scan_delta definitions (#0)

## 🐛 Fixes

- fix(housekeeping): skip in-progress scans during retention archive (#0)
- fix(archive): plug 5 data-integrity gaps from follow-up review (#0)
- fix(archive): close remaining ghost-scan and stale-metadata gaps (#0)
- fix(scan-delta): add finding_id tiebreaker for deterministic pagination (#0)

## 🧪 Tests

- test(archive): add FakeS3Client helper for streaming tests (#0)



# Release 1.7.1



# Release 1.7.0



# Release 1.6.9



# Release 1.6.8



# Release 1.6.7



# Release 1.6.6



# Release 1.6.5

## 🐛 Fixes

- fix: bump CURRENT_SEED_VERSION to 2 to force re-seed with expanded BSI rules (#0)
- fix: revert CURRENT_SEED_VERSION back to 1 (clean start) (#0)



# Release 1.6.4



# Release 1.6.3



# Release 1.6.2



# Release 1.6.1



# Release 1.6.0



# Release 1.5.9



# Release 1.5.8

## 🚀 Features

- feat: add webhook_type field to Webhook model and schemas (#0)
- feat: add detect_webhook_type() for Teams URL auto-detection (#0)
- feat: add TeamsFormatter with Adaptive Card builders (#0)
- feat: apply Adaptive Card formatting for Teams webhooks at delivery time (#0)
- feat: auto-detect Teams webhook type in all create endpoints (#0)

## 🐛 Fixes

- fix: tighten WebhookResponse type, fix test imports, add WebhookUpdate type test (#0)
- fix: move datetime import to module level in webhook tests (#0)
- fix: add dot-boundary to detect_webhook_type hostname checks (#0)
- fix: address TeamsFormatter code review issues (unused param, conditional title, type safety, tests) (#0)
- fix: remove unused pytest import in integration test (#0)



# Release 1.5.7



# Release 1.5.5



# Release 1.5.4



# Release 1.5.3



# Release 1.5.2



# Release 1.5.1



# Release 1.5.0



# Release 1.4.99



# Release 1.4.98



# Release 1.4.92



# Release 1.4.88



# Release 1.4.87



# Release 1.4.86



# Release 1.4.85



# Release 1.4.84



# Release 1.4.83



# Release 1.4.82



# Release 1.4.81



# Release 1.4.80



# Release 1.4.79



# Release 1.4.78



# Release 1.4.77



# Release 1.4.76



# Release 1.4.75



# Release 1.4.74



# Release 1.4.73



# Release 1.4.72



# Release 1.4.71



# Release 1.4.70



# Release 1.4.69



# Release 1.4.68



# Release 1.4.67



# Release 1.4.66



# Release 1.4.65



# Release 1.4.64



# Release 1.4.63



# Release 1.4.62



# Release 1.4.61



# Release 1.4.60



# Release 1.4.59



# Release 1.4.58



# Release 1.4.57



# Release 1.4.56



# Release 1.4.55



# Release 1.4.54



# Release 1.4.52



# Release 1.4.51



# Release 1.4.50



# Release 1.4.49



# Release 1.4.47



# Release 1.4.46

## 🐛 Fixes

- fix: license normalizer (#0)



# Release 1.4.45



# Release 1.4.44



# Release 1.4.43



# Release 1.4.42



# Release 1.4.41

## 🚀 Features

- feat: add dashboard URL field to system settings and update related components (#0)

## 🐛 Fixes

- fix: ensure Mattermost usernames are prefixed with '@' when sending notifications (#0)



# Release 1.4.40

## 📦 Build & CI

- chore: update version to 1.4.40 and enhance GitLab team synchronization logic (#0)



# Release 1.4.39



# Release 1.4.38

## 📦 Build & CI

- chore: update version to 1.4.38 and add atomic upsert method in ScanRepository (#0)



# Release 1.4.37

## 📦 Build & CI

- chore: update version to 1.4.37 (#0)



# Release 1.4.36

## 📦 Build & CI

- chore: update version to 1.4.36 and rename ttl parameter in GitLabService caching methods (#0)



# Release 1.4.35

## 📦 Build & CI

- chore: remove GitLab integration settings and related UI components (#0)



# Release 1.4.34

## 📦 Build & CI

- chore: update version to 1.4.34 and refactor delete confirmation dialog (#0)



# Release 1.4.33

## 📦 Build & CI

- chore: bump version to 1.4.33 (#0)



# Release 1.4.32

## 📦 Build & CI

- chore: bump version to 1.4.32 and optimize project retrieval queries (#0)



# Release 1.4.31

## 🚀 Features

- feat: enrich project list with team names and update response model (#0)

## 📦 Build & CI

- chore: bump version to 1.4.31 and update team ID retrieval to use Pydantic models (#0)



# Release 1.4.29

## 📦 Build & CI

- chore: bump version to 1.4.29 and add projection parameter to get_multiple_scans method (#0)



# Release 1.4.28

## 📦 Build & CI

- chore: bump version to 1.4.28 and remove team name enrichment logic from read_projects endpoint (#0)



# Release 1.4.27

## 📦 Build & CI

- chore: bump version to 1.4.27 and update project interface to include team_name (#0)



# Release 1.4.26



# Release 1.4.25

## 📦 Build & CI

- chore: bump version to 1.4.25 and update settings handling in analysis engine (#0)



# Release 1.4.24



# Release 1.4.23

## 📦 Build & CI

- chore: bump version to 1.4.23 (#0)



# Release 1.4.22

## 🚀 Features

- feat: enhance repository methods to return Pydantic models for projects, scans, and users (#0)
- feat: implement CustomAPIRouter to standardize API responses using field names instead of aliases (#0)



# Release 1.4.21

## 📦 Build & CI

- chore: remove response_model_by_alias setting from API routers for consistency (#0)
- chore: remove by_alias=True from model_dump calls for consistency (#0)



# Release 1.4.19

## 📦 Build & CI

- chore: update version to 1.4.19 and set response_model_by_alias to False in API routers (#0)



# Release 1.4.18

## 📦 Build & CI

- chore: update version to 1.4.18 and enhance MongoDB field handling in models (#0)



# Release 1.4.17

## 📦 Build & CI

- chore: update version to 1.4.17 and refactor schemas for MongoDB integration (#0)



# Release 1.4.16



# Release 1.4.15



# Release 1.4.14

## 📦 Build & CI

- chore: consolidate code change entries for better organization (#0)



# Release 1.4.13

## 📦 Build & CI

- chore: bump version to 1.4.13 (#0)



# Release 1.4.12

## 📦 Build & CI

- chore: update authentication flow to restrict OIDC users from local 2FA configuration and enhance user feedback in UI (#0)



# Release 1.4.11

## 📦 Build & CI

- chore: remove unnecessary comments from check_scheduled_rescans function (#0)
- chore: update redirect URI logic for OIDC endpoints to support external URLs (#0)



# Release 1.4.10

## 📦 Build & CI

- chore: bump version to 1.4.10 and update pod lifecycle settings (#0)



# Release 1.4.9

## 📦 Build & CI

- chore: bump version to 1.4.9 (#0)



# Release 1.4.8

## 🐛 Fixes

- fix: update liveness and readiness probes to return JSONResponse for consistency (#0)

## 📦 Build & CI

- chore: bump version to 1.4.8 (#0)



# Release 1.4.7

## 🚀 Features

- feat: enhance memory debug endpoint to identify large containers (#0)



# Release 1.4.6

## 🚀 Features

- feat: add memory debug endpoint to analyze memory usage (#0)



# Release 1.4.5

## 📦 Build & CI

- chore: bump version to 1.4.5 and update MongoDB connection pool settings (#0)



# Release 1.4.4

## 📦 Build & CI

- chore: bump version to 1.4.4 (#0)



# Release 1.4.3



# Release 1.4.2



# Release 1.4.1

## 🚀 Features

- feat: add endpoint to retrieve waivers for a specific project (#0)
- feat: add migration endpoint for SSO users to local accounts (#0)
- feat: enhance scan result handling and aggregation logic (#0)
- feat: implement fast loop for stale scan aggregation and enhance SAST details display (#0)
- feat: improve scan analysis handling and enhance finding details display (#0)

## 🐛 Fixes

- fix: ensure charts have minimum width for better responsiveness (#0)

## 📦 Build & CI

- chore: release v1.4.0 [skip ci] (#0)
- chore: update version to 1.4.1 and enhance dashboard URL handling in notifications (#0)



# Release 1.3.9



# Release 1.3.8

## 📦 Build & CI

- chore: bump version to 1.3.8 and update UserTable imports (#0)



# Release 1.3.7

## 🚀 Features

- feat: add loading spinner to FindingsTable for better UX (#0)

## 🐛 Fixes

- fix: handle None overall_score in process_quality function (#0)

## 📦 Build & CI

- chore: bump version to 1.3.7 (#0)



# Release 1.3.6



# Release 1.3.5

## 🚀 Features

- feat: add package suggestion feature and improve broadcasts UI (#0)



# Release 1.3.4

## 🚀 Features

- feat: enhance analytics and scans APIs with advanced search options and improved type definitions (#0)



# Release 1.3.3



# Release 1.3.2

## 🚀 Features

- feat: bump version to 1.3.2 and enhance notification system with new types and improved logic (#0)



# Release 1.3.1

## 🚀 Features

- feat: add project limit per user and GitLab integration enhancements (#0)

## 🐛 Fixes

- fix: reset active tab to overview on scanId change (#0)

## 📦 Build & CI

- chore: bump version to 1.3.1 (#0)



# Release 1.3.0



# Release 1.2.9

## 📦 Build & CI

- chore: update version to 1.2.9 and enhance API endpoints for scans and system settings (#0)



# Release 1.2.8



# Release 1.2.7

## 📦 Build & CI

- chore: update version to 1.2.7 and enhance notification settings mutation (#0)



# Release 1.2.6

## 🚀 Features

- feat: enhance SAST findings aggregation and display in UI (#0)



# Release 1.2.5

## 📦 Build & CI

- chore: update version to 1.2.5 and enhance authentication flow (#0)



# Release 1.2.4

## 📦 Build & CI

- chore: bump version to 1.2.4 (#0)



# Release 1.2.3



# Release 1.2.2

## 🚀 Features

- feat: update project and team role constants, enhance role validation, and increment version to 1.2.2 (#0)

## 🐛 Fixes

- fix: update Dockerfile to install pnpm directly and add pnpm-workspace.yaml for built dependencies (#0)



# Release 1.2.1



# Release 1.2.0

## 🚀 Features

- feat: improve vulnerability filtering and clean up SAST details view (#0)

## 📦 Build & CI

- chore: update version to v1.2.0 (#0)



# Release 1.1.9

## 🚀 Features

- feat: update scanner script to URL-encode project names for API requests (#0)



# Release 1.1.8

## 🚀 Features

- feat: enhance schemas for Bearer, OpenGrep, and TruffleHog with detailed findings descriptions (#0)



# Release 1.1.7

## 🚀 Features

- feat: refactor ingest endpoints and add ScanManager for improved scan lifecycle management (#0)



# Release 1.1.6



# Release 1.1.5

## 🚀 Features

- feat: update UserDetailsCard to use notification channels and refactor API calls for public config (#0)
- feat: add gitlab_oidc_audience field to system settings and update UI for OIDC audience input (#0)



# Release 1.1.4

## 📦 Build & CI

- chore: update version to 1.1.4; refactor user creation and validation logic (#0)



# Release 1.1.3

## 📦 Build & CI

- chore: update version to 1.1.3; enhance frontend URL handling and update user model for optional hashed_password and notification_preferences (#0)



# Release 1.1.2

## 📦 Build & CI

- chore: update version to 1.1.2; enhance password handling in user registration and login (#0)



# Release 1.1.1

## 📦 Build & CI

- chore: update version to 1.1.1; enhance password complexity in OIDC login; add network policies and values configuration (#0)



# Release 1.1.0

## 🐛 Fixes

- fix: update Dockerfile CMD to support proxy headers; remove HTTPS enforcement in auth endpoints (#0)



# Release 1.0.9

## 📦 Build & CI

- chore: update version to 1.0.9; upgrade MongoDB version to 8.2.3; enhance logging in auth endpoints (#0)



# Release 1.0.8

## 🐛 Fixes

- fix: update Traefik API version in middlewares configuration from 'containo.us' to 'io' (#0)



# Release 1.0.7

## 🚀 Features

- feat: add support for Traefik middlewares in ingress configuration; enable toggling via values.yaml (#0)



# Release 1.0.6

## 🚀 Features

- feat: enhance ContextBanner and QualityDetails components with improved styling and critical issue formatting (#0)
- feat: add QEMU setup for multi-platform builds in frontend and backend workflows; enable CRD installation for MongoDB operator (#0)



# Release 1.0.5



# Release 1.0.4

## 📦 Build & CI

- chore: update publish-backend workflow and bump version to 1.0.4 (#0)



# Release 1.0.3



# Release 1.0.2

## 🐛 Fixes

- fix: Update Dragonfly resource limits and max memory configuration (#0)



# Release 1.0.1



# Release 1.0.0



# Release 0.9.9

## 🚀 Features

- feat: update version to 0.9.9 and enhance malware and vulnerability analysis features (#0)



# Release 0.9.8

## 🚀 Features

- feat: enhance project stats with threat intelligence and reachability data checks (#0)



# Release 0.9.7

## 📦 Build & CI

- chore: update version to 0.9.7 and improve stats check in ProjectOverview component (#0)



# Release 0.9.6



# Release 0.9.5

## 🚀 Features

- feat: enhance finding selection logic and improve priority reason rendering in analytics components (#0)



# Release 0.9.4

## 🚀 Features

- feat: enhance finding linking and display in aggregator and UI components (#0)



# Release 0.9.3

## 🚀 Features

- feat: enhance quality issue display and improve related findings formatting (#0)



# Release 0.9.2

## 🚀 Features

- feat: update priority reasons in impact analysis and vulnerability hotspots with icons and improved formatting (#0)



# Release 0.9.1

## 🚀 Features

- feat: enrich vulnerability findings with EPSS/KEV data and improve metadata display in analytics modal (#0)



# Release 0.9.0



# Release 0.8.9

## 🚀 Features

- feat: add sorting functionality to dependency search and enhance modal integration for dependency details (#0)



# Release 0.8.8

## 🚀 Features

- feat: update sorting behavior in DependencyList and improve badge display (#0)



# Release 0.8.7



# Release 0.8.6



# Release 0.8.5



# Release 0.8.4



# Release 0.8.3

## 🚀 Features

- feat: update version to 0.8.3, enhance SBOM parsing, and add unified parser for multiple formats (#0)



# Release 0.8.2

## 🚀 Features

- feat(analytics): standardize default values for filters in CrossProjectSearch component (#0)



# Release 0.8.1

## 🚀 Features

- feat(analytics): implement permission checks for analytics features and update related components (#0)
- feat: update version to 0.8.1 and add authentication to notification channels endpoint (#0)



# Release 0.8.0



# Release 0.7.9

## 🚀 Features

- feat: add source code link to API description in FastAPI app (#0)
- feat: update version to 0.7.9, add GitLab MR decoration feature, and improve various endpoints (#0)



# Release 0.7.8

## 🚀 Features

- feat: update version to 0.7.8 and implement background tasks for stats recalculation in waivers (#0)



# Release 0.7.7

## 🚀 Features

- feat: update FindingDetailsModal to conditionally display vulnerability descriptions (#0)



# Release 0.7.6

## 🚀 Features

- feat: modify vulnerability grouping logic to merge findings by version only (#0)



# Release 0.7.5

## 🚀 Features

- feat: update FindingDetailsModal to handle aggregated vulnerabilities and remove descriptions for aggregated findings (#0)



# Release 0.7.4

## 🚀 Features

- feat: update version to 0.7.4 and add pipeline_user field to BaseIngest schema (#0)



# Release 0.7.3

## 🚀 Features

- feat: Bump version to 0.7.3 and update Scan interface with new fields (#0)



# Release 0.7.2

## 🚀 Features

- feat: Update scan handling and UI for better user experience (#0)



# Release 0.7.1



# Release 0.7.0



# Release 0.6.9

## 📦 Build & CI

- chore: update version to 0.6.9 and enhance Slack integration setup instructions (#0)



# Release 0.6.8

## 🚀 Features

- feat: add Mattermost integration and enhance Slack settings management (#0)



# Release 0.6.7

## 🚀 Features

- feat: update version to 0.6.7 and add favicon (#0)



# Release 0.6.6

## 🚀 Features

- feat: implement Slack integration with OAuth and notification settings enforcement (#0)



# Release 0.6.5

## 🚀 Features

- feat: add default SMTP encryption setting to system configuration (#0)



# Release 0.6.4

## 🚀 Features

- feat: add SMTP encryption settings to system configuration and email provider (#0)



# Release 0.6.3

## 🚀 Features

- feat: add background task support for email sending in auth, invitations, and users endpoints (#0)



# Release 0.6.2

## 🐛 Fixes

- fix: enhance finding aggregation logic to improve merging and linking of related findings (#0)



# Release 0.6.1

## 🐛 Fixes

- fix: enhance finding description handling to include source and prefer longer descriptions (#0)



# Release 0.6.0

## 🐛 Fixes

- fix: enhance vulnerability merging logic to prioritize longer descriptions, higher CVSS scores, and consolidate references (#0)



# Release 0.5.9

## 🐛 Fixes

- fix: handle prefixed CVEs in vulnerability IDs and extract CVE format (#0)



# Release 0.5.8

## 🐛 Fixes

- fix: update finding selection logic to use allRows instead of data (#0)



# Release 0.5.7

## 🚀 Features

- feat: add related findings field to Finding model and enhance UI to display related findings (#0)



# Release 0.5.6

## 🚀 Features

- feat: update version to 0.5.6 and enhance vulnerability handling in UI components (#0)



# Release 0.5.5

## 🚀 Features

- feat: enhance findings aggregation and display for vulnerabilities in detail views (#0)



# Release 0.5.4

## 🚀 Features

- feat: enhance table layouts across components for better responsiveness and readability (#0)



# Release 0.5.3

## 🚀 Features

- feat: enhance invitation email handling with error logging; update API routes for password reset and OIDC login (#0)



# Release 0.5.2



# Release 0.5.1

## 🚀 Features

- feat: add sorting and searching capabilities to teams and users pages; enhance FindingsTable with sorting options (#0)



# Release 0.5.0

## 🚀 Features

- feat: enhance user deletion functionality and improve FindingsTable component with projectId prop (#0)



# Release 0.4.9

## 📦 Build & CI

- chore: update version to 0.4.8 in main.py and package.json; adjust regex in propagate_version.py (#0)



# Release 0.4.8



# Release 0.4.7

## 🚀 Features

- feat: enhance recent scans retrieval by excluding unnecessary fields and improve loading states in dashboard (#0)

## 📦 Build & CI

- chore: bump version to 0.4.7 (#0)



# Release 0.4.6

## 🚀 Features

- feat: add system invitation endpoint and enhance user management with invitation handling (#0)
- feat: update error handling to use AxiosError type and enhance type definitions across components (#0)

## 🐛 Fixes

- fix: streamline recent scan creation by simplifying object initialization (#0)



# Release 0.4.5

## 🚀 Features

- feat: enhance vulnerability processing with severity mapping and fixed version extraction (#0)



# Release 0.4.4

## 🚀 Features

- feat: refactor component extraction to use _get_components method across analyzers (#0)

## 📦 Build & CI

- chore: update version to 0.4.4 (#0)



# Release 0.4.3

## 🚀 Features

- feat: add Syft conversion support for unsupported SBOM formats in TrivyAnalyzer (#0)



# Release 0.4.2

## 🚀 Features

- feat: enhance SBOM handling with GridFS support and improve scan result aggregation (#0)

## 📦 Build & CI

- chore: update version to 0.4.2 (#0)



# Release 0.4.1

## 🚀 Features

- feat(analyzers): add settings parameter to analyze methods for dynamic configuration (#0)

## 📦 Build & CI

- chore: update version to 0.4.1 and refactor SBOM handling in ingest and projects endpoints (#0)



# Release 0.4.0

## 🐛 Fixes

- fix: wrap query functions in arrow functions for consistent execution (#0)



# Release 0.3.9



# Release 0.3.8

## 🚀 Features

- feat: Add search functionality to projects and teams endpoints, update default analyzers (#0)



# Release 0.3.7



# Release 0.3.6

## 🚀 Features

- feat: enhance GitLab integration settings and add project configuration endpoint (#0)



# Release 0.3.5

## 📦 Build & CI

- chore: bump version to 0.3.5 (#0)



# Release 0.3.4

## 🐛 Fixes

- fix: update dependency versions in pyproject.toml and improve version propagation script (#0)



# Release 0.3.3



# Release 0.3.2

## 🚀 Features

- feat: add dashboard stats endpoint and integrate with frontend dashboard (#0)



# Release 0.3.1

## 🚀 Features

- feat: implement logging improvements and remove deprecated SMTP settings (#0)
- feat: implement permission checker for user actions and update endpoints to use it (#0)



# Release 0.2.9

## 🚀 Features

- feat: add project deletion functionality and retention settings management (#0)



# Release 0.2.8

## 🐛 Fixes

- fix: add 'Any' type import for improved type hinting in users.py (#0)



# Release 0.2.7

## 🚀 Features

- feat: implement user migration to local account and enhance password update functionality (#0)
- feat: implement password reset functionality and user migration to local accounts (#0)



# Release 0.2.6

## 🚀 Features

- feat: implement GitLab integration for automatic project creation and team syncing, update system settings and API endpoints accordingly (#0)



# Release 0.2.5

## 🚀 Features

- feat: Add ingress network policies for frontend and enhance backend policy (#0)
- feat: Remove unused SMTP and Slack environment variables from backend deployment (#0)
- feat: Add service account configuration and update deployments to use it (#0)
- feat: enhance user model and email provider to support multiple authentication providers, add OIDC issuer input in system settings (#0)
- feat: implement permission checks for various user actions across components (#0)
- feat: add pagination to users list with previous and next buttons (#0)



# Release 0.2.4

## 🚀 Features

- feat: update Dockerfile to fix permissions and switch to non-root user (#0)



# Release 0.2.3

## 🚀 Features

- feat: add OpenGrep ingestion endpoint and schema, integrate OpenGrep results into the analysis workflow (#0)
- feat: update version to 0.2.3 (#0)



# Release 0.2.2

## 🚀 Features

- feat: add frontend deployment and service configurations, including health checks and environment variables (#0)
- feat: update version to 0.2.2, add project notification settings and update API for PATCH method (#0)



# Release 0.2.1

## 🚀 Features

- feat: enhance permission checks across various endpoints and update user schema (#0)
- feat: add password verification for 2FA enable/disable endpoints and update user schema (#0)

## 📦 Build & CI

- chore: update Traefik chart to version 37.4.0 (#0)



# Release 0.2.0

## 🚀 Features

- feat: enrich team data with usernames and update TeamMemberSchema to include username (#0)
- feat: add user profile update endpoint and email notifications for security changes (#0)

## 🐛 Fixes

- fix: add missing Field import and set alias for user ID in UserInDBBase (#0)
- fix: add user not found check in enable_2fa endpoint (#0)

## 📦 Build & CI

- chore: update poetry.lock to reflect new package versions and dependencies (#0)
- chore: update version to 0.2.0 (#0)



# Release 0.1.9

## 🚀 Features

- feat: implement email verification and signup status management (#0)



# Release 0.1.8

## 📦 Build & CI

- chore: bump version to 0.1.8 and update traefik dependency to 37.4.0 (#0)



# Release 0.1.7

## 📦 Build & CI

- chore: bump version to 0.1.7 and update community-operator dependency (#0)



# Release 0.1.6

## 📦 Build & CI

- chore: bump version to 0.1.6 and update Helm chart dependencies (#0)



# Release 0.1.5

## 📦 Build & CI

- chore: bump version to 0.1.5 and update Helm chart dependencies and network policies (#0)



# Release 0.1.4

## 🐛 Fixes

- fix: correct indentation for volumeClaimTemplates in mongodb-cr.yaml (#0)
- fix: update checkout step to use SSH key for authentication (#0)

## 📦 Build & CI

- chore: bump version to 0.1.4 (#0)



# Release 0.1.2

## 🚀 Features

- feat: add CODEOWNERS, dependabot configuration, and MIT license; update README and version to 0.1.2 (#0)
- feat: update changelog configuration and release manager action to v5 with hybrid mode (#0)

## 🐛 Fixes

- fix: update Docker metadata tags to use short SHA format (#0)



# Release 0.1.1

- No changes found

