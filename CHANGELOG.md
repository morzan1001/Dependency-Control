# Upgrade notes

These notes cover the upgrade to 1.9.41. Run the steps in this order. Run mongosh commands in-pod against the application database, and Python and bash snippets in a backend pod, from the working directory where `app` is importable.

Before the rollout, resolve each gate before the first new pod starts:

1. Build the new indexes.
2. Check partial restores made by a pre-release 1.9.41 build.
3. Resolve email addresses that differ only in case, then add the case-insensitive unique index.
4. Check what each team-syncing GitLab token can see, and decide per instance.
5. Check SMTP in the database settings.
6. Set the base URL of GitHub Enterprise Server instances that have none.
7. Fix an empty or `local` OIDC provider name, and accounts with an empty provider.
8. Clean stored values that the stricter write schemas refuse.
9. Prepare stored waivers for the new matching rules, and set the expiry-sweep watermark.
10. Review synced team members and active accounts that are not verified (a review, not a gate).
11. Review accounts that hold only one of `project:update` and `project:delete` (a review).
12. List waivers that name scoped npm packages by their bare name (a review; keep its output, after-rollout step 14 re-creates the listed waivers from it).
13. Check projects that run `os_malware` without an API key (a review).

Deploy blocker, also before the rollout: fill the allowlists of the github.com and gitlab.com instances, or switch their auto-create off.

Last, right before the rollout starts: rotate `SECRET_KEY` (recommended), or end every session. Either way, snapshot the accounts.

After the rollout, once the last pod on the previous image has terminated:

1. End every session and review what was created during the rollout. Mandatory on every installation.
2. Remove duplicate scanner results, before the next housekeeping rescan cycle. Mandatory on every installation.
3. Remove TruffleHog plaintext secrets from `analysis_results`.
4. Rewrite archive bundles that still hold TruffleHog plaintext.
5. Name stored secret findings after their detector.
6. Backfill `first_seen_at`.
7. Purge leaked chat tool results, then rotate the exposed secrets.
8. Rotate GitHub Enterprise tokens that reached github.com.
9. Review GitLab bindings set through the old unchecked path.
10. Review the retention of projects created in the dialog.
11. Restamp every project under the new waiver rules. Mandatory on every installation.
12. Clean up callgraph languages.
13. Rewrite stored dependency type aliases.
14. Rename scoped npm dependency rows, rescan what they feed, and re-create the listed waivers.
15. Remove memberships of deleted users and leftovers of deleted projects.
16. Watch the primary's load, and remove the Helm values the chart does not read.

Once 1.9.41 is confirmed stable, drop the old indexes. Four optional checks look for abuse of the fixed gaps from before the upgrade, and optional repairs clean up data older code left behind. The behaviour changes that users and operators will notice are listed at the end.

## Before the rollout (gate): build the new indexes

The `(project_id, component, type)` findings index grows into a covering index for the first-detection lookup, and `(scan_id, severity)` grows into the key the CSV export streams from. The per-scan enrichment copy gets a `(scan_id, purl)` dependencies index, and the branch-tip lookup a scans index. Startup's `create_index` would build each in-line on a large collection and block pod start until the build finishes. Build them in-pod with mongosh before rolling out the new image, with the exact keys, so startup finds them and does nothing. The old image does not read them, so building them early is harmless.

```js
db.findings.createIndex({ project_id: 1, component: 1, type: 1, finding_id: 1, version: 1, first_seen_at: 1, scan_created_at: 1 })
db.findings.createIndex({ scan_id: 1, severity: 1, type: 1, finding_id: 1 })
db.dependencies.createIndex({ scan_id: 1, purl: 1 })
db.scans.createIndex({ project_id: 1, branch: 1, is_rescan: 1, created_at: -1, _id: 1 })
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

## Before the rollout (gate): fix an empty or `local` OIDC provider name

The settings form could store an empty provider name, and the first OIDC login copies that name into `users.auth_provider`. After the rollout, every save of the system settings answers 422 while the stored name is blank or `local`, ignoring case and surrounding spaces, and an account with `auth_provider: ""` counts as local: its SSO login is refused, and without a password it cannot sign in at all. Check the settings:

```js
db.system_settings.find({_id: "current", $expr: {$in: [{$toLower: {$trim: {input: {$ifNull: ["$oidc_provider_name", "GitLab"]}}}}, ["", "local"]]}}, {oidc_enabled: 1, oidc_provider_name: 1})
```

An empty result means the name is fine. Otherwise store the label of the SSO button (the default is "GitLab"):

```js
db.system_settings.updateOne({_id: "current"}, {$set: {oidc_provider_name: "<the SSO provider's label>"}})
```

Then give the passwordless accounts with an empty provider the stored name. An absent field means the default "GitLab":

```js
const provider = (db.system_settings.findOne({_id: "current"}) || {}).oidc_provider_name ?? "GitLab";
if (/^\s*(local)?\s*$/i.test(provider)) throw new Error("fix oidc_provider_name first");
db.users.find({auth_provider: ""}, {email: 1, hashed_password: 1, created_at: 1});
db.users.updateMany({auth_provider: "", hashed_password: {$in: [null, ""]}}, {$set: {auth_provider: provider}});
```

Accounts with `""` and a password keep password login. Set `auth_provider` by `_id` only for one known to sign in through SSO. If the settings check returned exactly `local`, the OIDC accounts created while it was set carry `auth_provider: "local"` and were refused SSO before too. List them with `db.users.find({auth_provider: "local", hashed_password: {$in: [null, ""]}}, {email: 1, created_at: 1})` and convert confirmed SSO users by `_id` only. Running the find with `auth_provider: ""` again then lists only accounts with a password.

## Before the rollout (gate): clean stored values that the stricter write schemas refuse

The write schemas now refuse unknown analyzers, out-of-range numbers, unknown modes, padded audiences and explicit nulls. The settings and project pages resend every stored value on save, so one refused stored value makes that page answer 422 until it is cleaned. The cleaned values are valid for the old image too, so run this before the rollout. Each find below returns nothing on a clean installation.

Analyzer names outside the selectable set. Crypto analyzers are left out on purpose: CBOM presence decides them, so a stored crypto name has no effect.

```js
const ok = ["trivy","grype","osv","deps_dev","epss_kev","reachability","end_of_life","license_compliance","os_malware","typosquatting","hash_verification","maintainer_risk","outdated_packages","opengrep","kics","bearer","trufflehog"];
db.projects.find({active_analyzers: {$elemMatch: {$nin: ok}}}, {name: 1, active_analyzers: 1});
db.system_settings.find({_id: "current", default_active_analyzers: {$elemMatch: {$nin: ok}}}, {default_active_analyzers: 1});
// after reviewing the hits:
db.projects.updateMany({active_analyzers: {$elemMatch: {$nin: ok}}}, {$pull: {active_analyzers: {$nin: ok}}});
db.system_settings.updateOne({_id: "current"}, {$pull: {default_active_analyzers: {$nin: ok}}});
```

Analyzer tunables under `analyzer_settings` that are not numbers, out of range or out of order. The analyzers read them as stored, so on the new image a stored `"365"` or `null` fails end_of_life, typosquatting or deps_dev on every scan, and maintainer_risk reports Partial with one warning per component it could not grade. The settings dialog cannot save such a value. Unsetting a key returns the project to the default, which the old image reads too. Run it with `DRY = true` for the counts, then with `DRY = false`. After the write, the last find lists projects whose effective values are out of order; unset the lower key of each hit:

```js
const DRY = true;
const specs = {
  "end_of_life.eol_high_after_days": [["int", "long"], 0, 3650],
  "end_of_life.eol_medium_after_days": [["int", "long"], 0, 3650],
  "maintainer_risk.stale_after_days": [["int", "long"], 30, 3650],
  "maintainer_risk.warn_after_days": [["int", "long"], 30, 3650],
  "typosquatting.critical_similarity": [["int", "long", "double"], 0.5, 1],
  "typosquatting.high_similarity": [["int", "long", "double"], 0.5, 1],
  "typosquatting.similarity_threshold": [["int", "long", "double"], 0.5, 1],
  "deps_dev.scorecard_threshold": [["int", "long", "double"], 0, 10],
};
for (const [path, [types, lo, hi]] of Object.entries(specs)) {
  const f = `analyzer_settings.${path}`;
  const bad = {[f]: {$exists: true}, $or: [{[f]: {$not: {$type: types}}}, {[f]: NaN}, {[f]: {$lt: lo}}, {[f]: {$gt: hi}}]};
  print(path, DRY ? db.projects.countDocuments(bad) : db.projects.updateMany(bad, {$unset: {[f]: ""}}).modifiedCount);
}
const eff = (p, d) => ({$ifNull: [`$analyzer_settings.${p}`, d]});
db.projects.find({$or: [
  {$expr: {$lt: [eff("end_of_life.eol_high_after_days", 365), eff("end_of_life.eol_medium_after_days", 180)]}},
  {$expr: {$lt: [eff("maintainer_risk.stale_after_days", 730), eff("maintainer_risk.warn_after_days", 365)]}},
  {$expr: {$lt: [eff("typosquatting.critical_similarity", 0.95), eff("typosquatting.high_similarity", 0.90)]}},
  {$expr: {$lt: [eff("typosquatting.high_similarity", 0.90), eff("typosquatting.similarity_threshold", 0.82)]}},
]}, {name: 1, analyzer_settings: 1});
```

The type check also unsets a whole-number double in a day field, such as `365.0`. Scans accept it, but the dialog cannot save it.

Project fields stored as explicit null, which the model cannot read. For every field other than `name`, `$unset` it so the default applies; give a null name a real one per project:

```js
const nullable = ["name","active_analyzers","retention_days","retention_action","gitlab_mr_comments_enabled","github_pr_comments_enabled","enforce_notification_settings"];
db.projects.find({$or: nullable.map(f => ({[f]: {$type: "null"}}))}, {name: 1});
nullable.slice(1).forEach(f => printjson(db.projects.updateMany({[f]: {$type: "null"}}, {$unset: {[f]: ""}})));
```

Project names that are blank or longer than 200 characters. Rename them by hand:

```js
db.projects.find({$expr: {$or: [{$gt: [{$strLenCP: {$ifNull: ["$name", ""]}}, 200]}, {$eq: [{$trim: {input: {$ifNull: ["$name", ""]}}}, ""]}]}}, {name: 1});
```

Retention beyond 36500 days, which also crashes housekeeping's cutoff on the old image, a negative global retention, which already means keep forever, and settings modes other than `project` and `global`:

```js
db.projects.updateMany({retention_days: {$gt: 36500}}, {$set: {retention_days: 36500}});
db.system_settings.updateOne({_id: "current", global_retention_days: {$gt: 36500}}, {$set: {global_retention_days: 36500}});
db.system_settings.updateOne({_id: "current", global_retention_days: {$lt: 0}}, {$set: {global_retention_days: 0}});
db.system_settings.find({_id: "current", $or: ["retention_mode","rescan_mode","crypto_policy_mode"].map(f => ({[f]: {$exists: true, $nin: ["project","global"]}}))});
```

Chat limits outside the range the settings page offers (tool rounds 1 to 50, rate limits at least 1). The stored settings are now the only source for these limits; the environment variables `CHAT_MAX_TOOL_ROUNDS`, `CHAT_RATE_LIMIT_PER_MINUTE` and `CHAT_RATE_LIMIT_PER_HOUR` are ignored:

```js
db.system_settings.find({_id: "current", $or: [{chat_max_tool_rounds: {$lt: 1}}, {chat_max_tool_rounds: {$gt: 50}}, {chat_rate_limit_per_minute: {$lt: 1}}, {chat_rate_limit_per_hour: {$lt: 1}}]}, {chat_max_tool_rounds: 1, chat_rate_limit_per_minute: 1, chat_rate_limit_per_hour: 1});
```

Fix a mode or chat hit with `$set` on the settings document.

OIDC audiences with leading or trailing whitespace. CI tokens already fail the exact audience match for these instances, and new writes are trimmed:

```js
for (const c of ["github_instances", "gitlab_instances"]) {
  printjson(db[c].find({oidc_audience: /^\s|\s$/}, {name: 1, oidc_audience: 1}).toArray());
  db[c].updateMany({oidc_audience: /^\s|\s$/}, [{$set: {oidc_audience: {$trim: {input: "$oidc_audience"}}}}]);
}
```

Accounts with an empty username, which every account form now requires, and legacy usernames equal to another account's email. Login resolves the username first, so such a name shadows the other account's email login. Give each hit a new username with `$set`:

```js
db.users.find({username: ""}, {email: 1});
db.users.aggregate([{$match: {username: /@/}}, {$lookup: {from: "users", let: {n: {$toLower: "$username"}, self: "$_id"}, pipeline: [{$match: {$expr: {$and: [{$eq: [{$toLower: "$email"}, "$$n"]}, {$ne: ["$_id", "$$self"]}]}}}], as: "shadowed"}}, {$match: {shadowed: {$ne: []}}}, {$project: {username: 1, email: 1, "shadowed._id": 1, "shadowed.email": 1}}]);
```

Crypto policies a write would now refuse. They still run as before, but the editor cannot save them and a revert to such a version answers 422. In a backend pod:

```bash
python - <<'PY'
from pymongo import MongoClient
from pydantic import ValidationError
from app.core.config import settings
from app.schemas.crypto_policy import CryptoPolicyPutRequest
db = MongoClient(settings.MONGODB_URL)[settings.DATABASE_NAME]
for doc in db.crypto_policies.find({}, {"rules": 1}):
    try:
        CryptoPolicyPutRequest(rules=doc.get("rules", []))
    except ValidationError as exc:
        print(doc["_id"], [e["msg"] for e in exc.errors()])
PY
```

Fix each printed policy in the editor: add a subject matcher, correct the finding type, order the expiry ladder or rename duplicate rule ids. No output means every policy saves.

## Before the rollout (gate): prepare stored waivers for the new matching rules

File and rule scope waivers now match by `rule_id`, and a stored placeholder or null field changes what a waiver matches after the rollout. Run these steps in this order, right before the rollout. Each find returns nothing on a clean installation.

Clear stored "Unknown" placeholders. After the rollout, a stored "Unknown" would require `component == "Unknown"` and the waiver would match nothing:

```js
["finding_id", "package_name", "package_version"].forEach(f =>
  printjson(db.waivers.updateMany({[f]: "Unknown"}, {$set: {[f]: null}})))
```

Waivers with an explicit null status or reason fail to load, and an expired one is dropped from the recalculation queue. Match the BSON null type: a missing field loads with its default.

```js
db.waivers.find({$or: [{status: {$type: "null"}}, {reason: {$type: "null"}}]}, {_id: 1, project_id: 1})
db.waivers.updateMany({status: {$type: "null"}}, {$set: {status: "accepted_risk"}})
```

Set each null reason by hand after checking with the waiver's owner.

Rule scope waivers whose `rule_id` was derived as "AGG" from a merged SAST id waived every merged SAST finding of the project and now match nothing. Review them, set the intended rule where it is known, and turn the rest into finding scope so each covers only its exact finding. Unsetting `rule_id` alone is not enough: the next step would fill it from the merged finding's first SAST entry and widen the waiver to every finding of that rule in the project:

```js
db.waivers.find({scope: "rule", rule_id: "AGG"}, {finding_id: 1, project_id: 1, reason: 1})
// optional, per waiver: db.waivers.updateOne({_id: <id>}, {$set: {rule_id: "<details.sast_findings[].id>"}})
db.waivers.updateMany({scope: "rule", rule_id: "AGG"}, {$set: {scope: "finding"}, $unset: {rule_id: ""}})
```

Give stored file and rule scope waivers their rule. One the script cannot resolve is printed and keeps covering only its exact finding:

```js
db.waivers.find({scope: {$in: ["file", "rule"]}, rule_id: null, finding_id: {$ne: null}}).forEach(w => {
  const f = w.project_id ? db.findings.findOne({project_id: w.project_id, finding_id: w.finding_id}, {details: 1}) : null;
  const d = (f && f.details) || {};
  const rule = ((d.sast_findings || [])[0] || {}).id || d.rule_id || d.detector;
  if (rule) db.waivers.updateOne({_id: w._id}, {$set: {rule_id: rule}});
  else print(`review ${w._id}: ${w.scope} ${w.finding_id} project=${w.project_id}`);
})
db.waivers.find({scope: "file", package_name: null}, {finding_id: 1, rule_id: 1, project_id: 1})  // review only
```

The last find lists file scope waivers without a file. They keep working, but creating one like them now answers 422.

Drop the stored `is_active`. Responses compute it now, and the stored value is frozen at write time:

```js
db.waivers.updateMany({is_active: {$exists: true}}, {$unset: {is_active: ""}})
```

Last, set the expiry-sweep watermark. Without it, the first recalculation on the new image queues every waiver that ever expired, and the mandatory restamp after the rollout covers those projects anyway. The old image does not read the collection:

```js
db.waiver_recalc.updateOne({_id: "expiry_sweep"}, {$set: {swept_until: new Date()}}, {upsert: true})
```

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

## Before the rollout (review): accounts that hold only one of `project:update` and `project:delete`

`project:update` now edits any project and `project:delete` deletes any project; neither grants the other's actions. An account meant to do both needs both grants. This lists the accounts that hold exactly one:

```js
db.users.find({$or: [{$and: [{permissions: "project:delete"}, {permissions: {$ne: "project:update"}}]}, {$and: [{permissions: "project:update"}, {permissions: {$ne: "project:delete"}}]}]}, {username: 1, permissions: 1})
```

Add the missing grant where the account needs it. An empty result means nobody loses an action.

## Before the rollout (review): waivers that name scoped npm packages by their bare name

CycloneDX npm components with a scope are now named like their purl, `@angular/core` instead of `core`. A waiver on `core`, `core:16.2.0` or `OUTDATED-core` stops matching after the rollout, and its findings re-open and can alert again. The listing reads the dependency rows that still carry the bare name, so run it before the rename step after the rollout. In a backend pod:

```bash
python - <<'PY'
import re
from pymongo import MongoClient
from app.core.config import settings
db = MongoClient(settings.MONGODB_URL)[settings.DATABASE_NAME]
npm = {"purl": {"$regex": "^pkg:npm/"}}
bare = {"group": {"$regex": "^@"}, "name": {"$type": "string", "$not": {"$regex": "^@"}}}
names = db.dependencies.distinct("name", {**npm, **bare})
token = re.compile(rf"(^|[-:/])({'|'.join(map(re.escape, names))})([-:@]|$)") if names else None
for w in db.waivers.find({"$or": [{"package_name": {"$ne": None}}, {"finding_id": {"$ne": None}}]}):
    if token and (w.get("package_name") in names or token.search(w.get("finding_id") or "")):
        print(w["_id"], w.get("project_id"), w.get("package_name"), w.get("finding_id"))
PY
```

It matches bare names as tokens inside finding ids, so review the list before acting on it. Keep it: each listed waiver is re-created under the scoped name after the rename. No output means no waiver is affected.

## Before the rollout (review): projects that run `os_malware` without an API key

Without the OpenSourceMalware API key, `os_malware` now reports Failed instead of skipping silently, so every scan of a project that runs it completes with errors and a SCAN-ERROR finding. It is not a default analyzer, so only projects that opted in are affected:

```js
db.system_settings.countDocuments({_id: "current", open_source_malware_api_key: {$nin: [null, ""]}})  // 1: a key is set
db.projects.countDocuments({active_analyzers: "os_malware"})
db.system_settings.countDocuments({_id: "current", default_active_analyzers: "os_malware"})  // 1: projects CI creates run it
```

If no key is set and either count is not 0, set the key under System Settings, or remove the analyzer where it is not wanted:

```js
db.projects.updateMany({active_analyzers: "os_malware"}, {$pull: {active_analyzers: "os_malware"}})
db.system_settings.updateOne({_id: "current"}, {$pull: {default_active_analyzers: "os_malware"}})
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

Otherwise, end every session right before the rollout. 1.9.40 honours `last_logout_at` too, so this refuses every token obtained before it. A token obtained on an old pod during the rollout stays valid until the reset after the rollout, and the review after the rollout covers what it did:

```js
db.users.updateMany({}, { $set: { last_logout_at: new Date() } })
```

In both cases, at the moment of the key change or the reset, snapshot the accounts and note the printed time:

```js
print(new Date().toISOString())
db.users.aggregate([{ $project: { email: 1, pending_email: 1, auth_provider: 1, totp_enabled: 1 } }, { $out: "tmp_account_snapshot" }])
```

## After the rollout (mandatory): end every session and review the rollout window

Run this on every installation, once the last pod on the previous image has terminated. An old pod that still serves keeps minting tokens by username, hence after the last old pod:

```js
db.users.updateMany({}, { $set: { last_logout_at: new Date() } })
```

Afterwards every earlier token has an `iat` before every account's `last_logout_at` and is refused (bearer 401, refresh 403), and everyone logs in again. Current usernames show no trace of the rename, so this step cannot depend on a collision check.

The reset does not revoke API keys, emails or passwords set during the window. Whether an old-image container served after the key change cannot be read off the cluster once the rollout is over, so run both queries on every installation; they only read. Replace `<T0>` with the time printed before the rollout.

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

Ask each listed owner whether the key or change was theirs. For each account with one that was not, run the steps that apply in this order, with `<user_id>` as the account's `_id`:

- Pending email: unset it, which voids its confirmation link, and end its sessions in the same update.

  ```js
  db.users.updateOne({ _id: "<user_id>" }, { $set: { last_logout_at: new Date() }, $unset: { pending_email: "" } })
  ```

- Changed email: set the snapshot's address back, unset the password and any pending email, and end its sessions in one update, since the new address could have reset the password. Then, if the snapshot's `auth_provider` is local, send the owner a password reset from the user's details in Users (Send Reset Email).

  ```js
  db.users.updateOne({ _id: "<user_id>" }, { $set: { email: "<before.email>", last_logout_at: new Date() }, $unset: { hashed_password: "", pending_email: "" } })
  ```

- Auth provider changed to local: set it back to the snapshot value, unset the password and end its sessions in one update, because password login accepts any account that has one.

  ```js
  db.users.updateOne({ _id: "<user_id>" }, { $set: { auth_provider: "<before.auth_provider>", last_logout_at: new Date() }, $unset: { hashed_password: "" } })
  ```

- Every repaired account: if `totp_enabled` differs from the snapshot, set it to false and unset `totp_secret`; disabling 2FA drops the secret, so the owner re-enrols if the snapshot had it on. Then run the account query again. It must list none of the repaired accounts.

- Account with only unrecognised keys: end its sessions. Each refresh mints a new refresh token, so a session opened during the window, or since with a password set in it, lives until `last_logout_at` moves.

  ```js
  db.users.updateOne({ _id: "<user_id>" }, { $set: { last_logout_at: new Date() } })
  ```

- Every account with an unrecognised key (repaired or not): revoke its keys created since `<T0>`, after its sessions end so none can create another, then run the API-key query again. It must list no key of the account.

  ```js
  db.api_keys.updateMany({ user_id: "<user_id>", created_at: { $gte: ISODate("<T0>") }, revoked_at: null }, { $set: { revoked_at: new Date() } })
  ```

Changes made through the account's roles persist too, such as team or project members and webhooks it added; check those from the same period for every account repaired above. Drop the snapshot after the review:

```js
db.tmp_account_snapshot.drop()
```

## After the rollout (mandatory): remove duplicate scanner results

Results of trufflehog, opengrep, kics and bearer are now stored once per scan and scanner, and a re-submission replaces the stored one. Older releases appended one row per CI attempt, and every rescan copies all rows of its original scan, so each housekeeping rescan cycle carries the duplicates onto new scans. Run this once the last old pod has terminated and before the next housekeeping rescan cycle. It keeps the newest row per scan and scanner, which also cleans the copies made before it runs. Where a past pipeline ran parallel jobs of one scanner, only the newest job's row survives. For a dry run, replace the `.forEach(...)` with `.toArray().length`, which counts the scan and scanner pairs that hold duplicates:

```js
db.analysis_results.aggregate([
  {$match: {analyzer_name: {$in: ["trufflehog", "opengrep", "kics", "bearer"]}, source: null}},
  {$sort: {created_at: -1}},
  {$group: {_id: {scan_id: "$scan_id", analyzer_name: "$analyzer_name"}, ids: {$push: "$_id"}, n: {$sum: 1}}},
  {$match: {n: {$gt: 1}}},
  {$project: {stale: {$slice: ["$ids", 1, {$subtract: ["$n", 1]}]}}}
], {allowDiskUse: true}).forEach(g => db.analysis_results.deleteMany({_id: {$in: g.stale}}))
```

A second run finds nothing. Duplicate rows of the built-in analyzers need nothing: the next analysis of their scan replaces them.

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

## After the rollout: name stored secret findings after their detector

Secret findings stored before the upgrade read `Secret detected: <number>` and have no `details.detector_name`, and their raw TruffleHog entries have no `DetectorName`. Until this runs, the findings table, CSV, delta, chat and the secrets recommendation show the number. Run it only once every backend pod is on the new image, so no old pod writes numbered rows afterwards. It never changes `finding_id` or `details.detector`, which waivers match on.

The detector table left the code base with this release, so copy it unchanged from the 1.9.40 tag into the pod:

```bash
git show v1.9.40:backend/app/core/trufflehog.py > th.py
kubectl cp th.py <namespace>/<backend-pod>:/tmp/th.py
```

Save the script as `backfill.py`. `kubectl exec -i -n <namespace> <backend-pod> -- python - < backfill.py` prints the counts; add `--write` after the `-` to write them.

```python
import sys

from pymongo import MongoClient

from app.core.config import settings

DRY_RUN = "--write" not in sys.argv
exec(open("/tmp/th.py").read())  # defines DETECTOR_TYPE_NAMES
NAMES = {str(k): v for k, v in DETECTOR_TYPE_NAMES.items()}
P = "Secret detected: "
db = MongoClient(settings.MONGODB_URL)[settings.DATABASE_NAME]

rows = entries = 0
for doc in db.analysis_results.find({"analyzer_name": "trufflehog"}, {"result.findings": 1}):
    findings = (doc.get("result") or {}).get("findings") or []
    named = 0
    for f in findings:
        if not f.get("DetectorName") and (name := NAMES.get(str(f.get("DetectorType")))):
            f["DetectorName"] = name
            named += 1
    if named:
        rows, entries = rows + 1, entries + named
        if not DRY_RUN:
            db.analysis_results.update_one({"_id": doc["_id"]}, {"$set": {"result.findings": findings}})
print(f"analysis_results: {entries} entries in {rows} rows")


def apply(flt, upd):
    return db.findings.count_documents(flt) if DRY_RUN else db.findings.update_many(flt, upd).modified_count


for d in db.findings.distinct("details.detector", {"type": "secret"}):
    if name := NAMES.get(d):
        base = {"type": "secret", "details.detector": d}
        n_name = apply({**base, "details.detector_name": None}, {"$set": {"details.detector_name": name}})
        n_desc = apply({**base, "description": P + d}, {"$set": {"description": P + name}})
        print(f"findings {d} -> {name}: detector_name {n_name}, description {n_desc}")
```

It names the raw entries first, so a re-aggregation that runs meanwhile already writes names. It walks `analysis_results` once and then runs two `update_many` per known detector on the `type` index. A second run reports 0. Numbers missing from the table (24, 28, 132, 400 and anything above 1063) stay unnamed. Run it again after restoring a scan from a bundle archived before the upgrade.

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

## After the rollout (mandatory): restamp every project under the new waiver rules

Scans keep the waived flags stamped under the old matching rules until the project's next waiver change or analysis: a global rule waiver with a type waived its whole type, and a merged-SAST file waiver covered every rule in the file. Projects in release mode would keep hiding those findings. Run this once every pod runs the new image, because an old pod still stamps by the old rules.

First drop the per-project bookkeeping and the pinned signature from global waivers, and the waiver fingerprint of scans the new image stamped with those signatures during the rollout. This queues nothing by itself:

```js
db.waivers.updateMany({project_id: null}, {$unset: {match: "", last_eval_scan_id: "", last_match_count: ""}})
db.scans.updateMany({waiver_fingerprint: {$exists: true}}, {$unset: {waiver_fingerprint: ""}})
```

Then queue one project-scoped entry per project. Each loads as a project waiver, so its project is recalculated unconditionally, and because no scan carries a waiver fingerprint yet, head, the branch tips built in the last 30 days and the released scans are all restamped:

```js
db.projects.find({}, {_id: 1}).forEach(p => db.waiver_recalc.insertOne({waiver: {_id: "restamp-" + p._id, project_id: p._id, reason: "post-deploy restamp", created_by: "operator"}}))
```

The next waiver request or housekeeping tick (every 5 minutes) works the queue off, one project at a time, in one pod. Follow it with `db.waiver_recalc.countDocuments({waiver: {$exists: true}})`; the restamp is done at 0. Older branch tips and other non-head scans keep their flags until they are analysed again.

## After the rollout: clean up callgraph languages

Callgraph languages are now stored in canonical form, and an upload of any language outside python, go, javascript, typescript, java, kotlin, scala and groovy answers 400. A Go callgraph stored as `golang` or with padding was keyed by host (`github.com`) and cannot be repaired, so it is deleted; the pipeline's next upload replaces it. Every other alias or case variant is renamed, unless a canonical twin for the same project, scan and language exists, in which case the variant is deleted. Unsupported languages are deleted. Run this once every pod runs the new image. Save it as `cleanup.js`, copy it to the MongoDB pod, dry-run it with `mongosh --quiet <db> cleanup.js`, then run `mongosh --quiet <db> --eval 'var execute = true' cleanup.js`:

```js
const EXECUTE = typeof execute !== "undefined" && execute;
const alias = {golang: "go", js: "javascript", node: "javascript", nodejs: "javascript", ts: "typescript", py: "python"};
const supported = ["python", "go", "javascript", "typescript", "java", "kotlin", "scala", "groovy"];
db.callgraphs.find({language: {$nin: supported}}, {project_id: 1, scan_id: 1, language: 1}).toArray().forEach(d => {
  const lower = String(d.language).trim().toLowerCase();
  const lang = alias[lower] || lower;
  const collapsedGo = lang === "go" && String(d.language).toLowerCase() !== "go";
  const twin = db.callgraphs.findOne({_id: {$ne: d._id}, project_id: d.project_id, scan_id: d.scan_id ?? null, language: lang});
  const drop = !supported.includes(lang) || collapsedGo || twin !== null;
  print(d._id, JSON.stringify(d.language), drop ? "delete" : `rename -> ${lang}`);
  if (EXECUTE) {
    if (drop) db.callgraphs.deleteOne({_id: d._id});
    else db.callgraphs.updateOne({_id: d._id}, {$set: {language: lang}});
  }
});
```

The dry run prints one line per callgraph it would touch; no output means every stored language is canonical. When two variants of one project and scan map to the same language, such as `JS` and `js`, the dry run prints a rename for both, but the real run renames the first and deletes the other as its twin. A Python callgraph keeps first-segment keys until its next upload, and dotted distributions read "unknown" until then.

## After the rollout: rewrite stored dependency type aliases

Dependency rows without a purl now store the purl type (`pypi`, `golang`, `maven`, ...) instead of Syft's package type (`python`, `go-module`, `java-archive`, ...). Reachability no longer reads `python` or `go-module`, so an older scan keeps its callgraph language only after this rewrite; the other aliases only unify the inventory's type facet. Run it once every pod runs the new image, because old pods keep writing the Syft types until then. It is idempotent. In one mongosh session, dry-run first:

```js
const A = {"python":"pypi","go-module":"golang","java-archive":"maven","jenkins-plugin":"maven","rust-crate":"cargo","php-composer":"composer","php-pear":"pear","php-pecl":"pecl","dotnet":"nuget","dart-pub":"pub","erlang-otp":"otp","github-action":"github","lua-rocks":"luarocks","portage":"ebuild","R-package":"cran","binary":"generic"};
db.dependencies.aggregate([{$match:{type:{$in:Object.keys(A)}}},{$group:{_id:"$type",n:{$sum:1}}}])
```

Then:

```js
db.dependencies.updateMany({type:{$in:Object.keys(A)}}, [{$set:{type:{$switch:{branches:Object.entries(A).map(([k,v])=>({case:{$eq:["$type",k]},then:v})),default:"$type"}}}}])
```

## After the rollout: rename scoped npm dependency rows

New ingests name a scoped CycloneDX npm component `@angular/core`. Stored rows still say `core` with group `@angular`, so they no longer join the findings of new scans. Run this once every pod runs the new image, because the old parser writes bare names. After this step a rollback makes new ingests bare again while the renamed rows stay scoped, so roll back before it if at all. A bare row whose scoped twin already exists is left alone. In a backend pod, dry-run first, then run again with `EXECUTE=1`:

```bash
env EXECUTE=0 python - <<'PY'
import os
from pymongo import MongoClient
from app.core.config import settings
EXECUTE = os.environ.get("EXECUTE") == "1"
db = MongoClient(settings.MONGODB_URL)[settings.DATABASE_NAME]
npm = {"purl": {"$regex": "^pkg:npm/"}}
bare = {"group": {"$regex": "^@"}, "name": {"$type": "string", "$not": {"$regex": "^@"}}}
starts_with_at = {"$eq": [{"$substrCP": ["$name", 0, 1]}, "@"]}
scoped_name = {"$cond": [starts_with_at, "$name", {"$concat": ["$group", "/", "$name"]}]}
clashes = [
    row["_id"]
    for key in db.dependencies.aggregate([
        {"$match": {**npm, "$or": [bare, {"name": {"$regex": "^@"}}]}},
        {"$group": {"_id": {"s": "$scan_id", "n": scoped_name, "v": "$version", "p": "$purl"},
                    "rows": {"$push": {"_id": "$_id", "name": "$name"}}}},
        {"$match": {"rows.1": {"$exists": True}}},
    ], allowDiskUse=True)
    for row in key["rows"] if not row["name"].startswith("@")
]
affected_scans = db.dependencies.distinct("scan_id", {**npm, **bare})
heads = list(db.projects.find({"latest_scan_id": {"$in": affected_scans}}, {"latest_scan_id": 1}))
lineage = affected_scans + db.scans.distinct("original_scan_id", {"_id": {"$in": affected_scans}})
pinned = list(db.releases.find({"scan_id": {"$in": lineage}}, {"project_id": 1, "scan_id": 1, "environment": 1}))
print("bare scoped npm rows:", db.dependencies.count_documents({**npm, **bare}))
print("left as they are (scoped twin exists):", len(clashes))
print("scans:", len(affected_scans), "of which project heads:", len(heads), "release rows:", len(pinned))
for project in heads:
    print("  head", project["_id"], project["latest_scan_id"])
for release in pinned:
    print("  release", release["project_id"], release["scan_id"], release.get("environment"))
if EXECUTE:
    result = db.dependencies.update_many(
        {**npm, **bare, "_id": {"$nin": clashes}},
        [{"$set": {"name": {"$concat": ["$group", "/", "$name"]}}}])
    print("renamed:", result.modified_count)
PY
```

`bare scoped npm rows: 0` means there is nothing to rename and nothing to rescan. Otherwise rescan every head and release row the script printed. Their findings came from analyzers fed by the old names, and the rescan also drops the rows left alone. Release views follow the rescan chain, so rescanning the pinned scan is enough, and only the newest release row per environment needs it. With an editor token, per printed pair:

```bash
curl -X POST -H "Authorization: Bearer <token>" https://<host>/api/v1/projects/<project_id>/scans/<scan_id>/rescan
```

Then re-create each waiver from the review before the rollout under the scoped package name or finding id.

## After the rollout: remove memberships of deleted users and leftovers of deleted projects

Deleting a user now removes them from every team and project, and deleting a project also deletes its webhooks and its project crypto policy. Deletions made before the upgrade left those behind. Count first, then write:

```js
const live = db.users.distinct("_id");
const ghost = {members: {$elemMatch: {user_id: {$nin: live}}}};
db.teams.countDocuments(ghost); db.projects.countDocuments(ghost);
db.teams.updateMany(ghost, {$pull: {members: {user_id: {$nin: live}}}, $set: {updated_at: new Date()}});
db.projects.updateMany(ghost, {$pull: {members: {user_id: {$nin: live}}}});
const pids = db.projects.distinct("_id");
db.webhooks.countDocuments({project_id: {$nin: [null, ...pids]}}); db.crypto_policies.countDocuments({scope: "project", project_id: {$nin: pids}});
db.webhooks.deleteMany({project_id: {$nin: [null, ...pids]}});
db.crypto_policies.deleteMany({scope: "project", project_id: {$nin: pids}});
```

Zero counts mean there is nothing to remove. Afterwards, check for teams and projects left without an admin before telling anyone.

## After the rollout: watch the primary's load, and remove unused Helm values

Every MongoDB read now goes to the primary; a `readPreference` in the URI is overridden. Watch the primary's CPU and connection count on the replica set after the rollout, and during the first restamp, whose reads all go there. The chart no longer reads `backend.env.mongodbReadPreference`, and no template ever read `chat.rateLimitPerMinute` or `chat.rateLimitPerHour`; remove all three from the deployment values. Leaving them is harmless but misleading. The updated Grafana dashboard `chat-ai-assistant.json` ships with the chart and shows the new `dc_chat_tool_calls_total` statuses on its "Tool Error Rate" panel.

## Once 1.9.41 is confirmed stable: drop the old indexes

The new findings indexes start with the old `(project_id, component, type)` and `(scan_id, severity)` keys, and nothing reads the webhook deliveries' `(success, webhook_id)` index, so the old indexes only cost writes now. Drop them only once a rollback is no longer expected: 1.9.40 recreates them at startup, in-line on the large findings collection, and pods do not start until that build finishes.

```js
db.findings.dropIndex("project_id_1_component_1_type_1")
db.findings.dropIndex("scan_id_1_severity_-1")
db.webhook_deliveries.dropIndex("success_1_webhook_id_1")
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

## Optional after the rollout: repair and reclaim stored data

None of these is needed for correctness. Each one fixes or trims data that older code wrote, and the next analysis of a project rewrites most of it for that project's latest scan. Run the bulk writes off-peak.

A root's `latest_rescan_id` now names its last delivered rescan. A root that points at a failed or pending rescan heals at its next delivered rescan. To repoint it now, dry-run first by replacing `updateOne` with `print(root._id, best && best._id)`:

```js
const usable = ["completed", "completed_with_errors"];
db.scans.find({ latest_rescan_id: { $ne: null } }, { latest_rescan_id: 1 }).forEach(root => {
  const pointed = db.scans.findOne({ _id: root.latest_rescan_id }, { status: 1 });
  if (pointed && usable.includes(pointed.status)) return;
  const best = db.scans.find({ original_scan_id: root._id, is_rescan: true, status: { $in: usable } }, { _id: 1 })
    .sort({ created_at: -1, _id: 1 }).limit(1).toArray()[0];
  db.scans.updateOne({ _id: root._id },
    best ? { $set: { latest_rescan_id: best._id } } : { $unset: { latest_rescan_id: "" } });
});
```

A rescan that stuck recovery failed before the upgrade still shows "rescan in progress", because its root's `latest_run` says pending. A scheduled target heals at its next rescan; a manually rescanned scan does not. The count takes one collection scan, and no result means there is nothing to repair:

```js
db.scans.aggregate([
  { $match: { "latest_run.status": "pending" } },
  { $lookup: { from: "scans", localField: "latest_run.scan_id", foreignField: "_id", as: "run" } },
  { $match: { "run.status": "failed" } },
  { $count: "roots" },
])
db.scans.find({ "latest_run.status": "pending" }, { "latest_run.scan_id": 1 }).forEach((root) => {
  const run = db.scans.findOne({ _id: root.latest_run.scan_id, status: "failed" }, { completed_at: 1 });
  if (!run) return;
  const failed = { scan_id: run._id, status: "failed" };
  if (run.completed_at) failed.completed_at = run.completed_at;
  db.scans.updateOne(
    { _id: root._id, "latest_run.scan_id": run._id, "latest_run.status": "pending" },
    { $set: { latest_run: failed } },
  );
});
```

Rescans stuck with `reachability_pending` get their reachability with this, in a backend pod. The next periodic rescan also fixes the head.

```bash
python - <<'PY'
import asyncio
from app.db.mongodb import connect_to_mongo, get_database
from app.services.reachability_enrichment import run_pending_reachability_for_scan
async def main():
    await connect_to_mongo()
    db = await get_database()
    async for s in db.scans.find({"is_rescan": True, "reachability_pending": True}, {"_id": 1, "project_id": 1}):
        print(s["_id"], await run_pending_reachability_for_scan(s["_id"], s["project_id"], db))
asyncio.run(main())
PY
```

Webhooks subscribed under the snake_case event names still receive their events. To store the canonical names, run the following; afterwards `db.webhooks.countDocuments({events: {$in: ["scan_completed", "vulnerability_found", "analysis_failed"]}})` must be 0:

```js
db.webhooks.updateMany(
  { events: { $in: ["scan_completed", "vulnerability_found", "analysis_failed"] } },
  [{ $set: { events: { $setUnion: [{ $map: { input: "$events", as: "e", in: { $switch: {
      branches: [
        { case: { $eq: ["$$e", "scan_completed"] }, then: "scan.completed" },
        { case: { $eq: ["$$e", "vulnerability_found"] }, then: "vulnerability.found" },
        { case: { $eq: ["$$e", "analysis_failed"] }, then: "analysis.failed" }
      ], default: "$$e" } } } }] } } }]
)
```

Nothing reads the Redis key `popular:npm` any more, stored as `dc:popular:npm` under the default `CACHE_PREFIX`. It expires within 24 hours; to drop it now, run `DEL dc:popular:npm` in `redis-cli`.

A stored `dependency_enrichments.enrichment_sources` holds only the last writer's list until its purl is enriched again. This derives the union now:

```js
db.dependency_enrichments.updateMany({deps_dev: {$exists: true}}, {$addToSet: {enrichment_sources: "deps_dev"}})
db.dependency_enrichments.updateMany({$or: [{license_category: {$exists: true}}, {license_risks: {$exists: true}}, {license_obligations: {$exists: true}}]}, {$addToSet: {enrichment_sources: "license_compliance"}})
```

On findings enriched before the upgrade, this sets the KEV due date to the earliest nested one, and copies the date added and required action onto a record's single KEV advisory. Records with several KEV advisories get theirs on re-analysis.

```js
db.findings.updateMany({type: "vulnerability", "details.in_kev": true, "details.vulnerabilities.kev_due_date": {$type: "string"}}, [{$set: {"details.kev_due_date": {$min: {$map: {input: {$filter: {input: "$details.vulnerabilities", cond: {$eq: [{$type: "$$this.kev_due_date"}, "string"]}}}, in: "$$this.kev_due_date"}}}}}])
db.findings.find({type: "vulnerability", "details.in_kev": true,
    "details.vulnerabilities": {$elemMatch: {in_kev: true, kev_date_added: {$exists: false}}}}).forEach(d => {
  if (d.details.vulnerabilities.filter(v => v.in_kev).length !== 1) return;
  db.findings.updateOne({_id: d._id, "details.vulnerabilities.in_kev": true}, {$set: {
    "details.vulnerabilities.$.kev_date_added": d.details.kev_date_added,
    "details.vulnerabilities.$.kev_required_action": d.details.kev_required_action}});
});
```

These reclaim the bytes of fields that are no longer written. After the SAST line, each row of the multi-scanner SAST view shows the merged finding's description, as it does for new scans. First check the Metabase cards for `details.vulnerabilities.source`, `details.vulnerabilities.description_source` and `details.github_advisory_url`, which are no longer written.

```js
db.findings.updateMany({type: "vulnerability", "details.vulnerabilities.0": {$exists: true}}, {$unset: {"details.github_advisory_url": "", "details.vulnerabilities.$[].description_source": "", "details.vulnerabilities.$[].source": "", "details.vulnerabilities.$[].details.fixed_version": "", "details.vulnerabilities.$[].details.cvss_score": "", "details.vulnerabilities.$[].details.cvss_vector": "", "details.vulnerabilities.$[].details.references": ""}})
db.findings.updateMany({type: "quality", "details.quality_issues.0": {$exists: true}}, {$unset: {"details.quality_issues.$[].source": ""}})
db.findings.updateMany({type: "sast", "details.sast_findings.0": {$exists: true}}, {$unset: {"details.cwe_ids": "", "details.owasp": "", "details.category_groups": "", "details.sast_findings.$[].title": "", "details.sast_findings.$[].description": ""}})
db.analysis_results.updateMany({analyzer_name: "trivy"}, {$unset: {"result.trivy_vulnerabilities": ""}})
db.analysis_results.updateMany({analyzer_name: "grype"}, {$unset: {"result.grype_vulnerabilities": ""}})
db.scan_update_deltas.updateMany({total_updates: {$exists: true}}, {$unset: {total_updates: ""}})
db.projects.updateMany({}, {$unset: {"analyzer_settings.deps_dev.scorecard_high_threshold": "", "analyzer_settings.deps_dev.scorecard_medium_threshold": "", "analyzer_settings.deps_dev.scorecard_low_threshold": ""}})
```

A sync no longer re-stamps an owner that carries a bare provider value (`gitlab` or `github`), so only the owner picker removes it. This count should be 0:

```js
db.projects.countDocuments({$expr: {$gt: [{$size: {$filter: {input: {$objectToArray: {$ifNull: ["$team_sources", {}]}}, cond: {$in: ["$$this.v", ["gitlab", "github"]]}}}}, 0]}})
```

Dependency rows now keep only the four `properties` keys osv reads, and callgraphs no longer store their `imports` and `calls` edge lists. These reclaim that space. The `properties` rewrite is one long write on a large collection, and its space returns only after `db.runCommand({compact: "dependencies"})` on each replica set member, secondaries first:

```js
db.dependencies.updateMany({properties:{$type:"object",$ne:{}}}, [{$set:{properties:{$arrayToObject:{$filter:{input:{$objectToArray:"$properties"},cond:{$in:["$$this.k",["aquasecurity:trivy:SrcName","aquasecurity:trivy:SrcVersion","aquasecurity:trivy:SrcRelease","aquasecurity:trivy:SrcEpoch"]]}}}}}}])
db.callgraphs.updateMany({$or: [{imports: {$exists: true}}, {calls: {$exists: true}}]}, {$unset: {imports: "", calls: ""}})
```

Scans no longer get `reachability_pending_since` or `reachability_completed_at`, findings no longer store `quality_info.overall_score`, `quality_info.quality_finding_id`, `license_info.license_finding_id` or `eol_info.eol_finding_id`, and quality aggregates no longer carry `scorecard_context`. Readers ignore the stale keys, and a project's next scan rewrites its findings. To drop them now:

```js
db.scans.updateMany({$or: [{reachability_pending_since: {$exists: true}}, {reachability_completed_at: {$exists: true}}]}, {$unset: {reachability_pending_since: "", reachability_completed_at: ""}})
db.findings.updateMany({$or: [{"details.quality_info.overall_score": {$exists: true}}, {"details.quality_info.quality_finding_id": {$exists: true}}, {"details.license_info.license_finding_id": {$exists: true}}, {"details.eol_info.eol_finding_id": {$exists: true}}]}, {$unset: {"details.quality_info.overall_score": "", "details.quality_info.quality_finding_id": "", "details.license_info.license_finding_id": "", "details.eol_info.eol_finding_id": ""}})
db.findings.updateMany({type: "quality", "details.scorecard_context": {$exists: true}}, {$unset: {"details.scorecard_context": ""}})
```

Two read-only counts show whether findings in the old SAST aggregate shape remain. Once both return 0, for example after retention has aged out old scans, a later release can stop reading that shape:

```js
db.findings.countDocuments({type: "sast", "details.sast_findings.1": {$exists: true}})
db.findings.countDocuments({finding_id: /^SAST-AGG-/})
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
- An account stored with `auth_provider: ""` counts as local on every path. It signs in only with a password, and OIDC login answers 400 "This account uses local authentication". `PUT /system/settings` answers 422 for an empty or `local` `oidc_provider_name`, so while such a name is stored, every settings save fails. See the OIDC provider gate above.
- An SSO account that also has a password can no longer reset it by email; migrate it to local first.
- `POST /users` answers 422 for `auth_provider`, unknown fields, `is_active: null` or a missing password. `PUT /users/{id}` needs `user:update` and answers 422 for a `password` field or a null `is_active` or `permissions`; self-service uses `PATCH /users/me`.
- A taken identity answers 400 "Email already registered" or "Username already taken" on every path, concurrent writes included, which used to get 500.
- Usernames that are empty, blank or contain "@" answer 422 on signup, admin create, admin update and invitation accept, and usernames are stored trimmed. A new SSO account whose `preferred_username` is empty or an email address is named after its mailbox, with a numeric suffix if taken.
- `POST /invitations/system` answers 422 for a malformed email and stores it lowercased. A system invitation is revoked with `DELETE /invitations/system/{id}` under `user:create`; `DELETE /users/{id}` answers 404 "User not found" for invitation ids.
- Deleting a user removes them from every team and project.
- `GET /users/` answers 422 for a `limit` outside 1-100 or a `skip` below 0.

### Teams, projects and permissions

- `team:read_all` is read-only. It still reads every team, but adding or changing members, deleting a team and writing team webhooks now need membership with the role the action requires, or the global permission for it such as `team:update` or `team:delete`. The frontend no longer offers team admin actions to users whose only team grant is `team:read_all`.
- `project:read_all` no longer writes project webhooks. Creating, updating, deleting and test-firing a project's webhooks with `webhook:create`, `webhook:update` or `webhook:delete` now also needs membership of the project, direct or through an owning team, or `project:update` or `project:delete`. Accounts that combine `project:read_all` with a webhook permission, such as automation or auditor accounts, now get 403 on projects they are not a member of, and the frontend no longer offers them the webhook controls there. `project:read_all` with `webhook:read` still lists and reads every project's webhooks.
- `GET /api/v1/analytics/projects/{project_id}/dependency-tree` answers 404 "No scan found for this project" for a `scan_id` of another project, which it used to serve, and 404 "Project not found" instead of 403 for an unknown project.
- New projects keep the retention action and analyzer settings chosen at creation. They used to be stored with `retention_action: "delete"` and no analyzer settings. When the system retention mode is `global`, the global retention settings still apply. Projects created before 1.9.41 with Archive or None are still stored as Delete, and housekeeping keeps deleting their scans until an owner corrects the setting. See "review the retention of projects created in the dialog" above.
- Team member add and project invite by email find only accounts with a verified email, in any case, and otherwise answer 404 "No user has verified this email address". Accounts created by an admin, or by a signup whose link was never clicked, are not verified.
- GitLab binding changes need an admin. Setting or changing `gitlab_instance_id` or `gitlab_project_id` through `PUT /api/v1/projects/{id}` needs `system:manage`, `project:update` or `project:delete`; project admins get 403. Clearing both stays open to project admins, and resending the stored values is unaffected. A half binding answers 400, an unknown instance 404, and a GitLab project bound to another project 409 instead of 500. When the instance answers, the stored path is GitLab's `path_with_namespace`.
- Project settings show other users a bound project's GitLab link read-only, with a "Remove GitLab link" action. Choosing "None" as the GitLab instance clears the project id and path too.
- `project:update` and `project:delete` are separate grants. `project:update` no longer deletes projects. `project:delete` no longer edits projects, rotates keys, manages members, writes callgraphs or webhooks, binds GitLab or grants teams. See the review of accounts holding only one of them above.
- Team reads, chat team tools and the analytics team scope included, need `team:read` or `team:read_all`, and they include only projects the caller can read. Chat team tools answer "Team not found or access denied" to both.
- Team-scope analytics (crypto hotspots, locations and trends, PQC plan, compliance reports) serve non-members holding `project:read_all`, `analytics:global` or `system:manage` with all of the team's projects. Members without a project read, and `team:read_all` holders who are not members, get 403. Only those three permissions see every team's compliance reports. A report outside the caller's scope, including another user's personal report, answers 404, ahead of the 409 and 410 status checks. A database error during a scope check answers 500.
- `DELETE /teams/{unknown}` answers 404. Demoting the last team admin answers 400. Editing or removing a member that a live GitLab or GitHub sync owns answers 409 naming the binding. A hand-added member whom the group also holds keeps their manual entry and role across syncs.
- A provider sync no longer takes over an owner that the project holds by hand, through another instance or with a bare provider value. The owner picker removes such owners.
- Write superusers may create a project for any team; an unknown team answers 404. `GET /projects/{id}` returns `notification_overrides`, and each member carries `effective_role`. `PUT /projects/{id}/members/{user_id}` requires `role` and takes nothing else, and an empty role answers 422. Write superusers may remove or demote the last direct project admin. Team-granted members can save project notification preferences, and team admins can enforce them.
- Deleting a project also deletes its webhooks and its project crypto policy.
- `POST` and `PUT /projects` answer 422 for a name that is blank or over 200 characters, `retention_days` above 36500 or an unknown analyzer. `PUT` also answers 422 for an explicit null on the name, analyzers, retention, comment toggles or `enforce_notification_settings`. Names are stored trimmed. `PUT /teams/{id}` with a null name answers 422. A project created in the UI without touching the analyzers gets the server defaults.
- The 403 on callgraph routes reads "Not enough permissions" instead of "Access denied", and archive and chat 403s name the missing permission. With chat disabled, a caller who lacks the chat permission gets that 403.

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

### Waivers

- File and rule waivers match by `rule_id`: across scanners, across merged SAST findings of that rule, and across a secret detector's files. A global rule waiver with a type waives only its rule, and one without a type now applies. A partial CVE waiver no longer lifts a whole-finding waiver on the same component, whatever the order the waivers were created in.
- A finding-scope location waiver without a finding id, such as the global dialog's "match broadly", now waives every finding it describes in stored scans. A waiver whose named finding has no signature falls back to its criteria instead of matching nothing. Expect more findings to show as waived after the restamp.
- `POST /waivers` answers 422 in these cases:
  - a file or rule waiver whose rule cannot be named (global ones must pass `rule_id`)
  - a file waiver without `package_name`
  - a finding type other than SAST, IaC, secret and crypto key management
  - a `LIC-` or `EOL-` finding id without `finding_type`
  - a waiver with no criteria

  `PATCH /waivers/{id}` answers 422 for an explicit null status or reason. The messages for an invalid status or scope come from the type, for example "Input should be 'accepted_risk' or 'false_positive'".
- `POST /waivers` takes an optional `scan_id`, which the finding modal sends, so a finding seen only on a feature or MR branch can be waived. A scan of another project answers 404 "Scan not found in this project".
- A waiver change is queued in `waiver_recalc` and survives a restart. One run at a time works the queue off, started by the request and by housekeeping every 5 minutes. An expiry restamps its project, or every project a global waiver reaches, within one housekeeping interval. Head and released scans are always restamped, and branch tips only when they were built in the last 30 days. A reason-only PATCH restamps too. Scans carry a new `waiver_fingerprint`, so an unchanged waiver set restamps nothing.
- Waiver responses carry the computed `is_active`, and list items no longer carry `match`. `waiver:read_all` opens and filters any project's waivers; `waiver:read` opens global waivers and `global_only=true`. The chat waiver tools need one of the two.
- The lapsed badge shows only for a candidate within 50 lines of the waiver's last line. Otherwise the waiver shows as orphaned ("Matches nothing"), and so do duplicates and waivers without criteria. Global waivers no longer show a badge taken from one project. Feature-branch and MR scans follow line drift at ingest.

### Scans, branches and retention

- Head, project stats, branch tips, the default in `/branches`, the CSV and inventory scan per branch, and the rescan target follow one rule. A scan with SBOMs outranks every scan without them. A late older build, a feature build or a tag build does not move head. `/projects/{id}/branches` and `/scans/branch-tips` do not list tags, and branch tips no longer return `flagged_release_scan`. The CSV export of a tag-only project answers 404.
- A manual rescan answers 409 while the scan is pending or processing, or while a rescan of its lineage runs, and it resets the scheduler's clock. Scheduled rescans show as pending (`latest_run`) in the scan list. `latest_rescan_id` names the last delivered rescan. "Recent Activity" no longer lists rescans.
- The daily retention pass keeps each build's newest 7 usable rescans, plus pinned ones. It deletes the rest, or archives them for `archive` projects. At the defaults (90 days, every 24 h) the first pass removes about 83 rescans per rescan target. `archive` projects upload each one first, so their first pass takes longer. Retention never deletes a project's head build.
- `POST /projects/{id}/sync-branches` answers 400 when the VCS link lacks coordinates, and 502 when the VCS cannot be reached or lists no branches. Branch sync and MR/PR decoration skip an inactive VCS instance.
- Every failed scan carries `completed_at`. Stuck recovery has its own budget of 3 (`stuck_retry_count`). A scheduler pass creates rescans only while the local queue is shorter than the worker count. With `rescan_mode=global`, housekeeping ignores projects' own rescan settings.
- Scans carry a new `sbom_generation`. Re-ingesting an SBOM while its scan is analysed reschedules the analysis on the new SBOM, and dependency rows keep their `_id`. Marking a commit as a release binds to its newest build that did not fail.
- When an SBOM of a payload fails to parse, the stored inventory stays as it was. The scan ends `completed_with_errors` with "N of M SBOMs failed to parse; dependency inventory left unchanged", and a rescan ends `failed`. A re-analysis whose SBOM cannot be loaded keeps the previous findings. The failure text for an unusable SBOM reads "SBOM could not be loaded or parsed for analysis".
- `analysis_completed`, `scan_completed` and the security alert fire once for each distinct content of a scan. `project.last_scan_at` is stamped by SBOM, CBOM and findings posts; analyses and rescans leave it alone.

### Analysis and uploads

- Callgraph uploads ignore a `scan_id` in the request body. The scan is always derived from the project in the path together with `pipeline_id` and the commit. Clients that still send `scan_id` keep working, and the field is dropped.
- New ad-hoc and callgraph size limits answer 413 before any parsing. Ad-hoc `/api/v1/analyze` refuses more than 50 000 callgraph entries and more than 250 000 SBOM dependency-graph entries, and SPDX `externalRefs` now count against the 20 000 component-evidence budget.
- A callgraph upload's 200 000-entry limit now also counts symbols, madge dependencies and analyzed modules, and an oversized upload with a bad format gets 413 instead of 400. A `callee_function` that is a JSON object or array fails the parse (400 on upload).
- A scanner result or callgraph too large for one MongoDB document answers 413 ("... exceeds the 16 MB document limit") instead of 500. The scanner 413 comes before waiver matching, so the scan can exist without that result. The callgraph entry limit stays at 200 000; a graph under it that does not fit one document gets the 413. An analyzer result too large to store is skipped with a log line, and its findings are kept.
- Results of trufflehog, opengrep, kics and bearer are stored once per scan and scanner. A re-submission replaces the stored result, and parallel jobs of one scanner in one pipeline replace each other's: only the last job to post is kept. KICS and Bearer results keep only the scanner payload, without the pipeline, commit, branch and project fields.
- `GET /callgraph` no longer returns `imports` or `calls`. In the generic callgraph format a non-string `file`, symbol, `callee_module`, `callee_function` or `caller_file` answers 400, and `line` is no longer checked.
- OSV malicious-package (MAL-) matches now produce a CRITICAL malware finding; they used to be dropped. Expect new malware findings, and the notifications they trigger, on the next scan of affected projects; a rescan surfaces them sooner. OSV findings now carry `published` and `modified`.
- Callgraph uploads answer 400 for a language outside python, go, javascript, typescript, java, kotlin, scala and groovy, which used to be stored and never matched; aliases such as `golang` or `ts` are mapped. GET filters accept any spelling of a supported language. An upload without a commit attaches to the pipeline's analysed scan.
- CycloneDX npm components with a scope group are stored as `@scope/name`, and dependency trees of syft, cyclonedx-npm and cyclonedx-py SBOMs nest.
- Directness follows each format's dependency graph:
  - a package that an SPDX document only CONTAINS is direct but inferred; CONTAINS no longer confirms directness
  - Trivy's pom, go.mod and Go binary root packages are skipped, and their children are direct
  - a single-crate Trivy Cargo scan counts the project crate itself as a direct dependency, and its dependencies as transitive; a Cargo workspace keeps every package
  - the scanned project's own npm, cargo, uv or pom lockfile package in a Syft SBOM is no longer ingested, so inventory counts drop by one per project
  - a runtime scope beats `optional` and `excluded` when duplicates merge

  Stored scans pick up the new directness when their SBOM is ingested again.
- A malformed dependency graph fails the whole SBOM: a Syft relationship that is not an object, or a CycloneDX `dependsOn` string, fails ingest instead of being skipped.
- Parsed SBOM fields changed:
  - hash keys are canonical (`sha256`), and Syft JSON digests and CycloneDX distribution references yield hashes, so hash verification checks more components
  - a placeholder version (`""`, `unknown`, `NOASSERTION`, `NONE`) takes the purl version
  - purl-less Syft components get purl types, so a fabricated purl such as `pkg:python/urllib3@2.0.0` becomes `pkg:pypi/urllib3@2.0.0` once
  - legacy Syft (schema 5) image SBOMs now parse, and SPDX packages from Syft carry the generator as `found_by`, so osv queries them
  - stored `properties` keep only the four Trivy source-package keys, so `/analytics/search` returns an empty `properties` for almost every row
- OSV now queries Debian and Alpine packages, so container scans get more findings. It no longer queries components without a version, and it reports a component it cannot take as not scanned. deps.dev is no longer asked about composer, pub, hex, cran, cocoapods and swift packages.
- The version order changed:
  - a Debian binNMU ranks above its base
  - prereleases rank below their release
  - post-release suffixes such as `.post1` rank above their bare release, and `.Final`, `.GA` and `.RELEASE` equal it
  - an epoch and trailing zeros past the minor drop out: `1:2.30-1` equals `2.30-1`, and `4.1.0` equals `4.1`
  - letter suffixes and Debian revisions compare numerically

  `details.fixed_version` is empty as soon as one advisory has no fix, and ignores fixes below the installed version.
- Licence resolution recognises many more URLs and names. Expect fewer "License could not be determined" findings, and new copyleft findings for GPL and LGPL declared by URL. EOL now covers Alpine, Tomcat, Apache httpd, Vue, Docker Engine, CouchDB, Maven, Packer and Spring or Rails through NVD CPEs; java and openjdk are no longer looked up.
- Trivy and Grype results no longer contain `trivy_vulnerabilities` or `grype_vulnerabilities`. New vulnerability, quality and SAST findings no longer store duplicate copies of their fields, and `details.github_advisory_url` is no longer written.
- New secret findings name their detector ("Secret detected: AWS"), and Bearer findings no longer show a "Fingerprint".
- Scan stats count differently. This covers `scan.stats`, `project.stats`, the `scan_completed` webhook and the ingest response:
  - weaponized counts only KEV findings with ransomware use, and active exploitation only KEV findings
  - scanner errors no longer count
  - every verified secret counts as actionable, also one no longer in the scanned tree or whose tree state is unknown
  - a waived advisory no longer counts as KEV, EPSS or actionable, and a KEV or EPSS value counts only when an unwaived advisory of the finding carries it, so recomputed stats of scans enriched before 1.9.41 can show lower KEV and EPSS counts until those scans are analysed again
- "Fix available" is claimed only when every live CRITICAL and HIGH advisory names a fix. An unenriched NEGLIGIBLE advisory scores 0, below LOW.
- Reachability:
  - "Analyzed N / M" counts only findings with a verdict, and "Vulnerable symbols searched, none used" drops from 0.63 to 0.35 confidence
  - a confirmed-transitive package that no callgraph uses is unknown instead of unreachable, so its adjusted risk score is no longer lowered
  - the callgraphs of one scan are judged together, and passes run one at a time per scan; a failed pass stays pending and is retried by the next upload or analysis
  - the callgraph upload response warns when a pass fails or when the per-run cap leaves findings without a verdict
- SAST findings keep their own ids, without `SAST-AGG-` ids or "Confirmed by N scanners", and keep the scanner's severity; an unmapped severity stays UNKNOWN. A SCAN-ERROR finding lists every distinct failure, and a result with an empty `error` counts as a failure, so its scan ends `completed_with_errors`.
- Vulnerability and quality aggregate ids use the smallest raw spelling of the package, whatever the arrival order. Some `finding_id`s change once (`Left-Pad` against `left-pad`), so the next delta can show one-time new and resolved findings.
- deps.dev prefers the version's license over the repository's, so `vault/api` shows MPL-2.0, not BUSL-1.1.
- Cross-linked banners changed. An `inactive_repo` maintainer risk counts as a maintenance concern. An OUTDATED finding ahead of the registry default no longer marks its package outdated. The License banner shows the package's most severe license. The OpenSSF score shows once, in the Scorecard banner. Same-type findings on one file are no longer listed in each other's related findings.
- Rollback hazard: SBOM references written by 1.9.41 carry only `type`, `gridfs_id` and `filename`, and the SBOM export of 1.9.40 answers 500 for those scans.

### Analytics, recommendations and search

- Recommendation actions changed:
  - `current_versions` and `versions` lists replace `current_version` and `version`
  - `transitive_deps[].parents` replaces `parent`
  - `parents_total` is gone
  - `action.target_version` is new, and `action.is_direct` may be `null`
  - update cards are per installed version
  - the license drift key is `restrictive_drift`

  The recommendations endpoint returns `findings_total`. The dev-in-production card covers npm packages only, `@vitest/*` included.
- Scans whose SBOM names a directory or file source no longer get an "Update Base Image" card for their deb, rpm or apk packages. Those vulnerabilities move to the direct and transitive update cards. Every other SBOM keeps the image card, including Trivy fs and rootfs SBOMs, which name an application source.
- Impact and Hotspots count NEGLIGIBLE, INFO and UNKNOWN CVEs, and UNKNOWN weighs 4.0, so `finding_count` equals `cve_count` and rankings shift. Hotspot `risk_score` of unenriched findings is on the 0-100 scale, where an unrated CVE counts 20. INFO now ranks above UNKNOWN everywhere, the findings-table sort included. Dependency tree, top dependencies and the dependency modal count distinct unwaived CVEs instead of finding documents.
- Analytics group packages by purl identity. Same-named packages of different groups or ecosystems no longer merge, and spellings such as PyYAML and pyyaml join.
- Go module paths are split per the purl spec, without a doubled host. Update-frequency deltas stored before 1.9.41 keep the doubled Go names, and SPDX Go dependencies keep `group: "github.com"`, until they are recomputed or their SBOM is re-ingested.
- Findings-delta severity keys are uppercase, as stored. Scan delta answers 404 for an unknown project and 404 "No scan found for this project" for a scan of another project. An empty `?scan_id=` on the dependency tree and on recommendations answers the same 404 instead of falling back to head.
- Analytics search reports `page: 1` for an empty result. Vulnerability search filters CVE rows, not documents, and each CVE row shows only its own KEV, EPSS and fix.
- The inventory licence tile counts `unknown`, and a component without an ecosystem counts as `unknown`. The three scorecard "severity below" settings are gone.
- Chat and MCP finding tools answer per advisory. `get_vulnerability_details` returns `advisories`, and `get_cve_details` returns `in_kev` and `scanners`.

### Webhooks, notifications and chat

- Webhook response bodies are capped and bound by a deadline. A delivery attempt or `POST /webhooks/{id}/test` fails as a timeout when the attempt as a whole takes longer than `WEBHOOK_TIMEOUT_SECONDS` (default 30 s). On 2xx the body is not read; on other statuses at most 64 KiB is read, decoded as UTF-8. Requests send `Accept-Encoding: identity`. The test's `response_time_ms` and the webhook duration histogram measure time to response headers.
- Deactivated users get no project notifications on any channel, whether they are direct or team members. Enforced notification settings come from the first active admin member with preferences.
- Chat and MCP tool arguments are type-checked. A wrong JSON type answers `{"error": "Argument '<name>' must be of type <type>"}` (`isError: true` over MCP), arguments that are not a JSON object answer "Tool arguments must be a JSON object", and undeclared keys are dropped.
- Chat and MCP tool results follow the REST response schemas. `get_system_settings` returns `*_configured` booleans instead of secrets, `get_project_details` no longer returns `api_key_hash`, and `list_project_webhooks` no longer returns `secret`, `headers` or the delivery counters. It also returns the webhooks of owning teams whose webhooks the caller may list, and for `system:manage` the global ones, each with a `scope` field. Members without `webhook:read` who are not project admins are refused the webhook tools, as in REST, and `get_webhook_deliveries` answers "Webhook not found or access denied" to every refusal.
- Webhook create, update and test store the canonical event names `scan.completed`, `vulnerability.found` and `analysis.failed`; the snake_case names are still accepted and matched. A webhook stored under older URL rules is listed, readable and deletable again. When its URL breaks today's rules, its delivery and test answer "Blocked target: ...".
- Deliveries to a Teams URL stored as a generic webhook get the Teams card, and every delivery is signed over the body actually sent.
- The email channel is offered whenever `smtp_host` and `emails_from_email` are set, an unauthenticated relay included.
- Chat and MCP finding search, CVE and component tools need `analytics:read` or `analytics:search`. The remediation plan needs `analytics:read` or `analytics:recommendations`, and the analytics summary `analytics:read` or `analytics:summary`. Users with only `project:read` lose them. `archive:read_all` alone opens the archive tools. A project the caller cannot see answers "Project not found or access denied".
- MR/PR decorations and scan notifications report the stats of the analysed pipeline, where they used to report head's. Advisory broadcasts also reach the admins of owning teams.
- `analysis_failed`, as a webhook and as a member notification, fires on every failure path: the engine's verdict, the worker's retry ceiling, a worker exception and the stuck-scan give-up. It fires once, from the pod whose write landed. A project-lookup error in the worker now fails the scan and sends it; the scan used to stay `processing` until the stale-scan check.

### API and database

- Every MongoDB read goes to the primary, and a `readPreference` in the URI is overridden. API datetimes end in `Z`, so displayed times move to the correct instant for users outside UTC.
- `sort_order` answers 422 for anything but `asc` and `desc`. Paged lists break ties on `_id`, and an empty list reports `pages: 1`. The GitLab and GitHub instance lists answer 422 for a `page` below 1 or a `size` outside 1-100.
- `GET /system/settings` no longer writes a defaults document, and `?auto_init=` is gone. `PUT /system/settings` answers 422 for:
  - a null instance name or sender address
  - a retention mode other than `project` or `global`
  - global retention outside 0-36500
  - an unknown default analyzer
  - `chat_max_tool_rounds` outside 1-50, or a chat rate limit below 1

  The environment variables `CHAT_MAX_TOOL_ROUNDS`, `CHAT_RATE_LIMIT_PER_MINUTE` and `CHAT_RATE_LIMIT_PER_HOUR` are ignored.
- Instance updates answer 422 for a null required field or a null `oidc_audience`, and audiences are stored trimmed.
- Broadcasts ignore the request's `type`. They answer 422 for an unknown `target_type`, an advisory package type that is not a purl type, or an advisory max version that is a wildcard or has no numeric release. Responses no longer carry `unique_user_count`, and advisory broadcasts gain `uncomparable_versions`, the matched packages whose version cannot be compared with the max version; a project matched only through them is not counted. The package typeahead `GET /notifications/packages/suggest` lists only names in head scans, and after 2 s it answers no names with `more: true`.
- Crypto policy updates and reverts answer 422 for:
  - unknown rules, or rules no analyzer evaluates
  - an inverted expiry ladder
  - duplicate or empty rule ids
  - more than 200 rules, or a list over 50 entries
- `analysis_results` rows of the built-in analyzers carry `source` `SBOM #n` and are replaced on every analysis. A rescan copies its original's scanner rows server-side under `_id` `<rescan id>:<original row id>`, and an analysis aggregates every scanner row of its scan, not only the first 10 000.
- Ad-hoc `analyzers.skipped_inputs` keys read `SBOM #N` instead of `sbom#N`.

### Monitoring

- The `endpoint` label of `http_requests_total`, `http_request_duration_seconds`, `http_request_size_bytes` and `http_response_size_bytes` now carries the matched route template, for example `/api/v1/projects/{project_id}`, instead of the raw path with ids masked as `{id}`. Unmatched requests share the label `<unmatched>`, and `http_requests_in_progress` is labelled by `method` only. Dashboards and alerts that filter on raw paths need updating. The bundled Grafana dashboard only groups by `endpoint` and needs no change.
- `db_operations_total` and `db_operation_duration_seconds` count every driver command, labelled by command name (`find`, `insert`, `update`, `findAndModify`) instead of `find_one` or `insert_one`. `db_errors_total` is labelled by the MongoDB `codeName`, and a failed heartbeat counts. The bundled dashboards group by collection and keep working.
- `dc_chat_tool_calls_total` gains the statuses `unknown`, `denied`, `rejected` and `refused`, and a call that raises after its handler answered counts as `error`. Alerts on `status="error"` no longer see permission, argument or answer errors.
- `analysis_waivers_applied_total` counts the waivers that matched, labelled `type` as `query`, `vulnerability` or `signature`.
- `worker_jobs_processed_total` counts an engine failure as `failed` and skips rescheduled or claim-lost runs. Reschedules caused by a re-ingest count in `analysis_race_conditions_total`.
- `analysis_enrichment_total{type="reachability"}` and `analysis_reachable_vulnerabilities_total` also count reachability passes run for a callgraph uploaded after the analysis.



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

