# Deploy runbook — a team member's provenance names the instance that added them

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

One migration, one image roll, and the order between them is the whole risk. Every number below was
executed against `percona/percona-server-mongodb:8.0.17-6` on an estate shaped like production —
29 teams, 114 member entries: 61 with no `source` at all, 45 `manual`, 8 `gitlab`, 0 `github`.

What changes: `teams.members[].source` used to record a provider alone — `gitlab`, `github`,
`manual`. A provider value now names the instance too: `gitlab:<instance id>`, the same encoding
`projects.team_sources` already uses for ownership. `manual` is unchanged, and so is a member
entry carrying no `source` field.

What it buys: each sync replaces **only** the members its own instance resolved. A team bound to
both providers, or to two instances of one provider, keeps every subset. Before this, each sync
relabelled the other provider's members `manual` — after one round trip nothing was ever refreshed
again — and two instances of one provider overwrote each other's member list on every CI run.

`VERSION` is `1.9.35`. Production runs `1.9.34`.

## 0. What ships, and in what order

**The image first, the migration second.** The previous image declares the value as
`Literal["gitlab", "github", "manual"]`, so it rejects `gitlab:gl-prod` outright. Measured on the
estate above:

| Estate | Previous image `Team(**doc)` | New image `Team(**doc)` |
| --- | --- | --- |
| Unmigrated (`gitlab`) | 29 of 29 load | 29 of 29 load |
| Migrated (`gitlab:gl-prod`) | **3 of 29 raise `ValidationError`** | 29 of 29 load |

Three teams is not three broken pages. `build_user_project_query` calls
`TeamRepository.find_by_member`, which parses every team the caller belongs to, so **23 of the 114
member entries** belong to a rejected team — for those users *every* project list and project read
served by a not-yet-replaced pod answers **500**, for the length of the rollout. Migrating first
buys nothing in exchange: the new image reads a bare value perfectly well, as nobody's to replace.

The reverse order is safe because the new image is indifferent to an unmigrated value, and every
sync **repairs** the members it still resolves as it goes: it writes its own instanced value for
each member the group still has. What the migration then attributes is the remainder — the members
who have *left* the group, which is exactly the subset that must become retirable.

| Step | What | Rollback |
| --- | --- | --- |
| 1 | Measure the estate | n/a — read-only |
| 2 | **Roll the backend image** | §6a |
| 3 | Migration `--execute` | §6b |
| 4 | Gate: `--verify` exits 0 | n/a |

The frontend is not involved: `TeamMemberSchema` never carried `source`, so no response changes.

## 0a. The migration Job

Every pass runs as a Kubernetes **Job**, not `kubectl exec`: the autoscaler evicts backend pods and
takes a long `exec` with them. A Job's pod template is immutable, so
`kubectl delete job dc-migration -n dependency-control` between passes.

Three things the manifest must get right, each of which has cost this namespace a window before:

- **No `grype-db` volume.** It is a GCSFuse CSI mount whose sidecar the webhook injects only into
  annotated Deployments; a Job mounting it hangs in `ContainerCreating` forever. Mount only
  `tmp-volume`, `internal-ca`, `mongodb-client-tls`.
- **Exactly these pod labels**, or the default-deny NetworkPolicy blocks even DNS:
  `app.kubernetes.io/instance: dependency-control`, `app.kubernetes.io/name: dependency-control`,
  `job: migration`. The policy `dependency-control-migration` already exists and selects on them.
  Do **not** add `app.kubernetes.io/component: backend` — that puts the Job pod into the backend
  Service's endpoints and it would receive live traffic.
- **The image.** This migration runs *after* the rollout, so the Job takes the image the Deployment
  is already on. A migration that has to run *before* a rollout needs the **new** tag explicitly —
  the script ships inside the image, and the running one does not have it.

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: dc-migration
  namespace: dependency-control
spec:
  backoffLimit: 0
  template:
    metadata:
      labels:
        app.kubernetes.io/instance: dependency-control
        app.kubernetes.io/name: dependency-control
        job: migration
    spec:
      restartPolicy: Never
      serviceAccountName: dependency-control
      containers:
        - name: migration
          image: <the image:tag the backend Deployment is running>
          workingDir: /app
          command: ["python", "-m", "scripts.backfill_team_member_sources"]
          envFrom: <copy verbatim from the backend Deployment>
          volumeMounts:
            - { name: tmp-volume, mountPath: /tmp }
            - { name: internal-ca, mountPath: /etc/ssl/internal-ca, readOnly: true }
            - { name: mongodb-client-tls, mountPath: /etc/mongodb-tls, readOnly: true }
      volumes:
        - name: tmp-volume
          emptyDir: {}
        - name: internal-ca
          secret:
            secretName: dependency-control-root-ca-secret
            items: [{ key: ca.crt, path: ca.crt }]
        - name: mongodb-client-tls
          secret:
            secretName: dependency-control-mongodb-client-tls
```

`workingDir: /app` because the script is invoked as a module and resolves `app.*` from there.

Wait for the Job **before** reading its logs: a log read against a still-running Job prints no
count line at all, which reads like a clean run.

```bash
kubectl wait --for=condition=complete --timeout=30m job/dc-migration -n dependency-control
kubectl logs -n dependency-control job/dc-migration
```

## 1. Measure the estate

```js
db.teams.countDocuments({})
db.teams.aggregate([
  { $unwind: "$members" },
  { $group: { _id: { $ifNull: ["$members.source", "<absent>"] }, n: { $sum: 1 } } }
])
db.gitlab_instances.find({}, { name: 1, sync_teams: 1 })
db.github_instances.find({}, { name: 1, sync_teams: 1 })
```

Two things have to hold before anything is written.

**Exactly one instance per provider has `sync_teams: true`.** A bare `gitlab` value can only have
been written by the one GitLab instance that syncs, and that is the instance §3 attributes it to.
With two, §3 **aborts** rather than guessing — see §3a. Check it now, not at §3: by then the image
is rolled and the window is half spent.

**The counts.** Note how many teams §4a's query selects and how many member entries carry a bare
provider value — they are the `teams planned` and `members planned` of §3, and expect both to come
out **lower** by whatever the syncs repaired between §2 and §3. On the measured estate: 29 teams,
3 selected, 8 bare member entries.

## 2. Roll the backend image

```bash
kubectl rollout status deployment/dependency-control-backend -n dependency-control
```

Old and new pods serve together for a few minutes and both read the estate correctly, because
nothing has been rewritten yet. What differs is what they **write**: a new pod writes
`gitlab:<instance id>` for the members it resolves, and an old pod writes `gitlab`. Neither
destroys the other's work — a value the other writes is simply one that pod's sync will not claim —
and §3 sweeps up whatever bare values are left. An old pod that writes a member list also
**relabels** the other provider's members `manual`; that is the bug being fixed and the window for
it is minutes.

Wait for `kubectl get pods` to show no pod on the previous image before §3. That is not a
formality: §3 is the pass the previous image cannot survive.

## 3. Stamp the member provenance

```yaml
command: ["python", "-m", "scripts.backfill_team_member_sources"]
```

The run prints the instance it attributes each provider's bare values to, then the plan:

```
[gitlab] bare member values attributed to instance gl-prod
batched=3 planned=3 members=8 matched=N/A
```

**Check that id against §1's instance list before executing.** It is the single decision the
migration makes and the one a re-run cannot undo. `teams planned` must equal what §4a's query
returns at the same moment — that is the check, not a fixed number.

Then, after deleting the Job:

```yaml
command: ["python", "-m", "scripts.backfill_team_member_sources", "--execute"]
```

`teams matched` must equal the `teams planned` of the same run — measured `planned=3 members=8
matched=3`. A second dry-run reports `planned 0`: a value already naming an instance is left
exactly as stored.

Members are addressed one array entry at a time, not by rewriting the array, so a member added or
removed by hand during the pass survives it.

### 3a. If it aborts

```
backfill_team_member_sources: ERROR — gitlab: 2 instance(s) have team sync enabled
(['gl-legacy', 'gl-prod']); exactly one is required to attribute the bare values. Resolve them by hand.
```

Exit code **1**, nothing written. Two instances with team sync on means a bare `gitlab` value could
have come from either, and attributing it to the wrong one hands that member to the wrong
instance's next sync to drop. Decide per team which instance added the member, set the value by
hand, then re-run.

## 4. The gate

```yaml
command: ["python", "-m", "scripts.backfill_team_member_sources", "--verify"]
```

It prints `teams with a bare member source:` and exits **0** only when that count is zero, **2**
otherwise — measured **2** before §3 and **0** after. This one does not release a deploy; the
deploy already happened. It releases the *claim* that every synced member is refreshable by exactly
one sync, which is the point of the change: re-run it a day later and it must still read 0.

### 4a. The same check from mongosh

`--verify` runs exactly this filter. It counts a team whenever any member's `source` is a provider
with no instance after it. `manual`, an absent `source`, and a value that already carries an
instance match none of it:

```js
db.teams.countDocuments({
  "members.source": { "$in": ["gitlab", "github"] }
})
```

To see which teams it selects rather than how many, pass the same filter to
`db.teams.find(…, {name: 1, members: 1})`.

## 5. What changes for an operator

- **A sync replaces only its own instance's members.** A hand-added member is untouched by every
  sync, as before; so now is a member another provider's sync added, and one added by another
  instance of the same provider. A team bound to three instances holds three independent subsets.
- **One person is one entry.** Somebody two of the bound groups both hold is stored once, under
  whichever instance synced last — the member list is keyed by user, and a second entry would break
  the guard that keeps a member from being added twice. If that group drops them, they disappear
  until the other instance's next run puts them back.
- **An empty group still empties its subset.** A group nobody is left in removes its members; only
  a *failed* fetch leaves them alone. That distinction is unchanged.
- **A member whose `source` names an instance that no longer exists is kept, and no sync ever
  touches them again.** Nothing can prove who that member is: the instance that could refresh or
  retire them is gone, and a sync knows only its own subset — having one provider's CI run delete
  people because an unrelated instance was deleted would make a silent, unaudited removal out of an
  unrelated event. Membership is an access grant, so this errs the expensive way: unlike an
  unattributable *owner*, which merely leaves a project listed under a team, an unattributable
  *member* keeps their access to everything that team owns until somebody looks. So look — these
  are the entries no configured instance answers for:

  ```js
  var live = db.gitlab_instances.find({}, {_id: 1}).toArray()
    .map(function (i) { return "gitlab:" + i._id; })
    .concat(db.github_instances.find({}, {_id: 1}).toArray()
      .map(function (i) { return "github:" + i._id; }))
    .concat(["manual"]);
  db.teams.aggregate([
    { $unwind: "$members" },
    { $match: { "members.source": { $exists: true, $nin: live } } },
    { $project: { name: 1, user_id: "$members.user_id", source: "$members.source" } }
  ])
  ```

  Remove the ones that should go with `DELETE /api/v1/teams/{id}/members/{user_id}`, which is
  audited and refuses to take the team's last admin. Removing a team's binding does **not** remove
  that instance's members: unbinding says "stop syncing this team", not "these people left".
- **A member carrying no `source` at all is kept and is nobody's to replace either.** The model
  reads an absent value as `manual`, which is what those entries already behaved as, so the
  migration leaves all 61 of them exactly as they are rather than writing a claim — that a human
  added them — which nothing in the data supports.

## 6. Rollback

### 6a. After §2, before §3

Nothing has been rewritten by the migration, but the new pods have been **repairing** member values
as they sync, so some teams already carry `gitlab:<instance id>`. Strip them before rolling back,
or the previous image answers 500 for every member of those teams (§0):

```js
db.teams.updateMany(
  { "members.source": /:/ },
  [
    { "$set": { "members": { "$map": {
        "input": "$members",
        "as": "m",
        "in": { "$cond": [
            { "$gt": [ { "$indexOfCP": [ { "$ifNull": ["$$m.source", ""] }, ":" ] }, -1 ] },
            { "$mergeObjects": [ "$$m", { "source": { "$arrayElemAt": [ { "$split": ["$$m.source", ":"] }, 0 ] } } ] },
            "$$m" ] } } } } }
  ]
)
```

Confirm with `db.teams.countDocuments({ "members.source": /:/ })` — it must return 0 — then
`kubectl rollout undo deployment/dependency-control-backend -n dependency-control`.

### 6b. After §3

The same strip, over the whole migrated set. Measured: `modified=3`, the member sources back to
`61 absent / 45 manual / 8 gitlab`, and the previous image then loads **29 of 29** teams. The
`$cond` is what leaves the 61 sourceless entries sourceless; a strip that stamped them `manual`
would still load, but it would be this migration inventing the provenance it refused to invent.

Run it **before** `kubectl rollout undo`, not after.

Accept what it costs: a provider's next sync again reads every instance's members as its own, and
each provider's sync again relabels the other's as hand-added. That is the state a rollback returns
to, and it is what this release removes.

## 7. What this window does not do

`TeamMember.role` and its validation are untouched, as is every other field of a member entry.
Nothing here touches `projects.team_sources`, `teams.bindings`, or project membership —
`projects.members[]` is a different list with a different meaning and carries no provenance at all.
