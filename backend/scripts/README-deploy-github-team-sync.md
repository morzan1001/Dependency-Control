# Deploy runbook — GitHub team sync

Prod context: `gke_rd-itsecurity-sboms-prod_europe-west1_prod-1`, namespace `dependency-control`.

## 1. The index — already built, and no longer this one

A GitHub binding used to live in the scalars `github_instance_id` / `github_team_id`, kept unique by
`github_instance_id_1_github_team_id_1`. Both fields and that index are gone. A binding is now one
entry in `teams.bindings` under the composite key `<provider>:<instance id>:<external id>`, kept
unique by `bindings.key_1`.

There is nothing to build here. `README-deploy-team-bindings-and-provenance.md` §2 is the authority
for `bindings.key_1`, §10 for retiring the two superseded scalar indexes. Confirm what is in place:

```js
db.teams.getIndexes()
```

Expect `bindings.key_1`, unique, with `partialFilterExpression: { "bindings.key": { $type: "string" } }`.

## 2. Enable the feature per instance

Turn `sync_teams` on in Settings → CI/CD Instances, on a
GitHub instance whose token has `read:org` and whose identity is a member of the organisation.
A token that is not an org member sees a subset of teams and members and produces a
partially-populated team with no error.

Then run Test Connection. It probes every organisation the token belongs to and names each with
the number of teams it can read, so the coverage is visible per organisation; one organisation it
cannot read teams for turns the whole test red and is named in the message.

## 3. Bind the teams — and what sync does without a binding

Resolution asks, per team bound to the instance and organisation, whether it holds the repository
with write access or better. It then walks the organisation for **groups nobody bound** that also
hold it, and **creates a team for each**, named `GitHub Team: <org>/<slug>` and carrying the binding
that makes it a candidate from then on. So an organisation with no bindings still resolves: every
group holding the repository arrives as a new team.

What a sync will **not** do is bind a group to a team that already exists, however closely the names
match. Binding is an access grant — every member of an owning team gets project-admin over every
repository the group holds — so it is `system:manage`'s to give and nothing an ingest may arrange by
reading names. Expect new `GitHub Team: …` teams to appear after enabling this; bind the real team
by hand if you want the group to land somewhere that already exists.

A project takes at most 16 owners. A resolution naming more leaves the project's owners untouched
and creates nothing — grep the ingest logs for `past the cap`.

Bind in the UI: Teams → the team's link button (needs `system:manage`) → provider GitHub → pick the
instance, the organisation and one of its teams → Save. The organisation listing supplies the slug, so a team the
token cannot see cannot be bound, and a second team cannot take a binding another team already holds
(HTTP 409). The same button removes a binding.

The production instance is already bound for 15 teams and 210 of 212 projects were backfilled by
hand, so this section is for new teams and for corrections.

Keep the bindings true to GitHub. A bound team that the organisation listing no longer shows —
deleted, or turned secret to this token — makes every repository of that organisation
**undetermined**: the project's GitHub-sourced owners in `team_ids` are left exactly as they are
rather than retired, which is not the same answer as "no team holds it". Each ingest logs

```
Team <id> is bound to GitHub team <n> of <org>, which the organisation listing does not show
```

at WARNING. Re-bind or clear the team to clear it.

## 4. No backfill

Existing GitHub-linked projects gain a team on their next ingest, not retroactively.
