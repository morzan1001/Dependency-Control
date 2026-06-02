# Project Authorization Model

**Status:** Implemented (W2 / Finding 22)
**Created:** 2026-06-01
**Scope:** Project-level authorization only (teams, OIDC, analytics out of scope)

This document is the human-readable single source of truth for project
authorization. It is kept consistent with:

- the matrix docstring in `backend/app/core/permissions.py`, and
- the single resource gate `check_project_access(project_id, user, db, required_role)`
  in `backend/app/api/v1/helpers/projects.py`.

If you change the rule, update all three together.

## The single gate

Every project access decision flows through one function:

```
check_project_access(project_id, user, db, required_role=None) -> Project   # or raises 403/404
```

There is **no** ad-hoc, divergent `project:update`-only bypass scattered across
endpoints any more. Every write path honours the SAME write-superuser rule
(`project:update` / `project:delete`, see `_WRITE_SUPERUSER_PERMISSIONS`):

- `rotate_api_key`, `update_project` (via `_load_project_for_update`), and
  `delete_project` defer to the gate at `required_role="admin"`.
- team transfer (`_assert_can_transfer_team`) applies the same write-superuser
  rule via the shared `is_write_superuser` helper, then additionally requires
  target-team membership — logic the gate cannot express, since it concerns the
  *destination* team rather than the project being accessed.

## Two layers

Authorization composes two independent layers.

### Layer 1 — global string permissions (`user.permissions`)

| Permission          | Meaning                                                                                                              |
|---------------------|----------------------------------------------------------------------------------------------------------------------|
| `project:read`      | Read feature-gate. A project **member** must hold this (or `project:read_all`) to read; absence => 403.              |
| `project:read_all`  | **READ-ONLY superuser.** Grants read to ANY project. Does **NOT** satisfy a WRITE `required_role`.                   |
| `project:update`    | **WRITE superuser** ("manage any project"). Bypasses membership for any request (write implies read). Admin-preset only. |
| `project:delete`    | Treated as a WRITE superuser too, so a delete-capable global admin satisfies the admin-level gate even without `project:update`. |

### Layer 2 — project roles

`PROJECT_ROLES = [viewer, editor, admin]` (ordered, ascending privilege).

- A request is **READ** when `required_role` is `None` or `"viewer"`.
- A request is **WRITE** when `required_role` is `"editor"` or `"admin"`.
- **Effective project role = MAX(direct member role, team-derived role).** A
  higher direct role is never downgraded by team membership, and vice versa.
- Team -> project mapping: team-admin -> project-admin; team-member -> project-viewer.

## Resolution order (as implemented in the gate)

1. Load the project; **404** if it does not exist.
2. If the user holds a WRITE superuser permission (`project:update` /
   `project:delete`) -> allow (write implies read).
3. Else if the request is READ and the user holds `project:read_all` -> allow.
   (`read_all` deliberately does NOT short-circuit a WRITE request.)
4. Resolve `(is_member, effective_role)` from direct + team membership.
   - Not a member -> **403**.
5. Read feature-gate: member must hold `project:read` or `project:read_all`,
   else **403**.
6. If `required_role` is set and `effective_role < required_role` -> **403**.
7. Otherwise -> allow.

## Quick matrix

Does the actor pass `check_project_access`?

| Actor / required_role          | `None` / `viewer` (READ) | `editor` / `admin` (WRITE) |
|--------------------------------|--------------------------|----------------------------|
| `project:read_all` (non-member)| yes                      | **NO -> 403**              |
| `project:update` (non-member)  | yes                      | yes                        |
| `project:delete` (non-member)  | yes                      | yes                        |
| member, role >= required       | yes                      | yes                        |
| member, role < required        | yes (if read-gate held)  | **NO -> 403**              |
| non-member, none of the above  | **NO -> 403**            | **NO -> 403**              |
| member without `project:read`* | **NO -> 403**            | **NO -> 403**              |

\* unless the member also holds `project:read_all`, which satisfies the read
feature-gate.

## Why this changed (Finding 22)

Previously `project:read_all` short-circuited the gate for *all* requests,
which silently let a read-only superuser perform WRITE operations (update,
delete, key rotation, team transfer). Additionally, the `project:update`
bypass was duplicated inline across several endpoints, and team membership
could **downgrade** a higher direct project role. The consolidated rule fixes
all three: `read_all` is read-only, `project:update` is the single uniform
write superuser, and the effective role is the MAX of direct and team-derived
roles.
