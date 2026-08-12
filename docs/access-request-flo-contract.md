# Access-Request Flo — Decision & Contract

_SDAP / Super Duper Admin Portal · agent-initiated privileged actions · v1.0 · 2026-06-07_

How the in-app AI agent requests a **destructive** or **creative** Okta action, and how that
request is approved and **executed** — with as much logic as possible living in Okta.

---

## 1. Decision (ADR-style)

### 1.1 Initiation — **Direct Okta Governance API v2**
The portal calls **`POST /governance/api/v2/requests`** directly to create an Access Request.
No Okta Workflows invoke hop.

**Why:** fewer moving parts; native OIG request lifecycle and System Log auditing; catalog entry +
approval sequence configured in Okta console; portal holds only `okta.accessRequests.request.manage`
(not a privileged-write credential for §4 operations).

### 1.2 Execution — **Okta executes on approval. The portal never does.** ⬅ key decision
On approval, **Okta performs the Okta operation** (via the access request condition / fulfillment).
The portal (and therefore the agent) holds **zero privileged-write capability** for destructive/creative actions.

**Why:** this is the strongest form of "keep logic in Okta" and the cleanest security story — the
agent has *no hands, only a voice*. It can **request**; Okta **decides** and **performs**. There is
no code path by which the agent executes a suspend/role-grant/policy-change directly.

**Consequence:** the portal's existing read path (`fetch_okta_data`, on-behalf-of XAA) stays for
**read-only** GETs. Anything that writes/mutates goes through this flo. The portal must not hold a
standing credential capable of the write (today's SSWS token should be scoped read-only or retired
in favor of the on-behalf-of token for reads).

### 1.3 Separation of duties — **approver resolution is the flo's job**
`requester == approver` (self-approval) is acceptable only for low-risk demo plumbing. Real approver
selection (group, manager, break-glass; never self for high-risk) is **policy in the flo / OIG**, not
hardcoded in the portal.

---

## 2. Architecture

```
 Agent (LLM, in /api/chat)                 Okta IGA (Governance API v2)          Okta core
 ──────────────────────────                ───────────────────────────────       ────────────────
 classify action as                        POST /governance/api/v2/requests      OIG Access Request
 destructive/creative   ──create request─▶ (catalog entry + requester fields)  (approval sequence)
 normalize {actor,                         GET  /governance/api/v2/requests/{id}        │
 action,target,...}                        status: SUBMITTED → PENDING → …              │ approve
 show "pending #id"                        Okta executes mapped op on approval  ──Okta──▶ user/app/…
 poll status endpoint                                                               System Log
```

- **Portal = thin intent emitter.** No OIG knowledge, no write privilege.
- **Flo = orchestrator + executor.** Holds the only privileged connection.
- **OIG = policy/approval/audit engine.**

---

## 3. Contract

Three messages. All carry `schemaVersion` and a portal-generated `correlationId` for tracing.

### 3.1 Invoke — portal → flo  `POST {base}/api/flo/{alias}/invoke`
```json
{
  "schemaVersion": "1.0",
  "source": "super-duper-admin-portal",
  "correlationId": "f1e2d3c4-....",
  "requestedAt": "2026-06-07T18:30:00Z",
  "actor": {
    "id": "00u...",
    "login": "demo-admin-3@example.com",
    "email": "demo-admin-3@example.com",
    "name": "Skylar Barnes"
  },
  "action": {
    "type": "suspend_user",
    "category": "destructive",
    "description": "Suspend Okta user jane.doe@sledai.com",
    "target": { "userId": "00uXXXX", "userLogin": "jane.doe@sledai.com" },
    "parameters": {}
  },
  "justification": "Offboarding per ticket SD-1421",
  "agentContext": { "agentId": "wlpzd73wrostoEGIn1d7", "model": "grok-4.3", "conversationId": null }
}
```
- `action.type` — canonical enum (snake_case), see §4. The flo rejects unknown types.
- `action.target` — shape depends on `action.type` (§4 lists required fields per type).
- `actor` — the **signed-in admin** (from the OIDC session). The invoke auth proves *the portal*
  is calling; the **actor identity is in the body** and is what OIG records as requester.

> **Migration note (implemented):** to avoid breaking the current flo (which reads the flat
> top-level `action` *string*, `actionType`, `description`, `requester`, `approver`, `target`), the
> portal currently sends this v1.0 envelope **nested under a top-level `v1` key**, alongside the
> unchanged legacy flat fields. The new flo reads `payload.v1.*`. Once the flo is cut over, the
> portal drops the legacy fields and promotes the envelope to top level (per the shape above).

### 3.2 Synchronous return — flo → portal
The flo's **Return** card MUST emit this deterministic shape (no more guessing across 7 fields):
```json
{
  "schemaVersion": "1.0",
  "ok": true,
  "status": "pending_approval",
  "requestId": "agr0a1b2c3...",
  "correlationId": "f1e2d3c4-....",
  "approval": { "approverType": "group", "approverRef": "Privileged Approvers", "channel": "okta-access-requests" },
  "links": { "requestUrl": "https://sledai.oktapreview.com/.../requests/agr0a1b2c3" },
  "message": "Access request created; pending approval.",
  "error": null
}
```
- `status`: `pending_approval` | `rejected_intake` (validation/policy failed at intake) | `error`.
- On failure: `ok=false`, `requestId=null`, `error={ code, message }`.

### 3.3 Terminal callback — flo → portal  `POST https://ai-admin-api.skylarbarnes.com/api/agent/access-request/callback`
Fired when the request reaches a terminal state (after approval+execution, or denial/expiry):
```json
{
  "schemaVersion": "1.0",
  "requestId": "agr0a1b2c3...",
  "correlationId": "f1e2d3c4-....",
  "status": "approved_executed",
  "decision": { "by": "00u...", "at": "2026-06-07T18:35:10Z", "comment": "Approved" },
  "execution": {
    "performed": true,
    "oktaOperation": "POST /api/v1/users/00uXXXX/lifecycle/suspend",
    "result": "success",
    "detail": null
  },
  "completedAt": "2026-06-07T18:35:11Z"
}
```
- `status`: `approved_executed` | `approved_execution_failed` | `denied` | `expired` | `cancelled`.

**Signing (implemented, required):** the flo MUST send `Content-Type: application/json` and sign the
**raw request body bytes** with HMAC-SHA256 using the shared secret `FLO_CALLBACK_SECRET`, presenting
it as header **`X-Flo-Signature: sha256=<hex>`**. The portal verifies in constant time and returns
`401` on any mismatch/missing signature, `400` on empty/non-JSON body, `200 {ok,requestId,recorded}`
on success. _(In Okta Workflows: HMAC card → SHA-256 over the JSON body with the secret → hex → set
the header.)_ The secret lives in the portal's `.env.local` (`FLO_CALLBACK_SECRET`) and must be
pasted into the flo's connection/config — it is the one shared secret for this hop.

**Status read (implemented):** `GET /api/agent/access-request/{requestId}/status` (auth-gated) returns
the latest recorded status for closed-loop UI/agent polling; `404` until the first callback lands.
Status is in-memory today (ephemeral; persist per §9).

---

## 4. Canonical action taxonomy

The agent may only request these `action.type`s. The flo maps each to exactly one Okta operation it
performs **on approval**. `risk` drives approver selection (§5).

| `action.type` | category | required `target` | Okta op the flo executes on approval | risk |
|---|---|---|---|---|
| `suspend_user` | destructive | `userId` | `POST /api/v1/users/{id}/lifecycle/suspend` | med |
| `unsuspend_user` | creative | `userId` | `POST /api/v1/users/{id}/lifecycle/unsuspend` | low |
| `activate_user` | creative | `userId` | `POST /api/v1/users/{id}/lifecycle/activate` | low |
| `deactivate_user` | destructive | `userId` | `POST /api/v1/users/{id}/lifecycle/deactivate` | high |
| `reset_user_mfa` | destructive | `userId` | `POST /api/v1/users/{id}/lifecycle/reset_factors` | med |
| `reset_user_password` | destructive | `userId` | `POST /api/v1/users/{id}/lifecycle/expire_password` | med |
| `create_user` | creative | `profile{firstName,lastName,email,login}` | `POST /api/v1/users?activate=false` | med |
| `add_user_to_group` | creative | `userId`,`groupId` | `PUT /api/v1/groups/{groupId}/users/{userId}` | med |
| `remove_user_from_group` | destructive | `userId`,`groupId` | `DELETE /api/v1/groups/{groupId}/users/{userId}` | med |
| `assign_app_to_user` | creative | `userId`,`appId` | `PUT /api/v1/apps/{appId}/users/{userId}` (or POST) | med |
| `assign_admin_role` | creative | `userId`,`roleType` | `POST /api/v1/users/{id}/roles` | **high** |
| `update_policy_rule` | destructive | `policyId`,`ruleId`,`parameters` | `PUT /api/v1/policies/{policyId}/rules/{ruleId}` | **high** |
| `delete_group` | destructive | `groupId` | `DELETE /api/v1/groups/{id}` | high |

Extensible — add a row + an OIG request type + a flo branch. The portal's `request_access` tool enum
must stay in sync with this list.

---

## 5. Approver resolution (in the flo)

Per `risk`, never hardcoded in the portal:
- **low** → optional auto-approve or single approver group.
- **med** → approver **group** (e.g. "Privileged Approvers"); requester ≠ approver.
- **high** → break-glass approver group + (optionally) dual approval; explicitly **disallow self**.

The flo reads the actor + target + risk and sets the OIG request's approver(s) accordingly. (The
current `approver = requester` self-route is a v0 stand-in to be replaced here.)

---

## 6. Security / auth

| Hop | Mechanism | Proves |
|---|---|---|
| Portal → flo (invoke) | `?clientToken=…` (mode 1) **or** OAuth `client_credentials` + `private_key_jwt` (mode 2) | the **portal** is the caller. Actor identity travels in the body. |
| Flo → OIG / Okta core | the flo's own Okta connection (the **only** privileged-write credential) | Okta-resident; never in the app. |
| Flo → portal (callback) | HMAC `X-Flo-Signature` over the raw body w/ a shared secret (`FLO_CALLBACK_SECRET`), or OAuth | the **flo** is the caller; portal rejects unsigned. |

The portal must **not** hold a credential that can perform any §4 operation. Reads use the
on-behalf-of XAA token; the static SSWS token should be read-scoped or removed.

---

## 7. Portal-side conformance checklist

- [x] `lib/oktaAccessRequests.js` `createAccessRequest()` POSTs **§3.1**-shaped payload to
      `POST /governance/api/v2/requests` (catalog entry from `OKTA_ACCESS_REQUEST_CATALOG_ENTRIES`).
- [x] Map the tool's free-form `action` → canonical `action.type` via `normalizeActionType()`
      (`CANONICAL_ACTIONS` in `lib/accessRequestActions.js`).
- [x] `request_access` tool schema constrains `action` to the §4 enum.
- [x] **Closed-loop:** `GET /api/agent/access-request/{id}/status` polls Okta v2;
      legacy `POST /api/agent/access-request/callback` (HMAC) still accepted if configured.
- [ ] **TODO:** ensure no write path remains in `fetch_okta_data` / `/api/agent/okta/*` (reads only);
      scope down / retire the static SSWS `OKTA_API_TOKEN` so the portal holds no write credential.
- [ ] **TODO:** wire `/api/chat` (or UI) to poll the status endpoint so the agent reports terminal
      outcome after approval.

## 8. Flo-side build checklist (Okta Workflows console — your hands)

1. API Endpoint trigger secured per §6 (keep current mode).
2. Validate `schemaVersion` + required fields for `action.type`; on fail → Return `rejected_intake`.
3. Resolve approver per §5.
4. Create OIG Access Request (request type mapped from `action.type`); stash `correlationId`,
   `agentContext`, `justification` as request attributes.
5. Return §3.2 synchronously.
6. On **approve** event (paused/resumed flo, or a second flo on the OIG "approved" event): execute the
   §4 Okta op via connector; capture result.
7. Callback portal (§3.3) with terminal status; rely on System Log for audit.
8. On **deny/expire**: callback with the matching terminal status.

## 9. Open questions

- Closed-loop callback in v1, or display-and-forget (Okta/Teams notifies the human)?
- Auto-approve any `low` risk types, or always require approval (better story)?
- Dual approval for `assign_admin_role` / `update_policy_rule`?
- Where does request **status** live portal-side — ephemeral map, or persist (also fixes the
  "restart logs everyone out / loses state" gap)?
