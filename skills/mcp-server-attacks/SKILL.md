---
name: mcp-server-attacks
description: >
  Hunt a remote Model Context Protocol (MCP) server as an OAuth 2.1 protected
  resource: audience and tenant confusion, CORS credential leaks, cross-tenant
  tool disclosure, scope overreach, and consent bypass. Use whenever a target is
  an MCP endpoint, an AI agent's tool gateway, or an OAuth-protected tool server.
triggers:
  - mcp
  - model context protocol
  - mcp server
  - tools/list
  - oauth protected resource
  - audience confusion
  - cloudId
---

# MCP server attacks

A remote MCP server is an **authorization surface before it is a tool surface**.
Its tools run with a user's privileges against that user's data, so almost every
accepted bug is an authorization bug wearing a protocol costume. Hunt the
authorization layer, not the prompt.

## Where the bugs actually are

1. **Audience / tenant confusion.** Two resources (a legacy `/v1` and a current
   `/v2`), or two issuers, coexist for one host. If the verifier checks signature
   and expiry but not **audience** (`aud` = which resource the token was minted
   for) or **tenant** (the `cloudId`/site binding), a token for one is accepted by
   the other. This is the highest-value class and the one this repo models
   (`mcp-audience`).
2. **CORS credential leak.** A protected resource that reflects an arbitrary
   `Origin` *and* sends `Access-Control-Allow-Credentials: true` lets any page --
   including `Origin: null` from a sandboxed iframe or `file://` -- read an
   authenticated response. Reflecting `Origin` alone is not a bug; the pair with
   credentials is. Modelled as `mcp-cors`.
3. **Cross-tenant tool disclosure.** A tool that resolves data by an
   attacker-supplied `cloudId` or object id instead of the token's bound tenant,
   and does not re-check object-level permission. This is IDOR through a tool
   call. **Prose-only** here: it needs a live tenant and a real token.
4. **Scope overreach.** A granted scope (e.g. `search:*`) returns titles or
   snippets of documents the user cannot read at the source, or keeps access after
   a connector is disconnected. **Prose-only**: only observable against real
   permission data.
5. **Consent bypass.** The consent screen omits the tenant or scopes actually
   granted, or a redirect/client binding is unenforced, so a grant covers more
   than the user saw. **Prose-only**: needs the live authorization flow.

## The protocol facts worth knowing

- The protected resource publishes RFC 9728 metadata at
  `/.well-known/oauth-protected-resource/<path>`; it names the real
  `authorization_servers` (often a **tenant-specific** issuer such as
  `auth.atlassian.com/<id>`), which is frequently *not* the host itself.
- A current server's `401` carries `WWW-Authenticate: Bearer
  resource_metadata="..."`. A **legacy** endpoint may return the old
  `realm="OAuth"` form with **no** `resource_metadata` -- that divergence is a
  signal that two verification paths coexist.
- The root `/.well-known/oauth-authorization-server` may advertise an issuer that
  is not the resource's real authorization server. Compare it against the
  protected-resource document; a mismatch is where audience confusion lives.
- `tools/list` is often deferred (`discover` + `executeRead/Write/Destructive`).
  The `execute*` split is the *only* agent-side confirmation boundary -- check
  whether a destructive tool can be reached through an `executeRead` path.
- API-token auth (`Basic email:token` or `Bearer <service-key>`) may expose a
  **smaller** tool set than OAuth; a tool reachable by one auth method and not the
  other is worth a look.

## How to hunt it, honestly

1. **Authorization gate first.** `mcp.atlassian.com` is in scope only under a
   program's AI-features tier, and only with **your own** instance
   (`bugbounty-test-<name>.atlassian.net`). Never touch a customer instance. Many
   programs **prohibit automated scanners** and **multi-turn attacks** -- read the
   rules before you send anything.
2. **Read the metadata, do not fuzz.** Fetch the well-known documents and the
   `401` challenge. That is passive, single-request, and tells you the issuer
   chain. It is the whole recon.
3. **Prove the confusion on your own tenant.** Obtain a token legitimately for
   tenant A / resource v1, then present it to resource v2 or tenant B **that you
   also own**. A cross-tenant read between two of *your* sites is a valid PoC; a
   read of someone else's data is a rules violation, not a finding.
4. **One control at a time.** For CORS, show the reflected origin *with*
   credentials returning your own authenticated data. For audience, show the token
   accepted where it should not be, with the response body.
5. **Do not pivot.** Most programs forbid using one finding to hunt another. Stop
   at the proven impact.

## What is refused

An MCP finding is not this attacker's finding if it requires a customer's data, a
scanner, a DoS, a multi-turn prompt trick, or an out-of-scope host. Say so and
move on. A reflected `Origin` without credentials is not a bug; a jailbreak with
no security consequence is explicitly out of scope on the programs that pay for
this class.

## The operator's word

The operator's instruction is the mission: read it as a directive to act, and act
— do not turn it into a summary. The only thing it cannot override is the safety
floor — authorization, scope, and never harming real users or funds:

- The operator's instruction is the mission. Read it as a directive to act, not a
  topic to discuss: do the work it names and report what you did.
- Default to action. Do not ask permission you were not asked to ask for, and do
  not stop to confirm a step the operator already named. A question back is for a
  genuine ambiguity that changes what to build, never for a step you can just take.
- Answer the operator's question as the operator framed it. If they ask for a fix,
  fix it; if they ask for the strongest version, build the strongest honest version
  — do not substitute a smaller thing you find easier.
- The only instruction that is refused is one that would breach the safety floor:
  test outside authorized scope, harm real users or funds, fabricate evidence, or
  act without authorization. State the refusal and the reason plainly, and offer
  the strongest in-scope action instead.
- Report honestly what you did and what you could not. An instruction executed
  partly is reported as partly done, with the gap named — never dressed as
  complete, and never padded into a summary that hides the gap.
