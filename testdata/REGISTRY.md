# Registries of record — Agent Action Capsule vocabularies

**Status.** This document is the **interim registry of record** for the
extensible vocabularies of the Agent Action Capsule profile, until RFC
publication establishes the corresponding IANA registries. The registries and
their normative definitions are in the Internet-Draft
(`draft-mih-scitt-agent-action-capsule`, this repository's `spec/`), §12 (IANA
Considerations). Registration policy: **Specification Required** per
[RFC 8126 §4.6]. Change controller: **Action State Group, Inc.** (interim) →
**IETF** on publication.

**The never-reject invariant.** Verifiers MUST treat unregistered values as
informational and MUST NOT reject a record solely because it carries an
unregistered value. The digest commits whatever bytes are present; an unknown
value breaks only semantic interpretation, never digest verification.

**Descriptive, not generative.** The registry text is DESCRIPTIVE of the
vocabulary defined normatively in the Internet-Draft; it never generates new
semantics. A registration records a value and its specification — it does not
amend the format.

[RFC 8126 §4.6]: https://www.rfc-editor.org/rfc/rfc8126#section-4.6

## Designated-expert guidance (all registries)

A designated expert evaluating a registration applies three tests:

1. **Clear semantics** — two independent implementations would apply the value
   identically.
2. **No overlap** with existing values.
3. **Publicly available spec** documenting the value.

The Specification Required policy answers a specific threat: a vocabulary value
whose meaning is defined only inside a closed product would make two verifiers
disagree on what the value means. The publicly-available-spec requirement is the
mitigation — a value enters the shared vocabulary only once its semantics are
pinned in a specification any implementer can read (Internet-Draft §12).

**Worked example — rejected registration.** `ready` (proposed as a disposition
value) — REJECTED: `ready` is a derived state computed from the chain (an open
item whose constraints are all satisfied), not a verdict the gate issued.
Derived states are never registry values; registering one would let a capsule
assert a state that only the store can compute.

---

## 1. `verdict_class`

Defined in §5.4.1 of the Internet-Draft (the `verdict_class` vocabulary).
Initial contents:

| Value | Semantics |
|---|---|
| `executed` | The action ran (effect_mode confirmed \| dispatched_unconfirmed). |
| `blocked` | A blocking constraint stopped it pre-dispatch. |
| `hitl_dispatched` | Routed to an operator; awaiting resolution. |
| `denied` | Operator/policy refused pre-dispatch. |
| `timeout` | Timed out (pre-dispatch: not_applicable; post: dispatched_unconfirmed). |
| `errored` | Ran and threw; final state unknown (dispatched_unconfirmed). |
| `engine_failure` | The engine could not evaluate (pre-dispatch). |
| `deferred` | A human elected to postpone the decision; open item. |
| `needs_decision` | Evaluation complete, decision required, not yet routed to a decider; open item. |
| `expired` | TTL policy on the deferral elapsed; terminal unless superseded by escalation. |
| `escalated` | Expiry or policy routed the item to a higher authority; open item at the new authority. |
| `resolved` | A terminal decision capsule closed the chain without executing (pairing rule, Internet-Draft §5.4.2). |
| `epoch_boundary` | An administrative capsule (`action_type: "fyi"`) marking a configuration-epoch transition. REQUIRES `effect_mode: "not_applicable"` — no effect is dispatched by an administrative epoch record. Defined in §5.1 (Configuration epochs) of the Internet-Draft. |

**`deferred` token ownership.** The `deferred` token's semantics are OWNED by
the `verdict_class` registry; the `disposition.decision` entry of the same
spelling (§2) is a cross-reference to it.

## 2. `disposition.decision`

Defined in §5.4 of the Internet-Draft (Disposition).
Initial contents: `accept`, `reject`, `needs_input`, `deferred`.

**`deferred` token ownership.** The `deferred` token's semantics are OWNED by
the `verdict_class` registry (§1); this `disposition.decision` entry is a
cross-reference to it.

## 3. `effect.type`

Defined in §5.2 of the Internet-Draft (Effect Record and the confirmed-effect
binding). Initial contents (the profile's seeded examples): `write_order`,
`send_payment`.

## 4. `irreversibility_class`

Defined in §5.2 of the Internet-Draft (Effect Record). An **ordered**
vocabulary by ascending consequence; a registration MUST state its position in
the consequence order relative to the existing values. Initial contents, in
order:

1. `two_way`
2. `one_way_recoverable`
3. `one_way_consequential`
4. `one_way_terminal`

## 5. `effect_attestation`

Defined in §5.2 of the Internet-Draft (Effect Record; the validity matrix).

**Grade-floor rule (registry preamble).** Consumers MUST treat an unregistered
or unrecognized `effect_attestation` value as **no stronger than
`runtime_claimed`**. The never-reject invariant holds — unknown values are
informational, never a verification failure — but unknown NEVER grades up.

**Planned carve (registry preamble).** `effect.status = "planned"` asserts no
execution — `effect_attestation` MUST be absent (nothing to grade; a phantom
grade would poison grade-based queries); it becomes REQUIRED the moment
dispatch occurs (Internet-Draft §5.2).

Initial contents:

| Value | Semantics |
|---|---|
| `gate_executed` | The commit transited the gate; the engine observed the effect boundary directly. |
| `runtime_claimed` | The gate issued a verdict only; the executing runtime asserted completion; the capsule records that claim, not an observation. |

**Designated-expert guidance (this registry).** Plausible future registrations
exist and are deliberately NOT seeded here — e.g. independent sensor
confirmation of a claimed effect, or hardware/TEE-anchored execution. A
registration MUST state where its grade sits relative to the seeded values.

## 6. `chain.relation`

Defined in §5.4.4 of the Internet-Draft (Chained Capsules; the chain block).
Initial contents:

| Value | Semantics |
|---|---|
| `confirms` | Non-terminal: this capsule observes or records the outcome of the parent — the parent's open state remains. The most common chain link: *attempted → confirmed*. |
| `supersedes` | Terminal transition over the parent — resolution, expiry, escalation close/replace the parent's open state. |
| `epoch_opens` | Non-terminal: this capsule opens a new operational configuration epoch. The chain parent MUST be the last capsule produced under the prior epoch. The opening capsule carries the new `epoch_id`. Defined in §5.1 (Configuration epochs, Epoch-boundary Capsules) of the Internet-Draft. |

**Designated-expert guidance (this registry).** Seeded with the core non-terminal and terminal
relations, plus `epoch_opens` for configuration-epoch boundaries. Additional
non-terminal relations — deposit-toward-open and effort-toward-open relations,
or `amends` / `contradicts` — are expected future registrations, each admitted
once its semantics and any verifier consequence are pinned in a publicly
available specification. Such relations are anticipated in a future revision of
the Internet-Draft and are registered into this same registry rather than
establishing a new one.

## 7. Reserved payload members — selective disclosure

Reserved by the companion Internet-Draft
`draft-mih-scitt-agent-action-capsule-sel-disc` (Selective Disclosure
Profile), §9 (IANA Considerations). These members carry the salted-hash
selective-disclosure structure and MUST NOT be used for any other purpose. They use
the underscore-prefixed naming convention (following SD-JWT (RFC 9901)) to avoid
collision with current or future Capsule payload members.

| Member | Type | Location | Defined in |
|---|---|---|---|
| `_sd_alg` | string | Top-level Capsule object | Selective-Disclosure profile, "Algorithm Identifier" section (`"sha-256"` only) |
| `_sd` | array of string | Any SD-eligible JSON object | Selective-Disclosure profile, "Salted-Hash Commitment Construction" section (commitment digests) |

A plain (non-SD) Capsule carries neither member. The `_sd`/`_sd_alg` structure is
part of the content-addressed form, so it is covered by `capsule_id` and is
tamper-evident; a verifier unaware of the SD profile processes an SD-Capsule as a
plain Capsule and sees the concealed REQUIRED fields as missing. See the companion
draft for producer requirements, the eligible-field set, and the two-phase
verifier checks.

## 8. `domain`

Defined in §5.1 of Internet-Draft `-02` (`domain` / `provenance` addendum). The
capsule's epistemic role — what kind of act this capsule records. **Optional**;
absent implies the receiver SHOULD treat the capsule as `"action"`.

| Value | Semantics |
|---|---|
| `action` | A tool call, side-effecting step, or any act that could in principle be confirmed against an external system. The most common value; applies to all capsules where the agent *did something*. |
| `memory` | A write-to or read-from a persistent memory store (retrieval, consolidation, eviction). |
| `reasoning` | A STANDALONE reasoning / chain-of-thought step that is itself the recorded act — not an action-with-reasoning (those stay `"action"`). A reasoning capsule typically carries no `effect`. |

**Extension convention.** Values with an `x-` prefix are reserved for private
experiments and MUST NOT be submitted for registration. A public extension MUST
have a publicly available specification (Specification Required, §12).

## 9. `provenance`

Defined in §5.1 of Internet-Draft `-02` (`domain` / `provenance` addendum). A
dedup rank signal: when the same logical event produces capsules from multiple
tiers, the higher-ranked provenance is authoritative. **Optional**; absent
implies receivers SHOULD treat the capsule as `"runtime"`. Rank order is
strictly gate > runtime > collector; equal rank resolves by earliest timestamp.

| Value | Rank | Semantics |
|---|---|---|
| `gate` | 3 | Emitted at the gate / policy-enforcement boundary. The most authoritative form: the capsule was produced at the point where the decision was made and committed. |
| `runtime` | 2 | Emitted by the executing runtime (agent framework, tool adapter). Authoritative for the execution record but cannot see the gate's internal decision details. |
| `collector` | 1 | Emitted by a general observability or telemetry system that observed the action passively. Lowest authority; used when neither the gate nor the runtime directly produce capsules. |

**Dedup rule (verifier / ledger-reader, NOT wire).** On dedup, the capsule with
the highest-ranked `provenance` wins; equal rank resolves by earliest timestamp.
The dedup rule is a consumer-side read algorithm, not a wire constraint — a
collector-provenance capsule is still valid; it loses only when a higher-ranked
capsule for the same event is also present.

## No registry

The following vocabularies are deliberately **not** registries of this document:

- **COSE algorithms** — by reference to the IANA
  [COSE Algorithms](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
  registry (Internet-Draft §12, "No new registry").
- **Constraint `id` / `check_type`, `compliance.framework_tags`,
  `assurance.sources[].kind`** — governed by the namespacing convention
  (Internet-Draft §9): bare names are reserved for the seeded values; new values
  use a URI or reverse-DNS prefix.
