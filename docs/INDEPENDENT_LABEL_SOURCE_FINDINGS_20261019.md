# Independent-label evidence acquisition findings

This follow-up targeted sample-level human adjudication and legitimate-owner
evidence, rather than re-listing ordinary phishing feeds. No model was scored,
no dataset owner was contacted, and no new human review attestation was created.
The existing source audit and protected-domain roles remain unchanged.

## Concrete acquisition: official owner evidence

The [CISA .gov registry](https://get.gov/about/data/) publishes registered domains
and registrant organizations. Its [official repository](https://github.com/cisagov/dotgov-data)
licenses registry metadata under [CC0](https://github.com/cisagov/dotgov-data/blob/main/LICENSE).
The registry includes inactive/on-hold names and does not promise a functioning
website. It establishes an organizational ownership lead, not a benign label for
an exact historical page or immunity from compromise.

The immutable local snapshot is
`lightgbm_dataset/source_candidates/cisa_dotgov_owner_evidence_20261019_v1/`.
It pins commit `86a82005c752e5fa4091bd691841af205a9bbee6`, dated
2026-10-18T12:00:55Z, and retains CSV, license, source README, commit metadata,
per-domain evidence candidates, source registration and checksums. The executed
snapshot script is archived separately at
`audit-output/owner_registry_snapshot_executed_20261019.py`; its hash matches the
registration. Future invocations retain their script inside the source package.

There are 16,907 unique domains. Of these, 1,148 overlap known protected domains
and 816 overlap known development domains; these sets intersect. A total of
15,517 avoid both known inventories. That is provisional known-domain novelty,
not certified untouched status: historical visual manifests still contain
unknown domains, counted repeatedly across versions in the inventory report.

Every candidate has `label=null`, `independent_page_label_supported=false`, and
`model_scored=false`. No target site was visited. This is a prospective unscored
source inventory, **not a registered release holdout**. No government domains
were added to training exclusions or reserved for evaluation. The current
frozen development selection is unaffected.

A future government control stratum can attach this ownership record to an
isolated timestamped capture, verify its origin/redirects and expected official
content, and obtain a genuine independent per-capture review. Government-only
controls cannot establish false-positive rates for arbitrary Internet traffic.

## Human-adjudication leads checked

- [Choo et al., SIGMETRICS 2024](https://userlab.utk.edu/files/papers/kim/2023/choo2023large.pdf)
  describe two-expert URL labeling, exclusion of disagreements, and repeated
  checks over three days. Their manually labeled set contains 773 records,
  including 421 benign; additional APWG and SiteAdvisor cohorts underwent
  attack-type labeling. This is a stronger documented curation procedure than
  feed membership alone. However, the checked [author publication page](https://userlab.utk.edu/publications/choo2023large)
  offers the paper, not a public sample-level evidence archive or dataset use
  license. No public paired artifact/reviewer record package was found. It is
  an owner-request lead, not an accessible qualifying corpus. No request was sent.
- [PhreshPhish's primary paper](https://arxiv.org/html/2507.10854v1)
  explicitly describes human inspection of representative prototypes, with
  decisions propagated to neighboring examples under a finite review budget.
  That is useful quality curation, but does not show independent human
  adjudication tied to every released sample. It also excludes host-based
  evidence. Publication-level quality claims cannot upgrade all rows to SCYTHE
  independent release labels; prior development use also constrains novelty.
- The official [PhishIntention experiment page](https://sites.google.com/view/phishintention/experiment-structure)
  identifies a 3,049-item misleading-legitimacy subset with human verification.
  Its size, specialized task, old collection dates, unresolved sample-level
  independent-label evidence, and dataset-specific access terms prevent it from
  satisfying the two-class 2,000/5,000 domain-group requirement. Logo annotation
  or visual quality inspection is not phishing-intent adjudication.

## Result

This work supplies a large, legally reusable **owner-evidence candidate pool**,
but adds **zero independently supported phishing or benign release labels**.
No checked public source establishes all required properties together:
per-sample independent evidence, dated paired captures, adequate disjoint
domain diversity, applicable use terms, and contemporaneous SCYTHE observations.
The concrete next path is genuine saved-evidence review with owner/reference
support and a new frozen release protocol. Restricted-corpus access and author
curation attestations must come from their actual owners. Neither an automated
agent nor a blanket .gov assumption can replace those decisions.
