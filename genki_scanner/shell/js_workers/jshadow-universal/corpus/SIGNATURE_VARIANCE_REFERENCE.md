# J-Shadow — Empirical Signature Variance Reference
**Method:** controlled corpus. One known source file obfuscated with the REAL
`javascript-obfuscator` (obfuscator.io engine) across 12 isolated option axes +
JSFuck + p.a.c.k.e.r. Ground truth is known per file, so we can measure which
detection signals are INVARIANT (fire in every variant → reliable anchor) vs
VARIANT-SPECIFIC (fire only under certain options → variant discriminators).

This is why we GENERATE instead of download: with generation we control the
exact option set behind each file, so the stable-vs-variant split is provable.

---

## Corpus (14 variants)
| variant | isolated axis |
|---|---|
| obfio_default | baseline |
| obfio_rotate_off | `stringArrayRotate:false` |
| obfio_enc_base64 | `stringArrayEncoding:['base64']` |
| obfio_enc_rc4 | `stringArrayEncoding:['rc4']` |
| obfio_selfdefend | `selfDefending:true` |
| obfio_cff | `controlFlowFlattening:true` |
| obfio_deadcode | `deadCodeInjection:true` |
| obfio_mangled_names | `identifierNamesGenerator:'mangled'` |
| obfio_debugprotect | `debugProtection:true` |
| obfio_split_strings | `splitStrings:true` |
| obfio_nums2expr | `numbersToExpressions:true` |
| obfio_HIGH_preset | all of the above combined |
| jsfuck | JSFuck encoder |
| packer | Dean Edwards p.a.c.k.e.r |

## Classification result
All 12 obfuscator.io variants → classified `obfuscator_io` (0.8–0.95).
JSFuck → `jsfuck` (0.99). packer → `packer_pack` (0.92). **0 misroutes.**

---

## KEY FINDING — signature stability

### 🟢 CORE INVARIANTS (fire in 12/12 — the anchor signatures)
- **`arrayFn`** — the string-array provider function (incl. the self-redefining
  `function F(){const a=[...];F=function(){return a};return F();}` shape).
- **`shiftedFetch`** — the accessor that subtracts a constant offset from the index.

> These two ALWAYS appear regardless of options. They are the reliable, highest-
> weight obfuscator.io signature. **Anchor detection on these, not on rotation.**

### 🟡 VARIANT DISCRIMINATORS (fire only under certain options)
| signal | fires in | what it tells you |
|---|---|---|
| `rotation` prelude | 11/12 | rotation enabled (absent = `stringArrayRotate:false`) |
| `hex_escape` | 10/12 | hex string-escaping on (absent on some encodings) |
| entropy `obfuscated-likely` | 3/12 | base64/rc4 string encoding (raises entropy) |
| `callController` prelude + `selfdefend_wrapper` trap | 3/12 | `selfDefending` and/or `debugProtection` on |
| `string_concealing` | 1/12 | heavy bracket-access (HIGH preset) |

---

## Practical consequences for detection

1. **Don't require rotation.** The earlier detector missed `rotate_off` because it
   treated rotation as mandatory. Rotation is an OPTION (11/12). Fixed: anchor on
   `arrayFn + shiftedFetch`; rotation only raises confidence.

2. **The `debugger` keyword is concealed.** In `debugProtection`/`selfDefending`
   output the literal `"debugger"` lives inside the encoded string array, so a
   `\bdebugger\b` regex finds nothing. The real invariant is the **call-controller
   wrapper** `IDENT(this, function(){...})`. Detect the wrapper shape, not the word.

3. **Encoding type is read via entropy, not a keyword.** base64 vs rc4 vs none all
   share the same structural preludes; the discriminator is the string-pool entropy.

4. **Small arrays still count.** A 5-string array with the self-redefining shape is
   still obfuscator.io. Size threshold lowered from ≥10 to ≥3 when the self-redefine
   shape is present.

## Round-trip validation
Generated `obfio_enc_rc4` with the real obfuscator, then ran the full J-Shadow
pipeline against it → recovered `processPayment` + the secret `sk_live_4242SECRET`,
output 0.11x. Real tool generates → J-Shadow cracks: closed loop.

## Not covered by generation (noted honestly)
- **JScrambler**: commercial, no free CLI — cannot be generated here. Its detectors
  are built from documented structure (polymorphic → structural features only).
- **VM/virtualization full samples**: obfuscator.io CFF on a tiny function produces
  minimal flattening; a larger corpus + a dedicated VM obfuscator is the next step.

---

## False-Positive Control (v1.6.4)
Audited all 25 non-JScrambler samples (21 corpus + 4 real obfuscator.io). Found
5 FPs: `string_concealing` fired on obfuscator.io (both use heavy `obj['prop']`
bracket-access). Fixed by splitting JScrambler features into:
- **SPECIFIC** (`jscrambler_ns` `.f=`, `jscrambler_domainlock_const` `[189638]`) — always reported.
- **GENERIC** (`string_concealing`, `self_defending`, domain/date/browser-lock) — cross-family; suppressed when a more specific family (obfuscator.io / js-confuser / packer / bundler) already claimed the file.

Result: **0 false positives across 25 samples**, true positives preserved
(a JScrambler-specific sample still classifies as jscrambler), classification 21/21.

## JScrambler live-API note
The bundled `JSCRAMBLER_CORPUS_GEN.js` generates a real JScrambler variant matrix
(basic / advanced+CFF / self-defending / domain-lock / VM-heavy). It must run on a
machine whose clock matches real time — JScrambler's HMAC auth is timestamp-based,
so it 401s from a clock-skewed sandbox. Run locally, zip `./jscr_corpus/`, and feed
it back to calibrate the JScrambler detector against ground truth.
