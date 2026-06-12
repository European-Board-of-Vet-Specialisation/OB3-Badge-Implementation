# Issuing Open Badges 3.0 credentials that import into Open Badge Passport

Implementation notes from the European Board of Veterinary Specialisation (EBVS). In June 2026 we deployed an Open Badges 3.0 Verifiable Credential for European Veterinary Specialist status that passes 1EdTech JSON-LD validation and imports, verifies and binds to its holder in Open Badge Passport (OBP). Conformance with the published specifications took a day. Verification in the real systems took a week of failed imports, because the behaviours that decide success on that path are documented nowhere. This repository records them so you can skip the week.

Behaviours described here were observed in June 2026 against the 1EdTech validator and openbadgepassport.com. Platforms change; retest before relying on any of it.

## Why no prior guidance existed

Earlier European badge initiatives avoided this problem rather than solving it. The Erasmus+ EU-OBP project (“European Open Badges Platform”, 2019-2021), to take a representative example, advised organisations to issue through a hosted commercial platform: when one platform mints, displays and verifies the badge, nothing ever has to interoperate, and issuer control of the credential is the price. An organisation that signs its own credentials, under its own DID, on its own infrastructure, and then asks an independent wallet to verify them, meets a different problem entirely. OBP has accepted Open Badges 3.0 only since autumn 2025, so the configuration this repository documents (self-sovereign issuer, independent wallet) has been possible for months, not years. At the time of writing, every error message below returned no useful results on a web search. They should now return this page.

## The configuration that works in both systems

One credential, secured one way, satisfies the 1EdTech validator and OBP:

- **Proof:** W3C Data Integrity, `DataIntegrityProof` with `cryptosuite: eddsa-rdfc-2022`. Not `Ed25519Signature2020` (predecessor suite, rejected), and not a JWT (no JWT algorithm satisfies both systems; finding 6).
- **Verification method:** a DID URL pointing at a **Multikey** entry (`publicKeyMultibase`) in the DID document. OBP’s key extractor does not read `publicKeyJwk` on this path (finding 3).
- **Issuer:** `issuer.id` is the DID that controls the signing key. An https issuer with a DID-hosted key fails verification in both systems (finding 1).
- **DID document:** served at `/.well-known/did.json` **and** `/did.json`; the two validators resolve did:web to different paths (finding 5).
- **Recipient:** email `IdentityObject` **first** in `credentialSubject.identifier` (finding 7), hashed as `sha256$` hex of the email with the salt appended (finding 10).
- **Display fields OBP requires:** `achievement.creator.url` as a string, and an `achievement.image` (finding 9).
- **Encoding:** the bytes you sign are the bytes verifiers canonicalise. Emit UTF-8 once; corrupted characters in a signed literal either break the hash or notarise the corruption permanently.

A sanitised working credential is in [`examples/credential.json`](examples/credential.json); the DID document shape is in [`examples/did.json`](examples/did.json).

## Findings, keyed by the error message

Each heading is the verbatim error a platform returned, so a search on the error lands here.

### 1. `Supplied key (null) is not a RSAPublicKey instance` (OBP)

OBP resolved the issuer, found no key it could use, and passed null to its RSA verifier. Two causes, and we hit both. The issuer identity and the signing key lived under different identifiers (`issuer.id` was an https URL while the key sat in a did:web document), so no key was authorised to sign for that issuer. And OBP’s JWT path treats `kid` as a URL to fetch (finding 2). Fix the identity first: `issuer.id` must be the DID that controls the verification method. This requirement is format-independent; it decides Data Integrity verification too.

### 2. `Error verifying jwt signature: Unable to retrieve jwk value from url specified in kid` (OBP)

OBP’s JWT verifier performs an HTTP GET on the `kid` value and expects a JWK in response. A DID URL with a fragment (`did:web:example.org#key-1`) is not a fetchable URL, so retrieval returns nothing even when the JWK exists in the DID document. A JWT for OBP needs `kid` set to an https URL serving the bare JWK with a JSON content type. We later abandoned the JWT path entirely (finding 6).

### 3. `Validation failed: Verification method does not contain either an Ed25519, P256 or P384 public key` (OBP)

Two facts in one error. RSA keys are excluded from verification entirely; the allowlist is Ed25519, P-256, P-384. And on the Data Integrity path, OBP’s extractor reads `publicKeyMultibase` only. Our verification method was a `JsonWebKey2020` entry carrying a valid Ed25519 `publicKeyJwk`, and OBP reported no usable key. Publish the same key as a `Multikey` entry and reference that entry in `proof.verificationMethod`. The eddsa-rdfc-2022 cryptosuite specification expects Multikey, so this is also the more conformant form.

### 4. `Cannot invoke "clojure.lang.IFn.invoke(Object, Object, Object)" because "verifier" is null` (OBP)

OBP’s stack is Clojure and its JWT verification uses the buddy library, which looks the JWT header’s `alg` up in an internal algorithm map and invokes the result as a three-argument function. The buddy generation in use has no EdDSA entry, so an `alg: EdDSA` JWT resolves to nil and Clojure throws exactly this exception. Read together with finding 3, OBP’s JWT path accepts ES256/ES384 at most. Its Data Integrity path verifies Ed25519 through different code and works.

### 5. `Key document not found at did:web:... URI: https://example.org/did.json doesn't return a valid document` (1EdTech)

The did:web specification resolves a bare-domain DID to `/.well-known/did.json`, which is where OBP looks. 1EdTech’s Java resolver requests `/did.json` at the root. Serve both. On Caddy:

```
rewrite /did.json /.well-known/did.json
```

### 6. 1EdTech: `alg must be present and must be 'RS256'`. OBP: no RSA keys (finding 3)

The two validation regimes impose mutually exclusive JWT requirements. 1EdTech’s JWT branch mandates RS256. OBP’s key gate excludes RSA and its JWT verifier lacks EdDSA. No single JWT satisfies both. The Linked Data proof (eddsa-rdfc-2022) is the only single-artifact route through both systems. The same conclusion settles PNG baking: the spec permits exactly one `openbadgecredential` iTXt chunk, so a PNG carries one envelope, and that envelope is the LD JSON.

### 7. `User does not own this badge` (OBP)

OBP binds a badge to an account by comparing **one** recipient identity against the account’s confirmed email addresses; the matching function in the open-source Salava codebase takes a single identity, and the OB3 converter appears to select the first entry in the `identifier` array. Our array listed an institutional `sourcedId` first and the email second, and ownership failed although the email matched the account exactly. Put the email `IdentityObject` first.

### 8. `$.proof: object found, array expected` and `required property 'issuanceDate' not found` (1EdTech, plain JSON branch)

Warnings, not failures, and they fire while the JSON-LD branch passes. The plain JSON branch checks VC 1.1-era schemas; 1EdTech’s own canonical 3.0.3 example uses `validFrom` with no `issuanceDate`, so the spec’s sample trips the same warning. Do not add `issuanceDate`: it is the deprecated field, and if the term is missing from your context it breaks the canonicalised signature. Wrapping `proof` in a one-element array is semantically identical JSON-LD and silences the other warning at the next re-sign.

### 9. `Value does not match schema: {:badge {:creator [{:url ...}]}}` (OBP)

After verification, OBP converts the OB3 credential into its internal badge model, and that model requires `achievement.creator.url` as a string. Add it. An `achievement.image` is needed in practice for the same display-model reason.

### 10. Hashed recipient identity fails ownership: hash order is email + salt (OBP)

OB3 permits hashed recipient identities (`hashed: true`, `salt`, `identityHash: sha256$<hex>`), which keeps the holder’s email out of the publicly fetchable credential document. OBP supports them, and its matcher computes `sha256(email + salt)`: the account email with the salt **appended**, following the Open Badges convention. Our pipeline hashed `salt + email` and ownership failed with no salt-specific error. Hash the lowercase account email exactly as the account holds it, concatenate the salt after it, and prefix the lowercase hex digest with `sha256$`. Hash in production regardless of platform: plaintext email addresses in credential JSON that anyone can fetch are a data-protection liability at register scale.

## What the specifications cover and what they do not

OB 3.0.3 and the VC Data Model 2.0 define the credential’s structure, vocabulary and permitted proof mechanisms, and a credential can conform to both while failing every real system it meets. The specifications do not state which proof suites and key representations a given platform reads, how a wallet binds a credential to an account, which paths a did:web resolver requests, or which display fields an importer’s internal schema demands. Every finding above came from a failed import and a corrected hypothesis, in two cases by reading the platform’s open-source code. Budget accordingly: conformance is a day; interoperability is the project.

## Repository contents

- `examples/credential.json`: sanitised working credential (names and identifiers replaced, hashed recipient identity)
- `examples/did.json`: DID document publishing the same Ed25519 key as both JsonWebKey2020 and Multikey
- `scripts/sign-eddsa.mjs`: Node signing script (jose) for the VC-JWT variant, kept for reference
- `notes/validator-feedback.md`: issues filed upstream with 1EdTech and Discendum

## Contact and citation

European Board of Veterinary Specialisation, <https://ebvs.eu>. This work was carried out within the Erasmus+ I-RESTART project (101055774). Cite as: EBVS (2026), *Issuing Open Badges 3.0 credentials that import into Open Badge Passport*, implementation note.
