import {
  PageHeader, Section, SubHeading, P, Code, CodeBlock,
  Callout, ParamTable, Returns, Throws, MethodSignature,
  JsonSchema,
} from '../../components/DocPrimitives';
import D6Demo from './D6Demo';

// ── Code snippets ──────────────────────────────────────
const updatePwdExample = `const newKeyStorage = cm.update_keystorage_password(
  keyStorage,
  'old_password',
  'new_password'
)`

const updateRecipientExample = `// After bob rotates his key pair:
const updated = cm.update_container_recipientKeys(
  container,
  ownerKeyStorage,
  'owner_password',
  [{ username: 'bob', publicKey: bobNewPublicKey }]
)`

const keystorageSchema = `{
  "metadata": {
    "key_type":     "Ed25519",
    "generated_at": string        // Date string (toDateString())
  },
  "kdf_parameters": {
    "algorithm":        "PBKDF2",
    "hash":             "SHA-256",
    "iterations":       524288,   // 2^19
    "key_length_bytes": 32
  },
  "privateKey_encryption": {
    "algorithm":      "XChacha20+Poly1305",
    "tag_size_bytes": 16
  },
  "salt":                    string,  // Base64 16-byte random salt
  "nonce":                   string,  // Base64 24-byte random nonce
  "public_key":              string,  // Base64 32-byte Ed25519 public key (plaintext)
  "encryptedPrivateKey_w_tag": string // Base64 ciphertext + Poly1305 tag
}`

export default function D6Page() {
  return (
    <div>
      <PageHeader
        badge="D6 — Key Management"
        title="Key Management Module"
        subtitle="Private key protection using PBKDF2 + XChaCha20-Poly1305, continues with the full hybrid encryption and signing pipeline from D5."
      />

      {/* ── 1. System Overview ── */}
      <Section id="overview" title="Module Overview">
        <P>
          D6 is the final iteration of the vault. It extends D5 by solving the last remaining vulnerability: raw private keys were exposed in plaintext. D6 introduces KeyStorage — an encrypted key container that enforces one principle: the private key never exists in plaintext outside of an operation's scope. Every method that needs the private key receives a KeyStorage and a password. The key is decrypted in memory, used, and discarded.
        </P>

        <SubHeading>KeyStorage — the encrypted key container</SubHeading>
        <P>
          <Code>generate_key_pair(password)</Code> produces a <Code>KeyStorage</Code> object —
          a self-describing JSON structure that holds the Ed25519 public key in plaintext and the
          private key encrypted with <Code>XChaCha20-Poly1305</Code>. The encryption key is derived
          from the user's password using <Code>PBKDF2-SHA256</Code> with a random 16-byte salt and
          524,288 iterations. The entire metadata (salt, nonce, KDF parameters, public key) is used
          as AAD, so any modification to those fields causes decryption to fail.
        </P>

        <Callout kind="info">
          PBKDF2 was chosen over Argon2 because it is natively supported in browser environments without excessive memory pressure on client hardware.
        </Callout>


        <SubHeading>Public key</SubHeading>
        <P>
          The public key is stored in plaintext inside <Code>KeyStorage.public_key</Code> and
          can be retrieved without a password via <Code>getPublicKey(keyStorage)</Code>. This means
          any operation that only needs to verify a signature or wrap a key for a recipient can
          work from the <Code>KeyStorage</Code> file alone — no password required.
        </P>

        {/* ── Key Lifecycle ── */}
        <Section id="lifecycle" title="Key Lifecycle">
          <P>
            Every key pair goes through three stages: <strong>generation</strong>, <strong>usage</strong>,
            and <strong>rotation</strong>. Rotation is the most critical — its impact on the system
            depends entirely on the user's role in each container.
          </P>

          <SubHeading>As owner — full container rebuild required</SubHeading>
          <P>
            If an owner rotates their key pair, all containers they signed with the old key must be
            completely rebuilt using the new credentials. This is mandatory — not just recommended.
            A compromised owner key means an attacker could not only decrypt existing containers but
            also forge new signatures, making any container signed with the old key untrustworthy.
            Rebuilding is the only way to establish a clean cryptographic anchor.
          </P>
          <P>
            To manage this without data loss, the system maintains a maximum of two key states per
            user: one <strong>active</strong> and one <strong>deprecated</strong>. When a rotation is
            triggered, the active key shifts to the deprecated slot, new keys are generated, and all
            existing containers are marked as <em>obsolete</em> and queued for rebuild.
          </P>
          <Callout kind="danger">
            A second rotation cannot be initiated while the rebuild queue is not empty. If allowed,
            it would overwrite the deprecated slot and permanently destroy access to every container
            still waiting to be rebuilt — an irreversible loss.
          </Callout>
          <P>
            Affected containers are detectable via <Code>validate_container_signature</Code> — it
            returns <Code>false</Code> for any container whose owner fingerprint no longer matches
            the current public key, signaling that a rebuild is needed.
          </P>

          <SubHeading>As recipient — key-update request</SubHeading>
          <P>
            Recipients do not have the cryptographic authority to modify a container directly —
            only the owner can re-wrap keys. When a recipient rotates their key pair, they must
            notify each container owner, who then calls <Code>update_container_recipientKeys</Code> to re-wrap the symmetric file key for the recipient's new public key. The file itself is
            never re-encrypted.
          </P>

          <Callout kind="warn">
            This creates a window of vulnerability between the moment of compromise and the moment
            the owner re-wraps the key. The system relies on the recipient acting quickly and the
            owner processing the request promptly.
          </Callout>

          <P>
            Speed is critical here. Until the owner processes the update, an attacker who obtained
            the old private key can still decrypt any container where the old wrapped key is present.
            However, since containers are immutable from the recipient's perspective — only the owner
            can change the content — the attacker cannot alter the data or escalate further. The
            damage is bounded to read access on already-shared containers.
          </P>

          <Callout kind="info">
          <strong>Application-level recommendation:</strong> maintain a maximum of two key pairs  —
          one <strong>active</strong> and one <strong>deprecated</strong>. When a rotation is
          triggered, the active key pair shifts to the deprecated slot and a new key pair is generated.
          Containers are not rebuilt all at once — they are queued and processed incrementally,
          which avoids a heavy all-at-once workload. During this period, both key slots are needed:
          the deprecated key still decrypts containers in the queue, while the active key handles
          new ones. A second rotation must be blocked until the queue is fully cleared — either by
          rebuilding all pending containers or explicitly discarding the obsolete ones. Allowing a
          consecutive rotation would overwrite the deprecated slot, making every queued container
          permanently inaccessible.
        </Callout>


        </Section>


      </Section>

      {/* ── 2. Container Structure ── */}
      <Section id="container" title="KeyStorage Structure">
        <P>
          <Code>KeyStorage</Code> is the only persistent artifact produced by this module.
          It is safe to store in a database, file, or <Code>localStorage</Code> because the
          private key is never exposed. The full metadata object (everything except{' '}
          <Code>encryptedPrivateKey_w_tag</Code>) is used as AAD during encryption, binding
          all parameters to the ciphertext cryptographically.
        </P>
        <JsonSchema schema={keystorageSchema} />

        <SubHeading>AAD binding</SubHeading>
        <P>
          All fields in the <Code>KeyStorage</Code> schema — except <Code>encryptedPrivateKey_w_tag</Code> itself — are used as AAD. This means any post-storage modification to the salt, nonce, KDF parameters, or public key will cause the Poly1305 tag verification to fail, making decryption impossible. An attacker who tries to swap the public key or alter the iteration count gains nothing — the tag will reject the tampered container before any key material is exposed.
        </P>
      </Section>

      {/* ── 3. API Reference ── */}
      <Section id="api" title="API Reference">

        <SubHeading>CryptoModule</SubHeading>
        <Callout kind="info">
          Some methods carry over the same logic from D5 with
          one difference: instead of receiving raw key bytes, they accept a <Code>KeyStorage</Code>
          and a password. Their behavior and parameters are otherwise identical, so they are not
          re-documented here. Refer to the <a href="/d5#api">D5 API Reference</a> for full details.
        </Callout>


        {/* generate_key_pair */}
        <MethodSignature signature="generate_key_pair(password, expiration_data?): KeyStorage" />
        <P>
          Generates a fresh Ed25519 key pair, derives an encryption key from the password using
          PBKDF2, and encrypts the private key with XChaCha20-Poly1305.
        </P>
        <ParamTable params={[
          { name: 'password',        type: 'string', description: 'User password. Used to derive the encryption key via PBKDF2-SHA256 with a fresh random salt.' },
          { name: 'expiration_data', type: 'Date',   description: 'Reserved parameter, not yet implemented.', required: false },
        ]} />
        <Returns type="KeyStorage" description="Self-describing encrypted key container." />

        {/* getPrivateKey */}
        <MethodSignature signature="getPrivateKey(secureKeyStorage, password): Uint8Array" />
        <P>
          Re-derives the PBKDF2 key from the stored salt and the provided password, then
          decrypts the private key with XChaCha20-Poly1305.
        </P>
        <ParamTable params={[
          { name: 'secureKeyStorage', type: 'KeyStorage', description: 'KeyStorage produced by generate_key_pair.' },
          { name: 'password',         type: 'string',     description: 'User password.' },
        ]} />
        <Returns type="Uint8Array" description="32-byte Ed25519 private key. Use immediately and let go out of scope." />
        <Throws description="Throws an Error if the password is wrong or if any KeyStorage field was modified (Poly1305 tag failure)." />

        {/* getPublicKey */}
        <MethodSignature signature="getPublicKey(secureKeyStorage): Uint8Array" />
        <P>
          Decodes <Code>KeyStorage.public_key</Code> from Base64 to bytes. No password required.
        </P>
        <Returns type="Uint8Array" description="32-byte Ed25519 public key." />

        {/* update_keystorage_password */}
        <MethodSignature signature="update_keystorage_password(secureKeyStore, old_password, new_password): KeyStorage" />
        <P>
          Decrypts the private key with the old password and re-encrypts it with the new one,
          generating fresh salt and nonce. The key pair itself does not change.
        </P>
        <ParamTable params={[
          { name: 'secureKeyStore', type: 'KeyStorage', description: 'Current KeyStorage to re-encrypt.' },
          { name: 'old_password',   type: 'string',     description: 'Current password (verified before changing).' },
          { name: 'new_password',   type: 'string',     description: 'New password to encrypt the private key with.' },
        ]} />
        <Returns type="KeyStorage" description="New KeyStorage with the same key pair but encrypted under the new password." />
        <Throws description='Throws an Error if old_password is wrong.' />
        <CodeBlock code={updatePwdExample} />


        {/* update_container_recipientKeys */}
        <MethodSignature signature="update_container_recipientKeys(container, owner_secureKeyStorage, password, recipientsUpdate): SignContainer" />
        <P>
          Re-wraps the symmetric key for each specified recipient using their new public key.
          Only recipients whose usernames already exist in the container are updated. Used
          after a recipient rotates their key pair.
        </P>
        <ParamTable params={[
          { name: 'container',              type: 'SignContainer', description: 'Original signed container.' },
          { name: 'owner_secureKeyStorage', type: 'KeyStorage',   description: "Owner's KeyStorage." },
          { name: 'password',               type: 'string',       description: "Owner's password." },
          { name: 'recipientsUpdate',       type: 'UserInfo[]',   description: 'Array of { username, publicKey } with new public keys.' },
        ]} />
        <Returns type="SignContainer" description="Updated container with re-wrapped keys and fresh signature." />
        <Throws description='"Invalid signature" if signature check fails. "Not able to update keys, something went wrong." on internal error.' />
        <CodeBlock code={updateRecipientExample} />


        {/* verify_container_structure */}
        <MethodSignature signature="verify_container_structure(container: object): boolean" />
        <P>Validates the SignContainer schema with zod without cryptographic operations.</P>
        <Returns type="boolean" description="true if the object matches the SignContainer schema." />

        {/* verify_key_container_structure */}
        <MethodSignature signature="verify_key_container_structure(container: object): boolean" />
        <P>
          Validates the <Code>KeyStorage</Code> schema with zod. Call this before{' '}
          <Code>getPrivateKey</Code> when loading a KeyStorage from an untrusted source to
          avoid cryptographic errors on malformed input.
        </P>
        <Returns type="boolean" description="true if the object matches the KeyStorage schema." />
      </Section>

      {/* ── 4. Demo ── */}
      <Section id="demo" title="Demo">
        <D6Demo />
      </Section>
    </div>
  )
}