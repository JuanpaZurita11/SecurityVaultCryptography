import {
  PageHeader, Section, SubHeading, P, Code, CodeBlock,
  Callout, ParamTable, Returns, Throws, MethodSignature,
} from '../../components/DocPrimitives';
import D6Demo from './D6Demo';

// ── Code snippets ──────────────────────────────────────
const keygenExample = `import { CryptoModule } from 'd6'

const cm = new CryptoModule()

// Generate key pair — private key is encrypted with password
const keyStorage = cm.generate_key_pair('my_secure_password')

// keyStorage is safe to persist (localStorage, file, database)
// The private key is encrypted; only the password can unlock it
console.log(keyStorage.public_key) // Base64 plaintext public key`

const getKeyExample = `// Recover public key — no password needed
const publicKey = cm.getPublicKey(keyStorage)  // Uint8Array 32 bytes

// Recover private key — password required
const privateKey = cm.getPrivateKey(keyStorage, 'my_secure_password')
// Use privateKey here, then let it go out of scope`

const encryptExample = `const container = cm.create_container(
  keyStorage,           // owner's KeyStorage
  'my_secure_password', // owner's password
  'alice',              // owner username → signer_id
  {
    data:      fileBytes,
    filename:  'report.pdf',
    file_type: 'application/pdf',
    recipients: [
      { username: 'bob', publicKey: bobPublicKey },
    ],
  }
)`

const decryptExample = `const plaintext = cm.decrypt_container(
  container,
  'bob',           // petitioner username
  bobKeyStorage,   // petitioner's KeyStorage
  'bob_password',  // petitioner's password
  alicePublicKey   // owner public key to verify signature
)`

const updatePwdExample = `const newKeyStorage = cm.update_keystorage_password(
  keyStorage,
  'old_password',
  'new_password'
)
// Replace persisted keyStorage with newKeyStorage`

const addExample = `const updated = cm.add_recipients_to_container(
  container,
  ownerKeyStorage,
  'owner_password',
  [{ username: 'carol', publicKey: carolPublicKey }]
)`

const removeExample = `const updated = cm.remove_recipients_from_container(
  container,
  ownerKeyStorage,
  'owner_password',
  ['bob']
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
        subtitle="Password-protected Ed25519 key storage using PBKDF2 + XChaCha20-Poly1305, integrated with the full hybrid encryption and signing pipeline from D5."
      />

      {/* ── 1. System Overview ── */}
      <Section id="overview" title="System Overview">
        <P>
          D6 is the final integration layer of the vault. It wraps everything from D5 inside a
          single <Code>CryptoModule</Code> class that enforces one principle:{' '}
          <strong>the private key never exists in plaintext outside of an operation's scope</strong>.
          Every method that needs the private key receives a <Code>KeyStorage</Code> (the encrypted
          key container) and a password. The key is decrypted in memory, used, and discarded.
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

        <SubHeading>Why PBKDF2 with 524,288 iterations?</SubHeading>
        <P>
          2<sup>19</sup> = 524,288 iterations make each brute-force attempt take roughly 500ms on
          modern hardware. An attacker who obtains the <Code>KeyStorage</Code> file faces an
          astronomically slow dictionary attack for passwords with reasonable entropy. PBKDF2 was
          chosen over Argon2 because it is natively supported in browser environments without
          excessive memory pressure on client hardware.
        </P>

        <SubHeading>Public key lifecycle</SubHeading>
        <P>
          The public key is stored in plaintext inside <Code>KeyStorage.public_key</Code> and
          can be retrieved without a password via <Code>getPublicKey(keyStorage)</Code>. This means
          any operation that only needs to verify a signature or wrap a key for a recipient can
          work from the <Code>KeyStorage</Code> file alone — no password required.
        </P>

        <SubHeading>Key rotation strategy</SubHeading>
        <P>
          When a user's key pair is compromised or expires, they must rotate. The impact depends
          on their role:
        </P>
        <P>
          <strong>As owner:</strong> All containers signed with the old key must be fully
          recreated — <Code>validate_container_signature</Code> will return <Code>false</Code>{' '}
          for any container signed with the old key pair, signaling to recipients that
          regeneration is needed.
        </P>
        <P>
          <strong>As recipient:</strong> The owner re-wraps the symmetric key for the recipient's
          new public key using <Code>update_container_recipientKeys</Code>, without touching the
          ciphertext or re-encrypting the file.
        </P>

        <Callout kind="danger">
          If a second key rotation is attempted while containers are still pending regeneration,
          the deprecated key slot is overwritten and those containers become permanently
          inaccessible. The system must block consecutive rotations until all affected containers
          are rebuilt.
        </Callout>

        <Callout kind="info">
          The public key can be derived from the private key in Ed25519, but{' '}
          <Code>KeyStorage</Code> stores it explicitly for convenience — avoiding an extra
          decryption step just to read the public key.
        </Callout>
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
        <CodeBlock code={keystorageSchema} lang="json" />

        <SubHeading>AAD binding</SubHeading>
        <P>
          Before encrypting the private key, the module builds a <Code>KeyStorageAad</Code>{' '}
          object containing all fields except <Code>encryptedPrivateKey_w_tag</Code>, serializes
          it with <Code>fast-json-stable-stringify</Code>, and passes it as AAD to{' '}
          <Code>XChaCha20-Poly1305</Code>. Any post-storage modification to salt, nonce,
          iterations, or public key will cause the Poly1305 tag to fail during decryption.
        </P>
      </Section>

      {/* ── 3. API Reference ── */}
      <Section id="api" title="API Reference">

        <SubHeading>CryptoModule</SubHeading>
        <P>
          Central class integrating key management with the full D5 encryption and signing
          pipeline. All methods that need the private key accept <Code>KeyStorage + password</Code>{' '}
          instead of raw key bytes.
        </P>

        {/* generate_key_pair */}
        <MethodSignature signature="generate_key_pair(password, expiration_data?): KeyStorage" />
        <P>
          Generates a fresh Ed25519 key pair, derives an encryption key from the password using
          PBKDF2, and encrypts the private key with XChaCha20-Poly1305. Returns a{' '}
          <Code>KeyStorage</Code> object safe for persistence.
        </P>
        <ParamTable params={[
          { name: 'password',        type: 'string', description: 'User password. Used to derive the encryption key via PBKDF2-SHA256 with a fresh random salt.' },
          { name: 'expiration_data', type: 'Date',   description: 'Reserved parameter, not yet implemented.', required: false },
        ]} />
        <Returns type="KeyStorage" description="Self-describing encrypted key container. Safe to persist." />
        <CodeBlock code={keygenExample} />

        {/* getPrivateKey */}
        <MethodSignature signature="getPrivateKey(secureKeyStorage, password): Uint8Array" />
        <P>
          Re-derives the PBKDF2 key from the stored salt and the provided password, then
          decrypts the private key with XChaCha20-Poly1305. Returns the raw 32-byte private key
          in memory only — it is never stored.
        </P>
        <ParamTable params={[
          { name: 'secureKeyStorage', type: 'KeyStorage', description: 'KeyStorage produced by generate_key_pair.' },
          { name: 'password',         type: 'string',     description: 'User password.' },
        ]} />
        <Returns type="Uint8Array" description="32-byte Ed25519 private key. Use immediately and let go out of scope." />
        <Throws description="Throws if the password is wrong or if any KeyStorage field was modified (Poly1305 tag failure)." />

        {/* getPublicKey */}
        <MethodSignature signature="getPublicKey(secureKeyStorage): Uint8Array" />
        <P>
          Decodes <Code>KeyStorage.public_key</Code> from Base64 to bytes. No password required.
        </P>
        <Returns type="Uint8Array" description="32-byte Ed25519 public key." />
        <CodeBlock code={getKeyExample} />

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
        <Throws description='"Hubo un problema, no se pudo actualizar la contraseña" if old_password is wrong.' />
        <CodeBlock code={updatePwdExample} />

        {/* create_container */}
        <MethodSignature signature="create_container(secureKeyStorage, password, owner_username, cipherObject): SignContainer" />
        <P>
          Decrypts the owner's private key, runs the full D5 encryption and signing pipeline,
          and returns a signed container. The owner always gets an independent{' '}
          <Code>ownerWrap</Code> entry and can always decrypt regardless of the recipients list.
        </P>
        <ParamTable params={[
          { name: 'secureKeyStorage',      type: 'KeyStorage',  description: "Owner's KeyStorage." },
          { name: 'password',              type: 'string',      description: "Owner's password." },
          { name: 'owner_username',        type: 'string',      description: 'Stored as signer_id in the container.' },
          { name: 'cipherObject.data',     type: 'Uint8Array',  description: 'Raw file bytes.' },
          { name: 'cipherObject.filename', type: 'string',      description: 'Original filename.' },
          { name: 'cipherObject.file_type',type: 'string',      description: 'MIME type.' },
          { name: 'cipherObject.recipients',type: 'UserInfo[]', description: 'Optional array of { username, publicKey }.', required: false },
        ]} />
        <Returns type="SignContainer" description="Encrypted and signed container ready to distribute." />
        <CodeBlock code={encryptExample} />

        {/* decrypt_container */}
        <MethodSignature signature="decrypt_container(container, petitioner_userName, petitioner_secureKeyStorage, password, owner_publicKey): Uint8Array" />
        <P>
          Verifies the container structure, validates the Ed25519 signature and owner fingerprint,
          decrypts the petitioner's private key from their <Code>KeyStorage</Code>, performs
          ECIES-style key unwrap, and decrypts the file.
        </P>
        <ParamTable params={[
          { name: 'container',                    type: 'SignContainer', description: 'Container to decrypt.' },
          { name: 'petitioner_userName',          type: 'string',       description: 'Username of the person requesting decryption.' },
          { name: 'petitioner_secureKeyStorage',  type: 'KeyStorage',   description: "Petitioner's KeyStorage." },
          { name: 'password',                     type: 'string',       description: "Petitioner's password." },
          { name: 'owner_publicKey',              type: 'Uint8Array',   description: 'Owner public key to verify the signature.' },
        ]} />
        <Returns type="Uint8Array" description="Original file bytes if all checks pass." />
        <Throws description='"Invalid container structure" if schema fails. "Invalid signature" if fingerprint or Ed25519 check fails. "Recipient not found in metadata" if username has no key wrap.' />
        <CodeBlock code={decryptExample} />

        {/* add_recipients_to_container */}
        <MethodSignature signature="add_recipients_to_container(container, owner_secureKeyStorage, password, recipientsInfo): SignContainer" />
        <P>
          Recovers the symmetric key from <Code>ownerWrap</Code>, wraps it for each new
          recipient via ECIES-style X25519/HKDF, and re-signs. Skips usernames already present.
        </P>
        <ParamTable params={[
          { name: 'container',             type: 'SignContainer', description: 'Original signed container.' },
          { name: 'owner_secureKeyStorage',type: 'KeyStorage',   description: "Owner's KeyStorage." },
          { name: 'password',              type: 'string',       description: "Owner's password." },
          { name: 'recipientsInfo',        type: 'UserInfo[]',   description: 'Array of { username, publicKey } to add.' },
        ]} />
        <Returns type="SignContainer" description="Updated container with new recipients and fresh signature." />
        <Throws description='"Firma no válida" if signature check fails. "No se puedieron actualizar las llaves" on internal error.' />
        <CodeBlock code={addExample} />

        {/* remove_recipients_from_container */}
        <MethodSignature signature="remove_recipients_from_container(container, owner_secureKeyStorage, password, usernamesToRemove): SignContainer" />
        <P>
          Validates the signature, filters the recipient list, and re-signs. No unwrap needed
          for removal — it is purely a list operation followed by re-signing.
        </P>
        <ParamTable params={[
          { name: 'container',              type: 'SignContainer', description: 'Original signed container.' },
          { name: 'owner_secureKeyStorage', type: 'KeyStorage',   description: "Owner's KeyStorage." },
          { name: 'password',               type: 'string',       description: "Owner's password." },
          { name: 'usernamesToRemove',      type: 'string[]',     description: 'Usernames to remove from the recipient list.' },
        ]} />
        <Returns type="SignContainer" description="Updated container with reduced recipient list and fresh signature." />
        <Throws description='"Firma no válida" if signature check fails. "No se pudo remover a los usuarios" on internal error.' />
        <CodeBlock code={removeExample} />

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
        <Throws description='"Firma no válida" if signature check fails. "No se puedieron actualizar las llaves" on internal error.' />
        <CodeBlock code={updateRecipientExample} />

        {/* validate_container_signature */}
        <MethodSignature signature="validate_container_signature(container, owner_publicKey): boolean" />
        <P>
          Verifies the owner fingerprint (<Code>SHA-256(owner_publicKey)</Code> vs stored
          value) and then the Ed25519 signature over the canonical payload. Returns{' '}
          <Code>false</Code> if either check fails — which signals key rotation when the
          stored fingerprint no longer matches the provided public key.
        </P>
        <Returns type="boolean" description="true if both fingerprint and signature are valid, false otherwise." />

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