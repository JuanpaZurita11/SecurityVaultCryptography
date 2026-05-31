import {
  PageHeader, Section, SubHeading, P, Code, CodeBlock,
  Callout, ParamTable, Returns, Throws, MethodSignature,
} from '../../components/DocPrimitives';
import D5Demo from './D5Demo';

const keygenExample = `import { KeyManager } from 'd5'

const km = new KeyManager()

// Generate Ed25519 key pair (synchronous, 32 bytes each)
const { publicKey, privateKey } = km.generate_key_pair()

// Serialize to PEM for storage
const publicPem  = await km.serialize_public_key_pem(publicKey)
const privatePem = await km.serialize_private_key_pem(privateKey)

// Deserialize back to raw bytes
const pubBytes  = await km.deserialize_public_key_pem(publicPem)
const privBytes = await km.deserialize_private_key_pem(privatePem)`

const encryptExample = `import { SignatureCryptoModule, KeyManager } from 'd5'

const km  = new KeyManager()
const scm = new SignatureCryptoModule()

const owner = km.generate_key_pair()
const alice = km.generate_key_pair()
const bob   = km.generate_key_pair()

const container = scm.create_container(
  owner.privateKey,
  owner.publicKey,
  'owner',
  {
    data:       new TextEncoder().encode('Secret document'),
    filename:   'document.txt',
    file_type:  'text/plain',
    recipients: [
      { username: 'alice', publicKey: alice.publicKey },
      { username: 'bob',   publicKey: bob.publicKey },
    ],
  }
)
// container.signature   → Ed25519 signature in Base64
// container.signer_id   → 'owner'
// container.signature_algo → 'Ed25519'`

const decryptExample = `import { SignatureCryptoModule } from 'd5'

const scm = new SignatureCryptoModule()

// Verify signature and decrypt in one step
const plaintext = scm.decrypt_container(
  container,
  'alice',           // petitioner username
  alice.privateKey,  // petitioner private key (Ed25519 raw)
  owner.publicKey    // owner public key to verify signature
)

console.log(new TextDecoder().decode(plaintext))
// → 'Secret document'`

const addExample = `const updated = scm.add_recipients_to_container(
  container,
  owner.publicKey,
  owner.privateKey,
  [{ username: 'carol', publicKey: carol.publicKey }]
)
// Container is re-signed automatically`

const removeExample = `const updated = scm.remove_recipients_from_container(
  container,
  owner.publicKey,
  owner.privateKey,
  ['bob']   // array of usernames to remove
)
// Container is re-signed automatically`

const containerSchema = `{
  "metaData": {
    "file_type":         string,        // MIME type
    "filename":          string,        // original file name
    "timestamp":         string,        // ISO 8601 (UTC)
    "owner_fingerprint": string,        // Base64 SHA-256(owner_publicKey) — AAD anchor
    "ownerWrap": {
      "wrapNonce":    string,           // Base64 192-bit nonce
      "wrappedKey":   string,           // Base64 XChaCha20(derivedKey, symmetric_key)
      "ephimeral_pub": string           // Base64 ephemeral X25519 public key
    },
    "encryption": {
      "cipher":          "XChacha20-Poly1305",
      "key_size_bits":   256,
      "nonce_size_bits": 192,
      "tag_size_bits":   128
    },
    "keyWrapping": {
      "scheme": "ECIES-STYLE",
      "asymmetric": { "curve": "X25519", "kdf": { "alg": "HKDF", "hash": "SHA-256", "salt": "" } },
      "symmetric":  { "cipher": "XChacha20", "key_size_bits": 256 }
    },
    "recipients": [                     // modifiable without re-encrypting
      {
        "username":     string,
        "wrapNonce":    string,
        "wrappedKey":   string,
        "ephimeral_pub": string
      }
    ],
    "nonce": string                     // Base64 192-bit nonce for main AEAD
  },
  "cipherText_w_tag": string,           // Base64 ciphertext + Poly1305 tag
  "signature_algo":   "Ed25519",
  "signer_id":        string,           // owner username
  "signature":        string            // Base64 Ed25519 signature over payload
}`

export default function D5Page() {
  return (
    <div>
      <PageHeader
        badge="D5 — Authenticated Cipher"
        title="Authenticated Cipher Module"
        subtitle="Hybrid ECIES-style encryption with Ed25519 digital signatures. Guarantees confidentiality, integrity, authenticity, and dynamic recipient management."
      />

      {/* ── 1. System Overview ── */}
      <Section id="overview" title="System Overview">
        <P>
          D5 extends D3 with two major upgrades: the RSA-OAEP key wrapping scheme is replaced by
          an <strong>ECIES-style scheme over Curve25519</strong>, and the container is
          <strong> digitally signed</strong> with Ed25519. Together these provide authenticity and
          allow the recipient list to be modified without re-encrypting the file.
        </P>

        <SubHeading>Why Ed25519 instead of RSA?</SubHeading>
        <P>
          Ed25519 offers 128-bit security with 32-byte keys — a fraction of the 256–512 bytes
          typical of RSA-2048. Signatures are deterministic (no RNG dependency), faster, and
          immune to a class of implementation errors that affect ECDSA. The same Ed25519 keys
          can be mathematically converted to Curve25519 Montgomery form for ECDH key agreement,
          eliminating the need for separate key pairs.
        </P>

        <SubHeading>ECIES-style key wrapping</SubHeading>
        <P>
          For each recipient a fresh ephemeral X25519 key pair is generated. The shared secret
          between the ephemeral private key and the recipient's X25519 public key (derived from
          their Ed25519 key) is fed through <Code>HKDF-SHA256</Code> to produce a 256-bit wrap
          key. The symmetric file key is then stream-ciphered with <Code>XChaCha20</Code> using
          that wrap key. Only the recipient — who holds the matching private key — can reverse
          the ECDH and recover the file key.
        </P>

        <SubHeading>Dynamic recipient management</SubHeading>
        <P>
          In D3 the recipient list was part of the AEAD AAD, making any modification require
          a full re-encryption. D5 moves recipient list protection to the signature layer:
          the owner can add or remove recipients and re-sign without touching the ciphertext.
          To prevent impersonation, the owner's public key fingerprint (<Code>SHA-256(owner_publicKey)</Code>)
          is embedded in the AAD — an attacker who re-signs with a different key cannot match
          the fingerprint stored inside the encrypted envelope.
        </P>

        <SubHeading>Verification before decryption</SubHeading>
        <P>
          <Code>decrypt_container</Code> always calls <Code>validate_container_signature</Code>
          first. If the fingerprint or signature fails, decryption never runs — preventing
          oracle attacks where error messages from a tampered container leak information.
        </P>

        <Callout kind="info">
          The AAD covers everything in <Code>metaData</Code> except <Code>recipients</Code> and{' '}
          <Code>nonce</Code>. This is what makes recipient management dynamic while keeping the
          ciphertext integrity intact.
        </Callout>

        <Callout kind="danger">
          The owner always has their own <Code>ownerWrap</Code> entry independent of the
          recipients list. Even if all recipients are removed, the owner can still decrypt.
        </Callout>
      </Section>

      {/* ── 2. Container Structure ── */}
      <Section id="container" title="Container Structure">
        <P>
          The <Code>SignContainer</Code> carries the encrypted file, per-recipient key wraps,
          and the Ed25519 signature. The signature covers{' '}
          <Code>{`{ metaData, cipherText_w_tag, signature_algo, signer_id }`}</Code> serialized
          with <Code>fast-json-stable-stringify</Code>, binding the ciphertext and full metadata
          to the signer's identity.
        </P>
        <CodeBlock code={containerSchema} lang="json" />
      </Section>

      {/* ── 3. API Reference ── */}
      <Section id="api" title="API Reference">

        <SubHeading>KeyManager</SubHeading>
        <P>
          Handles Ed25519 key generation and PEM serialization. Unlike D3's{' '}
          <Code>KeyManager</Code>, this one works with raw <Code>Uint8Array</Code> bytes
          (the native representation of <Code>@noble/curves</Code>) rather than opaque{' '}
          <Code>CryptoKey</Code> objects.
        </P>

        <MethodSignature signature="generate_key_pair(): { publicKey: Uint8Array; privateKey: Uint8Array }" />
        <P>Generates a fresh Ed25519 key pair synchronously using <Code>crypto.getRandomValues</Code> as entropy source.</P>
        <Returns type="{ publicKey: Uint8Array; privateKey: Uint8Array }" description="32-byte raw key arrays." />

        <MethodSignature signature="serialize_public_key_pem(rawKey: Uint8Array): Promise<string>" />
        <P>Exports a raw Ed25519 public key to SPKI PEM format via <Code>SubtleCrypto</Code>.</P>
        <Returns type="Promise<string>" description='SPKI PEM string with "-----BEGIN PUBLIC KEY-----" header.' />

        <MethodSignature signature="serialize_private_key_pem(rawKey: Uint8Array): Promise<string>" />
        <P>Builds a PKCS#8 DER structure manually following RFC 8410 and encodes it as PEM. The 48-byte DER layout is fixed for Ed25519.</P>
        <Returns type="Promise<string>" description='PKCS#8 PEM string with "-----BEGIN PRIVATE KEY-----" header.' />

        <MethodSignature signature="deserialize_public_key_pem(pem: string): Promise<Uint8Array>" />
        <P>Imports a SPKI PEM and exports the raw 32-byte public key.</P>
        <Throws description='Throws "La clave no tiene estructura PEM" if the PEM header/footer is missing.' />

        <MethodSignature signature="deserialize_private_key_pem(pem: string): Promise<Uint8Array>" />
        <P>Imports a PKCS#8 PEM, re-exports the DER, and slices off the 16-byte header to recover the raw 32-byte private key.</P>
        <Throws description='Throws "La clave no tiene estructura PEM" if the PEM header/footer is missing.' />
        <CodeBlock code={keygenExample} />

        <SubHeading>SignatureCryptoModule</SubHeading>
        <P>Main class combining ECIES-style hybrid encryption with Ed25519 signatures.</P>

        <MethodSignature signature="create_container(owner_privateKey, owner_publicKey, owner_username, cipherObject): SignContainer" />
        <P>
          Encrypts the file with <Code>XChaCha20-Poly1305</Code>, wraps the symmetric key for
          each recipient via ECIES-style X25519/HKDF, and signs the full container with
          Ed25519. The owner always gets their own independent <Code>ownerWrap</Code>.
        </P>
        <ParamTable params={[
          { name: 'owner_privateKey', type: 'Uint8Array', description: 'Owner Ed25519 private key (32 bytes). Used for signing and ownerWrap.' },
          { name: 'owner_publicKey',  type: 'Uint8Array', description: 'Owner Ed25519 public key (32 bytes). SHA-256 fingerprint stored in AAD.' },
          { name: 'owner_username',   type: 'string',     description: 'Stored as signer_id in the container.' },
          { name: 'cipherObject.data',      type: 'Uint8Array',   description: 'Raw file bytes.' },
          { name: 'cipherObject.filename',  type: 'string',       description: 'Original filename.' },
          { name: 'cipherObject.file_type', type: 'string',       description: 'MIME type.' },
          { name: 'cipherObject.recipients', type: 'UserInfo[]',  description: 'Optional array of { username, publicKey } for authorized recipients.', required: false },
        ]} />
        <Returns type="SignContainer" description="Signed container ready to distribute." />
        <CodeBlock code={encryptExample} />

        <MethodSignature signature="decrypt_container(container, petitioner_userName, petitioner_privateKey, owner_publicKey): Uint8Array" />
        <P>
          Verifies the Ed25519 signature and owner fingerprint, locates the petitioner's key wrap,
          performs ECDH → HKDF → XChaCha20 unwrap to recover the symmetric key, then decrypts
          the ciphertext. The owner can decrypt using their username and private key without
          being in the recipients list.
        </P>
        <ParamTable params={[
          { name: 'container',             type: 'SignContainer', description: 'Container produced by create_container.' },
          { name: 'petitioner_userName',   type: 'string',        description: 'Username of the person requesting decryption (owner or recipient).' },
          { name: 'petitioner_privateKey', type: 'Uint8Array',    description: 'Ed25519 private key of the petitioner (32 bytes).' },
          { name: 'owner_publicKey',       type: 'Uint8Array',    description: 'Ed25519 public key of the container owner, used to verify the signature.' },
        ]} />
        <Returns type="Uint8Array" description="Original file bytes if signature and authentication pass." />
        <Throws description='"Firma no valida" if the signature or fingerprint check fails. "Recipient not found in metadata" if the username has no key wrap entry.' />
        <CodeBlock code={decryptExample} />

        <MethodSignature signature="add_recipients_to_container(container, owner_publicKey, owner_privateKey, recipientsInfo): SignContainer" />
        <P>
          Validates the existing signature, recovers the symmetric key from the{' '}
          <Code>ownerWrap</Code>, wraps it for each new recipient via ECIES-style, and
          re-signs the container. Skips usernames already present in the recipient list.
        </P>
        <ParamTable params={[
          { name: 'container',      type: 'SignContainer', description: 'Original signed container.' },
          { name: 'owner_publicKey',  type: 'Uint8Array',  description: 'Owner public key to verify current signature.' },
          { name: 'owner_privateKey', type: 'Uint8Array',  description: 'Owner private key to unwrap symmetric key and re-sign.' },
          { name: 'recipientsInfo',   type: 'UserInfo[]',  description: 'Array of { username, publicKey } to add.' },
        ]} />
        <Returns type="SignContainer" description="New container with updated recipient list and fresh signature." />
        <Throws description='"Firma no válida" if the container signature does not match. "No se puedieron actualizar las llaves" if any cryptographic operation fails.' />
        <CodeBlock code={addExample} />

        <MethodSignature signature="remove_recipients_from_container(container, owner_publicKey, owner_privateKey, usernamesToRemove): SignContainer" />
        <P>
          Validates the signature, filters out the specified usernames from{' '}
          <Code>metaData.recipients</Code>, and re-signs. No cryptographic unwrap needed —
          removal is just a list filter followed by re-signing.
        </P>
        <ParamTable params={[
          { name: 'container',        type: 'SignContainer', description: 'Original signed container.' },
          { name: 'owner_publicKey',  type: 'Uint8Array',   description: 'Owner public key to verify current signature.' },
          { name: 'owner_privateKey', type: 'Uint8Array',   description: 'Owner private key to re-sign.' },
          { name: 'usernamesToRemove', type: 'string[]',    description: 'Usernames to remove from the recipient list.' },
        ]} />
        <Returns type="SignContainer" description="New container with reduced recipient list and fresh signature." />
        <Throws description='"Firma no válida" if signature check fails. "No se pudo remover a los usuarios" if re-signing fails.' />
        <CodeBlock code={removeExample} />

        <MethodSignature signature="validate_container_signature(container, owner_publicKey): boolean" />
        <P>
          Verifies the Ed25519 signature and owner fingerprint without decrypting. First checks
          that <Code>SHA-256(owner_publicKey)</Code> matches the <Code>owner_fingerprint</Code>{' '}
          in the metadata (preventing identity substitution), then verifies the Ed25519 signature
          over the canonical payload.
        </P>
        <ParamTable params={[
          { name: 'container',       type: 'SignContainer', description: 'Container to verify.' },
          { name: 'owner_publicKey', type: 'Uint8Array',   description: 'Expected owner public key.' },
        ]} />
        <Returns type="boolean" description="true if fingerprint matches and signature is valid, false otherwise." />

        <MethodSignature signature="verify_container_structure(container: object): boolean" />
        <P>
          Validates structural schema with <Code>zod</Code> without performing any cryptographic
          operations. Call this before <Code>validate_container_signature</Code> when processing
          untrusted JSON input.
        </P>
        <Returns type="boolean" description="true if the object matches the SignContainer schema, false otherwise." />
      </Section>

      {/* ── 4. Demo ── */}
      <Section id="demo" title="Demo">
        <D5Demo />
      </Section>
    </div>
  )
}