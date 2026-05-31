import {
  PageHeader, Section, SubHeading, P, Code, CodeBlock,
  Callout, ParamTable, Returns, Throws, MethodSignature,
} from '../../components/DocPrimitives';
import D2Demo from './D2Demo';


// ── Code snippets ──────────────────────────────────────
const encryptExample = `import { SymmetricEncryption } from 'd2'

const enc = new SymmetricEncryption()

const { container, symmetricKey } = enc.encrypt_file({
  data: new TextEncoder().encode('Secret document content'),
  filename: 'report.txt',
  file_type: 'text/plain',
})

// container → persist / send to recipient
// symmetricKey → wrap with recipient's public key (D3)`

const decryptExample = `import { SymmetricEncryption, b64ToBytes } from 'd2'

const enc = new SymmetricEncryption()

// Restore key from bytes (typically unwrapped from D3)
const plaintext = enc.decrypt_file(container, symmetricKey)

console.log(new TextDecoder().decode(plaintext))
// → 'Secret document content'`

const containerSchema = `{
  "metaData": {
    "filename":   string,        // original file name
    "file_type":  string,        // MIME type
    "timestamp":  string,        // ISO 8601 (UTC)
    "encryption": "Symmetric",
    "parameters": {
      "cipher":           "XChacha20+Poly1305",
      "key_size_bits":    256,
      "nonce_size_bytes": 24,
      "tag_size_bytes":   16
    },
    "nonce": string              // Base64-encoded 192-bit nonce (AAD)
  },
  "cipherText_w_tag": string     // Base64-encoded ciphertext + Poly1305 tag
}`

const utilExample = `import { bytesToB64, b64ToBytes } from 'd2'

const key   = crypto.getRandomValues(new Uint8Array(32))
const b64   = bytesToB64(key)    // → "aBcD…"
const back  = b64ToBytes(b64)    // → Uint8Array(32)`

export default function D2Page() {
  return (
    <div>
      <PageHeader
        badge="D2 — Symmetric Encryption"
        title="Symmetric Encryption Module"
        subtitle="Authenticated encryption for files using XChaCha20-Poly1305 (AEAD). Provides confidentiality, integrity, and tamper detection with a single 256-bit key."
      />

      {/* ── 1. Module Overview ── */}
      <Section id="overview" title="Module Overview">
        <P>
          Every file is encrypted with a freshly generated 256 bit symmetric key using <Code>XChaCha20-Poly1305</Code>, an Authenticated Encryption with Associated Data (AEAD)
          scheme that simultaneously guarantees confidentiality and integrity.
        </P>

        <SubHeading>XChaCha20</SubHeading>
        <P>
          XChaCha20 is a 256-bit stream cipher designed by Daniel J. Bernstein as an extension of
          ChaCha20. Its key advantage over AES is consistent software performance without requiring
          hardware acceleration, making it ideal for environments like browsers and mobile devices.
          The "X" variant extends the nonce from 96 bits to <strong>192 bits</strong>, making random
          nonce generation safe for virtually unlimited messages under the same key.
        </P>

        <SubHeading>Poly1305</SubHeading>
        <P>
          Poly1305 is a one-time Message Authentication Code (MAC) that produces a
          <strong> 128-bit authentication tag</strong>. When combined with XChaCha20, it creates the
          <Code>XChaCha20-Poly1305</Code> AEAD construction: the MAC covers both the ciphertext and
          the Additional Authenticated Data (AAD), so any modification to either will cause
          decryption to fail.
        </P>

        <SubHeading>Why AEAD over encryption + hash?</SubHeading>
        <P>
          A separate hash does not provide <em>authenticated</em> integrity — an attacker who can
          modify the ciphertext can also recompute the hash. AEAD binds the authentication tag
          cryptographically to the key and ciphertext, detecting both accidental corruption and deliberate tampering.
        </P>

        <Callout kind="info">
          The module uses <Code>@noble/ciphers</Code> for the XChaCha20-Poly1305 primitive and{' '}
          <Code>fast-json-stable-stringify</Code> for deterministic AAD serialization, ensuring the
          same metadata object always produces the same byte sequence regardless of key insertion order.
        </Callout>

        <SubHeading>Nonce strategy</SubHeading>
        <P>
          Every call to <Code>encrypt_file</Code> generates a fresh 192-bit nonce from a
          Cryptographically Secure Pseudo-Random Number Generator (CSPRNG). Nonce reuse would allow
          an attacker to XOR two ciphertexts and recover plaintext information — the 192-bit space
          makes random collisions negligible even at scale.
        </P>

      </Section>

      {/* ── 2. Container Structure ── */}
      <Section id="container" title="Container Structure">
        <P>
          The output of <Code>encrypt_file</Code> is a <Code>Container</Code> object — a
          self-describing JSON structure that carries everything needed to decrypt the file
          <em> except</em> the symmetric key. The metadata fields are included verbatim as AAD and
          are cryptographically bound to the ciphertext: any post-encryption modification will
          invalidate the Poly1305 tag and abort decryption.
        </P>

        <CodeBlock code={containerSchema} lang="json" />

        <SubHeading>metaData as AAD</SubHeading>
        <P>
          Before encryption, <Code>metaData</Code> is serialized with <Code>fast-json-stable-stringify</Code>
          (keys sorted lexicographically) and encoded as UTF-8. This canonical byte sequence is
          passed as the AAD argument to the cipher. During decryption the same serialization is
          recomputed, so any field alteration — including a reordered key — causes tag verification
          to fail.
        </P>

        <SubHeading>cipherText_w_tag layout</SubHeading>
        <P>
          The Base64-decoded value is the concatenation of{' '}
          <Code>ciphertext ‖ poly1305_tag</Code>. The last 16 bytes are always the authentication
          tag. The cipher library handles splitting internally during decryption.
        </P>
      </Section>

      {/* ── 3. API Reference ── */}
      <Section id="api" title="API Reference">

        {/* encrypt_file */}
        <SubHeading>SymmetricEncryption</SubHeading>
        <P>Main class. Stateless — a single instance can be reused across multiple operations.</P>

        <MethodSignature signature="encrypt_file(cipherObject: CipherObject): { container: Container; symmetricKey: Uint8Array }" />
        <P>
          Encrypts a file using XChaCha20-Poly1305. Generates a random 256-bit key and a random
          192-bit nonce internally. Metadata is assembled and used as AAD before encryption.
        </P>
        <ParamTable params={[
          { name: 'cipherObject.data',      type: 'Uint8Array', description: 'Raw bytes of the file to encrypt.' },
          { name: 'cipherObject.filename',  type: 'string',     description: 'Original filename, included in metadata and protected by AAD.' },
          { name: 'cipherObject.file_type', type: 'string',     description: 'MIME type (e.g. "application/pdf"), included in metadata and protected by AAD.' },
        ]} />
        <Returns
          type="{ container: Container; symmetricKey: Uint8Array }"
          description="The encrypted container (safe to store/send) and the 32-byte symmetric key."
        />
        <CodeBlock code={encryptExample} />

        {/* decrypt_file */}
        <MethodSignature signature="decrypt_file(container: Container, symmetricKey: Uint8Array): Uint8Array" />
        <P>
          Decrypts a container produced by <Code>encrypt_file</Code>. Reconstructs AAD from
          the container's metadata using the same deterministic serialization, then verifies
          the Poly1305 tag before returning plaintext.
        </P>
        <ParamTable params={[
          { name: 'container',    type: 'Container',   description: 'Container object produced by encrypt_file.' },
          { name: 'symmetricKey', type: 'Uint8Array',  description: '32-byte key originally returned by encrypt_file.' },
        ]} />
        <Returns type="Uint8Array" description="The original file bytes if tag verification passes." />
        <Throws description="Throws an Error if the key is incorrect, the ciphertext has been modified, or any metadata field has been altered." />
        <CodeBlock code={decryptExample} />

        {/* verify_container_structure */}
        <MethodSignature signature="verify_container_structure(container: object): boolean" />
        <P>
          Validates the shape of an untrusted object against the expected{' '}
          <Code>Container</Code> schema using <Code>zod</Code>. Use before attempting decryption
          on externally received data.
        </P>
        <ParamTable params={[
          { name: 'container', type: 'object', description: 'Any object to validate.' },
        ]} />
        <Returns type="boolean" description="true if the object matches the Container schema, false otherwise." />

        {/* Utilities */}
        <SubHeading>Utility functions</SubHeading>

        <MethodSignature signature="bytesToB64(bytes: Uint8Array): string" />
        <P>Encodes a byte array to a Base64 string.</P>

        <MethodSignature signature="b64ToBytes(b64: string): Uint8Array" />
        <P>Decodes a Base64 string back to a byte array.</P>

        <CodeBlock code={utilExample} />
      </Section>

      {/* ── 4. Demo ── */}
      <Section id="demo" title="Demo">
        <D2Demo />
      </Section>
    </div>
  )
}
