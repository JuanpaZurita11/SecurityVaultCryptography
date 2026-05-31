import {
  PageHeader, Section, SubHeading, P, Code, CodeBlock,
  Callout, ParamTable, Returns, Throws, MethodSignature,
  JsonSchema,
} from '../../components/DocPrimitives'
import D3Demo from './D3Demo'

// ── Code snippets ──────────────────────────────────────
const keygenExample = `import { KeyManager } from 'd3'

const km = new KeyManager()

// Generate RSA-2048 key pair
const { publicKey, privateKey } = await km.generate_key_pair()

// Export to PEM for storage or transfer
const publicPem  = await km.exportPublicKey(publicKey)
const privatePem = await km.exportPrivateKey(privateKey)

// Import back from PEM
const importedPub  = await km.importPublicKey(publicPem)
const importedPriv = await km.importPrivateKey(privatePem)`

const example = `import { HybridEncryption, KeyManager } from 'd3'

const enc = new HybridEncryption()
const km  = new KeyManager()

const alice = await km.generate_key_pair()
const bob   = await km.generate_key_pair()

const container = await enc.encrypt_file({
  data:       new TextEncoder().encode('Secret document'),
  filename:   'document.txt',
  file_type:  'text/plain',
  recipients: [
    { username: 'alice', publicKey: alice.publicKey },
    { username: 'bob',   publicKey: bob.publicKey },
  ],
})

const decryptedByAlice = await enc.decrypt_file(container, 'alice', alice.privateKey);
const decryptedByBob   = await enc.decrypt_file(container, 'bob', bob.privateKey);

console.log(new TextDecoder().decode(decryptedByAlice));

// decryptedByAlice === decryptedByBob -> true`


const containerSchema = `{
  "metaData": {
    "filename":   string,          // original file name
    "file_type":  string,          // MIME type
    "timestamp":  string,          // ISO 8601 (UTC)
    "encryption": "Hybrid",
    "symmetric": {
      "cipher":           "XChacha20-Poly1305",
      "key_size_bits":    256,
      "nonce_size_bytes": 24,
      "tag_size_bytes":   16
    },
    "asymmetric": {
      "cipher":           "RSA-OAEP",
      "key_size_bits":    2048,
      "public_exponent":  65537,
      "hash":             "SHA-256",
      "mgf":              "MGF1-SHA256"
    },
    "nonce":      string,          // Base64-encoded 192-bit nonce (AAD)
    "recipients": [                // one entry per authorized recipient
      {
        "username":   string,      // unique recipient identifier
        "wrappedKey": string       // Base64-encoded RSA-OAEP(file_key)
      }
    ]
  },
  "cipherText_w_tag": string       // Base64-encoded ciphertext + Poly1305 tag
}`

export default function D3Page() {
  return (
    <div>
      <PageHeader
        badge="D3 — Hybrid Encryption"
        title="Hybrid Encryption Module"
        subtitle="Multi-recipient secure file sharing using XChaCha20-Poly1305 for file encryption and RSA-OAEP for per-recipient key wrapping."
      />

      {/* ── 1. System Overview ── */}
      <Section id="overview" title="Module Overview">
        <P>
          D3 extends D2 by solving the <strong>key distribution problem</strong>: how to share an
          encrypted file with multiple recipients without encrypting it multiple times. The solution
          is <em>hybrid encryption</em> — the file is encrypted once with a fast symmetric key,
          and that key is wrapped individually for each recipient using their RSA public key.
        </P>

        <SubHeading>Why hybrid encryption?</SubHeading>
        <P>
          Pure asymmetric encryption (RSA-OAEP) is limited to small payloads — roughly 190 bytes
          for RSA-2048. Pure symmetric encryption requires a secure channel to distribute the key.
          Hybrid encryption combines both: <Code>XChaCha20-Poly1305</Code> handles the file
          (any size, very fast), while <Code>RSA-OAEP</Code> securely wraps the small symmetric
          key for each recipient independently.
        </P>

        <SubHeading>Encryption flow</SubHeading>
        <P>
          <strong>1.</strong> A random 256-bit <em>file key</em> and 192-bit nonce are generated.<br />
          <strong>2.</strong> The file is encrypted once with <Code>XChaCha20-Poly1305</Code>, including recipient list in the AAD.<br />
          <strong>3.</strong> The file key is wrapped with each recipient's RSA-2048 public key via <Code>RSA-OAEP</Code>, producing one <Code>wrappedKey</Code> per recipient.<br />
          <strong>4.</strong> Everything is packed into a single <Code>Container</Code>.
        </P>

        <SubHeading>Decryption flow</SubHeading>
        <P>
          <strong>1.</strong> The interested in decryption locates their entry in <Code>metaData.recipients</Code> by username.<br />
          <strong>2.</strong> Their RSA private key unwraps the file key via <Code>RSA-OAEP</Code>.<br />
          <strong>3.</strong> <Code>XChaCha20-Poly1305</Code> decrypts and authenticates the file — same as D2, but with the recipient list included in the AAD, binding authorized access to the ciphertext.
        </P>

        <Callout kind="info">
          The recipient list is part of the AAD. Any modification — adding, removing, or reordering
          recipients — invalidates the Poly1305 tag and makes decryption impossible.
        </Callout>

        <Callout kind="danger">
          Recipient usernames must be unique and deterministic. The decryption lookup is an exact
          string match on <Code>username</Code> — a mismatch means the wrapped key is never found.
        </Callout>
      </Section>

      {/* ── 2. Container Structure ── */}
      <Section id="container" title="Container Structure">
        <P>
          The container produced by <Code>encrypt_file</Code> is a self-describing JSON object.
          The <Code>metaData</Code> block is serialized with <Code>fast-json-stable-stringify</Code> and used verbatim as AAD, so any post-encryption modification breaks authentication.
        </P>

        <JsonSchema schema={containerSchema}/>

        <SubHeading>KeyWrap entries</SubHeading>
        <P>
          Each entry in <Code>metaData.recipients</Code> stores the file key encrypted with
          one recipient's RSA-2048 public key. The <Code>wrappedKey</Code> is
          Base64-encoded and is typically 256 bytes (2048-bit RSA output).
          Unauthorized users who lack the corresponding private key cannot unwrap it.
        </P>
      </Section>

      {/* ── 3. API Reference ── */}
      <Section id="api" title="API Reference">

        {/* KeyManager */}
        <SubHeading>KeyManager</SubHeading>
        <P>
          Handles RSA-2048 key generation, export and import using the browser's <Code>SubtleCrypto</Code> API. Keys are represented as opaque <Code>CryptoKey</Code> objects and serialized in SPKI/PKCS#8 PEM format (RFC 5958).
        </P>

        <MethodSignature signature="generate_key_pair(): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }>" />
        <P>Generates a fresh RSA-OAEP 2048-bit key pair. Fixed parameters: SHA-256 hash, public exponent 65537.</P>
        <Returns type="Promise<{ publicKey, privateKey }>" description="Web Crypto CryptoKey objects. publicKey for encryption, privateKey for decryption." />

        <MethodSignature signature="exportPublicKey(publicCryptoKey: CryptoKey): Promise<string>" />
        <P>Exports a public key to SPKI PEM format (<Code>-----BEGIN PUBLIC KEY-----</Code>).</P>
        <ParamTable params={[{ name: 'publicCryptoKey', type: 'CryptoKey', description: 'Public key generated by generate_key_pair().' }]} />
        <Returns type="Promise<string>" description="SPKI PEM string, compatible with OpenSSL and standard tooling." />

        <MethodSignature signature="exportPrivateKey(privateCryptoKey: CryptoKey): Promise<string>" />
        <P>Exports a private key to PKCS#8 PEM format (<Code>-----BEGIN PRIVATE KEY-----</Code>).</P>
        <ParamTable params={[{ name: 'privateCryptoKey', type: 'CryptoKey', description: 'Private key generated by generate_key_pair().' }]} />
        <Returns type="Promise<string>" description="PKCS#8 PEM string." />

        <MethodSignature signature="importPublicKey(pem: string): Promise<CryptoKey>" />
        <P>Imports a public key from SPKI PEM. Validates header/footer before importing.</P>
        <Throws description='Throws Error if the PEM does not contain "-----BEGIN PUBLIC KEY-----".' />

        <MethodSignature signature="importPrivateKey(pem: string): Promise<CryptoKey>" />
        <P>Imports a private key from PKCS#8 PEM. Validates header/footer before importing.</P>
        <Throws description='Throws Error if the PEM does not contain "-----BEGIN PRIVATE KEY-----".' />

        <CodeBlock code={keygenExample} />

        {/* HybridEncryption */}
        <SubHeading>HybridEncryption</SubHeading>
        <P>Main encryption/decryption class. All methods are async because RSA operations use <Code>SubtleCrypto</Code>.</P>

        <MethodSignature signature="encrypt_file(cipherObject: CipherObject): Promise<Container>" />
        <P>
          Encrypts a file for one or more recipients. Generates a random file key and nonce,
          encrypts the file with <Code>XChaCha20-Poly1305</Code>, and wraps the file key with
          each recipient's RSA public key.
        </P>
        <ParamTable params={[
          { name: 'cipherObject.data',       type: 'Uint8Array',  description: 'Raw bytes of the file to encrypt.' },
          { name: 'cipherObject.filename',   type: 'string',      description: 'Original filename, included in metadata and protected by AAD.' },
          { name: 'cipherObject.file_type',  type: 'string',      description: 'MIME type, included in metadata and protected by AAD.' },
          { name: 'cipherObject.recipients', type: 'UserInfo[]',  description: 'Array of { username, publicKey } for each authorized recipient. Must not be empty.' },
        ]} />
        <Returns type="Promise<Container>" description="Encrypted container with ciphertext and per-recipient wrapped keys." />
        <Throws description="Throws Error if recipients array is empty." />

        <MethodSignature signature="decrypt_file(container, recipientUsername, recipientPrivateKey): Promise<Uint8Array>" />
        <P>
          Decrypts a container for a specific recipient. Locates the recipient's wrapped key by
          username, unwraps the file key with RSA-OAEP, then decrypts and authenticates the
          ciphertext with <Code>XChaCha20-Poly1305</Code>.
        </P>
        <ParamTable params={[
          { name: 'container',            type: 'Container',  description: 'Container produced by encrypt_file.' },
          { name: 'recipientUsername',    type: 'string',     description: 'Exact username used during encryption.' },
          { name: 'recipientPrivateKey',  type: 'CryptoKey',  description: 'RSA private key corresponding to the public key used for this recipient.' },
        ]} />
        <Returns type="Promise<Uint8Array>" description="Original file bytes if authentication passes." />
        <Throws description='Throws "Invalid container structure" if the object does not match the expected schema. Throws "Recipient not found in metadata" if the username is not in the container. Throws a cryptographic error if the private key is wrong or metadata was tampered.' />

        <CodeBlock code={example} />

        <MethodSignature signature="verify_container_structure(container: object): boolean" />
        <P>
          Validates an untrusted object against the expected <Code>Container</Code> schema using
          {' '}<Code>zod</Code>. Checks that all required fields are present with the correct types and that{' '}
          <Code>recipients</Code> has at least one entry. Called internally by{' '}
          <Code>decrypt_file</Code> before any cryptographic operation.
        </P>
        <ParamTable params={[
          { name: 'container', type: 'object', description: 'Any object to validate — typically a JSON.parse() result from an untrusted source.' },
        ]} />
        <Returns type="boolean" description="true if the object matches the Container schema, false otherwise." />
      </Section>

      {/* ── 4. Demo ── */}
      <Section id="demo" title="Demo">
        <D3Demo />
      </Section>
    </div>
  )
}