import React from 'react'
import { useNavigate } from 'react-router-dom'

// ── Shared styles ──────────────────────────────────────
const mono: React.CSSProperties = { fontFamily: 'var(--font-mono)' }

const sectionTitle = (mb = '1rem'): React.CSSProperties => ({
  fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)',
  borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem', marginBottom: mb,
})

const modules = [
  {
    path: '/d2', id: 'D2',
    title: 'Symmetric Encryption',
    description: 'File encryption using XChaCha20-Poly1305. Generates a unique 256-bit key per file with a 192-bit random nonce.',
    tags: ['XChaCha20-Poly1305', 'AEAD'],
  },
  {
    path: '/d3', id: 'D3',
    title: 'Hybrid Encryption',
    description: 'Per-recipient key wrapping with RSA-OAEP. The file is encrypted once; only the symmetric key is wrapped for each authorized recipient.',
    tags: ['RSA-OAEP', 'Key Wrapping', 'Multi-recipient'],
  },
  {
    path: '/d5', id: 'D5',
    title: 'Authenticated Cipher',
    description: 'Ed25519 digital signatures + ECIES-style key encapsulation over X25519. Signature verification is enforced before any decryption.',
    tags: ['Ed25519', 'ECIES', 'X25519'],
  },
  {
    path: '/d6', id: 'D6',
    title: 'Key Management',
    description: 'PBKDF2-SHA256 password-based key derivation for private key protection at rest. Full key lifecycle: generation, password update, rotation, and recipient re-keying.',
    tags: ['PBKDF2', 'KeyStorage', 'Key Rotation'],
  },
]

const securityProps = [
  { property: 'Confidentiality',                  mechanism: 'XChaCha20-Poly1305 AEAD',         where: 'D2 / D3 / D5' },
  { property: 'Integrity',                        mechanism: 'Poly1305 authentication tag',      where: 'D2 / D3 / D5' },
  { property: 'Authenticity',                     mechanism: 'Ed25519 digital signature',        where: 'D5' },
  { property: 'Access control',                   mechanism: 'Per-recipient ECIES key wrap',     where: 'D3 / D5 / D6' },
  { property: 'Key protection at rest',           mechanism: 'PBKDF2 + XChaCha20-Poly1305',     where: 'D6' },
  { property: 'Metadata tamper-detection',        mechanism: 'AAD in AEAD',                     where: 'D2 / D3 / D5' },
  { property: 'Recipient list tamper-detection',  mechanism: 'AAD + signed container',          where: 'D3 / D5 / D6' },
  { property: 'Canonicalization',                 mechanism: 'fast-json-stable-stringify',       where: 'D2 / D3 / D5 / D6' },
]



export default function HomePage() {
  const navigate = useNavigate()

  return (
    <div>
      {/* ── Hero ── */}
      <div style={{ marginBottom: '3rem', paddingBottom: '2.5rem', borderBottom: '1px solid var(--border)' }}>
        <span style={{
          display: 'inline-block', ...mono, fontSize: '0.68rem', fontWeight: 600,
          background: 'var(--tag-bg)', color: 'var(--tag-text)',
          padding: '3px 10px', borderRadius: '4px', marginBottom: '0.85rem', letterSpacing: '0.04em',
        }}>
          Facultad de Ingeniería, UNAM - Criptografía - 2026
        </span>
        <h1 style={{
          fontSize: '2rem', fontWeight: 600, letterSpacing: '-0.035em',
          color: 'var(--text-primary)', marginBottom: '0.6rem', lineHeight: 1.15,
          fontFamily: 'var(--font-sans)',
        }}>
          Secure Digital Document Vault
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.975rem', maxWidth: '600px', lineHeight: 1.75, marginBottom: '1.25rem' }}>
          Secure Digital Document Vault is a cryptographic system for protecting, sharing, and verifying digital documents. Every encrypted file is packaged into a self-contained, self-protecting container — it carries its own encryption parameters, recipient access list, and digital signature. No external metadata is needed to verify or decrypt it.
          The system is built around a simple principle: keys and ciphertext are always separate. An attacker who obtains the encrypted file gains nothing without the corresponding private key, and vice versa. Identity is anchored by digital signatures — not by trust in the storage layer.
        </p>
      </div>

      {/* ── Project Evolution ── */}
      <div style={{ marginBottom: '2.5rem' }}>
        <h2 style={sectionTitle()}>Project Evolution</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.925rem', marginBottom: '1.25rem' }}>
          Each module is a complete, working iteration of the vault. Every delivery extends the previous one by solving a new security problem.
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0' }}>
          {([
            {
              id: 'D2', color: '#34d399',
              title: 'Symmetric Encryption',
              points: [
                { type: 'add', text: 'Confidentiality + Integrity: Authenticated encryption with Associated Data via XChaCha20-Poly1305 ' }
              ],
            },
            {
              id: 'D3', color: '#60a5fa',
              title: 'Hybrid Encryption',
              points: [
                { type: 'problem', text: 'D2 sharing with multiple users required sending the raw symmetric key or encrypting the file multiple times.' },
                { type: 'add', text: 'The file is encrypted exactly once; the symmetric key is wrapped per recipient with RSA-OAEP.' },
                { type: 'add', text: 'Recipient list is part of the AAD — adding, removing or reordering recipients invalidates the ciphertext tag.' },
              ],
            },
            {
              id: 'D5', color: '#c084fc',
              title: 'Authenticated Cipher',
              points: [
                { type: 'problem', text: 'D3 had no way to verify who created the container.' },
                { type: 'problem', text: 'Modifying the recipient list required full re-encryption because it was bound to the AEAD AAD.' },
                { type: 'add', text: 'Ed25519 digital signatures — authenticity and non-repudiation before any decryption.' },
                { type: 'add', text: 'RSA-OAEP replaced by ECIES/X25519 — the same Ed25519 key pair is used for both signing and encryption.' },
                { type: 'add', text: 'Recipient list moved to the signature layer — owner can add/remove recipients without re-encrypting the file, only re-signing it.' },
                { type: 'add', text: "Owner fingerprint (SHA-256 of public key) embedded in AAD — impersonation is detectable even if an attacker re-signs." },
              ],
            },
            {
              id: 'D6', color: '#fbbf24',
              title: 'Key Management',
              points: [
                { type: 'problem', text: 'D5 exposed private key — no protection if the key file was stolen.' },
                { type: 'add', text: 'Private keys encrypted at rest with PBKDF2-SHA256 (524,288 iterations) + XChaCha20-Poly1305.' },
                { type: 'add', text: 'Poly1305 used to detect tampering with KeyStorage metadata.' },
                { type: 'add', text: 'Key rotation: generates a new key pair — affected containers are detectable via signature validation.' },
                { type: 'add', text: "Recipient re-keying: owner re-wraps the symmetric key for a recipient's new public key without re-encrypting the file."},
              ],
            },
          ] as { id: string; color: string; title: string; points: { type: string; text: string }[] }[]).map((item, i, arr) => (
            <div key={item.id} style={{ display: 'flex', gap: '0', alignItems: 'stretch' }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '40px', flexShrink: 0 }}>
                <div style={{
                  width: '28px', height: '28px', borderRadius: '50%', flexShrink: 0,
                  background: item.color, display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontFamily: 'var(--font-mono)', fontSize: '0.65rem', fontWeight: 700, color: '#0f1117', zIndex: 1,
                  marginTop: '1.1rem',
                }}>
                  {item.id}
                </div>
                {i < arr.length - 1 && (
                  <div style={{ width: '2px', flex: 1, background: 'var(--border)', marginTop: '4px' }} />
                )}
              </div>
              <div style={{
                flex: 1, marginLeft: '1rem', marginBottom: i < arr.length - 1 ? '0.75rem' : 0,
                background: 'var(--bg-card)', border: '1px solid var(--border)',
                borderRadius: '8px', padding: '1rem 1.1rem',
              }}>
                <span style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '0.6rem' }}>{item.title}</span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                  {item.points.map((p, pi) => (
                    <div key={pi} style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start', fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                      <span style={{ color: p.type === 'add' ? '#4ade80' : '#f87171', flexShrink: 0, marginTop: '1px' }}>
                        {p.type === 'add' ? '+' : '✕'}
                      </span>
                      <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-sans)', fontSize: '0.85rem', lineHeight: 1.6 }}>{p.text}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

            {/* ── Modules ── */}
      <div style={{ marginBottom: '2.5rem' }}>
        <h2 style={sectionTitle()}>Modules</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem' }}>
          {modules.map(m => (
            <div
              key={m.path}
              onClick={() => navigate(m.path)}
              style={{
                background: 'var(--bg-card)', border: '1px solid var(--border)',
                borderRadius: '10px', padding: '1.25rem', cursor: 'pointer', transition: 'all 0.15s',
              }}
              onMouseEnter={e => { const el = e.currentTarget as HTMLDivElement; el.style.borderColor = 'var(--accent)'; el.style.boxShadow = '0 2px 12px rgba(26,86,219,0.08)' }}
              onMouseLeave={e => { const el = e.currentTarget as HTMLDivElement; el.style.borderColor = 'var(--border)'; el.style.boxShadow = 'none' }}
            >
              <div style={{ ...mono, fontSize: '0.68rem', fontWeight: 600, color: 'var(--accent)', marginBottom: '0.5rem', letterSpacing: '0.04em' }}>
                {m.id}
              </div>
              <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.4rem' }}>
                {m.title}
              </div>
              <p style={{ fontSize: '0.83rem', color: 'var(--text-muted)', marginBottom: '0.85rem', lineHeight: 1.65 }}>
                {m.description}
              </p>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                {m.tags.map(t => (
                  <span key={t} style={{ ...mono, fontSize: '0.62rem', background: 'var(--tag-bg)', color: 'var(--tag-text)', padding: '2px 7px', borderRadius: '4px', fontWeight: 500 }}>
                    {t}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Security Properties ── */}
      <div style={{ marginBottom: '2.5rem' }}>
        <h2 style={sectionTitle()}>Security Properties</h2>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-sidebar)' }}>
                {['Property', 'Mechanism', 'Where enforced'].map(h => (
                  <th key={h} style={{ padding: '0.5rem 0.9rem', textAlign: 'left', fontWeight: 600, fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)', border: '1px solid var(--border)', ...mono }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {securityProps.map(r => (
                <tr key={r.property}>
                  <td style={{ padding: '0.55rem 0.9rem', border: '1px solid var(--border-light)', color: 'var(--text-primary)', fontWeight: 500, fontSize: '0.85rem' }}>{r.property}</td>
                  <td style={{ padding: '0.55rem 0.9rem', border: '1px solid var(--border-light)', ...mono, fontSize: '0.78rem', color: 'var(--accent)' }}>{r.mechanism}</td>
                  <td style={{ padding: '0.55rem 0.9rem', border: '1px solid var(--border-light)', ...mono, fontSize: '0.78rem', color: 'var(--text-muted)' }}>{r.where}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>


      {/* ── Threat Model ── */}
      <div>
        <h2 style={sectionTitle()}>Threat Model</h2>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-sidebar)' }}>
                {['Adversary', 'Capability', 'System response'].map(h => (
                  <th key={h} style={{ padding: '0.5rem 0.9rem', textAlign: 'left', fontWeight: 600, fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)', border: '1px solid var(--border)', ...mono }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                { who: 'Attacker with storage access',   can: 'Reads encrypted containers',              response: 'Ciphertext is useless without private key' },
                { who: 'Attacker with stolen container', can: 'Modifies metadata or recipient list',     response: 'Poly1305 tag or Ed25519 signature fails' },
                { who: 'Attacker with stolen KeyStore',  can: 'Tries to extract private key',            response: 'Blocked by PBKDF2 and XChaCha20-Poly1305 — requires passphrase' },
                { who: 'Unauthorized recipient',         can: 'Tries to decrypt',                        response: 'No valid wrappedKey entry → decryption impossible' },
                { who: 'Impersonator',                   can: 'Crafts a fake container',                 response: "Signature fails without owner's private key" },
              ].map(r => (
                <tr key={r.who}>
                  <td style={{ padding: '0.55rem 0.9rem', border: '1px solid var(--border-light)', color: 'var(--text-primary)', fontWeight: 500, fontSize: '0.85rem' }}>{r.who}</td>
                  <td style={{ padding: '0.55rem 0.9rem', border: '1px solid var(--border-light)', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>{r.can}</td>
                  <td style={{ padding: '0.55rem 0.9rem', border: '1px solid var(--border-light)', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>{r.response}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}