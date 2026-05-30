import { useNavigate } from 'react-router-dom'

const modules = [
  {
    path: '/d2',
    id: 'D2',
    title: 'Symmetric Encryption',
    description: 'File encryption using XChaCha20-Poly1305 AEAD. Generates a unique 256-bit key per file with a 192-bit random nonce.',
    tags: ['XChaCha20', 'Poly1305', 'AEAD'],
  },
  {
    path: '/d3',
    id: 'D3',
    title: 'Hybrid Encryption',
    description: 'Key wrapping with RSA-OAEP. Allows the symmetric file key to be securely shared with one or more recipients.',
    tags: ['RSA-OAEP', 'Key Wrapping', 'Multi-recipient'],
  },
  {
    path: '/d5',
    id: 'D5',
    title: 'Authenticated Cipher',
    description: 'Digital signatures layered on top of encryption. Guarantees authenticity and non-repudiation before any decryption occurs.',
    tags: ['ECDSA', 'Signatures', 'Integrity'],
  },
  {
    path: '/d6',
    id: 'D6',
    title: 'Key Management',
    description: 'Password-based key derivation (PBKDF2/Argon2) for protecting private keys at rest, plus backup and recovery.',
    tags: ['PBKDF2', 'Key Store', 'Recovery'],
  },
]

export default function HomePage() {
  const navigate = useNavigate()

  return (
    <div>
      {/* Hero */}
      <div style={{ marginBottom: '3rem', paddingBottom: '2.5rem', borderBottom: '1px solid var(--border)' }}>
        <span style={{
          display: 'inline-block',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.68rem',
          fontWeight: 600,
          background: 'var(--tag-bg)',
          color: 'var(--tag-text)',
          padding: '3px 10px',
          borderRadius: '4px',
          marginBottom: '0.85rem',
          letterSpacing: '0.04em',
        }}>
          Semester Project — Applied Cryptography
        </span>
        <h1 style={{
          fontSize: '2rem',
          fontWeight: 600,
          letterSpacing: '-0.035em',
          color: 'var(--text-primary)',
          marginBottom: '0.6rem',
          lineHeight: 1.15,
          fontFamily: 'var(--font-sans)',
        }}>
          Secure Digital Document Vault
        </h1>
        <p style={{
          color: 'var(--text-secondary)',
          fontSize: '0.975rem',
          maxWidth: '580px',
          lineHeight: 1.75,
        }}>
          A system for protecting, sharing, and verifying digital documents using modern
          applied cryptographic techniques. Built in TypeScript using the{' '}
          <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85em', color: 'var(--accent)' }}>@noble</code>
          {' '}cryptography library.
        </p>
      </div>

      {/* Architecture note */}
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{
          fontSize: '1rem',
          fontWeight: 600,
          color: 'var(--text-primary)',
          borderBottom: '1px solid var(--border)',
          paddingBottom: '0.5rem',
          marginBottom: '1rem',
        }}>
          System Architecture
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.925rem', marginBottom: '1rem' }}>
          Each module is a self-contained TypeScript library that corresponds to a specific layer
          of the vault's security model. They compose together in the following order:
        </p>
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '0.78rem',
          background: 'var(--bg-code)',
          color: '#8b9fc7',
          borderRadius: '8px',
          padding: '1rem 1.25rem',
          lineHeight: 2,
          border: '1px solid var(--border)',
        }}>
          <span style={{ color: '#6eddb0' }}>User</span>
          {' → '}
          <span style={{ color: '#93c5fd' }}>D2</span> (AEAD encrypt file)
          {' → '}
          <span style={{ color: '#93c5fd' }}>D3</span> (wrap key for recipients)
          {' → '}
          <span style={{ color: '#93c5fd' }}>D5</span> (sign container)
          {' → '}
          <span style={{ color: '#fcd34d' }}>D6</span> (protect private key at rest)
          {' → '}
          <span style={{ color: '#6eddb0' }}>Encrypted File Container</span>
        </div>
      </div>

      {/* Module cards */}
      <h2 style={{
        fontSize: '1rem',
        fontWeight: 600,
        color: 'var(--text-primary)',
        borderBottom: '1px solid var(--border)',
        paddingBottom: '0.5rem',
        marginBottom: '1.25rem',
      }}>
        Modules
      </h2>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '1rem' }}>
        {modules.map(m => (
          <div
            key={m.path}
            onClick={() => navigate(m.path)}
            style={{
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: '10px',
              padding: '1.25rem',
              cursor: 'pointer',
              transition: 'all 0.15s',
            }}
            onMouseEnter={e => {
              const el = e.currentTarget as HTMLDivElement
              el.style.borderColor = 'var(--accent)'
              el.style.boxShadow = '0 2px 12px rgba(26,86,219,0.08)'
            }}
            onMouseLeave={e => {
              const el = e.currentTarget as HTMLDivElement
              el.style.borderColor = 'var(--border)'
              el.style.boxShadow = 'none'
            }}
          >
            <div style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '0.68rem',
              fontWeight: 600,
              color: 'var(--accent)',
              marginBottom: '0.5rem',
              letterSpacing: '0.04em',
            }}>
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
                <span key={t} style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.62rem',
                  background: 'var(--tag-bg)',
                  color: 'var(--tag-text)',
                  padding: '2px 7px',
                  borderRadius: '4px',
                  fontWeight: 500,
                }}>
                  {t}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}