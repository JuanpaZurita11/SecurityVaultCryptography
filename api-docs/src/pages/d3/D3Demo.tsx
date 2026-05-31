import { useState, useRef, useEffect } from 'react'
import { HybridEncryption, KeyManager } from 'd3-crypto'

// ── Shared styles ──────────────────────────────────────
const mono: React.CSSProperties = { fontFamily: 'var(--font-mono)' }

const labelStyle: React.CSSProperties = {
  ...mono,
  display: 'block',
  fontSize: '0.68rem',
  fontWeight: 600,
  textTransform: 'uppercase' as const,
  letterSpacing: '0.09em',
  color: 'var(--text-muted)',
  marginBottom: '0.35rem',
}

const panel: React.CSSProperties = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  borderRadius: '10px',
  overflow: 'hidden',
}

const panelHeader: React.CSSProperties = {
  borderBottom: '1px solid var(--border)',
  padding: '0.75rem 1.25rem',
  display: 'flex',
  alignItems: 'center',
  gap: '0.5rem',
  background: 'var(--bg-sidebar)',
}

const panelBody: React.CSSProperties = { padding: '1.25rem' }

// ── Types ──────────────────────────────────────────────
interface GeneratedUser {
  username: string
  publicKeyPem: string
  privateKeyPem: string
  publicKey: CryptoKey
  privateKey: CryptoKey
}

// ── FileDropZone ───────────────────────────────────────
function FileDropZone({
  label: lbl, accept, file, onChange, disabled,
}: {
  label: string; accept?: string; file: File | null
  onChange: (f: File) => void; disabled?: boolean
}) {
  const ref = useRef<HTMLInputElement>(null)
  const [drag, setDrag] = useState(false)

  return (
    <div style={{ marginBottom: '1rem' }}>
      <span style={labelStyle}>{lbl}</span>
      <div
        onClick={() => !disabled && ref.current?.click()}
        onDragOver={e => { if (!disabled) { e.preventDefault(); setDrag(true) } }}
        onDragLeave={() => setDrag(false)}
        onDrop={e => {
          e.preventDefault(); setDrag(false)
          if (!disabled) { const f = e.dataTransfer.files[0]; if (f) onChange(f) }
        }}
        style={{
          border: `1.5px dashed ${drag ? 'var(--accent)' : file ? 'var(--border)' : 'var(--border-light)'}`,
          borderRadius: '8px', padding: '0.85rem 1rem',
          cursor: disabled ? 'default' : 'pointer',
          background: drag ? 'var(--accent-dim)' : file ? 'var(--bg-sidebar)' : 'transparent',
          transition: 'all 0.15s', display: 'flex', alignItems: 'center', gap: '0.65rem',
          opacity: disabled ? 0.5 : 1,
        }}
      >
        <span style={{ fontSize: '1rem', flexShrink: 0 }}>{file ? '📄' : '📂'}</span>
        <span style={{ fontSize: '0.85rem', color: file ? 'var(--text-primary)' : 'var(--text-muted)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {file ? file.name : 'Click or drag & drop'}
        </span>
        {file && (
          <span style={{ ...mono, marginLeft: 'auto', fontSize: '0.68rem', color: 'var(--text-muted)', flexShrink: 0 }}>
            {file.size < 1024 ? `${file.size} B` : `${(file.size / 1024).toFixed(1)} KB`}
          </span>
        )}
      </div>
      <input ref={ref} type="file" accept={accept} style={{ display: 'none' }}
        onChange={e => { const f = e.target.files?.[0]; if (f) onChange(f) }} />
    </div>
  )
}

// ── Btn ────────────────────────────────────────────────
function Btn({ onClick, disabled, loading, children, variant = 'primary' }: {
  onClick: () => void; disabled?: boolean; loading?: boolean
  children: React.ReactNode; variant?: 'primary' | 'ghost'
}) {
  const isPrimary = variant === 'primary'
  return (
    <button onClick={onClick} disabled={disabled || loading} style={{
      ...mono, padding: '0.5rem 1.25rem', borderRadius: '6px',
      fontSize: '0.78rem', fontWeight: 500,
      cursor: disabled || loading ? 'not-allowed' : 'pointer',
      border: isPrimary ? 'none' : '1px solid var(--border)',
      background: isPrimary ? (disabled || loading ? '#93c5fd' : 'var(--accent)') : 'transparent',
      color: isPrimary ? '#fff' : 'var(--text-secondary)',
      opacity: disabled && !loading ? 0.55 : 1,
      transition: 'background 0.15s, opacity 0.15s',
      display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
    }}>
      {loading && <span style={{ display: 'inline-block', animation: 'spin 0.8s linear infinite' }}>⟳</span>}
      {children}
    </button>
  )
}

// ── StatusMsg ──────────────────────────────────────────
function StatusMsg({ ok, message }: { ok: boolean; message: string }) {
  return (
    <div style={{
      ...mono, display: 'flex', alignItems: 'flex-start', gap: '0.5rem',
      padding: '0.6rem 0.85rem', borderRadius: '6px',
      background: ok ? 'var(--success-bg)' : 'var(--error-bg)',
      border: `1px solid ${ok ? 'var(--success-border)' : 'var(--error-border)'}`,
      fontSize: '0.8rem', color: ok ? 'var(--success)' : 'var(--error)',
      wordBreak: 'break-all',
    }}>
      <span style={{ flexShrink: 0 }}>{ok ? '✓' : '✕'}</span>
      <span>{message}</span>
    </div>
  )
}

// ── PemDownloadBtn ─────────────────────────────────────
function PemDownloadBtn({ pem, filename, label: lbl, color }: {
  pem: string; filename: string; label: string; color: 'green' | 'blue'
}) {
  const download = () => {
    const blob = new Blob([pem], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = Object.assign(document.createElement('a'), { href: url, download: filename })
    document.body.appendChild(a); a.click(); document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const isGreen = color === 'green'
  return (
    <button onClick={download} style={{
      ...mono, display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
      padding: '0.4rem 1rem', borderRadius: '6px', fontSize: '0.78rem',
      fontWeight: 500, cursor: 'pointer', width: '100%', justifyContent: 'center',
      border: `1px solid ${isGreen ? '#16a34a' : '#1d4ed8'}`,
      background: isGreen ? '#16a34a' : '#1d4ed8',
      color: '#fff',
    }}>
      ↓ {lbl}
    </button>
  )
}

// ── DownloadBtn ────────────────────────────────────────
function DownloadBtn({ data, filename, label: lbl, mimeType }: {
  data: Uint8Array; filename: string; label: string; mimeType: string
}) {
  const download = () => {
    const blob = new Blob([data.buffer as ArrayBuffer], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = Object.assign(document.createElement('a'), { href: url, download: filename })
    document.body.appendChild(a); a.click(); document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }
  return (
    <button onClick={download} style={{
      ...mono,
      display: 'inline-flex',
      alignItems: 'center',
      gap: '0.5rem',
      padding: '0.5rem 1rem',
      borderRadius: '8px',
      border: '1px solid #1d4ed8', // Borde azul oscuro
      background: '#2563eb',       // Fondo azul brillante
      color: '#ffffff',            // Texto blanco
      fontSize: '0.85rem',
      fontWeight: 500,
      cursor: 'pointer',
      boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)'
    }}>
      ↓ {lbl}
    </button>
  )
}

// ── KEYS PANEL ─────────────────────────────────────────
function KeysPanel({ users }: { users: GeneratedUser[] }) {
  const isReady = users.length > 0

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <span style={{ ...mono, fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--accent)' }}>
          00
        </span>
        <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>
          Key Pairs
        </span>
      </div>

      <div style={panelBody}>
        {!isReady ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', ...mono, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            <span style={{ animation: 'spin 0.8s linear infinite', display: 'inline-block' }}>⟳</span>
            Generating RSA-2048 key pairs…
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ background: 'var(--bg-sidebar)' }}>
                  {['User ID', 'Public Key', 'Private Key'].map(h => (
                    <th key={h} style={{
                      padding: '0.5rem 0.9rem', textAlign: 'left',
                      fontWeight: 600, fontSize: '0.68rem', textTransform: 'uppercase',
                      letterSpacing: '0.07em', color: 'var(--text-muted)',
                      border: '1px solid var(--border)',
                      ...mono,
                    }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.username}>
                    <td style={{ padding: '0.6rem 0.9rem', border: '1px solid var(--border-light)', verticalAlign: 'middle' }}>
                      <span style={{
                        ...mono, fontSize: '0.82rem', fontWeight: 700,
                        background: '#f97316', color: '#fff',
                        padding: '3px 14px', borderRadius: '4px',
                        display: 'inline-block',
                      }}>
                        {u.username}
                      </span>
                    </td>
                    <td style={{ padding: '0.5rem 0.9rem', border: '1px solid var(--border-light)' }}>
                      <PemDownloadBtn
                        pem={u.publicKeyPem}
                        filename={`${u.username}_public.pem`}
                        label="Download public key"
                        color="green"
                      />
                    </td>
                    <td style={{ padding: '0.5rem 0.9rem', border: '1px solid var(--border-light)' }}>
                      <PemDownloadBtn
                        pem={u.privateKeyPem}
                        filename={`${u.username}_private.pem`}
                        label="Download private key"
                        color="blue"
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

// ── ENCRYPT PANEL ──────────────────────────────────────
function EncryptPanel({ users }: { users: GeneratedUser[] }) {
  const [file, setFile]           = useState<File | null>(null)
  const [selected, setSelected]   = useState<Set<string>>(new Set())
  const [loading, setLoading]     = useState(false)
  const [container, setContainer] = useState<object | null>(null)
  const [error, setError]         = useState<string | null>(null)

  const reset = () => { setContainer(null); setError(null) }

  const toggleUser = (username: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(username) ? next.delete(username) : next.add(username)
      return next
    })
    reset();
  }

  const doEncrypt = async () => {
    if (!file || selected.size === 0) return
    setLoading(true); reset()
    try {
      const enc = new HybridEncryption()
      const data = new Uint8Array(await file.arrayBuffer())
      const recipients = users
        .filter(u => selected.has(u.username))
        .map(u => ({ username: u.username, publicKey: u.publicKey }))
      const result = await enc.encrypt_file({
        data,
        filename: file.name,
        file_type: file.type || 'application/octet-stream',
        recipients,
      })
      setContainer(result)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Encryption failed.')
    } finally {
      setLoading(false)
    }
  }

  const canEncrypt = !!file && selected.size > 0 && users.length > 0

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <span style={{ ...mono, fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--accent)' }}>
          01
        </span>
        <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Encrypt</span>
      </div>

      <div style={panelBody}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr', gap: '1.5rem', alignItems: 'start' }}>

          {/* Left: file input */}
          <div>
            <FileDropZone
              label="File to encrypt"
              file={file}
              disabled={loading}
              onChange={f => { setFile(f); reset() }}
            />
          </div>

          {/* Center: recipient selector */}
          <div style={{ minWidth: '160px' }}>
            <span style={labelStyle}>Recipients</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              {users.map(u => {
                const active = selected.has(u.username)
                return (
                  <button
                    key={u.username}
                    onClick={() => toggleUser(u.username)}
                    style={{
                      ...mono, fontSize: '0.78rem', fontWeight: 600,
                      padding: '0.35rem 0.9rem', borderRadius: '6px', cursor: 'pointer',
                      border: `1.5px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
                      background: active ? 'var(--accent-dim)' : 'var(--bg)',
                      color: active ? 'var(--accent)' : 'var(--text-secondary)',
                      transition: 'all 0.15s', textAlign: 'left',
                      display: 'flex', alignItems: 'center', gap: '0.4rem',
                    }}
                  >
                    <span style={{
                      width: '14px', height: '14px', borderRadius: '3px', flexShrink: 0,
                      border: `1.5px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
                      background: active ? 'var(--accent)' : 'transparent',
                      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: '0.6rem', color: '#fff',
                    }}>
                      {active ? '✓' : ''}
                    </span>
                    {u.username}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Right: output */}
          <div>
            <span style={labelStyle}>Output</span>
            {container ? (
              <DownloadBtn
                data={new TextEncoder().encode(JSON.stringify(container, null, 2))}
                filename="secure_vault.json"
                label="Download container (.json)"
                mimeType="application/json"
              />
            ) : (
              <span style={{ ...mono, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                —
              </span>
            )}
          </div>
        </div>

        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div>
            <Btn onClick={doEncrypt} disabled={!canEncrypt} loading={loading}>
              Encrypt file
            </Btn>
          </div>
          {error && <StatusMsg ok={false} message={error} />}
          {container && <StatusMsg ok={true} message={`Encrypted for: ${[...selected].join(', ')}.`} />}
        </div>
      </div>
    </div>
  )
}

// ── DECRYPT PANEL ──────────────────────────────────────
function DecryptPanel() {
  const [containerFile, setContainerFile]   = useState<File | null>(null)
  const [container, setContainer]           = useState<any | null>(null)
  const [userId, setUserId]                 = useState('')
  const [privateKeyFile, setPrivateKeyFile] = useState<File | null>(null)
  const [loading, setLoading]               = useState(false)
  const [result, setResult]                 = useState<Uint8Array | null>(null)
  const [error, setError]                   = useState<string | null>(null)

  const reset = () => { setResult(null); setError(null) }

  useEffect(() => {
    if (!containerFile) return
    containerFile.text().then(json => {
      try { setContainer(JSON.parse(json)) }
      catch { setContainer(null) }
    })
  }, [containerFile])

  const doDecrypt = async () => {
    if (!container || !userId.trim() || !privateKeyFile) return
    setLoading(true); reset()
    try {
      const km = new KeyManager()
      const enc = new HybridEncryption()
      const pem = await privateKeyFile.text()
      const privateKey = await km.importPrivateKey(pem)
      const plaintext = await enc.decrypt_file(container, userId.trim(), privateKey)
      setResult(plaintext)
    } catch (e) {
      console.error('Decryption error:', e)
      setError('Decryption failed — wrong key, unknown recipient, or tampered container.')
    } finally {
      setLoading(false)
    }
  }

  const canRun = !!containerFile && !!userId.trim() && !!privateKeyFile

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <span style={{ ...mono, fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
          02
        </span>
        <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Decrypt</span>
      </div>

      <div style={panelBody}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: '1rem', alignItems: 'start' }}>

          <FileDropZone
            label="Encrypted container"
            accept=".json"
            file={containerFile}
            disabled={loading}
            onChange={f => { setContainerFile(f); reset() }}
          />

          <div>
            <span style={labelStyle}>Recipient User ID</span>
            <input
              type="text"
              value={userId}
              disabled={loading}
              onChange={e => { setUserId(e.target.value); reset() }}
              placeholder="e.g. Alice"
              style={{
                ...mono, width: '100%', fontSize: '0.78rem',
                padding: '0.5rem 0.85rem', border: '1px solid var(--border)',
                borderRadius: '6px', background: 'var(--bg)', color: 'var(--text-primary)',
                outline: 'none', boxSizing: 'border-box',
              }}
            />
          </div>

          <FileDropZone
            label="Private key (.pem)"
            accept=".pem,.txt"
            file={privateKeyFile}
            disabled={loading}
            onChange={f => { setPrivateKeyFile(f); reset() }}
          />

          <div>
            <span style={labelStyle}>Output</span>
            {result && container ? (
              <DownloadBtn
                data={result}
                filename={container?.metaData?.filename ?? 'decrypted_file'}
                label="Download file"
                mimeType={container?.metaData?.file_type ?? 'application/octet-stream'}
              />
            ) : (
              <span style={{ ...mono, fontSize: '0.75rem', color: 'var(--text-muted)' }}>—</span>
            )}
          </div>
        </div>

        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div>
            <Btn onClick={doDecrypt} disabled={!canRun} loading={loading} variant="ghost">
              Decrypt file
            </Btn>
          </div>
          {error && <StatusMsg ok={false} message={error} />}
          {result && container && (
            <StatusMsg ok={true} message={`Tag verified. File "${container?.metaData?.filename ?? 'file'}" recovered.`} />
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main export ────────────────────────────────────────
export default function D3Demo() {
  const [users, setUsers] = useState<GeneratedUser[]>([])

  // Generate key pairs automatically on mount
  useEffect(() => {
    const km = new KeyManager()
    Promise.all(
      ['Alice', 'Bob', 'Hank'].map(async username => {
        const { publicKey, privateKey } = await km.generate_key_pair()
        const publicKeyPem  = await km.exportPublicKey(publicKey)
        const privateKeyPem = await km.exportPrivateKey(privateKey)
        return { username, publicKey, privateKey, publicKeyPem, privateKeyPem }
      })
    ).then(setUsers)
  }, [])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      <div style={{
        ...mono, fontSize: '0.72rem', color: 'var(--text-muted)',
        background: 'var(--bg-sidebar)', border: '1px solid var(--border)',
        borderRadius: '6px', padding: '0.5rem 0.9rem', lineHeight: 1.6,
      }}>
        <strong style={{ color: 'var(--text-secondary)' }}>Live demo</strong>
        {' '}— Key pairs are generated automatically. Download them, encrypt a file for selected recipients, then decrypt with a private key. Runs entirely in your browser.
      </div>

      <KeysPanel users={users} />
      <EncryptPanel users={users} />
      <DecryptPanel />
    </div>
  )
}