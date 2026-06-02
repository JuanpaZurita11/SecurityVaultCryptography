import { useState, useRef, useEffect } from 'react'
import { CryptoModule } from 'd6-crypto'
import type { KeyStorage, SignContainer } from 'd6-crypto'

// ── Shared styles ──────────────────────────────────────
const mono: React.CSSProperties = { fontFamily: 'var(--font-mono)' }
const labelStyle: React.CSSProperties = {
  ...mono, display: 'block', fontSize: '0.68rem', fontWeight: 600,
  textTransform: 'uppercase' as const, letterSpacing: '0.09em',
  color: 'var(--text-muted)', marginBottom: '0.35rem',
}
const panel: React.CSSProperties = {
  background: 'var(--bg-card)', border: '1px solid var(--border)',
  borderRadius: '10px', overflow: 'hidden',
}
const panelHeader : React.CSSProperties = {
  borderBottom: '1px solid var(--border)', padding: '0.75rem 1.25rem',
  display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'var(--bg-sidebar)',
}

const panelBody: React.CSSProperties = { padding: '1.25rem' }
const inputStyle: React.CSSProperties = {
  ...mono, width: '100%', fontSize: '0.78rem', padding: '0.5rem 0.85rem',
  border: '1px solid var(--border)', borderRadius: '6px',
  background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none', boxSizing: 'border-box',
}

const DEFAULT_PASSWORD = 'crypto2026'
const baseURL = import.meta.env.BASE_URL;

const STATIC_KEYSTORES: { username: string; path: string }[] = [
  // Quitamos la '/' inicial de los paths para que se unan correctamente a baseURL
  { username: 'Alice', path: `${baseURL}keystorage/Alice_keystore.json` },
  { username: 'Bob',   path: `${baseURL}keystorage/Bob_keystore.json` },
];
// ── Types ──────────────────────────────────────────────
interface DictUser { username: string; password: string; keyStorage: KeyStorage }

// ── Helpers ────────────────────────────────────────────
const cm = new CryptoModule()

function downloadJson(data: object, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = Object.assign(document.createElement('a'), { href: url, download: filename })
  document.body.appendChild(a); a.click(); document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function downloadBytes(data: Uint8Array, filename: string, mimeType: string) {
  const blob = new Blob([data.buffer as ArrayBuffer], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const a = Object.assign(document.createElement('a'), { href: url, download: filename })
  document.body.appendChild(a); a.click(); document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// ── UI Atoms ───────────────────────────────────────────
function Btn({ onClick, disabled, loading, children, variant = 'primary', color }: {
  onClick: () => void; disabled?: boolean; loading?: boolean
  children: React.ReactNode; variant?: 'primary' | 'ghost'; color?: string
}) {
  const isPrimary = variant === 'primary'
  return (
    <button onClick={onClick} disabled={disabled || loading} style={{
      ...mono, padding: '0.5rem 1.25rem', borderRadius: '6px', fontSize: '0.78rem', fontWeight: 500,
      cursor: disabled || loading ? 'not-allowed' : 'pointer',
      border: isPrimary ? 'none' : '1px solid var(--border)',
      background: isPrimary ? (color || (disabled || loading ? '#93c5fd' : 'var(--accent)')) : 'transparent',
      color: isPrimary ? '#fff' : 'var(--text-secondary)',
      opacity: disabled && !loading ? 0.55 : 1, transition: 'background 0.15s',
      display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
    }}>
      {loading && <span style={{ display: 'inline-block', animation: 'spin 0.8s linear infinite' }}>⟳</span>}
      {children}
    </button>
  )
}

function StatusMsg({ ok, message }: { ok: boolean; message: string }) {
  return (
    <div style={{
      ...mono, display: 'flex', alignItems: 'flex-start', gap: '0.5rem',
      padding: '0.6rem 0.85rem', borderRadius: '6px',
      background: ok ? 'var(--success-bg)' : 'var(--error-bg)',
      border: `1px solid ${ok ? 'var(--success-border)' : 'var(--error-border)'}`,
      fontSize: '0.8rem', color: ok ? 'var(--success)' : 'var(--error)', wordBreak: 'break-all',
    }}>
      <span style={{ flexShrink: 0 }}>{ok ? '✓' : '✕'}</span><span>{message}</span>
    </div>
  )
}

function PanelNum({ num, label, accent = 'var(--accent)' }: { num: string; label: string; accent?: string }) {
  return (
    <>
      <span style={{ ...mono, fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: accent }}>{num}</span>
      <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>{label}</span>
    </>
  )
}

function FileDropZone({ label: lbl, accept, file, onChange, disabled }: {
  label: string; accept?: string; file: File | null; onChange: (f: File) => void; disabled?: boolean
}) {
  const ref = useRef<HTMLInputElement>(null)
  const [drag, setDrag] = useState(false)
  return (
    <div style={{ marginBottom: '0.75rem' }}>
      <span style={labelStyle}>{lbl}</span>
      <div
        onClick={() => !disabled && ref.current?.click()}
        onDragOver={e => { if (!disabled) { e.preventDefault(); setDrag(true) } }}
        onDragLeave={() => setDrag(false)}
        onDrop={e => { e.preventDefault(); setDrag(false); if (!disabled) { const f = e.dataTransfer.files[0]; if (f) onChange(f) } }}
        style={{
          border: `1.5px dashed ${drag ? 'var(--accent)' : file ? 'var(--border)' : 'var(--border-light)'}`,
          borderRadius: '8px', padding: '0.7rem 1rem', cursor: disabled ? 'default' : 'pointer',
          background: drag ? 'var(--accent-dim)' : file ? 'var(--bg-sidebar)' : 'transparent',
          transition: 'all 0.15s', display: 'flex', alignItems: 'center', gap: '0.65rem', opacity: disabled ? 0.5 : 1,
        }}
      >
        <span style={{ fontSize: '1rem', flexShrink: 0 }}>{file ? '📄' : '📂'}</span>
        <span style={{ fontSize: '0.82rem', color: file ? 'var(--text-primary)' : 'var(--text-muted)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {file ? file.name : 'Click or drag & drop'}
        </span>
      </div>
      <input ref={ref} type="file" accept={accept} style={{ display: 'none' }} onChange={e => { const f = e.target.files?.[0]; if (f) onChange(f) }} />
    </div>
  )
}

function TextInput({ label: lbl, value, onChange, placeholder, type = 'text', disabled }: {
  label: string; value: string; onChange: (v: string) => void
  placeholder?: string; type?: string; disabled?: boolean
}) {
  return (
    <div style={{ marginBottom: '0.75rem' }}>
      <span style={labelStyle}>{lbl}</span>
      <input type={type} value={value} disabled={disabled} onChange={e => onChange(e.target.value)}
        placeholder={placeholder} style={inputStyle} />
    </div>
  )
}

function UserChip({ username, active, onClick, color = 'accent' }: {
  username: string; active: boolean; onClick: () => void; color?: 'accent' | 'red' | 'orange'
}) {
  const colors = {
    accent: { border: 'var(--accent)', bg: 'var(--accent-dim)', text: 'var(--accent)' },
    red:    { border: 'var(--error)',  bg: 'var(--error-bg)',   text: 'var(--error)' },
    orange: { border: '#f97316',       bg: 'rgba(249,115,22,0.1)', text: '#f97316' },
  }
  const c = active ? colors[color] : { border: 'var(--border)', bg: 'var(--bg)', text: 'var(--text-secondary)' }
  return (
    <button onClick={onClick} style={{
      ...mono, fontSize: '0.78rem', fontWeight: 600, padding: '0.35rem 0.9rem',
      borderRadius: '6px', cursor: 'pointer', border: `1.5px solid ${c.border}`,
      background: c.bg, color: c.text, transition: 'all 0.15s',
      display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
    }}>
      <span style={{
        width: '13px', height: '13px', borderRadius: '3px', flexShrink: 0,
        border: `1.5px solid ${active ? c.border : 'var(--border)'}`,
        background: active ? c.border : 'transparent',
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        fontSize: '0.6rem', color: '#fff',
      }}>{active ? (color === 'red' ? '✕' : '✓') : ''}</span>
      {username}
    </button>
  )
}

function DownloadJsonBtn({ data, filename, label: lbl }: { data: object; filename: string; label: string }) {
  return (
    <button onClick={() => downloadJson(data, filename)} style={{
      ...mono, display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
      padding: '0.45rem 1.1rem', borderRadius: '6px',
      border: '1px solid var(--success-border)', background: 'var(--success-bg)',
      color: 'var(--success)', fontSize: '0.78rem', fontWeight: 500, cursor: 'pointer',
    }}>
      ↓ {lbl}
    </button>
  )
}

function AppNote({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      ...mono, fontSize: '0.7rem', color: '#92400e',
      background: '#fffbeb', border: '1px solid #fcd34d',
      borderRadius: '6px', padding: '0.5rem 0.85rem', lineHeight: 1.6, marginBottom: '1rem',
    }}>
      {children}
    </div>
  )
}

// ── 00 — KEY DICTIONARY ────────────────────────────────
function KeyDictionary({ users }: { users: DictUser[] }) {
  const [revealed, setRevealed] = useState<Set<string>>(new Set())
  const toggleReveal = (username: string) => {
    setRevealed(prev => { const n = new Set(prev); n.has(username) ? n.delete(username) : n.add(username); return n })
  }

  if (users.length === 0) return (
    <div style={panel}>
      <div style={panelHeader}>
        <PanelNum num="00" label="Key Dictionary" />
      </div>
      <div style={panelBody}>
        <div style={{ ...mono, fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <span style={{ animation: 'spin 0.8s linear infinite', display: 'inline-block' }}>⟳</span>
          Loading KeyStorages…
        </div>
      </div>
    </div>
  )

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <PanelNum num="00" label="Key Dictionary" />
        <span style={{ ...mono, fontSize: '0.72rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
          — Source of truth for all user key pairs
        </span>
      </div>
      <div style={panelBody}>
        <div style={{
          ...mono, fontSize: '0.7rem', color: '#1e40af',
          background: '#eff6ff', border: '1px solid #93c5fd',
          borderRadius: '6px', padding: '0.5rem 0.85rem', marginBottom: '1rem',
        }}>
          ℹ The dictionary stores each user's KeyStorage (encrypted private key + plaintext public key) and their current password.
          In this demo, password updates and key rotations automatically reflect here — in a real application this would be handled server-side.
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
            <thead>
              <tr style={{ background: 'var(--bg-sidebar)' }}>
                {['User ID', 'Password', 'Public Key (from KeyStorage)', 'KeyStorage'].map(h => (
                  <th key={h} style={{ padding: '0.5rem 0.9rem', textAlign: 'left', fontWeight: 600, fontSize: '0.65rem', textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)', border: '1px solid var(--border)', ...mono }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map(u => {
                const pubKeyB64 = u.keyStorage.public_key
                const isRevealed = revealed.has(u.username)
                return (
                  <tr key={u.username}>
                    <td style={{ padding: '0.6rem 0.9rem', border: '1px solid var(--border-light)', verticalAlign: 'middle' }}>
                      <span style={{ ...mono, fontSize: '0.82rem', fontWeight: 700, background: '#f97316', color: '#fff', padding: '3px 14px', borderRadius: '4px', display: 'inline-block' }}>
                        {u.username}
                      </span>
                    </td>
                    <td style={{ padding: '0.5rem 0.9rem', border: '1px solid var(--border-light)', verticalAlign: 'middle' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span style={{ ...mono, fontSize: '0.75rem', color: 'var(--text-primary)' }}>
                          {isRevealed ? u.password : '••••••••'}
                        </span>
                        <button onClick={() => toggleReveal(u.username)} style={{ ...mono, fontSize: '0.62rem', background: 'none', border: '1px solid var(--border)', borderRadius: '4px', padding: '1px 6px', cursor: 'pointer', color: 'var(--text-muted)' }}>
                          {isRevealed ? 'hide' : 'show'}
                        </button>
                      </div>
                    </td>
                    <td style={{ padding: '0.5rem 0.9rem', border: '1px solid var(--border-light)', verticalAlign: 'middle', maxWidth: '200px' }}>
                      <span style={{ ...mono, fontSize: '0.65rem', color: 'var(--text-muted)', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={pubKeyB64}>
                        {pubKeyB64.slice(0, 24)}…
                      </span>
                    </td>
                    <td style={{ padding: '0.5rem 0.9rem', border: '1px solid var(--border-light)', verticalAlign: 'middle' }}>
                      <DownloadJsonBtn data={u.keyStorage} filename={`${u.username}_keystore.json`} label={`${u.username}_keystore.json`} />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── 01 — ENCRYPT & SIGN ────────────────────────────────
function EncryptPanel({ users }: { users: DictUser[] }) {
  const [file, setFile]           = useState<File | null>(null)
  const [ownerId, setOwnerId]     = useState<string | null>(null)
  const [password, setPassword]   = useState('')
  const [selected, setSelected]   = useState<Set<string>>(new Set())
  const [loading, setLoading]     = useState(false)
  const [container, setContainer] = useState<SignContainer | null>(null)
  const [error, setError]         = useState<string | null>(null)

  const reset = () => { setContainer(null); setError(null) }

  const handleOwner = (username: string) => {
    setOwnerId(username)
    setSelected(prev => { const n = new Set(prev); n.delete(username); return n })
    reset()
  }

  const toggleRecipient = (username: string) => {
    if (username === ownerId) return
    setSelected(prev => { const n = new Set(prev); n.has(username) ? n.delete(username) : n.add(username); return n })
    reset()
  }

  const doEncrypt = async () => {
    if (!file || !ownerId || !password) return
    setLoading(true); reset()
    try {
      const ownerUser = users.find(u => u.username === ownerId)!
      const recipients = users.filter(u => selected.has(u.username))
        .map(u => ({ username: u.username, publicKey: cm.getPublicKey(u.keyStorage) }))
      const data = new Uint8Array(await file.arrayBuffer())
      const result = cm.create_container(ownerUser.keyStorage, password, ownerId, {
        data, filename: file.name, file_type: file.type || 'application/octet-stream', recipients,
      })
      setContainer(result)
    } catch (e) {
      setError('Wrong password.')
    } finally { setLoading(false) }
  }

  const recipientCandidates = users.filter(u => u.username !== ownerId)

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <PanelNum num="01" label="Encrypt & Sign" />
      </div>
      <div style={panelBody}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto auto auto', gap: '1.5rem', alignItems: 'start' }}>
          <div>
            <FileDropZone label="File to encrypt" file={file} disabled={loading} onChange={f => { setFile(f); reset() }} />
            <TextInput label="Owner password" value={password} onChange={v => { setPassword(v); reset() }} type="text" placeholder="Enter password" disabled={loading} />
          </div>
          <div style={{ minWidth: '140px' }}>
            <span style={labelStyle}>Owner (signer)</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              {users.map(u => (
                <button key={u.username} onClick={() => handleOwner(u.username)} style={{
                  ...mono, fontSize: '0.78rem', fontWeight: 600, padding: '0.35rem 0.9rem',
                  borderRadius: '6px', cursor: 'pointer',
                  border: `1.5px solid ${ownerId === u.username ? '#f97316' : 'var(--border)'}`,
                  background: ownerId === u.username ? 'rgba(249,115,22,0.1)' : 'var(--bg)',
                  color: ownerId === u.username ? '#f97316' : 'var(--text-secondary)', transition: 'all 0.15s',
                }}>
                  {ownerId === u.username ? '● ' : ''}{u.username}
                </button>
              ))}
            </div>
          </div>
          <div style={{ minWidth: '140px' }}>
            <span style={labelStyle}>Recipients</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              {recipientCandidates.length === 0
                ? <span style={{ ...mono, fontSize: '0.72rem', color: 'var(--text-muted)' }}>Select an owner first</span>
                : recipientCandidates.map(u => (
                  <UserChip key={u.username} username={u.username} active={selected.has(u.username)} onClick={() => toggleRecipient(u.username)} />
                ))}
            </div>
            <p style={{ ...mono, fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
              Public keys from dictionary
            </p>
          </div>
          <div>
            <span style={labelStyle}>Output</span>
            {container
              ? <DownloadJsonBtn data={container} filename="secure_vault.json" label="Download container" />
              : <span style={{ ...mono, fontSize: '0.75rem', color: 'var(--text-muted)' }}>—</span>}
          </div>
        </div>
        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <Btn onClick={doEncrypt} disabled={!file || !ownerId || !password} loading={loading}>Encrypt & Sign</Btn>
          {error && <StatusMsg ok={false} message={error} />}
          {container && <StatusMsg ok={true} message={`Signed by ${ownerId}. Recipients: ${selected.size > 0 ? [...selected].join(', ') : 'none'}.`} />}
        </div>
      </div>
    </div>
  )
}

// ── 02 — UPDATE PASSWORD ───────────────────────────────
function UpdatePasswordPanel({ users, onUpdateUser }: { users: DictUser[]; onUpdateUser: (u: string, p: Partial<DictUser>) => void }) {
  const [userId, setUserId]           = useState('')
  const [ksFile, setKsFile]           = useState<File | null>(null)
  const [ks, setKs]                   = useState<KeyStorage | null>(null)
  const [ksError, setKsError]         = useState<string | null>(null)
  const [oldPwd, setOldPwd]           = useState('')
  const [newPwd, setNewPwd]           = useState('')
  const [loading, setLoading]         = useState(false)
  const [error, setError]             = useState<string | null>(null)
  const [dictUpdated, setDictUpdated] = useState(false)


  useEffect(() => {
    if (!ksFile) return
    ksFile.text().then(json => {
      try {
        const parsed = JSON.parse(json)
        if (!cm.verify_key_container_structure(parsed)) {
          setKsError('Invalid KeyStorage structure.'); setKs(null); return
        }
        setKs(parsed); setKsError(null)
      } catch { setKs(null); setKsError('Could not parse file.') }
    })
  }, [ksFile])

  const doUpdate = async () => {
    if (!ks || !oldPwd || !newPwd || !userId.trim()) return
    const userInDict = users.find(u => u.username.toLowerCase() === userId.trim().toLowerCase())
    if (!userInDict) { setError(`User "${userId.trim()}" not found in the Key Dictionary.`); return }
    setLoading(true);
    try {
      const newKs = cm.update_keystorage_password(ks, oldPwd, newPwd)
      onUpdateUser(userInDict.username, { keyStorage: newKs, password: newPwd })
      setDictUpdated(true)
    } catch { setError('Wrong password or corrupted KeyStorage.') }
    finally { setLoading(false) }
  }

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <PanelNum num="02" label="Update Password" />
      </div>
      <div style={panelBody}>
        <AppNote>⚠ <strong>Application-level note:</strong> This demo does not verify that the uploaded KeyStorage belongs to the specified User ID. In a real application, the server must enforce that a user can only update their own KeyStorage.</AppNote>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
          <div>
            <TextInput label="User ID" value={userId} onChange={v => { setUserId(v)}} placeholder="e.g. Alice" disabled={loading} />
            <FileDropZone label="KeyStorage (.json)" accept=".json" file={ksFile} disabled={loading} onChange={f => { setKsFile(f)}} />
            {ksError && <div style={{ ...mono, fontSize: '0.72rem', color: 'var(--error)', marginTop: '0.25rem' }}>{ksError}</div>}
          </div>
          <div>
            <TextInput label="Current password" value={oldPwd} onChange={v => { setOldPwd(v)}} type="text" placeholder="Current password" disabled={loading} />
            <TextInput label="New password" value={newPwd} onChange={v => { setNewPwd(v)}} type="text" placeholder="New password" disabled={loading} />
          </div>
        </div>
        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <Btn onClick={doUpdate} disabled={!ks || !oldPwd || !newPwd || !userId.trim()} loading={loading}>Update password</Btn>
          {error && <StatusMsg ok={false} message={error} />}
          {dictUpdated && <StatusMsg ok={true} message={`Password updated for ${userId}. The KeyStorage in the dictionary has been refreshed — download it from the Key Dictionary.`} />}
        </div>
      </div>
    </div>
  )
}

// ── 03 — KEY ROTATION ──────────────────────────────────
function KeyRotationPanel({ users, onUpdateUser }: { users: DictUser[]; onUpdateUser: (u: string, p: Partial<DictUser>) => void }) {
  const [userId, setUserId]           = useState('')
  const [ksFile, setKsFile]           = useState<File | null>(null)
  const [ks, setKs]                   = useState<KeyStorage | null>(null)
  const [ksError, setKsError]         = useState<string | null>(null)
  const [oldPwd, setOldPwd]           = useState('')
  const [newPwd, setNewPwd]           = useState('')
  const [loading, setLoading]         = useState(false)
  const [error, setError]             = useState<string | null>(null)
  const [dictUpdated, setDictUpdated] = useState(false)

  useEffect(() => {
    if (!ksFile) return
    ksFile.text().then(json => {
      try {
        const parsed = JSON.parse(json)
        if (!cm.verify_key_container_structure(parsed)) {
          setKsError('Invalid KeyStorage structure.'); setKs(null); return
        }
        setKs(parsed); setKsError(null)
      } catch { setKs(null); setKsError('Could not parse file.') }
    })
  }, [ksFile])

  const doRotate = async () => {
    if (!ks || !oldPwd || !newPwd || !userId.trim()) return
    const userInDict = users.find(u => u.username.toLowerCase() === userId.trim().toLowerCase())
    if (!userInDict) { setError(`User "${userId.trim()}" not found in the Key Dictionary.`); return }
    setLoading(true)
    try {
      cm.getPrivateKey(ks, oldPwd)
      const newKs = cm.generate_key_pair(newPwd)
      onUpdateUser(userInDict.username, { keyStorage: newKs, password: newPwd })
      setDictUpdated(true)
    } catch { setError('Wrong password or corrupted KeyStorage.') }
    finally { setLoading(false) }
  }

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <PanelNum num="03" label="Key Rotation" accent="#c0392b" />
      </div>
      <div style={panelBody}>
        <AppNote>⚠ <strong>Application-level note:</strong> This demo does not verify that the uploaded KeyStorage belongs to the specified User ID. In a real application, the server must enforce that a user can only rotate their own keys.</AppNote>
        <div style={{
          ...mono, fontSize: '0.7rem', color: 'var(--error)',
          background: 'var(--error-bg)', border: '1px solid var(--error-border)',
          borderRadius: '6px', padding: '0.5rem 0.85rem', marginBottom: '1rem',
        }}>
          🚨 Key rotation generates a completely new key pair. All containers where this user is the <strong>owner</strong> must be recreated. Use "Validate Container" to detect affected containers.
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
          <div>
            <TextInput label="User ID" value={userId} onChange={v => { setUserId(v); setDictUpdated(false); setError(null) }} placeholder="e.g. Alice" disabled={loading} />
            <FileDropZone label="Current KeyStorage (.json)" accept=".json" file={ksFile} disabled={loading} onChange={f => { setKsFile(f); setDictUpdated(false); setError(null) }} />
            {ksError && <div style={{ ...mono, fontSize: '0.72rem', color: 'var(--error)', marginTop: '0.25rem' }}>{ksError}</div>}
          </div>
          <div>
            <TextInput label="Current password" value={oldPwd} onChange={v => { setOldPwd(v); setDictUpdated(false); setError(null) }} type="text" placeholder="Current password" disabled={loading} />
            <TextInput label="New password" value={newPwd} onChange={v => { setNewPwd(v); setDictUpdated(false); setError(null) }} type="text" placeholder="New password" disabled={loading} />
          </div>
        </div>
        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <Btn onClick={doRotate} disabled={!ks || !oldPwd || !newPwd || !userId.trim()} loading={loading} color="#c0392b">Rotate keys</Btn>
          {error && <StatusMsg ok={false} message={error} />}
          {dictUpdated && <StatusMsg ok={true} message={`New key pair generated for ${userId}. The KeyStorage in the dictionary has been refreshed — download it from the Key Dictionary.`} />}
        </div>
      </div>
    </div>
  )
}

// ── 04 — UPDATE RECIPIENT KEY ──────────────────────────
function UpdateRecipientKeyPanel({ users }: { users: DictUser[] }) {
  const [containerFile, setContainerFile] = useState<File | null>(null)
  const [container, setContainer]         = useState<SignContainer | null>(null)
  const [ownerKsFile, setOwnerKsFile]     = useState<File | null>(null)
  const [ownerKs, setOwnerKs]             = useState<KeyStorage | null>(null)
  const [ownerKsError, setOwnerKsError]   = useState<string | null>(null)
  const [userId, setUserId]               = useState('')
  const [password, setPassword]           = useState('')
  const [toUpdate, setToUpdate]           = useState<Set<string>>(new Set())
  const [loading, setLoading]             = useState(false)
  const [result, setResult]               = useState<SignContainer | null>(null)
  const [error, setError]                 = useState<string | null>(null)

  const reset = () => { setResult(null); setError(null) }

  useEffect(() => {
    if (!containerFile) return
    containerFile.text().then(json => {
      try {
        const parsed = JSON.parse(json)
        if (!cm.verify_container_structure(parsed)) { setContainer(null); return }
        setContainer(parsed); setToUpdate(new Set())
      } catch { setContainer(null) }
    })
  }, [containerFile])

  useEffect(() => {
    if (!ownerKsFile) return
    ownerKsFile.text().then(json => {
      try {
        const parsed = JSON.parse(json)
        if (!cm.verify_key_container_structure(parsed)) {
          setOwnerKsError('Invalid KeyStorage structure.'); setOwnerKs(null); return
        }
        setOwnerKs(parsed); setOwnerKsError(null)
      } catch { setOwnerKs(null); setOwnerKsError('Could not parse file.') }
    })
  }, [ownerKsFile])

  const currentRecipients: string[] = (container as any)?.metaData?.recipients?.map((r: any) => r.username) ?? []

  const doUpdate = async () => {
    if (!container || !ownerKs || !password || toUpdate.size === 0) return
    setLoading(true); reset()
    try {
      const recipientsUpdate = users.filter(u => toUpdate.has(u.username))
        .map(u => ({ username: u.username, publicKey: cm.getPublicKey(u.keyStorage) }))
      const updated = cm.update_container_recipientKeys(container, ownerKs, password, recipientsUpdate)
      setResult(updated)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update recipient keys.')
    } finally { setLoading(false) }
  }

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <PanelNum num="04" label="Update Recipient Key" />
      </div>
      <div style={panelBody}>
        <div style={{
          ...mono, fontSize: '0.7rem', color: '#1e40af',
          background: '#eff6ff', border: '1px solid #93c5fd',
          borderRadius: '6px', padding: '0.5rem 0.85rem', marginBottom: '1rem',
        }}>
          ℹ Use this after a recipient rotates their key pair. The new public key is read from the Key Dictionary.
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: '1rem', alignItems: 'start' }}>
          <FileDropZone label="Container (.json)" accept=".json" file={containerFile} disabled={loading} onChange={f => { setContainerFile(f); reset() }} />
          <div>
            <TextInput label="Owner User ID" value={userId} onChange={v => { setUserId(v); reset() }} placeholder="e.g. Alice" disabled={loading} />
            <FileDropZone label="Owner KeyStorage (.json)" accept=".json" file={ownerKsFile} disabled={loading} onChange={f => { setOwnerKsFile(f); reset() }} />
            {ownerKsError && <div style={{ ...mono, fontSize: '0.72rem', color: 'var(--error)', marginTop: '0.25rem' }}>{ownerKsError}</div>}
            <TextInput label="Owner password" value={password} onChange={v => { setPassword(v); reset() }} type="text" placeholder="Enter password" disabled={loading} />
          </div>
          <div>
            <span style={labelStyle}>Recipients to update</span>
            <p style={{ ...mono, fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>New public keys from dictionary</p>
            {currentRecipients.length === 0
              ? <span style={{ ...mono, fontSize: '0.72rem', color: 'var(--text-muted)' }}>{container ? 'No recipients' : 'Load container first'}</span>
              : <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                  {currentRecipients.map(username => (
                    <UserChip key={username} username={username} active={toUpdate.has(username)}
                      onClick={() => { setToUpdate(prev => { const n = new Set(prev); n.has(username) ? n.delete(username) : n.add(username); return n }); reset() }} />
                  ))}
                </div>}
          </div>
          <div>
            <span style={labelStyle}>Output</span>
            {result
              ? <DownloadJsonBtn data={result} filename="secure_vault_updated_recipientKey.json" label="Download updated" />
              : <span style={{ ...mono, fontSize: '0.75rem', color: 'var(--text-muted)' }}>—</span>}
          </div>
        </div>
        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <Btn onClick={doUpdate} disabled={!container || !ownerKs || !password || toUpdate.size === 0} loading={loading}>Update recipient keys</Btn>
          {error && <StatusMsg ok={false} message={error} />}
          {result && <StatusMsg ok={true} message={`Re-wrapped keys for: ${[...toUpdate].join(', ')}. Container re-signed.`} />}
        </div>
      </div>
    </div>
  )
}

// ── 05 — VALIDATE CONTAINER ────────────────────────────
function ValidatePanel() {
  const [containerFile, setContainerFile] = useState<File | null>(null)
  const [container, setContainer]         = useState<SignContainer | null>(null)
  const [ownerKsFile, setOwnerKsFile]     = useState<File | null>(null)
  const [ownerKs, setOwnerKs]             = useState<KeyStorage | null>(null)
  const [ownerKsError, setOwnerKsError]   = useState<string | null>(null)
  const [loading, setLoading]             = useState(false)
  const [status, setStatus]               = useState<'valid' | 'rotated' | null>(null)
  const [error, setError]                 = useState<string | null>(null)

  useEffect(() => {
    if (!containerFile) return
    containerFile.text().then(json => {
      try {
        const parsed = JSON.parse(json)
        if (!cm.verify_container_structure(parsed)) { setContainer(null); return }
        setContainer(parsed); setStatus(null)
      } catch { setContainer(null) }
    })
  }, [containerFile])

  useEffect(() => {
    if (!ownerKsFile) return
    ownerKsFile.text().then(json => {
      try {
        const parsed = JSON.parse(json)
        if (!cm.verify_key_container_structure(parsed)) {
          setOwnerKsError('Invalid KeyStorage structure.'); setOwnerKs(null); return
        }
        setOwnerKs(parsed); setOwnerKsError(null)
      } catch { setOwnerKs(null); setOwnerKsError('Could not parse file.') }
    })
  }, [ownerKsFile])

  const doValidate = async () => {
    if (!container || !ownerKs) return
    setLoading(true); setStatus(null); setError(null)
    try {
      const ownerPubKey = cm.getPublicKey(ownerKs)
      const valid = cm.validate_container_signature(container, ownerPubKey)
      setStatus(valid ? 'valid' : 'rotated')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Validation failed.')
    } finally { setLoading(false) }
  }

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <PanelNum num="05" label="Validate Container" />
      </div>
      <div style={panelBody}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
          <FileDropZone label="Container (.json)" accept=".json" file={containerFile} disabled={loading} onChange={f => { setContainerFile(f); setStatus(null) }} />
          <div>
            <FileDropZone label="Owner KeyStorage (.json)" accept=".json" file={ownerKsFile} disabled={loading} onChange={f => { setOwnerKsFile(f); setStatus(null) }} />
            {ownerKsError && <div style={{ ...mono, fontSize: '0.72rem', color: 'var(--error)', marginTop: '0.25rem' }}>{ownerKsError}</div>}
          </div>
        </div>
        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <Btn onClick={doValidate} disabled={!container || !ownerKs} loading={loading}>Validate signature</Btn>
          {error && <StatusMsg ok={false} message={error} />}
          {status === 'valid' && <StatusMsg ok={true} message="Signature valid — container is authentic and untampered." />}
          {status === 'rotated' && (
            <div style={{
              padding: '0.75rem 1rem', borderRadius: '8px',
              background: 'var(--error-bg)', border: '1px solid var(--error-border)',
              display: 'flex', flexDirection: 'column', gap: '0.4rem',
            }}>
              <div style={{ ...mono, fontSize: '0.8rem', color: 'var(--error)', fontWeight: 600 }}>
                🔑 Signature mismatch for signer "{(container as any)?.signer_id}"
              </div>
              <div style={{ ...mono, fontSize: '0.75rem', color: 'var(--error)' }}>
                The public key in the provided KeyStorage does not match the fingerprint stored in the container.
                Either the wrong KeyStorage was provided, or the owner has rotated their key pair since this container was created.
                If this is the correct owner's KeyStorage, the container must be regenerated with the new credentials.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── 06 — DECRYPT ───────────────────────────────────────
function DecryptPanel() {
  const [containerFile, setContainerFile] = useState<File | null>(null)
  const [container, setContainer]         = useState<SignContainer | null>(null)
  const [userId, setUserId]               = useState('')
  const [petKsFile, setPetKsFile]         = useState<File | null>(null)
  const [petKs, setPetKs]                 = useState<KeyStorage | null>(null)
  const [petKsError, setPetKsError]       = useState<string | null>(null)
  const [password, setPassword]           = useState('')
  const [ownerKsFile, setOwnerKsFile]     = useState<File | null>(null)
  const [ownerKs, setOwnerKs]             = useState<KeyStorage | null>(null)
  const [ownerKsError, setOwnerKsError]   = useState<string | null>(null)
  const [loading, setLoading]             = useState(false)
  const [result, setResult]               = useState<Uint8Array | null>(null)
  const [error, setError]                 = useState<string | null>(null)

  const reset = () => { setResult(null); setError(null) }

  useEffect(() => {
    if (!containerFile) return
    containerFile.text().then(json => {
      try {
        const parsed = JSON.parse(json)
        if (!cm.verify_container_structure(parsed)) { setContainer(null); return }
        setContainer(parsed)
      } catch { setContainer(null) }
    })
  }, [containerFile])

  useEffect(() => {
    if (!petKsFile) return
    petKsFile.text().then(json => {
      try {
        const parsed = JSON.parse(json)
        if (!cm.verify_key_container_structure(parsed)) {
          setPetKsError('Invalid KeyStorage structure.'); setPetKs(null); return
        }
        setPetKs(parsed); setPetKsError(null)
      } catch { setPetKs(null); setPetKsError('Could not parse file.') }
    })
  }, [petKsFile])

  useEffect(() => {
    if (!ownerKsFile) return
    ownerKsFile.text().then(json => {
      try {
        const parsed = JSON.parse(json)
        if (!cm.verify_key_container_structure(parsed)) {
          setOwnerKsError('Invalid KeyStorage structure.'); setOwnerKs(null); return
        }
        setOwnerKs(parsed); setOwnerKsError(null)
      } catch { setOwnerKs(null); setOwnerKsError('Could not parse file.') }
    })
  }, [ownerKsFile])

  const doDecrypt = async () => {
    if (!container || !petKs || !password || !ownerKs || !userId.trim()) return
    setLoading(true); reset()
    try {
      const ownerPubKey = cm.getPublicKey(ownerKs)
      const plaintext = cm.decrypt_container(container, userId.trim(), petKs, password, ownerPubKey)
      setResult(plaintext)
    } catch (e) {
      console.error('Decryption error:', e)
      setError('Decryption failed — wrong password, invalid signature, or unknown recipient.')
    } finally { setLoading(false) }
  }

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <PanelNum num="06" label="Decrypt" accent="var(--text-secondary)" />
      </div>
      <div style={panelBody}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: '1rem', alignItems: 'start' }}>
          <FileDropZone label="Container (.json)" accept=".json" file={containerFile} disabled={loading} onChange={f => { setContainerFile(f); reset() }} />
          <div>
            <TextInput label="Recipient User ID" value={userId} onChange={v => { setUserId(v); reset() }} placeholder="e.g. Alice" disabled={loading} />
            <FileDropZone label="Recipient KeyStorage (.json)" accept=".json" file={petKsFile} disabled={loading} onChange={f => { setPetKsFile(f); reset() }} />
            {petKsError && <div style={{ ...mono, fontSize: '0.72rem', color: 'var(--error)', marginTop: '0.25rem' }}>{petKsError}</div>}
            <TextInput label="Recipient password" value={password} onChange={v => { setPassword(v); reset() }} type="text" placeholder="Enter password" disabled={loading} />
          </div>
          <div>
            <FileDropZone label="Owner KeyStorage (.json) — public key only, no password needed" accept=".json" file={ownerKsFile} disabled={loading} onChange={f => { setOwnerKsFile(f); reset() }} />
            {ownerKsError && <div style={{ ...mono, fontSize: '0.72rem', color: 'var(--error)', marginTop: '0.25rem' }}>{ownerKsError}</div>}
          </div>
          <div>
            <span style={labelStyle}>Output</span>
            {result && container
              ? <button onClick={() => downloadBytes(result, (container as any)?.metaData?.filename ?? 'decrypted', (container as any)?.metaData?.file_type ?? 'application/octet-stream')} style={{
                  ...mono, display: 'inline-flex', alignItems: 'center', gap: '0.4rem', padding: '0.45rem 1.1rem',
                  borderRadius: '6px', border: '1px solid #1d4ed8', background: '#2563eb', color: '#fff',
                  fontSize: '0.78rem', fontWeight: 500, cursor: 'pointer',
                }}>↓ Download file</button>
              : <span style={{ ...mono, fontSize: '0.75rem', color: 'var(--text-muted)' }}>—</span>}
          </div>
        </div>
        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <Btn onClick={doDecrypt} disabled={!container || !petKs || !password || !ownerKs || !userId.trim()} loading={loading} variant="ghost">Decrypt</Btn>
          {error && <StatusMsg ok={false} message={error} />}
          {result && container && <StatusMsg ok={true} message={`Signature verified. File "${(container as any)?.metaData?.filename ?? 'file'}" recovered.`} />}
        </div>
      </div>
    </div>
  )
}

// ── Main export ────────────────────────────────────────
export default function D6Demo() {
  const [users, setUsers] = useState<DictUser[]>([])

  useEffect(() => {
    Promise.all(
      STATIC_KEYSTORES.map(async ({ username, path }) => {
        const res = await fetch(path)
        const keyStorage = await res.json()
        return { username, password: DEFAULT_PASSWORD, keyStorage }
      })
    ).then(setUsers)
  }, [])

  const updateUser = (username: string, updates: Partial<DictUser>) => {
    setUsers(prev => prev.map(u => u.username === username ? { ...u, ...updates } : u))
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      <div style={{ ...mono, fontSize: '0.72rem', color: 'var(--text-muted)', background: 'var(--bg-sidebar)', border: '1px solid var(--border)', borderRadius: '6px', padding: '0.5rem 0.9rem', lineHeight: 1.6 }}>
        <strong style={{ color: 'var(--text-secondary)' }}>Live demo</strong>
        {' '}— All users start with password <code style={{ color: 'var(--accent)' }}>{DEFAULT_PASSWORD}</code>. KeyStorages are loaded from static files. The Key Dictionary is the source of truth for all public keys. Runs entirely in your browser.
      </div>
      <KeyDictionary users={users} />
      <div style={{
        ...mono, fontSize: '0.72rem', color: '#1e40af',
        background: '#eff6ff', border: '1px solid #93c5fd',
        borderRadius: '6px', padding: '0.5rem 0.9rem', lineHeight: 1.6,
      }}>
        ℹ <strong style={{ color: '#1e40af' }}>Note:</strong> Adding and removing recipients is supported by this module — see the{' '}
        <a href="/d5#demo" style={{ color: 'var(--accent)' }}>D5 demo</a>{' '}
        for a live example. It was omitted here to keep the demo lightweight.
      </div>
      <EncryptPanel users={users} />
      <UpdatePasswordPanel users={users} onUpdateUser={updateUser} />
      <KeyRotationPanel users={users} onUpdateUser={updateUser} />
      <UpdateRecipientKeyPanel users={users} />
      <ValidatePanel />
      <DecryptPanel />
    </div>
  )
}