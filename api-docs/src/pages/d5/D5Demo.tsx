import { useState, useRef, useEffect } from 'react';
import { SignatureCryptoModule, KeyManager } from 'd5-crypto';

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
  publicKey: Uint8Array
  privateKey: Uint8Array
  publicKeyPem: string
  privateKeyPem: string
}

const PRESET_USERS = ['Alice', 'Bob', 'Hank', 'Carol', 'Dave']

// ── FileDropZone ───────────────────────────────────────
function FileDropZone({ label: lbl, accept, file, onChange, disabled }: {
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
        onDrop={e => { e.preventDefault(); setDrag(false); if (!disabled) { const f = e.dataTransfer.files[0]; if (f) onChange(f) } }}
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
        {file && <span style={{ ...mono, marginLeft: 'auto', fontSize: '0.68rem', color: 'var(--text-muted)', flexShrink: 0 }}>
          {file.size < 1024 ? `${file.size} B` : `${(file.size / 1024).toFixed(1)} KB`}
        </span>}
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
      background: isGreen ? '#16a34a' : '#1d4ed8', color: '#fff',
    }}>
      ↓ {lbl}
    </button>
  )
}

// ── DownloadBtn ────────────────────────────────────────
function DownloadBtn({ data, filename, label: lbl, mimeType }: {
  data: Uint8Array | string; filename: string; label: string; mimeType: string
}) {
  const download = () => {
    const blob = typeof data === 'string'
      ? new Blob([data], { type: mimeType })
      : new Blob([data.buffer as ArrayBuffer], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = Object.assign(document.createElement('a'), { href: url, download: filename })
    document.body.appendChild(a); a.click(); document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }
  return (
    <button onClick={download} style={{
      ...mono, display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
      padding: '0.45rem 1.1rem', borderRadius: '6px',
      border: '1px solid #1d4ed8', background: '#2563eb',
      color: '#fff', fontSize: '0.78rem', fontWeight: 500, cursor: 'pointer',
    }}>
      ↓ {lbl}
    </button>
  )
}

// ── UserChip ───────────────────────────────────────────
function UserChip({ username, active, onClick }: {
  username: string; active: boolean; onClick: () => void
}) {
  return (
    <button onClick={onClick} style={{
      ...mono, fontSize: '0.78rem', fontWeight: 600,
      padding: '0.35rem 0.9rem', borderRadius: '6px', cursor: 'pointer',
      border: `1.5px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
      background: active ? 'var(--accent-dim)' : 'var(--bg)',
      color: active ? 'var(--accent)' : 'var(--text-secondary)',
      transition: 'all 0.15s', display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
    }}>
      <span style={{
        width: '13px', height: '13px', borderRadius: '3px', flexShrink: 0,
        border: `1.5px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
        background: active ? 'var(--accent)' : 'transparent',
        display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
        fontSize: '0.6rem', color: '#fff',
      }}>{active ? '✓' : ''}</span>
      {username}
    </button>
  )
}

// ── 00 — KEYS PANEL ────────────────────────────────────
function KeysPanel({ users }: { users: GeneratedUser[] }) {
  return (
    <div style={panel}>
      <div style={panelHeader}>
        <span style={{ ...mono, fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--accent)' }}>00</span>
        <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Key Pairs</span>
      </div>
      <div style={panelBody}>
        {users.length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', ...mono, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            <span style={{ animation: 'spin 0.8s linear infinite', display: 'inline-block' }}>⟳</span>
            Generating Ed25519 key pairs…
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ background: 'var(--bg-sidebar)' }}>
                  {['User ID', 'Public Key', 'Private Key'].map(h => (
                    <th key={h} style={{ padding: '0.5rem 0.9rem', textAlign: 'left', fontWeight: 600, fontSize: '0.68rem', textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)', border: '1px solid var(--border)', ...mono }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.username}>
                    <td style={{ padding: '0.6rem 0.9rem', border: '1px solid var(--border-light)', verticalAlign: 'middle' }}>
                      <span style={{ ...mono, fontSize: '0.82rem', fontWeight: 700, background: '#f97316', color: '#fff', padding: '3px 14px', borderRadius: '4px', display: 'inline-block' }}>
                        {u.username}
                      </span>
                    </td>
                    <td style={{ padding: '0.5rem 0.9rem', border: '1px solid var(--border-light)' }}>
                      <PemDownloadBtn pem={u.publicKeyPem} filename={`${u.username}_public.pem`} label="Download public key" color="green" />
                    </td>
                    <td style={{ padding: '0.5rem 0.9rem', border: '1px solid var(--border-light)' }}>
                      <PemDownloadBtn pem={u.privateKeyPem} filename={`${u.username}_private.pem`} label="Download private key" color="blue" />
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

// ── 01 — ENCRYPT PANEL ─────────────────────────────────
function EncryptPanel({ users }: { users: GeneratedUser[] }) {
  const [file, setFile]           = useState<File | null>(null)
  const [owner, setOwner]         = useState<string | null>(null)
  const [selected, setSelected]   = useState<Set<string>>(new Set())
  const [loading, setLoading]     = useState(false)
  const [container, setContainer] = useState<object | null>(null)
  const [error, setError]         = useState<string | null>(null)

  const reset = () => { setContainer(null); setError(null) }

  // When owner changes, remove them from recipients
  const handleOwnerSelect = (username: string) => {
    setOwner(username)
    setSelected(prev => { const next = new Set(prev); next.delete(username); return next })
    reset()
  }

  const toggleRecipient = (username: string) => {
    if (username === owner) return
    setSelected(prev => {
      const next = new Set(prev)
      next.has(username) ? next.delete(username) : next.add(username)
      return next
    })
    reset()
  }

  const doEncrypt = async () => {
    if (!file || !owner) return
    setLoading(true); reset()
    try {
      const scm = new SignatureCryptoModule()
      const ownerUser = users.find(u => u.username === owner)!
      const recipients = users
        .filter(u => selected.has(u.username))
        .map(u => ({ username: u.username, publicKey: u.publicKey }))
      const data = new Uint8Array(await file.arrayBuffer())
      const result = scm.create_container(
        ownerUser.privateKey,
        ownerUser.publicKey,
        ownerUser.username,
        { data, filename: file.name, file_type: file.type || 'application/octet-stream', recipients }
      )
      setContainer(result)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Encryption failed.')
    } finally {
      setLoading(false)
    }
  }

  const canEncrypt = !!file && !!owner && users.length > 0

  // Recipient candidates: everyone except the owner
  const recipientCandidates = users.filter(u => u.username !== owner)

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <span style={{ ...mono, fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--accent)' }}>01</span>
        <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Encrypt & Sign</span>
      </div>
      <div style={panelBody}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto auto auto', gap: '1.5rem', alignItems: 'start' }}>

          {/* File */}
          <FileDropZone label="File to encrypt" file={file} disabled={loading} onChange={f => { setFile(f); reset() }} />

          {/* Owner selector */}
          <div style={{ minWidth: '140px' }}>
            <span style={labelStyle}>Owner (signer)</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              {users.map(u => (
                <button key={u.username} onClick={() => handleOwnerSelect(u.username)} style={{
                  ...mono, fontSize: '0.78rem', fontWeight: 600,
                  padding: '0.35rem 0.9rem', borderRadius: '6px', cursor: 'pointer',
                  border: `1.5px solid ${owner === u.username ? '#f97316' : 'var(--border)'}`,
                  background: owner === u.username ? 'rgba(249,115,22,0.1)' : 'var(--bg)',
                  color: owner === u.username ? '#f97316' : 'var(--text-secondary)',
                  transition: 'all 0.15s',
                }}>
                  {owner === u.username ? '● ' : ''}{u.username}
                </button>
              ))}
            </div>
          </div>

          {/* Recipients selector */}
          <div style={{ minWidth: '140px' }}>
            <span style={labelStyle}>Recipients</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              {recipientCandidates.length === 0 ? (
                <span style={{ ...mono, fontSize: '0.72rem', color: 'var(--text-muted)' }}>Select an owner first</span>
              ) : recipientCandidates.map(u => (
                <UserChip key={u.username} username={u.username} active={selected.has(u.username)} onClick={() => toggleRecipient(u.username)} />
              ))}
            </div>
          </div>

          {/* Output */}
          <div>
            <span style={labelStyle}>Output</span>
            {container ? (
              <DownloadBtn data={JSON.stringify(container, null, 2)} filename="secure_vault.json" label="Download container" mimeType="application/json" />
            ) : (
              <span style={{ ...mono, fontSize: '0.75rem', color: 'var(--text-muted)' }}>—</span>
            )}
          </div>
        </div>

        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <Btn onClick={doEncrypt} disabled={!canEncrypt} loading={loading}>Encrypt & Sign</Btn>
          {error && <StatusMsg ok={false} message={error} />}
          {container && <StatusMsg ok={true} message={`Signed by ${owner}. Recipients: ${selected.size > 0 ? [...selected].join(', ') : 'none'}.`} />}
        </div>
      </div>
    </div>
  )
}

// ── 02 — ADD RECIPIENTS ─────────────────────────────────
function AddRecipientsPanel({ users }: { users: GeneratedUser[] }) {
  const [containerFile, setContainerFile] = useState<File | null>(null)
  const [container, setContainer]         = useState<any | null>(null)
  const [ownerPrivFile, setOwnerPrivFile] = useState<File | null>(null)
  const [ownerPubFile, setOwnerPubFile]   = useState<File | null>(null)
  const [toAdd, setToAdd]                 = useState<Set<string>>(new Set())
  const [loading, setLoading]             = useState(false)
  const [result, setResult]               = useState<object | null>(null)
  const [error, setError]                 = useState<string | null>(null)

  const reset = () => { setResult(null); setError(null) }

  useEffect(() => {
    if (!containerFile) return
    containerFile.text().then(json => {
      try { setContainer(JSON.parse(json)) } catch { setContainer(null) }
    })
  }, [containerFile])

  // Candidates: users not already in container recipients and not the owner
  const existingUsernames = new Set<string>([
    ...(container?.metaData?.recipients?.map((r: any) => r.username) ?? []),
    container?.signer_id ?? '',
  ])
  const candidates = users.filter(u => !existingUsernames.has(u.username))

  const toggleAdd = (username: string) => {
    setToAdd(prev => { const next = new Set(prev); next.has(username) ? next.delete(username) : next.add(username); return next })
    reset()
  }

  const doAdd = async () => {
    if (!container || toAdd.size === 0 || !ownerPrivFile || !ownerPubFile) return
    setLoading(true); reset()
    try {
      const km = new KeyManager()
      const scm = new SignatureCryptoModule()
      const privPem = await ownerPrivFile.text()
      const pubPem  = await ownerPubFile.text()
      const ownerPrivKey = await km.deserialize_private_key_pem(privPem)
      const ownerPubKey  = await km.deserialize_public_key_pem(pubPem)
      const recipientsInfo = users
        .filter(u => toAdd.has(u.username))
        .map(u => ({ username: u.username, publicKey: u.publicKey }))
      const updated = scm.add_recipients_to_container(container, ownerPubKey, ownerPrivKey, recipientsInfo)
      setResult(updated)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to add recipients.')
    } finally {
      setLoading(false)
    }
  }

  const canRun = !!container && toAdd.size > 0 && !!ownerPrivFile && !!ownerPubFile

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <span style={{ ...mono, fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--accent)' }}>02</span>
        <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Add Recipients</span>
      </div>
      <div style={panelBody}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: '1rem', alignItems: 'start' }}>

          <FileDropZone label="Container" accept=".json" file={containerFile} disabled={loading}
            onChange={f => { setContainerFile(f); reset() }} />

          <div>
            <FileDropZone label="Owner private key (.pem)" accept=".pem,.txt" file={ownerPrivFile} disabled={loading}
              onChange={f => { setOwnerPrivFile(f); reset() }} />
            <FileDropZone label="Owner public key (.pem)" accept=".pem,.txt" file={ownerPubFile} disabled={loading}
              onChange={f => { setOwnerPubFile(f); reset() }} />
          </div>

          <div>
            <span style={labelStyle}>Users to add</span>
            {candidates.length === 0 ? (
              <span style={{ ...mono, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                {container ? 'All users already included' : 'Load a container first'}
              </span>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                {candidates.map(u => (
                  <UserChip key={u.username} username={u.username} active={toAdd.has(u.username)} onClick={() => toggleAdd(u.username)} />
                ))}
              </div>
            )}
          </div>

          <div>
            <span style={labelStyle}>Output</span>
            {result ? (
              <DownloadBtn data={JSON.stringify(result, null, 2)} filename="secure_vault_updated_add.json" label="Download updated" mimeType="application/json" />
            ) : (
              <span style={{ ...mono, fontSize: '0.75rem', color: 'var(--text-muted)' }}>—</span>
            )}
          </div>
        </div>

        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <Btn onClick={doAdd} disabled={!canRun} loading={loading}>Add recipients</Btn>
          {error && <StatusMsg ok={false} message={error} />}
          {result && <StatusMsg ok={true} message={`Added: ${[...toAdd].join(', ')}. Container re-signed.`} />}
        </div>
      </div>
    </div>
  )
}

// ── 03 — REMOVE RECIPIENTS ─────────────────────────────
function RemoveRecipientsPanel() {
  const [containerFile, setContainerFile] = useState<File | null>(null)
  const [container, setContainer]         = useState<any | null>(null)
  const [ownerPrivFile, setOwnerPrivFile] = useState<File | null>(null)
  const [ownerPubFile, setOwnerPubFile]   = useState<File | null>(null)
  const [toRemove, setToRemove]           = useState<Set<string>>(new Set())
  const [loading, setLoading]             = useState(false)
  const [result, setResult]               = useState<object | null>(null)
  const [error, setError]                 = useState<string | null>(null)

  const reset = () => { setResult(null); setError(null) }

  useEffect(() => {
    if (!containerFile) return
    containerFile.text().then(json => {
      try { setContainer(JSON.parse(json)); setToRemove(new Set()) } catch { setContainer(null) }
    })
  }, [containerFile])

  const currentRecipients: string[] = container?.metaData?.recipients?.map((r: any) => r.username) ?? []

  const toggleRemove = (username: string) => {
    setToRemove(prev => { const next = new Set(prev); next.has(username) ? next.delete(username) : next.add(username); return next })
    reset()
  }

  const doRemove = async () => {
    if (!container || toRemove.size === 0 || !ownerPrivFile || !ownerPubFile) return
    setLoading(true); reset()
    try {
      const km = new KeyManager()
      const scm = new SignatureCryptoModule()
      const privPem = await ownerPrivFile.text()
      const pubPem  = await ownerPubFile.text()
      const ownerPrivKey = await km.deserialize_private_key_pem(privPem)
      const ownerPubKey  = await km.deserialize_public_key_pem(pubPem)
      const updated = scm.remove_recipients_from_container(container, ownerPubKey, ownerPrivKey, [...toRemove])
      setResult(updated)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to remove recipients.')
    } finally {
      setLoading(false)
    }
  }

  const canRun = !!container && toRemove.size > 0 && !!ownerPrivFile && !!ownerPubFile

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <span style={{ ...mono, fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>03</span>
        <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Remove Recipients</span>
      </div>
      <div style={panelBody}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: '1rem', alignItems: 'start' }}>

          <FileDropZone label="Container" accept=".json" file={containerFile} disabled={loading}
            onChange={f => { setContainerFile(f); reset() }} />

          <div>
            <FileDropZone label="Owner private key (.pem)" accept=".pem,.txt" file={ownerPrivFile} disabled={loading}
              onChange={f => { setOwnerPrivFile(f); reset() }} />
            <FileDropZone label="Owner public key (.pem)" accept=".pem,.txt" file={ownerPubFile} disabled={loading}
              onChange={f => { setOwnerPubFile(f); reset() }} />
          </div>

          <div>
            <span style={labelStyle}>Recipients to remove</span>
            {currentRecipients.length === 0 ? (
              <span style={{ ...mono, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                {container ? 'No recipients in container' : 'Load a container first'}
              </span>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                {currentRecipients.map(username => (
                  <button key={username} onClick={() => toggleRemove(username)} style={{
                    ...mono, fontSize: '0.78rem', fontWeight: 600,
                    padding: '0.35rem 0.9rem', borderRadius: '6px', cursor: 'pointer',
                    border: `1.5px solid ${toRemove.has(username) ? 'var(--error)' : 'var(--border)'}`,
                    background: toRemove.has(username) ? 'var(--error-bg)' : 'var(--bg)',
                    color: toRemove.has(username) ? 'var(--error)' : 'var(--text-secondary)',
                    transition: 'all 0.15s', display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
                  }}>
                    {toRemove.has(username) ? '✕ ' : ''}{username}
                  </button>
                ))}
              </div>
            )}
          </div>

          <div>
            <span style={labelStyle}>Output</span>
            {result ? (
              <DownloadBtn data={JSON.stringify(result, null, 2)} filename="secure_vault_updated_remove.json" label="Download updated" mimeType="application/json" />
            ) : (
              <span style={{ ...mono, fontSize: '0.75rem', color: 'var(--text-muted)' }}>—</span>
            )}
          </div>
        </div>

        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <Btn onClick={doRemove} disabled={!canRun} loading={loading} variant="ghost">Remove recipients</Btn>
          {error && <StatusMsg ok={false} message={error} />}
          {result && <StatusMsg ok={true} message={`Removed: ${[...toRemove].join(', ')}. Container re-signed.`} />}
        </div>
      </div>
    </div>
  )
}

// ── 04 — DECRYPT PANEL ─────────────────────────────────
function DecryptPanel() {
  const [containerFile, setContainerFile] = useState<File | null>(null)
  const [container, setContainer]         = useState<any | null>(null)
  const [userId, setUserId]               = useState('')
  const [privFile, setPrivFile]           = useState<File | null>(null)
  const [pubFile, setPubFile]             = useState<File | null>(null)
  const [loading, setLoading]             = useState(false)
  const [result, setResult]               = useState<Uint8Array | null>(null)
  const [error, setError]                 = useState<string | null>(null)

  const reset = () => { setResult(null); setError(null) }

  useEffect(() => {
    if (!containerFile) return
    containerFile.text().then(json => {
      try { setContainer(JSON.parse(json)) } catch { setContainer(null) }
    })
  }, [containerFile])

  const doDecrypt = async () => {
    if (!container || !userId.trim() || !privFile || !pubFile) return
    setLoading(true); reset()
    try {
      const km = new KeyManager()
      const scm = new SignatureCryptoModule()
      const privPem = await privFile.text()
      const pubPem  = await pubFile.text()
      const petitionerPrivKey = await km.deserialize_private_key_pem(privPem)
      const ownerPubKey       = await km.deserialize_public_key_pem(pubPem)
      const plaintext = scm.decrypt_container(container, userId.trim(), petitionerPrivKey, ownerPubKey)
      setResult(plaintext)
    } catch (e) {
      console.error('Decryption error:', e)
      setError('Decryption failed — invalid signature, wrong key, or unknown recipient.')
    } finally {
      setLoading(false)
    }
  }

  const canRun = !!containerFile && !!userId.trim() && !!privFile && !!pubFile

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <span style={{ ...mono, fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>04</span>
        <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Decrypt</span>
      </div>
      <div style={panelBody}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: '1rem', alignItems: 'start' }}>

          <FileDropZone label="Container" accept=".json" file={containerFile} disabled={loading}
            onChange={f => { setContainerFile(f); reset() }} />

          <div>
            <div style={{ marginBottom: '0.5rem' }}>
              <span style={labelStyle}>Recipient User ID</span>
              <input type="text" value={userId} disabled={loading}
                onChange={e => { setUserId(e.target.value); reset() }}
                placeholder="e.g. Alice"
                style={{ ...mono, width: '100%', fontSize: '0.78rem', padding: '0.5rem 0.85rem', border: '1px solid var(--border)', borderRadius: '6px', background: 'var(--bg)', color: 'var(--text-primary)', outline: 'none', boxSizing: 'border-box' }}
              />
            </div>
            <FileDropZone label="Recipient private key (.pem)" accept=".pem,.txt" file={privFile} disabled={loading}
              onChange={f => { setPrivFile(f); reset() }} />
          </div>

          <FileDropZone label="Owner public key (.pem)" accept=".pem,.txt" file={pubFile} disabled={loading}
            onChange={f => { setPubFile(f); reset() }} />

          <div>
            <span style={labelStyle}>Output</span>
            {result && container ? (
              <DownloadBtn data={result} filename={container?.metaData?.filename ?? 'decrypted_file'}
                label="Download file" mimeType={container?.metaData?.file_type ?? 'application/octet-stream'} />
            ) : (
              <span style={{ ...mono, fontSize: '0.75rem', color: 'var(--text-muted)' }}>—</span>
            )}
          </div>
        </div>

        <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <Btn onClick={doDecrypt} disabled={!canRun} loading={loading} variant="ghost">Decrypt</Btn>
          {error && <StatusMsg ok={false} message={error} />}
          {result && container && <StatusMsg ok={true} message={`Signature verified. File "${container?.metaData?.filename ?? 'file'}" recovered.`} />}
        </div>
      </div>
    </div>
  )
}

// ── Main export ────────────────────────────────────────
export default function D5Demo() {
  const [users, setUsers] = useState<GeneratedUser[]>([])

  useEffect(() => {
    const km = new KeyManager()
    Promise.all(
      PRESET_USERS.map(async username => {
        const { publicKey, privateKey } = km.generate_key_pair()
        const publicKeyPem  = await km.serialize_public_key_pem(publicKey)
        const privateKeyPem = await km.serialize_private_key_pem(privateKey)
        return { username, publicKey, privateKey, publicKeyPem, privateKeyPem }
      })
    ).then(setUsers)
  }, [])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      <div style={{ ...mono, fontSize: '0.72rem', color: 'var(--text-muted)', background: 'var(--bg-sidebar)', border: '1px solid var(--border)', borderRadius: '6px', padding: '0.5rem 0.9rem', lineHeight: 1.6 }}>
        <strong style={{ color: 'var(--text-secondary)' }}>Live demo</strong>
        {' '}— Ed25519 key pairs generated automatically. Encrypt & sign, then manage recipients or decrypt. Runs entirely in your browser.
      </div>
      <KeysPanel users={users} />
      <EncryptPanel users={users} />
      <AddRecipientsPanel users={users} />
      <RemoveRecipientsPanel/>
      <DecryptPanel />
    </div>
  )
}