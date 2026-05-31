
import { useState, useRef, useEffect} from 'react';
import { SymmetricEncryption, b64ToBytes, bytesToB64} from 'd2-crypto';
import type { CipherObject } from 'd2-crypto';

// ── Shared styles ──────────────────────────────────────
const mono: React.CSSProperties = { fontFamily: 'var(--font-mono)' }

const label: React.CSSProperties = {
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

const panelBody: React.CSSProperties = {
  padding: '1.25rem',
}

// ── FileDropZone ───────────────────────────────────────
function FileDropZone({
  label: lbl,
  accept,
  file,
  onChange,
  disabled,
}: {
  label: string
  accept?: string
  file: File | null
  onChange: (f: File) => void
  disabled?: boolean
}) {
  const ref = useRef<HTMLInputElement>(null)
  const [drag, setDrag] = useState(false)

  return (
    <div style={{ marginBottom: '1rem' }}>
      <span style={label}>{lbl}</span>
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
          borderRadius: '8px',
          padding: '0.85rem 1rem',
          cursor: disabled ? 'default' : 'pointer',
          background: drag ? 'var(--accent-dim)' : file ? 'var(--bg-sidebar)' : 'transparent',
          transition: 'all 0.15s',
          display: 'flex',
          alignItems: 'center',
          gap: '0.65rem',
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
      <input
        ref={ref}
        type="file"
        accept={accept}
        style={{ display: 'none' }}
        onChange={e => { const f = e.target.files?.[0]; if (f) onChange(f) }}
      />
    </div>
  )
}

// ── Btn ────────────────────────────────────────────────
function Btn({
  onClick, disabled, loading, children, variant = 'primary',
}: {
  onClick: () => void
  disabled?: boolean
  loading?: boolean
  children: React.ReactNode
  variant?: 'primary' | 'ghost'
}) {
  const isPrimary = variant === 'primary'
  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      style={{
        ...mono,
        padding: '0.5rem 1.25rem',
        borderRadius: '6px',
        fontSize: '0.78rem',
        fontWeight: 500,
        cursor: disabled || loading ? 'not-allowed' : 'pointer',
        border: isPrimary ? 'none' : '1px solid var(--border)',
        background: isPrimary
          ? disabled || loading ? '#93c5fd' : 'var(--accent)'
          : 'transparent',
        color: isPrimary ? '#fff' : 'var(--text-secondary)',
        opacity: disabled && !loading ? 0.55 : 1,
        transition: 'background 0.15s, opacity 0.15s',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.4rem',
      }}
    >
      {loading && <span style={{ display: 'inline-block', animation: 'spin 0.8s linear infinite' }}>⟳</span>}
      {children}
    </button>
  )
}

// ── KeyDisplay ─────────────────────────────────────────
function KeyDisplay({ keyB64, onCopy }: { keyB64: string; onCopy?: () => void }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(keyB64).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
    onCopy?.()
  }

  return (
    <div style={{ marginBottom: '0.75rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
        <span style={label}>
          Symmetric Key{' '}
          <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0, color: 'var(--text-muted)' }}>
            (Base64)
          </span>
        </span>
        <button
          onClick={copy}
          style={{
            ...mono,
            fontSize: '0.65rem',
            background: 'none',
            border: `1px solid ${copied ? 'var(--success-border)' : 'var(--border)'}`,
            borderRadius: '4px',
            padding: '1px 8px',
            cursor: 'pointer',
            color: copied ? 'var(--success)' : 'var(--text-muted)',
            transition: 'all 0.2s',
          }}
        >
          {copied ? '✓ copied' : 'copy'}
        </button>
      </div>
      <div style={{
        ...mono,
        fontSize: '0.72rem',
        background: '#fffbeb',
        border: '1px solid var(--warn-border)',
        borderRadius: '6px',
        padding: '0.6rem 0.85rem',
        wordBreak: 'break-all',
        color: 'var(--text-primary)',
        lineHeight: 1.65,
        userSelect: 'all',
      }}>
        {keyB64}
      </div>
      <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.3rem' }}>
        ⚠ Save this key. Without it the file cannot be decrypted.
      </p>
    </div>
  )
}

// ── DownloadBtn ────────────────────────────────────────
function DownloadBtn({ data, filename, label, mimeType }: {
  data: Uint8Array
  filename: string
  label: string
  mimeType: string
}) {
  const download = () => {
    const blob = new Blob([data.buffer as ArrayBuffer], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <button onClick={download} style={{
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
      ↓ {label}
    </button>
  );
}



// ── StatusMsg ──────────────────────────────────────────
function StatusMsg({ ok, message }: { ok: boolean; message: string }) {
  return (
    <div style={{
      ...mono,
      display: 'flex',
      alignItems: 'flex-start',
      gap: '0.5rem',
      padding: '0.6rem 0.85rem',
      borderRadius: '6px',
      background: ok ? 'var(--success-bg)' : 'var(--error-bg)',
      border: `1px solid ${ok ? 'var(--success-border)' : 'var(--error-border)'}`,
      fontSize: '0.8rem',
      color: ok ? 'var(--success)' : 'var(--error)',
      wordBreak: 'break-all',
    }}>
      <span style={{ flexShrink: 0 }}>{ok ? '✓' : '✕'}</span>
      <span>{message}</span>
    </div>
  )
}

// ── EncryptPanel ───────────────────────────────────────
function EncryptPanel() {
  const [file, setFile]       = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState<{container: object, symmetricKey: Uint8Array}| null >(null);
  const [error, setError]     = useState<string | null>(null);

  const reset = () => { setResult(null); setError(null) }

  const doEncrypt = async () => {
    if (!file) return
    setLoading(true);
    reset();

    try {
      const rawData = new Uint8Array(await file.arrayBuffer());
      const symmetricModule = new SymmetricEncryption();
      const cipherObject : CipherObject = {
        data: rawData,
        file_type: file.type,
        filename: file.name,
      }


      setResult(symmetricModule.encrypt_file(cipherObject));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Encryption failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <span style={{ ...mono, fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--accent)' }}>
          01
        </span>
        <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Encrypt</span>
      </div>

      <div style={panelBody}>
        <FileDropZone
          label="File to encrypt"
          file={file}
          disabled={loading}
          onChange={f => { setFile(f); reset() }}
        />

        <Btn onClick={doEncrypt} disabled={!file} loading={loading}>
          Encrypt file
        </Btn>

        {error && <div style={{ marginTop: '0.75rem' }}><StatusMsg ok={false} message={error} /></div>}

        {result && (
          <div style={{ marginTop: '1.1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            <StatusMsg ok={true} message="File encrypted successfully." />
            <KeyDisplay keyB64={bytesToB64(result.symmetricKey)} />
            <div>
              <span style={label}>Output</span>
              <DownloadBtn data={new TextEncoder().encode(JSON.stringify(result.container))} filename={"secure_vaul.json"} label="Download container (.json)" mimeType="application/json" />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}



// ── DecryptPanel ───────────────────────────────────────
function DecryptPanel() {
  const [containerFile, setContainerFile] = useState<File | null>(null);
  const [keyInput, setKeyInput]           = useState('');
  const [loading, setLoading]             = useState(false);
  const [result, setResult]               = useState<Uint8Array | null>(null);
  const [error, setError]                 = useState<string | null>(null);
  const [container, setContainer]           = useState<any | null>(null);

  const reset = () => { setResult(null); setError(null) }

  useEffect(() => {
    if (!containerFile) return
    containerFile.text().then(json => {
      try {
        const container = JSON.parse(json)
        setContainer(container)
      } catch {
        setContainer(null)
      }
    })
  }, [containerFile])

  const doDecrypt = async () => {
    const symmetricModule = new SymmetricEncryption();
    setLoading(true);
    reset();
    try {
      if (!container) return;
      setResult(symmetricModule.decrypt_file(container, b64ToBytes(keyInput)));
    } catch (error) {
      console.error('Decryption error:', error);
      setError('Decryption failed — Wrong key or tampered container.');
    } finally {
      setLoading(false);
    }
  }

  const canRun = !!containerFile && keyInput.trim().length > 0

  return (
    <div style={panel}>
      <div style={panelHeader}>
        <span style={{ ...mono, fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
          02
        </span>
        <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>Decrypt</span>
      </div>

      <div style={panelBody}>
        <FileDropZone
          label="Encrypted container"
          accept=".json"
          file={containerFile}
          disabled={loading}
          onChange={f => { setContainerFile(f); reset() }}
        />

        <div style={{ marginBottom: '1rem' }}>
          <span style={label}>Symmetric Key (Base64)</span>
          <input
            type="text"
            value={keyInput}
            disabled={loading}
            onChange={e => { setKeyInput(e.target.value); reset() }}
            placeholder="Paste the Base64 key"
            style={{
              ...mono,
              width: '100%',
              fontSize: '0.78rem',
              padding: '0.5rem 0.85rem',
              border: '1px solid var(--border)',
              borderRadius: '6px',
              background: 'var(--bg)',
              color: 'var(--text-primary)',
              outline: 'none',
              boxSizing: 'border-box',
            }}
          />
        </div>

        <Btn onClick={doDecrypt} disabled={!canRun} loading={loading} variant="ghost">
          Decrypt file
        </Btn>

        {error && <div style={{ marginTop: '0.75rem' }}><StatusMsg ok={false} message={error} /></div>}

        {result && (
          <div style={{ marginTop: '1.1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            <StatusMsg ok={true} message={`Tag verified. File "${container?.filename ?? 'file'}" recovered.`} />
            <div>
              <span style={label}>Output</span>
              <DownloadBtn
                data={result}
                filename={container?.metaData.filename}
                label="Download decrypted file"
                mimeType={container?.metaData.file_type}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
// ── Main export ────────────────────────────────────────
export default function D2Demo() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
      <div style={{
        ...mono,
        fontSize: '0.72rem',
        color: 'var(--text-muted)',
        background: 'var(--bg-sidebar)',
        border: '1px solid var(--border)',
        borderRadius: '6px',
        padding: '0.5rem 0.9rem',
        lineHeight: 1.6,
      }}>
        <strong style={{ color: 'var(--text-secondary)' }}>Live demo</strong>
        {' '}— Runs entirely in your browser. No data is sent to any server.
      </div>

      <EncryptPanel/>
      <DecryptPanel/>

    </div>
  )
}