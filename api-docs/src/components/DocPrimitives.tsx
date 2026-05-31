import React, { useState } from 'react'

/* ── Section wrapper ─────────────────────────────────── */
export function Section({
  id,
  title,
  children,
  style,
}: {
  id?: string
  title?: string
  children: React.ReactNode
  style?: React.CSSProperties
}) {
  return (
    <section
      id={id}
      style={{
        marginBottom: '3rem',
        paddingTop: '0.25rem',
        ...style,
      }}
    >
      {title && (
        <h2 style={{
          fontSize: '1.05rem',
          fontWeight: 600,
          color: 'var(--text-primary)',
          borderBottom: '1px solid var(--border)',
          paddingBottom: '0.5rem',
          marginBottom: '1.25rem',
          fontFamily: 'var(--font-sans)',
          letterSpacing: '-0.01em',
        }}>
          {title}
        </h2>
      )}
      {children}
    </section>
  )
}

/* ── Page title block ────────────────────────────────── */
export function PageHeader({
  badge,
  title,
  subtitle,
}: {
  badge: string
  title: string
  subtitle: string
}) {
  return (
    <div style={{ marginBottom: '3rem', paddingBottom: '2rem', borderBottom: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '0.68rem',
          fontWeight: 600,
          background: 'var(--tag-bg)',
          color: 'var(--tag-text)',
          padding: '3px 10px',
          borderRadius: '4px',
          letterSpacing: '0.04em',
        }}>
          {badge}
        </span>
        <a
          href="#demo"
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.72rem',
            fontWeight: 500,
            color: 'var(--accent)',
            textDecoration: 'none',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.3rem',
            padding: '4px 12px',
            border: '1px solid var(--accent)',
            borderRadius: '6px',
            background: 'var(--accent-dim)',
          }}
        >
          ↓ Jump to demo
        </a>
      </div>
      <h1 style={{
        fontSize: '1.9rem',
        fontWeight: 600,
        letterSpacing: '-0.03em',
        color: 'var(--text-primary)',
        marginBottom: '0.5rem',
        lineHeight: 1.2,
        fontFamily: 'var(--font-sans)',
      }}>
        {title}
      </h1>
      <p style={{ color: 'var(--text-secondary)', fontSize: '0.975rem', maxWidth: '600px' }}>
        {subtitle}
      </p>
    </div>
  )
}

/* ── Sub-heading (h3) ────────────────────────────────── */
export function SubHeading({ children }: { children: React.ReactNode }) {
  return (
    <h3 style={{
      fontFamily: 'var(--font-mono)',
      fontSize: '0.82rem',
      fontWeight: 500,
      color: 'var(--accent)',
      margin: '1.75rem 0 0.6rem',
      letterSpacing: '0.02em',
    }}>
      {children}
    </h3>
  )
}

/* ── Prose paragraph ─────────────────────────────────── */
export function P({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <p style={{
      color: 'var(--text-secondary)',
      marginBottom: '0.9rem',
      fontSize: '0.925rem',
      lineHeight: 1.8,
      ...style,
    }}>
      {children}
    </p>
  )
}

/* ── Inline code ─────────────────────────────────────── */
export function Code({ children }: { children: React.ReactNode }) {
  return (
    <code style={{
      fontFamily: 'var(--font-mono)',
      fontSize: '0.82em',
      background: '#e8e4dc',
      color: '#c0392b',
      padding: '1px 5px',
      borderRadius: '4px',
    }}>
      {children}
    </code>
  )
}

/* ── Code block ──────────────────────────────────────── */
export function CodeBlock({ code, lang = 'typescript' }: { code: string; lang?: string }) {
  const [copied, setCopied] = useState(false)

  const copy = () => {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div style={{
      margin: '1.25rem 0',
      borderRadius: '8px',
      border: '1px solid var(--border)',
      overflow: 'hidden',
      fontSize: '0.82rem',
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: '#22252f',
        padding: '0.45rem 1rem',
        borderBottom: '1px solid #333',
      }}>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '0.65rem',
          color: '#6b7280',
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
        }}>
          {lang}
        </span>
        <button
          onClick={copy}
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.65rem',
            background: 'none',
            border: '1px solid #444',
            borderRadius: '4px',
            padding: '2px 8px',
            cursor: 'pointer',
            color: copied ? '#4ade80' : '#6b7280',
            borderColor: copied ? '#4ade80' : '#444',
            transition: 'all 0.2s',
          }}
        >
          {copied ? '✓ copied' : 'copy'}
        </button>
      </div>
      <pre style={{
        background: 'var(--bg-code)',
        margin: 0,
        padding: '1.1rem 1.25rem',
        overflowX: 'auto',
        lineHeight: 1.65,
      }}>
        <code style={{
          fontFamily: 'var(--font-mono)',
          color: 'var(--text-code)',
          fontSize: '0.82rem',
        }}>
          {code}
        </code>
      </pre>
    </div>
  )
}

/* ── Callout ─────────────────────────────────────────── */
type CalloutKind = 'info' | 'warn' | 'danger'
const calloutStyles: Record<CalloutKind, { bg: string; border: string; icon: string; labelColor: string; label: string }> = {
  info:   { bg: '#eff6ff', border: '#93c5fd', icon: 'ℹ', labelColor: '#1e40af', label: 'Note' },
  warn:   { bg: 'var(--warn-bg)', border: 'var(--warn-border)', icon: '⚠', labelColor: 'var(--warn-text)', label: 'Warning' },
  danger: { bg: 'var(--error-bg)', border: '#fca5a5', icon: '!', labelColor: 'var(--error)', label: 'Important' },
}

export function Callout({ kind = 'info', children }: { kind?: CalloutKind; children: React.ReactNode }) {
  const s = calloutStyles[kind]
  return (
    <div style={{
      background: s.bg,
      borderLeft: `3px solid ${s.border}`,
      borderRadius: '0 6px 6px 0',
      padding: '0.8rem 1.1rem',
      margin: '1.25rem 0',
      fontSize: '0.88rem',
    }}>
      <span style={{ fontWeight: 600, color: s.labelColor, marginRight: '0.4rem' }}>
        {s.icon} {s.label}:
      </span>
      <span style={{ color: 'var(--text-secondary)' }}>{children}</span>
    </div>
  )
}

/* ── API parameter table ─────────────────────────────── */
export interface Param {
  name: string
  type: string
  description: string
  required?: boolean
}

export function ParamTable({ params }: { params: Param[] }) {
  return (
    <div style={{ overflowX: 'auto', margin: '0.75rem 0 1.5rem' }}>
      <table style={{
        width: '100%',
        borderCollapse: 'collapse',
        fontSize: '0.85rem',
        fontFamily: 'var(--font-sans)',
      }}>
        <thead>
          <tr style={{ background: 'var(--bg-sidebar)' }}>
            {['Parameter', 'Type', 'Description'].map(h => (
              <th key={h} style={{
                padding: '0.5rem 0.9rem',
                textAlign: 'left',
                fontWeight: 600,
                fontSize: '0.72rem',
                textTransform: 'uppercase',
                letterSpacing: '0.07em',
                color: 'var(--text-muted)',
                border: '1px solid var(--border)',
              }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {params.map(p => (
            <tr key={p.name} style={{ borderBottom: '1px solid var(--border-light)' }}>
              <td style={{ padding: '0.55rem 0.9rem', border: '1px solid var(--border-light)', verticalAlign: 'top' }}>
                <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent)', fontWeight: 500 }}>
                  {p.name}
                </code>
                {p.required === false && (
                  <span style={{ marginLeft: '6px', fontSize: '0.65rem', color: 'var(--text-muted)' }}>optional</span>
                )}
              </td>
              <td style={{ padding: '0.55rem 0.9rem', border: '1px solid var(--border-light)', verticalAlign: 'top' }}>
                <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#c0392b' }}>{p.type}</code>
              </td>
              <td style={{ padding: '0.55rem 0.9rem', border: '1px solid var(--border-light)', color: 'var(--text-secondary)', verticalAlign: 'top', lineHeight: 1.6 }}>
                {p.description}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* ── Returns block ───────────────────────────────────── */
export function Returns({ type, description }: { type: string; description: string }) {
  return (
    <div style={{
      display: 'flex',
      gap: '0.75rem',
      alignItems: 'flex-start',
      background: 'var(--bg-sidebar)',
      border: '1px solid var(--border)',
      borderRadius: '6px',
      padding: '0.65rem 1rem',
      margin: '0.75rem 0 1.5rem',
      fontSize: '0.85rem',
    }}>
      <span style={{ color: 'var(--text-muted)', fontWeight: 600, whiteSpace: 'nowrap', fontSize: '0.72rem', paddingTop: '2px' }}>
        RETURNS
      </span>
      <div>
        <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: '#c0392b' }}>{type}</code>
        <span style={{ color: 'var(--text-secondary)', marginLeft: '0.5rem' }}>— {description}</span>
      </div>
    </div>
  )
}

/* ── Throws block ────────────────────────────────────── */
export function Throws({ description }: { description: string }) {
  return (
    <div style={{
      display: 'flex',
      gap: '0.75rem',
      alignItems: 'flex-start',
      background: 'var(--error-bg)',
      border: '1px solid var(--error-border)',
      borderRadius: '6px',
      padding: '0.65rem 1rem',
      margin: '0.75rem 0 1.5rem',
      fontSize: '0.85rem',
    }}>
      <span style={{ color: 'var(--error)', fontWeight: 600, whiteSpace: 'nowrap', fontSize: '0.72rem', paddingTop: '2px' }}>
        THROWS
      </span>
      <span style={{ color: 'var(--text-secondary)' }}>{description}</span>
    </div>
  )
}

/* ── Method signature heading ────────────────────────── */
export function MethodSignature({ signature }: { signature: string }) {
  return (
    <div style={{
      fontFamily: 'var(--font-mono)',
      fontSize: '0.88rem',
      background: '#f0f4ff',
      border: '1px solid #c7d4f8',
      borderRadius: '6px',
      padding: '0.65rem 1rem',
      margin: '1.5rem 0 0.75rem',
      color: 'var(--text-primary)',
      overflowX: 'auto',
      whiteSpace: 'pre',
    }}>
      {signature}
    </div>
  )
}