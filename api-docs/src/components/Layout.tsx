import React, { useState } from 'react'
import { NavLink} from 'react-router-dom'

const modules = [
  { path: '/',   label: 'Overview',             badge: null },
  { path: '/d2', label: 'Symmetric Encryption', badge: 'D2' },
  { path: '/d3', label: 'Hybrid Encryption',    badge: 'D3' },
  { path: '/d5', label: 'Authenticated Cipher', badge: 'D5' },
  { path: '/d6', label: 'Key Management',       badge: 'D6' },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      {/* ── Header ── */}
      <header style={{
        height: 'var(--header-h)',
        background: 'var(--bg-card)',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        alignItems: 'center',
        padding: '0 1.5rem',
        gap: '0.75rem',
        position: 'fixed',
        top: 0, left: 0, right: 0,
        zIndex: 100,
      }}>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontWeight: 600,
          fontSize: '0.9rem',
          color: 'var(--text-primary)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
        }}>
          <span style={{ fontSize: '1rem' }}>🔐</span>
          Secure Digital Document Vault
        </span>
        <span style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '0.65rem',
          background: 'var(--tag-bg)',
          color: 'var(--tag-text)',
          padding: '2px 8px',
          borderRadius: '4px',
          fontWeight: 500,
        }}>
          Cryptography Docs
        </span>

        {/* Mobile toggle */}
        <button
          onClick={() => setMobileOpen(o => !o)}
          style={{
            marginLeft: 'auto',
            display: 'none',
            background: 'none',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            padding: '4px 10px',
            cursor: 'pointer',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.75rem',
            color: 'var(--text-secondary)',
          }}
          className="mobile-toggle"
          aria-label="Toggle nav"
        >
          ☰
        </button>
      </header>

      <div style={{ display: 'flex', marginTop: 'var(--header-h)', flex: 1 }}>
        {/* ── Sidebar ── */}
        <nav
          className={`sidebar ${mobileOpen ? 'open' : ''}`}
          style={{
            width: 'var(--sidebar-w)',
            background: 'var(--bg-sidebar)',
            borderRight: '1px solid var(--border)',
            position: 'fixed',
            top: 'var(--header-h)',
            bottom: 0,
            overflowY: 'auto',
            padding: '1.75rem 0',
          }}
        >
          <div style={{
            fontSize: '0.65rem',
            fontWeight: 600,
            letterSpacing: '0.1em',
            textTransform: 'uppercase',
            color: 'var(--text-muted)',
            padding: '0 1.25rem',
            marginBottom: '0.5rem',
          }}>
            Modules
          </div>

          {modules.map(m => (
            <NavLink
              key={m.path}
              to={m.path}
              end={m.path === '/'}
              onClick={() => setMobileOpen(false)}
              style={({ isActive }) => ({
                display: 'flex',
                alignItems: 'center',
                gap: '0.6rem',
                padding: '0.45rem 1.25rem',
                fontSize: '0.875rem',
                color: isActive ? 'var(--accent)' : 'var(--text-secondary)',
                borderLeft: isActive ? '2px solid var(--accent)' : '2px solid transparent',
                background: isActive ? 'var(--accent-dim)' : 'transparent',
                textDecoration: 'none',
                transition: 'all 0.15s',
                fontWeight: isActive ? 500 : 400,
              })}
            >
              {m.label}
              {m.badge && (
                <span style={{
                  marginLeft: 'auto',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.6rem',
                  fontWeight: 600,
                  background: 'var(--tag-bg)',
                  color: 'var(--tag-text)',
                  padding: '1px 6px',
                  borderRadius: '4px',
                }}>
                  {m.badge}
                </span>
              )}
            </NavLink>
          ))}

          {/* In-page anchor nav — populated by active page */}
          <div id="sidebar-anchors" style={{ marginTop: '2rem' }} />
        </nav>

        {/* ── Main content ── */}
        <main style={{
          marginLeft: 'var(--sidebar-w)',
          flex: 1,
          padding: '3rem 3.5rem',
          maxWidth: 'calc(var(--sidebar-w) + var(--content-max))',
        }}>
          {children}
        </main>
      </div>

      <style>{`
        @media (max-width: 768px) {
          .sidebar { transform: translateX(-100%); transition: transform 0.25s; z-index: 90; }
          .sidebar.open { transform: translateX(0); }
          main { margin-left: 0 !important; padding: 2rem 1.25rem !important; }
          .mobile-toggle { display: block !important; }
        }
      `}</style>
    </div>
  )
}
