/**
 * ZeroID Widget — Proof Status Component
 * © thesecretlab | "Verify the human. Drop the liability."
 */

import React from 'react';
import type { ZeroIdStatus } from './useZeroId.js';

export interface ProofStatusProps {
  /** Current verification status */
  status: ZeroIdStatus;
  /** Error message (when status === 'error') */
  error?: string | null;
}

// User-facing labels — NO crypto terminology ("ZK proof", "nullifier", etc.)
// Users should feel like Apple Pay, not a blockchain lab.
const STATUS_CONFIG: Record<
  ZeroIdStatus,
  { label: string; icon: string; color: string; animate: boolean }
> = {
  idle: { label: 'Ready', icon: '🔐', color: '#6b7280', animate: false },
  initializing: { label: 'Starting...', icon: '⚙️', color: '#3b82f6', animate: true },
  kyc_pending: { label: 'Reading your ID...', icon: '📷', color: '#f59e0b', animate: true },
  generating_proof: { label: 'Confirming securely...', icon: '🔒', color: '#8b5cf6', animate: true },
  complete: { label: 'Verified ✓', icon: '✅', color: '#10b981', animate: false },
  error: { label: 'Something went wrong', icon: '⚠️', color: '#ef4444', animate: false },
};

const styles = {
  container: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '16px 20px',
    borderRadius: '12px',
    backgroundColor: '#f9fafb',
    border: '1px solid #e5e7eb',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    transition: 'all 0.3s ease',
  } as React.CSSProperties,
  icon: {
    fontSize: '24px',
    lineHeight: 1,
    flexShrink: 0,
  } as React.CSSProperties,
  content: {
    flex: 1,
    minWidth: 0,
  } as React.CSSProperties,
  label: {
    fontSize: '14px',
    fontWeight: 600,
    margin: 0,
    lineHeight: 1.4,
  } as React.CSSProperties,
  error: {
    fontSize: '12px',
    color: '#ef4444',
    margin: '4px 0 0',
    lineHeight: 1.4,
  } as React.CSSProperties,
  spinner: {
    width: '20px',
    height: '20px',
    border: '2px solid #e5e7eb',
    borderTopColor: '#3b82f6',
    borderRadius: '50%',
    animation: 'zeroid-spin 0.8s linear infinite',
    flexShrink: 0,
  } as React.CSSProperties,
  progressBar: {
    height: '4px',
    borderRadius: '2px',
    backgroundColor: '#e5e7eb',
    overflow: 'hidden',
    marginTop: '8px',
  } as React.CSSProperties,
  progressFill: {
    height: '100%',
    borderRadius: '2px',
    transition: 'width 0.5s ease',
  } as React.CSSProperties,
};

const PROGRESS_MAP: Record<ZeroIdStatus, number> = {
  idle: 0,
  initializing: 15,
  kyc_pending: 45,
  generating_proof: 75,
  complete: 100,
  error: 0,
};

/**
 * Displays the current status of ZeroID proof generation with animated states.
 */
export const ProofStatus: React.FC<ProofStatusProps> = ({ status, error }) => {
  const config = STATUS_CONFIG[status];
  const progress = PROGRESS_MAP[status];

  return (
    <>
      <style>{`
        @keyframes zeroid-spin {
          to { transform: rotate(360deg); }
        }
        @keyframes zeroid-pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.6; }
        }
      `}</style>
      <div
        style={{
          ...styles.container,
          borderColor: config.color + '40',
          ...(config.animate ? { animation: 'zeroid-pulse 2s ease-in-out infinite' } : {}),
        }}
        role="status"
        aria-live="polite"
      >
        <span style={styles.icon} aria-hidden="true">
          {config.icon}
        </span>
        <div style={styles.content}>
          <p style={{ ...styles.label, color: config.color }}>{config.label}</p>
          {status === 'error' && error && <p style={styles.error}>{error}</p>}
          {config.animate && (
            <div style={styles.progressBar}>
              <div
                style={{
                  ...styles.progressFill,
                  width: `${progress}%`,
                  backgroundColor: config.color,
                }}
              />
            </div>
          )}
        </div>
        {config.animate && <div style={styles.spinner} aria-hidden="true" />}
      </div>
    </>
  );
};
