/**
 * ZeroID Widget — Modal Component
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * UX TARGET: 3 taps, <15 seconds. Apple Pay level frictionless.
 * - Tap 1: "Verify" button (in host app)
 * - Tap 2: Hold ID in frame → auto-capture (no manual shutter)
 * - Tap 3: Biometric confirm (Face ID / fingerprint via passkey)
 * - Auto-dismiss on success — user is back in the app
 *
 * IMPORTANT: No crypto terminology in ANY user-facing string.
 * No "wallet", "blockchain", "proof", "nullifier", "ZK", "credential".
 * Users see: "Verify your identity" → "Confirmed ✓"
 */

import React, { useCallback, useEffect, useRef } from 'react';
import type { ProofRequirement, Proof } from '@zeroid/sdk';
import { useZeroId, type UseZeroIdConfig } from './useZeroId.js';
import { ProofStatus } from './ProofStatus.js';

export interface ZeroIdModalProps {
  /** ZeroID API key */
  apiKey: string;
  /** Proof requirements for verification */
  requirements: ProofRequirement[];
  /** Called when verification succeeds — auto-dismiss after this */
  onSuccess: (proof: Proof, publicSignals: string[]) => void;
  /** Called when verification fails */
  onError: (error: string) => void;
  /** Whether the modal is open */
  isOpen?: boolean;
  /** Called when user requests to close the modal */
  onClose?: () => void;
  /** User ID to verify */
  userId?: string;
  /** Optional prover config override */
  proverConfig?: UseZeroIdConfig['prover'];
  /** Custom base URL for the API */
  baseUrl?: string;
  /** Auto-dismiss delay after success in ms (default: 1500) */
  autoDismissMs?: number;
  /** Auto-start verification when modal opens (default: true) */
  autoStart?: boolean;
}

const modalStyles = {
  overlay: {
    position: 'fixed' as const,
    inset: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.6)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 10000,
    backdropFilter: 'blur(4px)',
    animation: 'zeroid-fadeIn 0.2s ease',
  },
  modal: {
    backgroundColor: '#ffffff',
    borderRadius: '20px',
    width: '100%',
    maxWidth: '400px',
    margin: '16px',
    boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
    overflow: 'hidden',
    animation: 'zeroid-slideUp 0.3s ease',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  },
  header: {
    padding: '28px 24px 0',
    textAlign: 'center' as const,
  },
  title: {
    fontSize: '20px',
    fontWeight: 700,
    color: '#111827',
    margin: 0,
  },
  subtitle: {
    fontSize: '14px',
    color: '#6b7280',
    margin: '6px 0 0',
    lineHeight: 1.5,
  },
  closeBtn: {
    position: 'absolute' as const,
    top: '16px',
    right: '16px',
    background: 'none',
    border: 'none',
    fontSize: '18px',
    cursor: 'pointer',
    color: '#9ca3af',
    padding: '4px 8px',
    borderRadius: '8px',
    lineHeight: 1,
  },
  body: {
    padding: '24px',
  },
  /** PRIVACY: Shown during processing to reassure users */
  privacyBadge: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '6px',
    padding: '8px 16px',
    margin: '16px 0 0',
    borderRadius: '20px',
    backgroundColor: '#f0fdf4',
    border: '1px solid #bbf7d0',
    fontSize: '12px',
    color: '#166534',
    fontWeight: 500,
  },
  cameraArea: {
    width: '100%',
    aspectRatio: '4/3',
    borderRadius: '12px',
    backgroundColor: '#000',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    overflow: 'hidden',
    position: 'relative' as const,
    marginBottom: '16px',
  },
  cameraOverlay: {
    position: 'absolute' as const,
    inset: 0,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  cameraFrame: {
    width: '80%',
    height: '60%',
    border: '2px solid rgba(255, 255, 255, 0.6)',
    borderRadius: '12px',
  },
  cameraHint: {
    position: 'absolute' as const,
    bottom: '12px',
    left: 0,
    right: 0,
    textAlign: 'center' as const,
    color: '#ffffff',
    fontSize: '13px',
    fontWeight: 500,
    textShadow: '0 1px 3px rgba(0,0,0,0.5)',
  },
  successContainer: {
    textAlign: 'center' as const,
    padding: '32px 0',
  },
  successIcon: {
    fontSize: '56px',
    lineHeight: 1,
    marginBottom: '16px',
  },
  successTitle: {
    fontSize: '20px',
    fontWeight: 700,
    color: '#111827',
    margin: '0 0 6px',
  },
  successSubtitle: {
    fontSize: '14px',
    color: '#6b7280',
  },
  footer: {
    padding: '0 24px 24px',
  },
  button: {
    width: '100%',
    padding: '14px 24px',
    borderRadius: '12px',
    border: 'none',
    fontSize: '16px',
    fontWeight: 600,
    cursor: 'pointer',
    transition: 'all 0.2s ease',
    backgroundColor: '#111827',
    color: '#ffffff',
  },
  brand: {
    textAlign: 'center' as const,
    padding: '12px',
    fontSize: '11px',
    color: '#c9cdd3',
  },
};

// User-facing step labels — NO crypto terminology
const STEPS = [
  { icon: '📷', label: 'Scanning your ID...' },
  { icon: '🔒', label: 'Verifying securely...' },
  { icon: '✨', label: 'Almost done...' },
];

/**
 * Drop-in identity verification modal.
 * 3 taps, <15 seconds, auto-dismiss on success.
 *
 * NO crypto terminology in any user-facing string.
 * Users see a simple "verify identity" flow, not a ZK proof generation pipeline.
 */
export const ZeroIdModal: React.FC<ZeroIdModalProps> = ({
  apiKey,
  requirements,
  onSuccess,
  onError,
  isOpen = true,
  onClose,
  userId = 'anonymous',
  proverConfig,
  baseUrl,
  autoDismissMs = 1500,
  autoStart = true,
}) => {
  const { startVerification, proof, publicSignals, status, error, reset } =
    useZeroId({
      apiKey,
      baseUrl,
      prover: proverConfig,
    });

  const overlayRef = useRef<HTMLDivElement>(null);
  const hasStarted = useRef(false);

  // Auto-start verification when modal opens
  useEffect(() => {
    if (isOpen && autoStart && !hasStarted.current && status === 'idle') {
      hasStarted.current = true;
      startVerification(userId, requirements);
    }
  }, [isOpen, autoStart, status, startVerification, userId, requirements]);

  // Reset on close
  useEffect(() => {
    if (!isOpen) hasStarted.current = false;
  }, [isOpen]);

  // Auto-dismiss on success
  useEffect(() => {
    if (status === 'complete' && proof && publicSignals) {
      onSuccess(proof, publicSignals);
      if (autoDismissMs > 0) {
        const timer = setTimeout(() => {
          reset();
          onClose?.();
        }, autoDismissMs);
        return () => clearTimeout(timer);
      }
    }
  }, [status, proof, publicSignals, onSuccess, onClose, reset, autoDismissMs]);

  // Notify parent on error
  useEffect(() => {
    if (status === 'error' && error) onError(error);
  }, [status, error, onError]);

  const handleClose = useCallback(() => {
    reset();
    hasStarted.current = false;
    onClose?.();
  }, [reset, onClose]);

  const handleRetry = useCallback(() => {
    reset();
    startVerification(userId, requirements);
  }, [reset, startVerification, userId, requirements]);

  // Close on overlay click
  const handleOverlayClick = useCallback(
    (e: React.MouseEvent) => {
      if (e.target === overlayRef.current) handleClose();
    },
    [handleClose],
  );

  // Close on Escape
  useEffect(() => {
    if (!isOpen) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') handleClose();
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [isOpen, handleClose]);

  if (!isOpen) return null;

  const isDone = status === 'complete';
  const isError = status === 'error';
  const isWorking = !isDone && !isError && status !== 'idle';

  return (
    <>
      <style>{`
        @keyframes zeroid-fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes zeroid-slideUp { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        @keyframes zeroid-scan { 0% { top: 10%; } 50% { top: 80%; } 100% { top: 10%; } }
      `}</style>
      <div ref={overlayRef} style={modalStyles.overlay} onClick={handleOverlayClick}>
        <div style={{ ...modalStyles.modal, position: 'relative' }} role="dialog" aria-modal="true" aria-label="Identity Verification">
          {/* Close button */}
          <button style={modalStyles.closeBtn} onClick={handleClose} aria-label="Close" type="button">✕</button>

          {/* === SUCCESS STATE === */}
          {isDone && (
            <div style={modalStyles.body}>
              <div style={modalStyles.successContainer}>
                <div style={modalStyles.successIcon}>✅</div>
                <p style={modalStyles.successTitle}>You're verified</p>
                <p style={modalStyles.successSubtitle}>Your identity has been confirmed</p>
              </div>
            </div>
          )}

          {/* === WORKING STATE (camera / processing) === */}
          {isWorking && (
            <>
              <div style={modalStyles.header}>
                <h2 style={modalStyles.title}>Verify your identity</h2>
                <p style={modalStyles.subtitle}>
                  {status === 'kyc_pending'
                    ? 'Hold your ID in the frame'
                    : 'Verifying securely...'}
                </p>
              </div>
              <div style={modalStyles.body}>
                {/* Simulated camera area (auto-capture) */}
                {status === 'kyc_pending' && (
                  <div style={modalStyles.cameraArea}>
                    <div style={modalStyles.cameraOverlay}>
                      <div style={modalStyles.cameraFrame} />
                    </div>
                    <div style={modalStyles.cameraHint}>
                      Auto-capturing — hold steady
                    </div>
                  </div>
                )}

                <ProofStatus status={status} error={error} />

                {/* PRIVACY: Reassure users during processing */}
                <div style={modalStyles.privacyBadge}>
                  <span>🛡️</span>
                  <span>Your data stays on your device</span>
                </div>
              </div>
            </>
          )}

          {/* === ERROR STATE === */}
          {isError && (
            <>
              <div style={modalStyles.header}>
                <h2 style={modalStyles.title}>Something went wrong</h2>
                <p style={modalStyles.subtitle}>{error ?? 'Please try again'}</p>
              </div>
              <div style={modalStyles.footer}>
                <button style={modalStyles.button} onClick={handleRetry} type="button">
                  Try again
                </button>
              </div>
            </>
          )}

          {/* === IDLE STATE (should auto-start, but fallback) === */}
          {status === 'idle' && !autoStart && (
            <>
              <div style={modalStyles.header}>
                <h2 style={modalStyles.title}>Verify your identity</h2>
                <p style={modalStyles.subtitle}>Quick and private — takes about 10 seconds</p>
              </div>
              <div style={{ ...modalStyles.footer, paddingTop: '24px' }}>
                <button
                  style={modalStyles.button}
                  onClick={() => startVerification(userId, requirements)}
                  type="button"
                >
                  Continue
                </button>
              </div>
            </>
          )}

          {/* Branding — subtle */}
          <div style={modalStyles.brand}>
            Secured by ZeroID
          </div>
        </div>
      </div>
    </>
  );
};
