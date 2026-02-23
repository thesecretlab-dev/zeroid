/**
 * ZeroID SDK — API Client
 * © thesecretlab | "Verify the human. Drop the liability."
 */

import type {
  ZeroIdConfig,
  VerificationRequest,
  VerificationStatusResponse,
  Credential,
  VerificationResult,
  KycData,
  PasskeyOptions,
} from './types.js';

const DEFAULT_BASE_URL = 'https://api.zeroid.io';
const DEFAULT_TIMEOUT = 30_000;

/**
 * ZeroID API client for integrating zero-knowledge KYC into applications.
 *
 * @example
 * ```ts
 * const zeroid = new ZeroID({ apiKey: 'zid_live_...' });
 * const { id } = await zeroid.requestVerification('user-123', [
 *   { type: 'age_gte', value: 18 },
 *   { type: 'country_not', value: 408 },
 * ]);
 * ```
 */
export class ZeroID {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeout: number;

  constructor(config: ZeroIdConfig) {
    if (!config.apiKey) {
      throw new Error('ZeroID: apiKey is required');
    }
    this.apiKey = config.apiKey;
    this.baseUrl = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.timeout = config.timeout ?? DEFAULT_TIMEOUT;
  }

  /**
   * Start a KYC verification flow for a user.
   * Returns a verification ID to track the process.
   */
  async requestVerification(
    userId: string,
    requirements: VerificationRequest['requirements'],
  ): Promise<{ id: string; status: string }> {
    return this.post<{ id: string; status: string }>('/api/v1/verify', {
      userId,
      requirements,
    });
  }

  /**
   * Issue a signed credential after KYC data has been verified.
   * The raw PII is encrypted to escrow and never stored in plaintext.
   */
  async issueCredential(kycData: KycData): Promise<Credential> {
    return this.post<Credential>('/api/v1/credential', kycData);
  }

  /**
   * Get the current status of a verification, including proof if ready.
   */
  async getProofStatus(proofId: string): Promise<VerificationStatusResponse> {
    return this.get<VerificationStatusResponse>(`/api/v1/verify/${proofId}`);
  }

  /**
   * Submit a proof for on-chain or off-chain verification.
   */
  async verifyProof(
    proof: unknown,
    publicSignals: string[],
  ): Promise<VerificationResult> {
    return this.post<VerificationResult>('/api/v1/proof/verify', {
      proof,
      publicSignals,
    });
  }

  /**
   * Request passkey registration options from the server.
   * The passkey becomes the owner of the user's ERC-4337 smart account.
   */
  async getPasskeyOptions(userId: string): Promise<PasskeyOptions> {
    return this.post<PasskeyOptions>('/api/v1/passkey/register', { userId });
  }

  /**
   * Bind a credential to an ERC-4337 smart account address.
   * Once bound, the credential can prove "my owner is verified" on-chain.
   */
  async bindCredential(
    credentialId: string,
    boundAddress: string,
  ): Promise<Credential> {
    return this.post<Credential>('/api/v1/credential/bind', {
      credentialId,
      boundAddress,
    });
  }

  // ---- HTTP helpers ----

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
          'X-ZeroID-Version': '1',
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => 'Unknown error');
        throw new Error(
          `ZeroID API error ${response.status}: ${errorBody}`,
        );
      }

      return (await response.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  private get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  private post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }
}
