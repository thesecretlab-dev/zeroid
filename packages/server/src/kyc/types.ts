/**
 * ZeroID Server — KYC Types
 * © thesecretlab | "Verify the human. Drop the liability."
 */

/** Supported document types for KYC verification */
export type DocumentType = 'passport' | 'drivers_license' | 'national_id';

/** Raw KYC data submitted for verification */
export interface KycSubmission {
  /** User's full legal name */
  fullName: string;
  /** Date of birth (ISO 8601 date string) */
  dateOfBirth: string;
  /** ISO 3166-1 numeric country code */
  countryCode: number;
  /** Document type used for verification */
  documentType: DocumentType;
  /** Document number */
  documentNumber: string;
}

/** Result of KYC verification (extracted + validated data) */
export interface KycResult {
  /** Whether the KYC check passed */
  passed: boolean;
  /** User's full legal name (verified) */
  fullName: string;
  /** Date of birth (ISO 8601) */
  dateOfBirth: string;
  /** ISO 3166-1 numeric country code */
  countryCode: number;
  /** Document type */
  documentType: DocumentType;
  /** Document number */
  documentNumber: string;
  /** Confidence score (0-1) */
  confidence: number;
  /** Provider-specific reference ID */
  providerRef?: string;
  /** Timestamp of verification */
  verifiedAt: number;
}

/** KYC provider interface */
export interface KycProvider {
  /** Provider name */
  name: string;
  /** Verify a KYC submission and return the result */
  verify(submission: KycSubmission): Promise<KycResult>;
}
