/**
 * ZeroID Server — API Middleware
 * © thesecretlab | "Verify the human. Drop the liability."
 *
 * API key authentication, rate limiting, and request validation.
 */

import type { Request, Response, NextFunction } from 'express';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import { z, type ZodSchema } from 'zod';

// --- API Key Authentication ---

/** Valid API keys (in production, load from database) */
const API_KEYS = new Set(
  (process.env.ZEROID_API_KEYS ?? 'zid_dev_testkey123').split(',').map((k) => k.trim()),
);

/**
 * Middleware: Validate API key from Authorization header.
 * Expects: `Authorization: Bearer <api_key>`
 */
export function apiKeyAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Missing or invalid Authorization header. Use: Bearer <api_key>',
    });
    return;
  }

  const apiKey = authHeader.slice(7);
  if (!API_KEYS.has(apiKey)) {
    res.status(403).json({
      error: 'Forbidden',
      message: 'Invalid API key',
    });
    return;
  }

  // Attach API key to request for rate limiting
  (req as any).apiKey = apiKey;
  next();
}

// --- Rate Limiting ---

const rateLimiter = new RateLimiterMemory({
  points: 100,    // 100 requests
  duration: 60,   // per 60 seconds
  keyPrefix: 'zeroid_rl',
});

/**
 * Middleware: Rate limit requests by API key (100 req/min).
 */
export async function rateLimit(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const key = (req as any).apiKey ?? req.ip ?? 'unknown';
  try {
    await rateLimiter.consume(key);
    next();
  } catch {
    res.status(429).json({
      error: 'Too Many Requests',
      message: 'Rate limit exceeded. Maximum 100 requests per minute.',
    });
  }
}

// --- Request Validation ---

/**
 * Create a middleware that validates the request body against a Zod schema.
 */
export function validateBody<T>(schema: ZodSchema<T>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      res.status(400).json({
        error: 'Validation Error',
        message: 'Invalid request body',
        details: result.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      });
      return;
    }
    (req as any).validated = result.data;
    next();
  };
}

// --- Common Zod Schemas ---

export const verifyRequestSchema = z.object({
  userId: z.string().min(1).max(256),
  requirements: z.array(
    z.object({
      type: z.enum(['age_gte', 'country_not', 'sanctions_clear', 'sybil_unique']),
      value: z.number().int(),
    }),
  ).min(1).max(10),
});

export const credentialRequestSchema = z.object({
  fullName: z.string().min(1).max(512),
  dateOfBirth: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  countryCode: z.number().int().min(1).max(999),
  documentType: z.enum(['passport', 'drivers_license', 'national_id']),
  documentNumber: z.string().min(1).max(128),
  /** ERC-4337 smart account address to bind the credential to */
  boundAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/).optional(),
  /** Requested verification level (0-4, progressive disclosure) */
  level: z.number().int().min(0).max(4).optional(),
});

export const proofVerifyRequestSchema = z.object({
  proof: z.record(z.unknown()),
  publicSignals: z.array(z.string()).min(1).max(50),
});

export const aggregateRequestSchema = z.object({
  proofs: z.array(
    z.object({
      proof: z.record(z.unknown()),
      publicSignals: z.array(z.string()).min(1).max(50),
    }),
  ).min(1).max(100),
});
