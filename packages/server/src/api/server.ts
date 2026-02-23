/**
 * ZeroID Server — Express Application
 * © thesecretlab | "Verify the human. Drop the liability."
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { apiKeyAuth, rateLimit } from './middleware.js';
import verifyRouter from './routes/verify.js';
import credentialRouter from './routes/credential.js';
import proofRouter from './routes/proof.js';
import aggregateRouter from './routes/aggregate.js';

/**
 * Create and configure the Express application.
 */
export function createApp(): express.Application {
  const app = express();

  // --- Global Middleware ---
  app.use(helmet());
  app.use(cors({
    origin: process.env.ZEROID_CORS_ORIGIN ?? '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-ZeroID-Version'],
  }));
  app.use(express.json({ limit: '1mb' }));

  // --- Health Check (no auth required) ---
  app.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'zeroid',
      version: '0.1.0',
      timestamp: new Date().toISOString(),
    });
  });

  // --- API Routes (auth + rate limiting required) ---
  app.use('/api/v1/verify', apiKeyAuth, rateLimit, verifyRouter);
  app.use('/api/v1/credential', apiKeyAuth, rateLimit, credentialRouter);
  app.use('/api/v1/proof/verify', apiKeyAuth, rateLimit, proofRouter);
  app.use('/api/v1/proof/aggregate', apiKeyAuth, rateLimit, aggregateRouter);

  // --- 404 Handler ---
  app.use((_req, res) => {
    res.status(404).json({
      error: 'Not Found',
      message: 'The requested endpoint does not exist',
    });
  });

  // --- Global Error Handler ---
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
      error: 'Internal Server Error',
      message: process.env.NODE_ENV === 'production'
        ? 'An unexpected error occurred'
        : err.message,
    });
  });

  return app;
}
