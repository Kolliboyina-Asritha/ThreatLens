import { createApp } from './app.js';
import { connectDB } from './config/db.js';
import { env } from './config/env.js';

const startServer = async () => {
  try {
    await connectDB();
    const app = createApp();

    const server = app.listen(env.PORT, () => {
      console.log(`===========================================`);
      console.log(` ThreatLens AI - Phase 1 Engine Active`);
      console.log(` Port:    ${env.PORT}`);
      console.log(` Mode:    ${env.NODE_ENV}`);
      console.log(` API Base: http://localhost:${env.PORT}/api`);
      console.log(`===========================================`);
    });

    const shutdown = async (signal) => {
      console.log(`\n[Server] Received ${signal}. Gracefully shutting down...`);
      server.close(() => {
        console.log('[Server] HTTP listener closed.');
        process.exit(0);
      });
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  } catch (error) {
    console.error(`[Server] Startup failure: ${error.message}`);
    process.exit(1);
  }
};

startServer();
