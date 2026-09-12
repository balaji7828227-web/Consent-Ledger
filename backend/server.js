const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 3000;
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || 'consent_ledger';

let client;
let db;
let eventsCollection;

// ============================================================================
// MONGODB CONNECTION
// ============================================================================

async function connectToMongoDB() {
  try {
    if (!MONGODB_URI) {
      throw new Error('MONGODB_URI is missing in the .env file.');
    }

    client = new MongoClient(MONGODB_URI);

    await client.connect();

    db = client.db(DB_NAME);
    eventsCollection = db.collection('events');

    // Create indexes for faster evidence queries
    await eventsCollection.createIndex({ website: 1 });
    await eventsCollection.createIndex({ tracker: 1 });
    await eventsCollection.createIndex({ timestamp: -1 });

    await eventsCollection.createIndex({ id: 1 }, { unique: true });

    console.log('==============================================');
    console.log('[MONGODB] Successfully connected to MongoDB Atlas');
    console.log(`[MONGODB] Database: ${DB_NAME}`);
    console.log('[MONGODB] Collection: events');
    console.log('==============================================');
  } catch (error) {
    console.error('[MONGODB ERROR] Failed to connect:', error.message);
    process.exit(1);
  }
}

// ============================================================================
// MIDDLEWARE CONFIGURATION
// ============================================================================

app.use(
  cors({
    origin: CORS_ORIGIN,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  })
);

app.use(express.json({ limit: '10mb' }));

app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`);
  next();
});

// ============================================================================
// ROUTES
// ============================================================================

/**
 * GET /health
 * Returns server and MongoDB connection status.
 */
app.get('/health', async (req, res) => {
  try {
    const storedEventsCount = await eventsCollection.countDocuments();

    res.status(200).json({
      status: 'healthy',
      database: 'connected',
      timestamp: new Date().toISOString(),
      uptime: `${process.uptime().toFixed(2)}s`,
      environment: process.env.NODE_ENV || 'development',
      storedEventsCount
    });
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      database: 'disconnected',
      error: error.message
    });
  }
});

/**
 * POST /api/events
 * Receives privacy tracking events and stores them in MongoDB.
 */
app.post('/api/events', async (req, res, next) => {
  try {
    const payload = req.body;

    if (
      !payload ||
      (typeof payload === 'object' &&
        !Array.isArray(payload) &&
        Object.keys(payload).length === 0)
    ) {
      return res.status(400).json({
        success: false,
        error: 'Invalid payload: Request body cannot be empty.'
      });
    }

    const rawEvents = Array.isArray(payload) ? payload : [payload];
    const receivedAt = new Date().toISOString();

    const processedEvents = rawEvents.map((item) => {
      const eventId =
        item.id ||
        item.evidenceId ||
        (crypto.randomUUID
          ? crypto.randomUUID()
          : `evt_${Date.now()}_${Math.random()
              .toString(36)
              .slice(2, 9)}`);

      return {
        id: eventId,
        receivedAt,
        ...item
      };
    });

    await eventsCollection.insertMany(processedEvents);

    const totalCount = await eventsCollection.countDocuments();

    console.log(
      `[INFO] Stored ${processedEvents.length} event(s) in MongoDB. Total events: ${totalCount}`
    );

    return res.status(201).json({
      success: true,
      message: `Successfully received and stored ${processedEvents.length} event(s) in MongoDB.`,
      storedCount: processedEvents.length,
      totalCount,
      events: processedEvents
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/events
 * Returns all events stored in MongoDB.
 */
app.get('/api/events', async (req, res, next) => {
  try {
    const events = await eventsCollection
      .find({})
      .sort({ receivedAt: -1 })
      .toArray();

    res.status(200).json({
      success: true,
      count: events.length,
      events
    });
  } catch (error) {
    next(error);
  }
});

// ============================================================================
// 404 HANDLER
// ============================================================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: `Cannot ${req.method} ${req.originalUrl}`
  });
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

app.use((err, req, res, next) => {
  console.error('[ERROR] Unhandled error:', err);
  // Handle duplicate MongoDB event IDs
  if (err.code === 11000) {
    return res.status(409).json({
      success: false,
      error: 'Duplicate event already exists.'
    });
  }

  if (
    err instanceof SyntaxError &&
    err.status === 400 &&
    'body' in err
  ) {
    return res.status(400).json({
      success: false,
      error: 'Malformed JSON in request body.'
    });
  }

  return res.status(500).json({
    success: false,
    error: 'Internal server error.'
  });
});

// ============================================================================
// SERVER INITIALIZATION
// ============================================================================

let server;

async function startServer() {
  await connectToMongoDB();

  server = app.listen(PORT, () => {
    console.log('==============================================');
    console.log(`Consent Ledger Backend running on port ${PORT}`);
    console.log(`Health endpoint: http://localhost:${PORT}/health`);
    console.log(`Events API:      http://localhost:${PORT}/api/events`);
    console.log('==============================================');
  });
}

startServer();

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

const handleShutdown = async (signal) => {
  console.log(`\n[INFO] Received ${signal}. Gracefully shutting down...`);

  if (server) {
    server.close(async () => {
      console.log('[INFO] HTTP server closed.');

      if (client) {
        await client.close();
        console.log('[INFO] MongoDB connection closed.');
      }

      process.exit(0);
    });
  } else {
    if (client) {
      await client.close();
    }

    process.exit(0);
  }

  setTimeout(() => {
    console.error('[ERROR] Forced shutdown after timeout.');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => handleShutdown('SIGTERM'));
process.on('SIGINT', () => handleShutdown('SIGINT'));

module.exports = app;