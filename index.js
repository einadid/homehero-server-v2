// ============================================================
// HOMEHERO BACKEND SERVER - VERCEL COMPATIBLE VERSION (FIXED)
// ============================================================

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// ============================================================
// MIDDLEWARE CONFIGURATION (FIXED CORS)
// ============================================================
//hello don
// ✅ CORS Configuration - Single, Complete Setup
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:5174',
  'http://localhost:3000',
  'https://homehero-client.vercel.app',
  'https://homehero-server-v2.vercel.app'
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('Blocked by CORS:', origin);
      callback(null, true); // Allow all for debugging - change to callback(new Error('Not allowed by CORS')) in strict mode
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'authorization', 'X-Requested-With'],
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));

// ✅ Handle preflight requests for all routes (Important for Mobile)
app.options('*', cors(corsOptions));

app.use(express.json());
app.use(cookieParser());

// Request Logger (Development)
if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    if (req.headers.authorization) {
      console.log('Auth Header Present:', req.headers.authorization.substring(0, 20) + '...');
    }
    next();
  });
}

// ============================================================
// MONGODB CONNECTION - SERVERLESS COMPATIBLE
// ============================================================

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@homehero.4vzhoed.mongodb.net/?retryWrites=true&w=majority&appName=HomeHero`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Global DB Reference for Serverless
let cachedDb = null;

// Connect to Database Function
async function connectDB() {
  if (cachedDb) {
    return cachedDb;
  }

  try {
    await client.connect();
    cachedDb = client.db(process.env.DB_NAME || 'homeHeroDB');
    console.log('✅ MongoDB Connected Successfully!');
    return cachedDb;
  } catch (error) {
    console.error('❌ MongoDB Connection Error:', error);
    throw error;
  }
}

// Middleware to Attach DB Collections to Request
app.use(async (req, res, next) => {
  try {
    const db = await connectDB();
    req.db = db;
    req.servicesCollection = db.collection('services');
    req.bookingsCollection = db.collection('bookings');
    req.usersCollection = db.collection('users');
    next();
  } catch (error) {
    console.error('Database Middleware Error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Database Connection Failed',
      error: process.env.NODE_ENV !== 'production' ? error.message : undefined
    });
  }
});

// ============================================================
// ✅ JWT VERIFICATION MIDDLEWARE (FIXED - Robust Token Extraction)
// ============================================================

const verifyToken = (req, res, next) => {
  // ✅ Check token from multiple sources (Cookie + Header with case handling)
  const cookieToken = req.cookies?.token;
  
  // Handle both lowercase and uppercase Authorization header
  const authHeader = req.headers.authorization || req.headers.Authorization;
  const headerToken = authHeader?.startsWith('Bearer ') 
    ? authHeader.split(' ')[1] 
    : authHeader?.split(' ')[1];
  
  // Also check localStorage token sent as custom header (fallback)
  const customToken = req.headers['x-access-token'];
  
  const token = cookieToken || headerToken || customToken;

  console.log('Token Sources Check:', {
    hasCookie: !!cookieToken,
    hasHeader: !!headerToken,
    hasCustom: !!customToken,
    finalToken: token ? 'Present' : 'Missing'
  });

  if (!token) {
    return res.status(401).json({ 
      success: false,
      message: 'Unauthorized access - No token provided',
      hint: 'Please login again'
    });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.error('JWT Verification Error:', err.message);
      return res.status(401).json({ 
        success: false,
        message: 'Unauthorized access - Invalid or expired token',
        error: err.message
      });
    }
    req.user = decoded;
    console.log('Token verified for:', decoded.email);
    next();
  });
};

// ============================================================
// ROOT & HEALTH CHECK ROUTES
// ============================================================

// Root route
app.get('/', (req, res) => {
  res.json({
    message: '🏠 HomeHero API Server is Running!',
    version: '2.3.0',
    status: 'OK',
    timestamp: new Date().toISOString(),
    authMethod: 'Cookie + Bearer Token + LocalStorage Support',
    endpoints: {
      auth: {
        login: 'POST /jwt',
        logout: 'POST /logout',
      },
      services: {
        getAll: 'GET /services',
        getAllNoPagination: 'GET /services/all',
        getFeatured: 'GET /services/featured',
        getTopRated: 'GET /services/top-rated',
        getPopular: 'GET /services/popular',
        getById: 'GET /services/:id',
        getByProvider: 'GET /services/provider/:email',
        create: 'POST /services',
        update: 'PUT /services/:id',
        delete: 'DELETE /services/:id',
        addReview: 'POST /services/:id/reviews',
      },
      bookings: {
        create: 'POST /bookings',
        getUserBookings: 'GET /bookings/user/:email',
        getProviderBookings: 'GET /bookings/provider/:email',
        getById: 'GET /bookings/:id',
        updateStatus: 'PATCH /bookings/:id/status',
        delete: 'DELETE /bookings/:id',
      },
      users: {
        save: 'POST /users',
        getByEmail: 'GET /users/:email',
        getStats: 'GET /users/stats/:email',
      },
      categories: 'GET /categories',
      stats: {
        platform: 'GET /stats/platform',
        provider: 'GET /stats/provider/:email',
      },
    },
  });
});

// Health check
app.get('/health', async (req, res) => {
  try {
    await req.db.admin().ping();
    res.json({
      status: 'OK',
      message: 'Server is healthy',
      database: 'Connected',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
    });
  } catch (error) {
    res.status(500).json({
      status: 'ERROR',
      message: 'Database connection issue',
      timestamp: new Date().toISOString(),
    });
  }
});

// ============================================================
// ✅ AUTH ROUTES (FIXED - Better Cookie + Token Response)
// ============================================================

// Generate JWT Token
app.post('/jwt', async (req, res) => {
  try {
    const user = req.body;

    if (!user?.email) {
      return res.status(400).json({ 
        success: false,
        message: 'Email is required' 
      });
    }

    const token = jwt.sign(
      { email: user.email },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '7d' }
    );

    console.log('JWT Generated for:', user.email);

    // ✅ Cookie settings for cross-site (Vercel)
    const cookieOptions = {
      httpOnly: true,
      secure: true, // Always true for production
      sameSite: 'none', // Required for cross-site cookies
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    };

    // Set cookie AND return token in response body
    res
      .cookie('token', token, cookieOptions)
      .json({ 
        success: true, 
        message: 'Token generated successfully',
        token, // ✅ Token included for localStorage storage
        expiresIn: '7d'
      });
  } catch (error) {
    console.error('JWT Generation Error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to generate token' 
    });
  }
});

// Clear JWT Token (Logout)
app.post('/logout', (req, res) => {
  try {
    res
      .clearCookie('token', {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        path: '/',
      })
      .json({ 
        success: true, 
        message: 'Logged out successfully' 
      });
  } catch (error) {
    console.error('Logout Error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to logout' 
    });
  }
});

// ============================================================
// USER ROUTES
// ============================================================

// Save or update user in database
app.post('/users', async (req, res) => {
  try {
    const user = req.body;

    if (!user?.email) {
      return res.status(400).json({ 
        success: false,
        message: 'Email is required' 
      });
    }

    const query = { email: user.email };
    const existingUser = await req.usersCollection.findOne(query);

    if (existingUser) {
      await req.usersCollection.updateOne(query, {
        $set: { lastLoginAt: new Date().toISOString() },
      });
      return res.json({ 
        success: true,
        message: 'User login recorded',
        insertedId: null 
      });
    }

    const newUser = {
      ...user,
      role: user.role || 'user',
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
    };

    const result = await req.usersCollection.insertOne(newUser);
    res.status(201).json({ 
      success: true,
      message: 'User created successfully', 
      insertedId: result.insertedId 
    });
  } catch (error) {
    console.error('Error saving user:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to save user' 
    });
  }
});

// Get user by email
app.get('/users/:email', verifyToken, async (req, res) => {
  try {
    const email = req.params.email;

    if (req.user.email !== email) {
      return res.status(403).json({ 
        success: false,
        message: 'Forbidden access' 
      });
    }

    const user = await req.usersCollection.findOne({ email });

    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found' 
      });
    }

    res.json({
      success: true,
      data: user
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch user' 
    });
  }
});

// Get user statistics
app.get('/users/stats/:email', verifyToken, async (req, res) => {
  try {
    const email = req.params.email;

    if (req.user.email !== email) {
      return res.status(403).json({ 
        success: false,
        message: 'Forbidden access' 
      });
    }

    const totalServices = await req.servicesCollection.countDocuments({
      providerEmail: email,
    });

    const services = await req.servicesCollection
      .find({ providerEmail: email })
      .toArray();

    const serviceIds = services.map((s) => s._id.toString());

    const providerBookings = await req.bookingsCollection
      .find({ serviceId: { $in: serviceIds } })
      .toArray();

    const userBookings = await req.bookingsCollection
      .find({ userEmail: email })
      .toArray();

    const totalBookingsReceived = providerBookings.length;
    const completedBookings = providerBookings.filter(
      (b) => b.status === 'completed'
    ).length;
    const pendingBookings = providerBookings.filter(
      (b) => b.status === 'pending'
    ).length;
    const totalRevenue = providerBookings
      .filter((b) => b.status === 'completed')
      .reduce((sum, b) => sum + (parseFloat(b.price) || 0), 0);

    let totalRating = 0;
    let totalReviews = 0;

    services.forEach((service) => {
      if (service.reviews && service.reviews.length > 0) {
        service.reviews.forEach((review) => {
          totalRating += review.rating || 0;
          totalReviews++;
        });
      }
    });

    const averageRating = totalReviews > 0 
      ? parseFloat((totalRating / totalReviews).toFixed(1)) 
      : 0;

    res.json({
      success: true,
      data: {
        totalServices,
        totalBookingsReceived,
        completedBookings,
        pendingBookings,
        totalRevenue: parseFloat(totalRevenue.toFixed(2)),
        averageRating,
        totalReviews,
        myBookings: userBookings.length,
      },
    });
  } catch (error) {
    console.error('Error fetching user stats:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch statistics' 
    });
  }
});

// ============================================================
// SERVICE ROUTES
// ============================================================

// Get ALL services (no pagination)
app.get('/services/all', async (req, res) => {
  try {
    const services = await req.servicesCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      success: true,
      data: services,
      count: services.length,
    });
  } catch (error) {
    console.error('Error fetching all services:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch services' 
    });
  }
});

// Get featured services (latest)
app.get('/services/featured', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 6;

    const services = await req.servicesCollection
      .find({})
      .sort({ createdAt: -1 })
      .limit(limit)
      .toArray();

    res.json({
      success: true,
      data: services,
    });
  } catch (error) {
    console.error('Error fetching featured services:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch featured services' 
    });
  }
});

// Get top rated services
app.get('/services/top-rated', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 6;

    const services = await req.servicesCollection
      .aggregate([
        {
          $addFields: {
            avgRating: {
              $cond: {
                if: { $gt: [{ $size: { $ifNull: ['$reviews', []] } }, 0] },
                then: { $avg: '$reviews.rating' },
                else: 0,
              },
            },
            reviewCount: { $size: { $ifNull: ['$reviews', []] } },
          },
        },
        { $match: { reviewCount: { $gt: 0 } } },
        { $sort: { avgRating: -1, reviewCount: -1 } },
        { $limit: limit },
      ])
      .toArray();

    res.json({
      success: true,
      data: services,
    });
  } catch (error) {
    console.error('Error fetching top rated services:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch top rated services' 
    });
  }
});

// Get popular services (most booked)
app.get('/services/popular', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 6;

    const popularServices = await req.bookingsCollection
      .aggregate([
        { $group: { _id: '$serviceId', bookingCount: { $sum: 1 } } },
        { $sort: { bookingCount: -1 } },
        { $limit: limit },
      ])
      .toArray();

    const serviceIds = popularServices.map((s) => {
      try {
        return new ObjectId(s._id);
      } catch {
        return null;
      }
    }).filter(id => id !== null);

    const services = await req.servicesCollection
      .find({ _id: { $in: serviceIds } })
      .toArray();

    const servicesWithCount = services.map((service) => {
      const booking = popularServices.find(
        (b) => b._id === service._id.toString()
      );
      return {
        ...service,
        bookingCount: booking?.bookingCount || 0,
      };
    });

    servicesWithCount.sort((a, b) => b.bookingCount - a.bookingCount);

    res.json({
      success: true,
      data: servicesWithCount,
    });
  } catch (error) {
    console.error('Error fetching popular services:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch popular services' 
    });
  }
});

// Get services with filtering, search, sorting & OPTIONAL pagination
app.get('/services', async (req, res) => {
  try {
    const {
      search,
      category,
      minPrice,
      maxPrice,
      sortBy,
      sortOrder = 'desc',
      page,
      limit,
    } = req.query;

    const filter = {};

    if (search) {
      filter.$or = [
        { serviceName: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { category: { $regex: search, $options: 'i' } },
      ];
    }

    if (category && category !== 'all') {
      filter.category = category;
    }

    if (minPrice || maxPrice) {
      filter.price = {};
      if (minPrice) filter.price.$gte = parseFloat(minPrice);
      if (maxPrice) filter.price.$lte = parseFloat(maxPrice);
    }

    let sort = {};
    switch (sortBy) {
      case 'price-low':
        sort = { price: 1 };
        break;
      case 'price-high':
        sort = { price: -1 };
        break;
      case 'name-asc':
        sort = { serviceName: 1 };
        break;
      case 'name-desc':
        sort = { serviceName: -1 };
        break;
      case 'oldest':
        sort = { createdAt: 1 };
        break;
      case 'newest':
      default:
        sort = { createdAt: -1 };
    }

    const total = await req.servicesCollection.countDocuments(filter);

    let query = req.servicesCollection.find(filter).sort(sort);

    let paginationInfo = null;

    if (limit) {
      const limitNum = parseInt(limit);
      const pageNum = parseInt(page) || 1;
      const skip = (pageNum - 1) * limitNum;

      query = query.skip(skip).limit(limitNum);

      paginationInfo = {
        total,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(total / limitNum),
        hasNextPage: pageNum * limitNum < total,
        hasPrevPage: pageNum > 1,
      };
    }

    const services = await query.toArray();

    const response = {
      success: true,
      data: services,
      count: services.length,
      total: total,
    };

    if (paginationInfo) {
      response.pagination = paginationInfo;
    }

    res.json(response);
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch services' 
    });
  }
});

// Get single service by ID
app.get('/services/:id', async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid service ID' 
      });
    }

    const service = await req.servicesCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!service) {
      return res.status(404).json({ 
        success: false,
        message: 'Service not found' 
      });
    }

    res.json({
      success: true,
      data: service,
    });
  } catch (error) {
    console.error('Error fetching service:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch service' 
    });
  }
});

// Get services by provider email
app.get('/services/provider/:email', verifyToken, async (req, res) => {
  try {
    const email = req.params.email;

    if (req.user.email !== email) {
      return res.status(403).json({ 
        success: false,
        message: 'Forbidden access' 
      });
    }

    const services = await req.servicesCollection
      .find({ providerEmail: email })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      success: true,
      data: services,
      count: services.length,
    });
  } catch (error) {
    console.error('Error fetching provider services:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch services' 
    });
  }
});

// Add new service
app.post('/services', verifyToken, async (req, res) => {
  try {
    const serviceData = req.body;

    const requiredFields = [
      'serviceName',
      'category',
      'price',
      'description',
      'imageUrl',
      'providerName',
      'providerEmail',
    ];

    const missingFields = requiredFields.filter(
      (field) => !serviceData[field]
    );

    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing required fields: ${missingFields.join(', ')}`,
      });
    }

    if (serviceData.providerEmail !== req.user.email) {
      return res.status(403).json({
        success: false,
        message: 'You can only add services for your own account'
      });
    }

    const newService = {
      serviceName: serviceData.serviceName,
      category: serviceData.category,
      price: parseFloat(serviceData.price),
      description: serviceData.description,
      imageUrl: serviceData.imageUrl,
      providerName: serviceData.providerName,
      providerEmail: serviceData.providerEmail,
      providerImage: serviceData.providerImage || null,
      location: serviceData.location || null,
      duration: serviceData.duration || null,
      reviews: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const result = await req.servicesCollection.insertOne(newService);

    res.status(201).json({
      success: true,
      message: 'Service added successfully',
      insertedId: result.insertedId,
      data: { ...newService, _id: result.insertedId },
    });
  } catch (error) {
    console.error('Error adding service:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to add service' 
    });
  }
});

// Update service
app.put('/services/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid service ID' 
      });
    }

    const existingService = await req.servicesCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!existingService) {
      return res.status(404).json({ 
        success: false,
        message: 'Service not found' 
      });
    }

    if (existingService.providerEmail !== req.user.email) {
      return res.status(403).json({ 
        success: false,
        message: 'You can only update your own services' 
      });
    }

    const updateDoc = {
      $set: {
        serviceName: updateData.serviceName,
        category: updateData.category,
        price: parseFloat(updateData.price),
        description: updateData.description,
        imageUrl: updateData.imageUrl,
        location: updateData.location || existingService.location,
        duration: updateData.duration || existingService.duration,
        updatedAt: new Date().toISOString(),
      },
    };

    const result = await req.servicesCollection.updateOne(
      { _id: new ObjectId(id) },
      updateDoc
    );

    res.json({
      success: true,
      message: 'Service updated successfully',
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error('Error updating service:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to update service' 
    });
  }
});

// Delete service
app.delete('/services/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid service ID' 
      });
    }

    const existingService = await req.servicesCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!existingService) {
      return res.status(404).json({ 
        success: false,
        message: 'Service not found' 
      });
    }

    if (existingService.providerEmail !== req.user.email) {
      return res.status(403).json({ 
        success: false,
        message: 'You can only delete your own services' 
      });
    }

    const result = await req.servicesCollection.deleteOne({
      _id: new ObjectId(id),
    });

    await req.bookingsCollection.deleteMany({ serviceId: id });

    res.json({
      success: true,
      message: 'Service deleted successfully',
      deletedCount: result.deletedCount,
    });
  } catch (error) {
    console.error('Error deleting service:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to delete service' 
    });
  }
});

// Add review to service
app.post('/services/:id/reviews', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { rating, comment, bookingId } = req.body;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid service ID' 
      });
    }

    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ 
        success: false,
        message: 'Rating must be between 1 and 5' 
      });
    }

    const service = await req.servicesCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!service) {
      return res.status(404).json({ 
        success: false,
        message: 'Service not found' 
      });
    }

    const booking = await req.bookingsCollection.findOne({
      serviceId: id,
      userEmail: req.user.email,
      status: 'completed',
      hasReviewed: { $ne: true },
    });

    if (!booking) {
      return res.status(400).json({
        success: false,
        message: 'You can only review services you have booked and completed',
      });
    }

    const review = {
      _id: new ObjectId(),
      rating: parseInt(rating),
      comment: comment || '',
      userEmail: req.user.email,
      userName: booking.userName,
      userPhoto: booking.userPhoto || null,
      createdAt: new Date().toISOString(),
    };

    await req.servicesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $push: { reviews: review } }
    );

    await req.bookingsCollection.updateOne(
      { _id: booking._id },
      { $set: { hasReviewed: true } }
    );

    res.status(201).json({
      success: true,
      message: 'Review added successfully',
      data: review,
    });
  } catch (error) {
    console.error('Error adding review:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to add review' 
    });
  }
});

// ============================================================
// BOOKING ROUTES
// ============================================================

// Create new booking
app.post('/bookings', verifyToken, async (req, res) => {
  try {
    const bookingData = req.body;

    const requiredFields = [
      'serviceId',
      'serviceName',
      'serviceImage',
      'providerEmail',
      'providerName',
      'userEmail',
      'userName',
      'bookingDate',
      'price',
    ];

    const missingFields = requiredFields.filter(
      (field) => !bookingData[field]
    );

    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing required fields: ${missingFields.join(', ')}`,
      });
    }

    if (bookingData.userEmail !== req.user.email) {
      return res.status(403).json({
        success: false,
        message: 'You can only create bookings for yourself'
      });
    }

    if (!ObjectId.isValid(bookingData.serviceId)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid service ID' 
      });
    }

    const service = await req.servicesCollection.findOne({
      _id: new ObjectId(bookingData.serviceId),
    });

    if (!service) {
      return res.status(404).json({ 
        success: false,
        message: 'Service not found' 
      });
    }

    if (service.providerEmail === bookingData.userEmail) {
      return res.status(400).json({ 
        success: false,
        message: 'You cannot book your own service' 
      });
    }

    const newBooking = {
      serviceId: bookingData.serviceId,
      serviceName: bookingData.serviceName,
      serviceImage: bookingData.serviceImage,
      providerEmail: bookingData.providerEmail,
      providerName: bookingData.providerName,
      userEmail: bookingData.userEmail,
      userName: bookingData.userName,
      userPhoto: bookingData.userPhoto || null,
      userPhone: bookingData.userPhone || null,
      bookingDate: bookingData.bookingDate,
      specialInstructions: bookingData.specialInstructions || '',
      price: parseFloat(bookingData.price),
      status: 'pending',
      hasReviewed: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const result = await req.bookingsCollection.insertOne(newBooking);

    res.status(201).json({
      success: true,
      message: 'Booking created successfully',
      insertedId: result.insertedId,
      data: { ...newBooking, _id: result.insertedId },
    });
  } catch (error) {
    console.error('Error creating booking:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to create booking' 
    });
  }
});

// Get user's bookings (as customer)
app.get('/bookings/user/:email', verifyToken, async (req, res) => {
  try {
    const email = req.params.email;

    if (req.user.email !== email) {
      return res.status(403).json({ 
        success: false,
        message: 'Forbidden access' 
      });
    }

    const bookings = await req.bookingsCollection
      .find({ userEmail: email })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      success: true,
      data: bookings,
      count: bookings.length,
    });
  } catch (error) {
    console.error('Error fetching user bookings:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch bookings' 
    });
  }
});

// Get bookings for provider's services (as service provider)
app.get('/bookings/provider/:email', verifyToken, async (req, res) => {
  try {
    const email = req.params.email;

    if (req.user.email !== email) {
      return res.status(403).json({ 
        success: false,
        message: 'Forbidden access' 
      });
    }

    const bookings = await req.bookingsCollection
      .find({ providerEmail: email })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      success: true,
      data: bookings,
      count: bookings.length,
    });
  } catch (error) {
    console.error('Error fetching provider bookings:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch bookings' 
    });
  }
});

// Get single booking by ID
app.get('/bookings/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid booking ID' 
      });
    }

    const booking = await req.bookingsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!booking) {
      return res.status(404).json({ 
        success: false,
        message: 'Booking not found' 
      });
    }

    if (
      booking.userEmail !== req.user.email &&
      booking.providerEmail !== req.user.email
    ) {
      return res.status(403).json({ 
        success: false,
        message: 'Forbidden access' 
      });
    }

    res.json({
      success: true,
      data: booking,
    });
  } catch (error) {
    console.error('Error fetching booking:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch booking' 
    });
  }
});

// Update booking status
app.patch('/bookings/:id/status', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid booking ID' 
      });
    }

    const validStatuses = [
      'pending',
      'confirmed',
      'in-progress',
      'completed',
      'cancelled',
    ];

    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: `Invalid status. Must be one of: ${validStatuses.join(', ')}`,
      });
    }

    const booking = await req.bookingsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!booking) {
      return res.status(404).json({ 
        success: false,
        message: 'Booking not found' 
      });
    }

    if (status === 'cancelled') {
      if (booking.userEmail !== req.user.email && booking.providerEmail !== req.user.email) {
        return res.status(403).json({ 
          success: false,
          message: 'You do not have permission to cancel this booking' 
        });
      }
    } else {
      if (booking.providerEmail !== req.user.email) {
        return res.status(403).json({ 
          success: false,
          message: 'Only the service provider can update booking status' 
        });
      }
    }

    const result = await req.bookingsCollection.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          status,
          updatedAt: new Date().toISOString(),
        },
      }
    );

    res.json({
      success: true,
      message: `Booking status updated to ${status}`,
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error('Error updating booking status:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to update booking status' 
    });
  }
});

// Delete booking
app.delete('/bookings/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid booking ID' 
      });
    }

    const booking = await req.bookingsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!booking) {
      return res.status(404).json({ 
        success: false,
        message: 'Booking not found' 
      });
    }

    if (booking.userEmail !== req.user.email) {
      return res.status(403).json({ 
        success: false,
        message: 'You can only delete your own bookings' 
      });
    }

    if (booking.status === 'completed') {
      return res.status(400).json({ 
        success: false,
        message: 'Cannot delete completed bookings' 
      });
    }

    const result = await req.bookingsCollection.deleteOne({
      _id: new ObjectId(id),
    });

    res.json({
      success: true,
      message: 'Booking deleted successfully',
      deletedCount: result.deletedCount,
    });
  } catch (error) {
    console.error('Error deleting booking:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to delete booking' 
    });
  }
});

// ============================================================
// CATEGORY ROUTES
// ============================================================

app.get('/categories', async (req, res) => {
  try {
    const categories = await req.servicesCollection
      .aggregate([
        { $group: { _id: '$category', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $project: { category: '$_id', count: 1, _id: 0 } },
      ])
      .toArray();

    res.json({
      success: true,
      data: categories,
    });
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch categories' 
    });
  }
});

// ============================================================
// STATISTICS ROUTES
// ============================================================

app.get('/stats/platform', async (req, res) => {
  try {
    const totalServices = await req.servicesCollection.countDocuments();
    const totalBookings = await req.bookingsCollection.countDocuments();
    const completedBookings = await req.bookingsCollection.countDocuments({
      status: 'completed',
    });
    const totalUsers = await req.usersCollection.countDocuments();

    const providers = await req.servicesCollection.distinct('providerEmail');

    res.json({
      success: true,
      data: {
        totalServices,
        totalBookings,
        completedBookings,
        totalUsers,
        totalProviders: providers.length,
      },
    });
  } catch (error) {
    console.error('Error fetching platform stats:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch statistics' 
    });
  }
});

app.get('/stats/provider/:email', verifyToken, async (req, res) => {
  try {
    const email = req.params.email;

    if (req.user.email !== email) {
      return res.status(403).json({ 
        success: false,
        message: 'Forbidden access' 
      });
    }

    const services = await req.servicesCollection
      .find({ providerEmail: email })
      .toArray();

    const serviceIds = services.map((s) => s._id.toString());

    const bookings = await req.bookingsCollection
      .find({ serviceId: { $in: serviceIds } })
      .toArray();

    const totalBookings = bookings.length;
    const pendingBookings = bookings.filter((b) => b.status === 'pending').length;
    const confirmedBookings = bookings.filter((b) => b.status === 'confirmed').length;
    const inProgressBookings = bookings.filter((b) => b.status === 'in-progress').length;
    const completedBookings = bookings.filter((b) => b.status === 'completed').length;
    const cancelledBookings = bookings.filter((b) => b.status === 'cancelled').length;

    const totalRevenue = bookings
      .filter((b) => b.status === 'completed')
      .reduce((sum, b) => sum + (parseFloat(b.price) || 0), 0);

    let totalRating = 0;
    let totalReviews = 0;

    services.forEach((service) => {
      if (service.reviews?.length > 0) {
        service.reviews.forEach((review) => {
          totalRating += review.rating || 0;
          totalReviews++;
        });
      }
    });

    const averageRating = totalReviews > 0
      ? parseFloat((totalRating / totalReviews).toFixed(1))
      : 0;

    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    const monthlyRevenue = await req.bookingsCollection
      .aggregate([
        {
          $match: {
            serviceId: { $in: serviceIds },
            status: 'completed',
            createdAt: { $gte: sixMonthsAgo.toISOString() },
          },
        },
        {
          $group: {
            _id: { $substr: ['$createdAt', 0, 7] },
            revenue: { $sum: '$price' },
            count: { $sum: 1 },
          },
        },
        { $sort: { _id: 1 } },
      ])
      .toArray();

    res.json({
      success: true,
      data: {
        totalServices: services.length,
        totalBookings,
        pendingBookings,
        confirmedBookings,
        inProgressBookings,
        completedBookings,
        cancelledBookings,
        totalRevenue: parseFloat(totalRevenue.toFixed(2)),
        averageRating,
        totalReviews,
        monthlyRevenue,
      },
    });
  } catch (error) {
    console.error('Error fetching provider stats:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to fetch statistics' 
    });
  }
});

// ============================================================
// 404 & ERROR HANDLERS
// ============================================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
    requestedUrl: req.originalUrl,
    availableEndpoints: '/',
  });
});

app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV !== 'production' ? err.message : undefined,
  });
});

// ============================================================
// START SERVER (Local Development)
// ============================================================

if (process.env.NODE_ENV !== 'production') {
  app.listen(port, () => {
    console.log(`
  ╔═══════════════════════════════════════════════╗
  ║                                               ║
  ║   🏠 HomeHero Server is Running!              ║
  ║                                               ║
  ║   📍 Local:    http://localhost:${port}          ║
  ║   🌐 Network:  Check your IP                  ║
  ║   📝 API Docs: http://localhost:${port}/         ║
  ║   🔐 Auth:     Cookie + Bearer Token          ║
  ║                                               ║
  ╚═══════════════════════════════════════════════╝
    `);
  });
}

// ============================================================
// EXPORT FOR VERCEL SERVERLESS
// ============================================================

module.exports = app;