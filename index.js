// ============================================================
// HOMEHERO BACKEND SERVER - MOBILE COMPATIBLE VERSION
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
// CORS - Mobile Friendly
// ============================================================

const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:5174',
  'http://localhost:3000',
  'https://homehero-client.vercel.app',
  'https://homehero-server-v2.vercel.app'
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(null, true); // Allow all for now
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'authorization', 'X-Requested-With'],
}));

app.options('*', cors());
app.use(express.json());
app.use(cookieParser());

// ============================================================
// MongoDB Connection
// ============================================================

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@homehero.4vzhoed.mongodb.net/?retryWrites=true&w=majority&appName=HomeHero`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let cachedDb = null;

async function connectDB() {
  if (cachedDb) return cachedDb;
  
  try {
    await client.connect();
    cachedDb = client.db(process.env.DB_NAME || 'homeHeroDB');
    console.log('✅ MongoDB Connected!');
    return cachedDb;
  } catch (error) {
    console.error('❌ MongoDB Error:', error);
    throw error;
  }
}

// DB Middleware
app.use(async (req, res, next) => {
  try {
    const db = await connectDB();
    req.db = db;
    req.servicesCollection = db.collection('services');
    req.bookingsCollection = db.collection('bookings');
    req.usersCollection = db.collection('users');
    next();
  } catch (error) {
    res.status(500).json({ success: false, message: 'Database Error' });
  }
});

// ============================================================
// ✅ JWT VERIFICATION - MOBILE FRIENDLY (No Cookie Dependency)
// ============================================================

const verifyToken = (req, res, next) => {
  // ✅ শুধু Authorization Header থেকে token নেওয়া হবে
  // Cookie আর দরকার নেই - Mobile এ কাজ করবে না
  
  const authHeader = req.headers.authorization || req.headers.Authorization;
  
  console.log('🔍 Auth Header:', authHeader ? 'Present' : 'Missing');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      success: false,
      message: 'Unauthorized - No token provided',
      hint: 'Send token in Authorization header as: Bearer <token>'
    });
  }
  
  const token = authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ 
      success: false,
      message: 'Unauthorized - Token missing after Bearer'
    });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.error('❌ JWT Error:', err.message);
      return res.status(401).json({ 
        success: false,
        message: 'Unauthorized - Invalid or expired token',
        error: err.message
      });
    }
    
    console.log('✅ Token verified for:', decoded.email);
    req.user = decoded;
    next();
  });
};

// ============================================================
// Routes
// ============================================================

app.get('/', (req, res) => {
  res.json({
    message: '🏠 HomeHero API - Mobile Compatible',
    version: '2.4.0',
    status: 'OK',
    authMethod: 'Bearer Token Only (No Cookie)',
  });
});

// ============================================================
// ✅ JWT Route - Returns token in response body only
// ============================================================

app.post('/jwt', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        success: false,
        message: 'Email is required' 
      });
    }

    const token = jwt.sign(
      { email },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: '7d' }
    );

    console.log('🎫 Token generated for:', email);

    // ✅ শুধু Response body তে token পাঠানো - Cookie নয়
    res.json({ 
      success: true, 
      message: 'Token generated',
      token,
      expiresIn: '7 days'
    });
    
  } catch (error) {
    console.error('JWT Error:', error);
    res.status(500).json({ success: false, message: 'Failed to generate token' });
  }
});

// Logout
app.post('/logout', (req, res) => {
  res.json({ success: true, message: 'Logged out' });
});

// ============================================================
// USER ROUTES
// ============================================================

app.post('/users', async (req, res) => {
  try {
    const user = req.body;
    if (!user?.email) {
      return res.status(400).json({ success: false, message: 'Email required' });
    }

    const existingUser = await req.usersCollection.findOne({ email: user.email });

    if (existingUser) {
      await req.usersCollection.updateOne(
        { email: user.email },
        { $set: { lastLoginAt: new Date().toISOString() } }
      );
      return res.json({ success: true, message: 'Login recorded' });
    }

    const result = await req.usersCollection.insertOne({
      ...user,
      role: 'user',
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
    });

    res.status(201).json({ success: true, insertedId: result.insertedId });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to save user' });
  }
});

app.get('/users/:email', verifyToken, async (req, res) => {
  try {
    if (req.user.email !== req.params.email) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    
    const user = await req.usersCollection.findOne({ email: req.params.email });
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    res.json({ success: true, data: user });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch user' });
  }
});

app.get('/users/stats/:email', verifyToken, async (req, res) => {
  try {
    const email = req.params.email;
    if (req.user.email !== email) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    const totalServices = await req.servicesCollection.countDocuments({ providerEmail: email });
    const services = await req.servicesCollection.find({ providerEmail: email }).toArray();
    const serviceIds = services.map(s => s._id.toString());

    const providerBookings = await req.bookingsCollection.find({ serviceId: { $in: serviceIds } }).toArray();
    const userBookings = await req.bookingsCollection.find({ userEmail: email }).toArray();

    let totalRating = 0, totalReviews = 0;
    services.forEach(s => {
      if (s.reviews?.length) {
        s.reviews.forEach(r => { totalRating += r.rating || 0; totalReviews++; });
      }
    });

    res.json({
      success: true,
      data: {
        totalServices,
        totalBookingsReceived: providerBookings.length,
        completedBookings: providerBookings.filter(b => b.status === 'completed').length,
        pendingBookings: providerBookings.filter(b => b.status === 'pending').length,
        totalRevenue: providerBookings.filter(b => b.status === 'completed').reduce((sum, b) => sum + (parseFloat(b.price) || 0), 0),
        averageRating: totalReviews > 0 ? parseFloat((totalRating / totalReviews).toFixed(1)) : 0,
        totalReviews,
        myBookings: userBookings.length,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch stats' });
  }
});

// ============================================================
// SERVICE ROUTES
// ============================================================

app.get('/services/all', async (req, res) => {
  try {
    const services = await req.servicesCollection.find({}).sort({ createdAt: -1 }).toArray();
    res.json({ success: true, data: services, count: services.length });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch services' });
  }
});

app.get('/services/featured', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 6;
    const services = await req.servicesCollection.find({}).sort({ createdAt: -1 }).limit(limit).toArray();
    res.json({ success: true, data: services });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch featured services' });
  }
});

app.get('/services/top-rated', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 6;
    const services = await req.servicesCollection.aggregate([
      {
        $addFields: {
          avgRating: { $cond: { if: { $gt: [{ $size: { $ifNull: ['$reviews', []] } }, 0] }, then: { $avg: '$reviews.rating' }, else: 0 } },
          reviewCount: { $size: { $ifNull: ['$reviews', []] } },
        },
      },
      { $match: { reviewCount: { $gt: 0 } } },
      { $sort: { avgRating: -1, reviewCount: -1 } },
      { $limit: limit },
    ]).toArray();
    res.json({ success: true, data: services });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch top rated' });
  }
});

app.get('/services/popular', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 6;
    const popular = await req.bookingsCollection.aggregate([
      { $group: { _id: '$serviceId', bookingCount: { $sum: 1 } } },
      { $sort: { bookingCount: -1 } },
      { $limit: limit },
    ]).toArray();

    const serviceIds = popular.map(s => { try { return new ObjectId(s._id); } catch { return null; } }).filter(Boolean);
    const services = await req.servicesCollection.find({ _id: { $in: serviceIds } }).toArray();

    const result = services.map(s => ({
      ...s,
      bookingCount: popular.find(p => p._id === s._id.toString())?.bookingCount || 0,
    })).sort((a, b) => b.bookingCount - a.bookingCount);

    res.json({ success: true, data: result });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch popular' });
  }
});

app.get('/services', async (req, res) => {
  try {
    const { search, category, minPrice, maxPrice, sortBy, page, limit } = req.query;
    const filter = {};

    if (search) {
      filter.$or = [
        { serviceName: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { category: { $regex: search, $options: 'i' } },
      ];
    }
    if (category && category !== 'all') filter.category = category;
    if (minPrice || maxPrice) {
      filter.price = {};
      if (minPrice) filter.price.$gte = parseFloat(minPrice);
      if (maxPrice) filter.price.$lte = parseFloat(maxPrice);
    }

    let sort = { createdAt: -1 };
    if (sortBy === 'price-low') sort = { price: 1 };
    else if (sortBy === 'price-high') sort = { price: -1 };
    else if (sortBy === 'name-asc') sort = { serviceName: 1 };
    else if (sortBy === 'name-desc') sort = { serviceName: -1 };

    const total = await req.servicesCollection.countDocuments(filter);
    let query = req.servicesCollection.find(filter).sort(sort);

    if (limit) {
      const limitNum = parseInt(limit);
      const pageNum = parseInt(page) || 1;
      query = query.skip((pageNum - 1) * limitNum).limit(limitNum);
    }

    const services = await query.toArray();
    res.json({ success: true, data: services, count: services.length, total });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch services' });
  }
});

app.get('/services/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid ID' });
    }
    const service = await req.servicesCollection.findOne({ _id: new ObjectId(id) });
    if (!service) {
      return res.status(404).json({ success: false, message: 'Not found' });
    }
    res.json({ success: true, data: service });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch service' });
  }
});

app.get('/services/provider/:email', verifyToken, async (req, res) => {
  try {
    if (req.user.email !== req.params.email) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const services = await req.servicesCollection.find({ providerEmail: req.params.email }).sort({ createdAt: -1 }).toArray();
    res.json({ success: true, data: services, count: services.length });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch services' });
  }
});

app.post('/services', verifyToken, async (req, res) => {
  try {
    const data = req.body;
    const required = ['serviceName', 'category', 'price', 'description', 'imageUrl', 'providerName', 'providerEmail'];
    const missing = required.filter(f => !data[f]);

    if (missing.length) {
      return res.status(400).json({ success: false, message: `Missing: ${missing.join(', ')}` });
    }
    if (data.providerEmail !== req.user.email) {
      return res.status(403).json({ success: false, message: 'Can only add own services' });
    }

    const newService = {
      ...data,
      price: parseFloat(data.price),
      reviews: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const result = await req.servicesCollection.insertOne(newService);
    res.status(201).json({ success: true, insertedId: result.insertedId, data: { ...newService, _id: result.insertedId } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to add service' });
  }
});

app.put('/services/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid ID' });
    }

    const existing = await req.servicesCollection.findOne({ _id: new ObjectId(id) });
    if (!existing) return res.status(404).json({ success: false, message: 'Not found' });
    if (existing.providerEmail !== req.user.email) {
      return res.status(403).json({ success: false, message: 'Can only update own services' });
    }

    const result = await req.servicesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { ...req.body, price: parseFloat(req.body.price), updatedAt: new Date().toISOString() } }
    );
    res.json({ success: true, modifiedCount: result.modifiedCount });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update' });
  }
});

app.delete('/services/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid ID' });
    }

    const existing = await req.servicesCollection.findOne({ _id: new ObjectId(id) });
    if (!existing) return res.status(404).json({ success: false, message: 'Not found' });
    if (existing.providerEmail !== req.user.email) {
      return res.status(403).json({ success: false, message: 'Can only delete own services' });
    }

    await req.servicesCollection.deleteOne({ _id: new ObjectId(id) });
    await req.bookingsCollection.deleteMany({ serviceId: id });
    res.json({ success: true, message: 'Deleted' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to delete' });
  }
});

app.post('/services/:id/reviews', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { rating, comment } = req.body;

    if (!ObjectId.isValid(id)) return res.status(400).json({ success: false, message: 'Invalid ID' });
    if (!rating || rating < 1 || rating > 5) return res.status(400).json({ success: false, message: 'Rating 1-5 required' });

    const service = await req.servicesCollection.findOne({ _id: new ObjectId(id) });
    if (!service) return res.status(404).json({ success: false, message: 'Service not found' });

    const booking = await req.bookingsCollection.findOne({
      serviceId: id,
      userEmail: req.user.email,
      status: 'completed',
      hasReviewed: { $ne: true },
    });

    if (!booking) {
      return res.status(400).json({ success: false, message: 'Can only review completed bookings' });
    }

    const review = {
      _id: new ObjectId(),
      rating: parseInt(rating),
      comment: comment || '',
      userEmail: req.user.email,
      userName: booking.userName,
      createdAt: new Date().toISOString(),
    };

    await req.servicesCollection.updateOne({ _id: new ObjectId(id) }, { $push: { reviews: review } });
    await req.bookingsCollection.updateOne({ _id: booking._id }, { $set: { hasReviewed: true } });

    res.status(201).json({ success: true, data: review });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to add review' });
  }
});

// ============================================================
// BOOKING ROUTES
// ============================================================

app.post('/bookings', verifyToken, async (req, res) => {
  try {
    const data = req.body;
    const required = ['serviceId', 'serviceName', 'serviceImage', 'providerEmail', 'providerName', 'userEmail', 'userName', 'bookingDate', 'price'];
    const missing = required.filter(f => !data[f]);

    if (missing.length) {
      return res.status(400).json({ success: false, message: `Missing: ${missing.join(', ')}` });
    }
    if (data.userEmail !== req.user.email) {
      return res.status(403).json({ success: false, message: 'Can only book for yourself' });
    }
    if (!ObjectId.isValid(data.serviceId)) {
      return res.status(400).json({ success: false, message: 'Invalid service ID' });
    }

    const service = await req.servicesCollection.findOne({ _id: new ObjectId(data.serviceId) });
    if (!service) return res.status(404).json({ success: false, message: 'Service not found' });
    if (service.providerEmail === data.userEmail) {
      return res.status(400).json({ success: false, message: 'Cannot book own service' });
    }

    const newBooking = {
      ...data,
      price: parseFloat(data.price),
      status: 'pending',
      hasReviewed: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const result = await req.bookingsCollection.insertOne(newBooking);
    res.status(201).json({ success: true, insertedId: result.insertedId, data: { ...newBooking, _id: result.insertedId } });
  } catch (error) {
    console.error('Booking Error:', error);
    res.status(500).json({ success: false, message: 'Failed to create booking' });
  }
});

app.get('/bookings/user/:email', verifyToken, async (req, res) => {
  try {
    if (req.user.email !== req.params.email) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const bookings = await req.bookingsCollection.find({ userEmail: req.params.email }).sort({ createdAt: -1 }).toArray();
    res.json({ success: true, data: bookings, count: bookings.length });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch bookings' });
  }
});

app.get('/bookings/provider/:email', verifyToken, async (req, res) => {
  try {
    if (req.user.email !== req.params.email) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }
    const bookings = await req.bookingsCollection.find({ providerEmail: req.params.email }).sort({ createdAt: -1 }).toArray();
    res.json({ success: true, data: bookings, count: bookings.length });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch bookings' });
  }
});

app.get('/bookings/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ success: false, message: 'Invalid ID' });

    const booking = await req.bookingsCollection.findOne({ _id: new ObjectId(id) });
    if (!booking) return res.status(404).json({ success: false, message: 'Not found' });
    if (booking.userEmail !== req.user.email && booking.providerEmail !== req.user.email) {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    res.json({ success: true, data: booking });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch booking' });
  }
});

app.patch('/bookings/:id/status', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!ObjectId.isValid(id)) return res.status(400).json({ success: false, message: 'Invalid ID' });

    const validStatuses = ['pending', 'confirmed', 'in-progress', 'completed', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }

    const booking = await req.bookingsCollection.findOne({ _id: new ObjectId(id) });
    if (!booking) return res.status(404).json({ success: false, message: 'Not found' });

    if (status === 'cancelled') {
      if (booking.userEmail !== req.user.email && booking.providerEmail !== req.user.email) {
        return res.status(403).json({ success: false, message: 'Cannot cancel' });
      }
    } else {
      if (booking.providerEmail !== req.user.email) {
        return res.status(403).json({ success: false, message: 'Only provider can update' });
      }
    }

    await req.bookingsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status, updatedAt: new Date().toISOString() } }
    );
    res.json({ success: true, message: `Status updated to ${status}` });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update status' });
  }
});

app.delete('/bookings/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ success: false, message: 'Invalid ID' });

    const booking = await req.bookingsCollection.findOne({ _id: new ObjectId(id) });
    if (!booking) return res.status(404).json({ success: false, message: 'Not found' });
    if (booking.userEmail !== req.user.email) return res.status(403).json({ success: false, message: 'Can only delete own' });
    if (booking.status === 'completed') return res.status(400).json({ success: false, message: 'Cannot delete completed' });

    await req.bookingsCollection.deleteOne({ _id: new ObjectId(id) });
    res.json({ success: true, message: 'Deleted' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to delete' });
  }
});

// ============================================================
// OTHER ROUTES
// ============================================================

app.get('/categories', async (req, res) => {
  try {
    const categories = await req.servicesCollection.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $project: { category: '$_id', count: 1, _id: 0 } },
    ]).toArray();
    res.json({ success: true, data: categories });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch categories' });
  }
});

app.get('/stats/platform', async (req, res) => {
  try {
    const [totalServices, totalBookings, completedBookings, totalUsers] = await Promise.all([
      req.servicesCollection.countDocuments(),
      req.bookingsCollection.countDocuments(),
      req.bookingsCollection.countDocuments({ status: 'completed' }),
      req.usersCollection.countDocuments(),
    ]);
    const providers = await req.servicesCollection.distinct('providerEmail');
    res.json({ success: true, data: { totalServices, totalBookings, completedBookings, totalUsers, totalProviders: providers.length } });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch stats' });
  }
});

app.get('/stats/provider/:email', verifyToken, async (req, res) => {
  try {
    if (req.user.email !== req.params.email) return res.status(403).json({ success: false, message: 'Forbidden' });

    const services = await req.servicesCollection.find({ providerEmail: req.params.email }).toArray();
    const serviceIds = services.map(s => s._id.toString());
    const bookings = await req.bookingsCollection.find({ serviceId: { $in: serviceIds } }).toArray();

    let totalRating = 0, totalReviews = 0;
    services.forEach(s => { if (s.reviews?.length) s.reviews.forEach(r => { totalRating += r.rating || 0; totalReviews++; }); });

    res.json({
      success: true,
      data: {
        totalServices: services.length,
        totalBookings: bookings.length,
        pendingBookings: bookings.filter(b => b.status === 'pending').length,
        completedBookings: bookings.filter(b => b.status === 'completed').length,
        totalRevenue: bookings.filter(b => b.status === 'completed').reduce((sum, b) => sum + (parseFloat(b.price) || 0), 0),
        averageRating: totalReviews > 0 ? parseFloat((totalRating / totalReviews).toFixed(1)) : 0,
        totalReviews,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch stats' });
  }
});

// 404
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// Start server
if (process.env.NODE_ENV !== 'production') {
  app.listen(port, () => console.log(`🏠 Server running on port ${port}`));
}

module.exports = app;