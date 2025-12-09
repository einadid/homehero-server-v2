// ============================================================
// HOMEHERO BACKEND SERVER - COMPLETE CODE
// ============================================================

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 5000;

// ============================================================
// MIDDLEWARE CONFIGURATION
// ============================================================

// CORS Configuration
const corsOptions = {
  origin: [
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:3000',
    // Add your production URLs here
    'https://your-app.netlify.app',
    'https://your-app.vercel.app',
    'https://your-app.web.app',
  ],
  credentials: true,
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// ============================================================
// MONGODB CONNECTION
// ============================================================

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// ============================================================
// JWT VERIFICATION MIDDLEWARE
// ============================================================

const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized access - No token provided' });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.error('JWT Verification Error:', err.message);
      return res.status(401).json({ message: 'Unauthorized access - Invalid token' });
    }
    req.user = decoded;
    next();
  });
};

// Verify user owns the data (optional middleware)
const verifyOwnership = (req, res, next) => {
  const emailParam = req.params.email;
  const tokenEmail = req.user?.email;

  if (emailParam !== tokenEmail) {
    return res.status(403).json({ message: 'Forbidden access - You can only access your own data' });
  }
  next();
};

// ============================================================
// MAIN SERVER FUNCTION
// ============================================================

async function run() {
  try {
    // Connect to MongoDB (Comment out for Vercel serverless)
    await client.connect();
    console.log('✅ Connected to MongoDB successfully!');

    // Database & Collections
    const database = client.db(process.env.DB_NAME || 'homeHeroDB');
    const servicesCollection = database.collection('services');
    const bookingsCollection = database.collection('bookings');
    const usersCollection = database.collection('users');

    // ========================================================
    // AUTH ROUTES
    // ========================================================

    // Generate JWT Token
    app.post('/jwt', async (req, res) => {
      try {
        const user = req.body;

        if (!user?.email) {
          return res.status(400).json({ message: 'Email is required' });
        }

        const token = jwt.sign(
          { email: user.email },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: '7d' }
        );

        res
          .cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          })
          .json({ success: true, message: 'Token generated successfully' });
      } catch (error) {
        console.error('JWT Generation Error:', error);
        res.status(500).json({ message: 'Failed to generate token' });
      }
    });

    // Clear JWT Token (Logout)
    app.post('/logout', (req, res) => {
      try {
        res
          .clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 0,
          })
          .json({ success: true, message: 'Logged out successfully' });
      } catch (error) {
        console.error('Logout Error:', error);
        res.status(500).json({ message: 'Failed to logout' });
      }
    });

    // ========================================================
    // USER ROUTES
    // ========================================================

    // Save or update user in database
    app.post('/users', async (req, res) => {
      try {
        const user = req.body;

        if (!user?.email) {
          return res.status(400).json({ message: 'Email is required' });
        }

        const query = { email: user.email };
        const existingUser = await usersCollection.findOne(query);

        if (existingUser) {
          // Update last login time
          await usersCollection.updateOne(query, {
            $set: { lastLoginAt: new Date().toISOString() },
          });
          return res.json({ message: 'User already exists', insertedId: null });
        }

        // Create new user
        const newUser = {
          ...user,
          role: 'user',
          createdAt: new Date().toISOString(),
          lastLoginAt: new Date().toISOString(),
        };

        const result = await usersCollection.insertOne(newUser);
        res.status(201).json({ message: 'User created successfully', insertedId: result.insertedId });
      } catch (error) {
        console.error('Error saving user:', error);
        res.status(500).json({ message: 'Failed to save user' });
      }
    });

    // Get user by email
    app.get('/users/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;

        if (req.user.email !== email) {
          return res.status(403).json({ message: 'Forbidden access' });
        }

        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }

        res.json(user);
      } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ message: 'Failed to fetch user' });
      }
    });

    // Get user statistics
    app.get('/users/stats/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;

        if (req.user.email !== email) {
          return res.status(403).json({ message: 'Forbidden access' });
        }

        // Get total services by this provider
        const totalServices = await servicesCollection.countDocuments({
          providerEmail: email,
        });

        // Get all services by this provider
        const services = await servicesCollection
          .find({ providerEmail: email })
          .toArray();

        // Get service IDs
        const serviceIds = services.map((s) => s._id.toString());

        // Get bookings for this provider's services
        const providerBookings = await bookingsCollection
          .find({ serviceId: { $in: serviceIds } })
          .toArray();

        // Get user's own bookings (as customer)
        const userBookings = await bookingsCollection
          .find({ userEmail: email })
          .toArray();

        // Calculate statistics
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

        // Calculate average rating from all services
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
            totalRevenue,
            averageRating,
            totalReviews,
            myBookings: userBookings.length,
          },
        });
      } catch (error) {
        console.error('Error fetching user stats:', error);
        res.status(500).json({ message: 'Failed to fetch statistics' });
      }
    });

    // ========================================================
    // SERVICE ROUTES
    // ========================================================

    // Get all services with filtering, search, sorting & pagination
    app.get('/services', async (req, res) => {
      try {
        const {
          search,
          category,
          minPrice,
          maxPrice,
          sortBy,
          sortOrder = 'desc',
          page = 1,
          limit = 12,
        } = req.query;

        // Build filter query
        const filter = {};

        // Search by service name, description, or category
        if (search) {
          filter.$or = [
            { serviceName: { $regex: search, $options: 'i' } },
            { description: { $regex: search, $options: 'i' } },
            { category: { $regex: search, $options: 'i' } },
          ];
        }

        // Filter by category
        if (category && category !== 'all') {
          filter.category = category;
        }

        // Price range filter
        if (minPrice || maxPrice) {
          filter.price = {};
          if (minPrice) filter.price.$gte = parseFloat(minPrice);
          if (maxPrice) filter.price.$lte = parseFloat(maxPrice);
        }

        // Build sort options
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

        // Pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Execute query
        const services = await servicesCollection
          .find(filter)
          .sort(sort)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        // Get total count for pagination
        const total = await servicesCollection.countDocuments(filter);

        res.json({
          success: true,
          data: services,
          pagination: {
            total,
            page: parseInt(page),
            limit: parseInt(limit),
            totalPages: Math.ceil(total / parseInt(limit)),
            hasNextPage: page * limit < total,
            hasPrevPage: page > 1,
          },
        });
      } catch (error) {
        console.error('Error fetching services:', error);
        res.status(500).json({ message: 'Failed to fetch services' });
      }
    });

    // Get featured services (latest)
    app.get('/services/featured', async (req, res) => {
      try {
        const limit = parseInt(req.query.limit) || 6;

        const services = await servicesCollection
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
        res.status(500).json({ message: 'Failed to fetch featured services' });
      }
    });

    // Get top rated services
    app.get('/services/top-rated', async (req, res) => {
      try {
        const limit = parseInt(req.query.limit) || 6;

        const services = await servicesCollection
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
        res.status(500).json({ message: 'Failed to fetch top rated services' });
      }
    });

    // Get popular services (most booked)
    app.get('/services/popular', async (req, res) => {
      try {
        const limit = parseInt(req.query.limit) || 6;

        const popularServices = await bookingsCollection
          .aggregate([
            { $group: { _id: '$serviceId', bookingCount: { $sum: 1 } } },
            { $sort: { bookingCount: -1 } },
            { $limit: limit },
          ])
          .toArray();

        const serviceIds = popularServices.map((s) => new ObjectId(s._id));

        const services = await servicesCollection
          .find({ _id: { $in: serviceIds } })
          .toArray();

        // Add booking count to each service
        const servicesWithCount = services.map((service) => {
          const booking = popularServices.find(
            (b) => b._id === service._id.toString()
          );
          return {
            ...service,
            bookingCount: booking?.bookingCount || 0,
          };
        });

        res.json({
          success: true,
          data: servicesWithCount,
        });
      } catch (error) {
        console.error('Error fetching popular services:', error);
        res.status(500).json({ message: 'Failed to fetch popular services' });
      }
    });

    // Get single service by ID
    app.get('/services/:id', async (req, res) => {
      try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid service ID' });
        }

        const service = await servicesCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!service) {
          return res.status(404).json({ message: 'Service not found' });
        }

        res.json({
          success: true,
          data: service,
        });
      } catch (error) {
        console.error('Error fetching service:', error);
        res.status(500).json({ message: 'Failed to fetch service' });
      }
    });

    // Get services by provider email
    app.get('/services/provider/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;

        if (req.user.email !== email) {
          return res.status(403).json({ message: 'Forbidden access' });
        }

        const services = await servicesCollection
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
        res.status(500).json({ message: 'Failed to fetch services' });
      }
    });

    // Add new service
    app.post('/services', verifyToken, async (req, res) => {
      try {
        const serviceData = req.body;

        // Validate required fields
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
            message: `Missing required fields: ${missingFields.join(', ')}`,
          });
        }

        // Create new service object
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

        const result = await servicesCollection.insertOne(newService);

        res.status(201).json({
          success: true,
          message: 'Service added successfully',
          insertedId: result.insertedId,
          data: { ...newService, _id: result.insertedId },
        });
      } catch (error) {
        console.error('Error adding service:', error);
        res.status(500).json({ message: 'Failed to add service' });
      }
    });

    // Update service
    app.put('/services/:id', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const updateData = req.body;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid service ID' });
        }

        // Check if service exists and user owns it
        const existingService = await servicesCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!existingService) {
          return res.status(404).json({ message: 'Service not found' });
        }

        if (existingService.providerEmail !== req.user.email) {
          return res
            .status(403)
            .json({ message: 'You can only update your own services' });
        }

        // Build update object
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

        const result = await servicesCollection.updateOne(
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
        res.status(500).json({ message: 'Failed to update service' });
      }
    });

    // Delete service
    app.delete('/services/:id', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid service ID' });
        }

        // Check if service exists and user owns it
        const existingService = await servicesCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!existingService) {
          return res.status(404).json({ message: 'Service not found' });
        }

        if (existingService.providerEmail !== req.user.email) {
          return res
            .status(403)
            .json({ message: 'You can only delete your own services' });
        }

        // Delete the service
        const result = await servicesCollection.deleteOne({
          _id: new ObjectId(id),
        });

        // Also delete related bookings (optional)
        await bookingsCollection.deleteMany({ serviceId: id });

        res.json({
          success: true,
          message: 'Service deleted successfully',
          deletedCount: result.deletedCount,
        });
      } catch (error) {
        console.error('Error deleting service:', error);
        res.status(500).json({ message: 'Failed to delete service' });
      }
    });

    // Add review to service
    app.post('/services/:id/reviews', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const { rating, comment, bookingId } = req.body;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid service ID' });
        }

        if (!rating || rating < 1 || rating > 5) {
          return res
            .status(400)
            .json({ message: 'Rating must be between 1 and 5' });
        }

        // Check if service exists
        const service = await servicesCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!service) {
          return res.status(404).json({ message: 'Service not found' });
        }

        // Check if user has a completed booking for this service
        const booking = await bookingsCollection.findOne({
          serviceId: id,
          userEmail: req.user.email,
          status: 'completed',
          hasReviewed: { $ne: true },
        });

        if (!booking) {
          return res.status(400).json({
            message:
              'You can only review services you have booked and completed',
          });
        }

        // Create review object
        const review = {
          _id: new ObjectId(),
          rating: parseInt(rating),
          comment: comment || '',
          userEmail: req.user.email,
          userName: booking.userName,
          userPhoto: booking.userPhoto || null,
          createdAt: new Date().toISOString(),
        };

        // Add review to service
        await servicesCollection.updateOne(
          { _id: new ObjectId(id) },
          { $push: { reviews: review } }
        );

        // Mark booking as reviewed
        await bookingsCollection.updateOne(
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
        res.status(500).json({ message: 'Failed to add review' });
      }
    });

    // ========================================================
    // BOOKING ROUTES
    // ========================================================

    // Create new booking
    app.post('/bookings', verifyToken, async (req, res) => {
      try {
        const bookingData = req.body;

        // Validate required fields
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
            message: `Missing required fields: ${missingFields.join(', ')}`,
          });
        }

        // Check if service exists
        if (!ObjectId.isValid(bookingData.serviceId)) {
          return res.status(400).json({ message: 'Invalid service ID' });
        }

        const service = await servicesCollection.findOne({
          _id: new ObjectId(bookingData.serviceId),
        });

        if (!service) {
          return res.status(404).json({ message: 'Service not found' });
        }

        // Check if user is trying to book their own service
        if (service.providerEmail === bookingData.userEmail) {
          return res
            .status(400)
            .json({ message: 'You cannot book your own service' });
        }

        // Create booking object
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

        const result = await bookingsCollection.insertOne(newBooking);

        res.status(201).json({
          success: true,
          message: 'Booking created successfully',
          insertedId: result.insertedId,
          data: { ...newBooking, _id: result.insertedId },
        });
      } catch (error) {
        console.error('Error creating booking:', error);
        res.status(500).json({ message: 'Failed to create booking' });
      }
    });

    // Get user's bookings (as customer)
    app.get('/bookings/user/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;

        if (req.user.email !== email) {
          return res.status(403).json({ message: 'Forbidden access' });
        }

        const bookings = await bookingsCollection
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
        res.status(500).json({ message: 'Failed to fetch bookings' });
      }
    });

    // Get bookings for provider's services (as service provider)
    app.get('/bookings/provider/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;

        if (req.user.email !== email) {
          return res.status(403).json({ message: 'Forbidden access' });
        }

        const bookings = await bookingsCollection
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
        res.status(500).json({ message: 'Failed to fetch bookings' });
      }
    });

    // Get single booking by ID
    app.get('/bookings/:id', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid booking ID' });
        }

        const booking = await bookingsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!booking) {
          return res.status(404).json({ message: 'Booking not found' });
        }

        // Check if user owns this booking
        if (
          booking.userEmail !== req.user.email &&
          booking.providerEmail !== req.user.email
        ) {
          return res.status(403).json({ message: 'Forbidden access' });
        }

        res.json({
          success: true,
          data: booking,
        });
      } catch (error) {
        console.error('Error fetching booking:', error);
        res.status(500).json({ message: 'Failed to fetch booking' });
      }
    });

    // Update booking status (for provider)
    app.patch('/bookings/:id/status', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        const { status } = req.body;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid booking ID' });
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
            message: `Invalid status. Must be one of: ${validStatuses.join(', ')}`,
          });
        }

        // Check if booking exists
        const booking = await bookingsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!booking) {
          return res.status(404).json({ message: 'Booking not found' });
        }

        // Only provider can update status (except cancel which user can do)
        if (status !== 'cancelled' && booking.providerEmail !== req.user.email) {
          return res
            .status(403)
            .json({ message: 'Only the service provider can update status' });
        }

        // User can only cancel their own booking
        if (status === 'cancelled' && booking.userEmail !== req.user.email && booking.providerEmail !== req.user.email) {
          return res.status(403).json({ message: 'Forbidden access' });
        }

        const result = await bookingsCollection.updateOne(
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
        res.status(500).json({ message: 'Failed to update booking status' });
      }
    });

    // Cancel/Delete booking
    app.delete('/bookings/:id', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid booking ID' });
        }

        // Check if booking exists
        const booking = await bookingsCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!booking) {
          return res.status(404).json({ message: 'Booking not found' });
        }

        // Only the user who made the booking can delete it
        if (booking.userEmail !== req.user.email) {
          return res
            .status(403)
            .json({ message: 'You can only cancel your own bookings' });
        }

        // Can't delete completed bookings
        if (booking.status === 'completed') {
          return res
            .status(400)
            .json({ message: 'Cannot delete completed bookings' });
        }

        const result = await bookingsCollection.deleteOne({
          _id: new ObjectId(id),
        });

        res.json({
          success: true,
          message: 'Booking cancelled successfully',
          deletedCount: result.deletedCount,
        });
      } catch (error) {
        console.error('Error cancelling booking:', error);
        res.status(500).json({ message: 'Failed to cancel booking' });
      }
    });

    // ========================================================
    // CATEGORY ROUTES
    // ========================================================

    // Get all categories with count
    app.get('/categories', async (req, res) => {
      try {
        const categories = await servicesCollection
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
        res.status(500).json({ message: 'Failed to fetch categories' });
      }
    });

    // ========================================================
    // STATISTICS ROUTES
    // ========================================================

    // Get platform statistics (public)
    app.get('/stats/platform', async (req, res) => {
      try {
        const totalServices = await servicesCollection.countDocuments();
        const totalBookings = await bookingsCollection.countDocuments();
        const completedBookings = await bookingsCollection.countDocuments({
          status: 'completed',
        });
        const totalUsers = await usersCollection.countDocuments();

        // Get total providers (users who have at least one service)
        const providers = await servicesCollection.distinct('providerEmail');

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
        res.status(500).json({ message: 'Failed to fetch statistics' });
      }
    });

    // Get provider statistics
    app.get('/stats/provider/:email', verifyToken, async (req, res) => {
      try {
        const email = req.params.email;

        if (req.user.email !== email) {
          return res.status(403).json({ message: 'Forbidden access' });
        }

        // Get provider's services
        const services = await servicesCollection
          .find({ providerEmail: email })
          .toArray();

        const serviceIds = services.map((s) => s._id.toString());

        // Get bookings for provider's services
        const bookings = await bookingsCollection
          .find({ serviceId: { $in: serviceIds } })
          .toArray();

        // Calculate stats
        const totalBookings = bookings.length;
        const pendingBookings = bookings.filter(
          (b) => b.status === 'pending'
        ).length;
        const completedBookings = bookings.filter(
          (b) => b.status === 'completed'
        ).length;
        const cancelledBookings = bookings.filter(
          (b) => b.status === 'cancelled'
        ).length;

        const totalRevenue = bookings
          .filter((b) => b.status === 'completed')
          .reduce((sum, b) => sum + (parseFloat(b.price) || 0), 0);

        // Calculate ratings
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

        // Monthly revenue (last 6 months)
        const sixMonthsAgo = new Date();
        sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

        const monthlyRevenue = await bookingsCollection
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
                _id: { $substr: ['$createdAt', 0, 7] }, // YYYY-MM format
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
            completedBookings,
            cancelledBookings,
            totalRevenue,
            averageRating,
            totalReviews,
            monthlyRevenue,
          },
        });
      } catch (error) {
        console.error('Error fetching provider stats:', error);
        res.status(500).json({ message: 'Failed to fetch statistics' });
      }
    });

    // ========================================================
    // HEALTH CHECK & ROOT ROUTES
    // ========================================================

    // Health check
    app.get('/health', (req, res) => {
      res.json({
        status: 'OK',
        message: 'Server is healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
      });
    });

    // Root route
    app.get('/', (req, res) => {
      res.json({
        message: '🏠 HomeHero API Server is Running!',
        version: '1.0.0',
        documentation: '/api-docs',
        endpoints: {
          auth: {
            login: 'POST /jwt',
            logout: 'POST /logout',
          },
          services: {
            getAll: 'GET /services',
            getFeatured: 'GET /services/featured',
            getTopRated: 'GET /services/top-rated',
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

    // 404 handler
    app.use((req, res) => {
      res.status(404).json({
        success: false,
        message: 'Route not found',
        requestedUrl: req.originalUrl,
      });
    });

    // Error handler
    app.use((err, req, res, next) => {
      console.error('Server Error:', err);
      res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined,
      });
    });

  } catch (error) {
    console.error('❌ Failed to connect to MongoDB:', error);
  }
}

// Run the server
run().catch(console.dir);

// Start listening
app.listen(port, () => {
  console.log(`
  ╔═══════════════════════════════════════════════╗
  ║                                               ║
  ║   🏠 HomeHero Server is Running!              ║
  ║                                               ║
  ║   📍 Local:    http://localhost:${port}          ║
  ║   🌐 Network:  Check your IP                  ║
  ║   📝 API Docs: http://localhost:${port}/         ║
  ║                                               ║
  ╚═══════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🔴 Shutting down gracefully...');
  await client.close();
  console.log('📦 MongoDB connection closed.');
  process.exit(0);
});