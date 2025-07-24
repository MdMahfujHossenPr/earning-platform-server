// === ENV SETUP ===
require("dotenv").config();

// === MODULES ===
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const Stripe = require("stripe");
const path = require("path");
const admin = require("firebase-admin");
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// === FIREBASE INIT ===
admin.initializeApp({
  credential: admin.credential.cert(path.resolve(process.env.FIREBASE_SERVICE_ACCOUNT)),
});

// === EXPRESS APP ===
const app = express();
const corsOptions = {
  origin: ["http://localhost:5173"],
  credentials: true,
};
app.use(cors(corsOptions));
app.use(express.json());

// === MONGOOSE CONNECTION ===
mongoose
  .connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// === JWT TOKEN GENERATOR ===
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
};

// === MODELS ===
const { Schema, model } = mongoose;

const userSchema = new Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  photo_url: String,
  role: { type: String, enum: ["Worker", "Buyer", "Admin"], default: "Worker" },
  coin: { type: Number, default: 0 },
  googleId: String,
  uid: { type: String, required: true, unique: true }, // Add uid here to store Firebase UID
}, { timestamps: true });

const User = model("User", userSchema);

 

const taskSchema = new Schema({
  task_title: String,
  task_detail: String,
  required_workers: Number,
  payable_amount: Number,
  completion_date: Date,
  submission_info: String,
  task_image_url: String,
  buyer_id: { type: Schema.Types.ObjectId, ref: "User" },
  buyer_name: String,
  buyer_email: String,
  submissions: [{ type: Schema.Types.ObjectId, ref: "Submission" }],
}, { timestamps: true });
const Task = model("Task", taskSchema);

const submissionSchema = new Schema({
  task_id: { type: Schema.Types.ObjectId, ref: "Task" },
  task_title: String,
  payable_amount: Number,
  worker_email: String,
  submission_details: String,
  worker_name: String,
  buyer_name: String,
  buyer_email: String,
  status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
  current_date: { type: Date, default: Date.now },
}, { timestamps: true });
const Submission = model("Submission", submissionSchema);

const paymentSchema = new Schema({
  buyer_id: { type: Schema.Types.ObjectId, ref: "User" },
  amount: Number,
  coin: Number,
  payment_date: { type: Date, default: Date.now },
  stripe_id: String,
}, { timestamps: true });
const Payment = model("Payment", paymentSchema);

const withdrawalSchema = new Schema({
  worker_id: { type: Schema.Types.ObjectId, ref: "User" },
  worker_email: String,
  worker_name: String,
  withdrawal_coin: Number,
  withdrawal_amount: Number,
  payment_system: String,
  account_number: String,
  withdraw_date: { type: Date, default: Date.now },
  status: { type: String, enum: ["pending", "approved"], default: "pending" },
}, { timestamps: true });
const Withdrawal = model("Withdrawal", withdrawalSchema);

const notificationSchema = new Schema({
  message: String,
  toEmail: String,
  actionRoute: String,
  time: { type: Date, default: Date.now },
}, { timestamps: true });
const Notification = model("Notification", notificationSchema);

// === MIDDLEWARE ===
const verifyFirebaseToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decodedUser = await admin.auth().verifyIdToken(token);
    
    // Set req.user with decoded data
    req.user = decodedUser;
    
    // Explicitly set req.user.id
    req.user.id = decodedUser.uid;  // Assuming uid from Firebase is used as the user ID

    console.log('Decoded user:', req.user);  // Debugging: Log the decoded user
    
    next();
  } catch (error) {
    return res.status(403).json({ error: "Forbidden: Invalid token" });
  }
};



const checkRole = (requiredRole) => async (req, res, next) => {
  const user = await User.findOne({ email: req.user.email });
  if (!user || user.role !== requiredRole) {
    return res.status(403).json({ message: "Forbidden: Insufficient permissions" });
  }
  req.user.role = user.role;
  req.user._id = user._id;
  next();
};

const authMiddleware = verifyFirebaseToken;
const roleMiddleware = checkRole;

// --- Stripe Payment Route ---
app.post("/api/payments", authMiddleware, roleMiddleware("Buyer"), async (req, res) => {
  const { coin, amount } = req.body;
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount * 100,  // amount is in cents
      currency: 'usd',  // Currency can be adjusted as needed
      description: 'Coin Purchase',
      payment_method: req.body.payment_method,  // Payment method passed from frontend
      confirm: true,
    });

    const buyer = await User.findById(req.user.id);
    buyer.coin += coin;
    await buyer.save();

    const payment = await Payment.create({ buyer_id: buyer._id, coin, amount });
    res.json(payment);
  } catch (error) {
    console.error("Stripe Payment Error:", error);
    res.status(500).json({ message: "Payment failed", error: error.message });
  }
});

// --- Image Upload Route ---
app.post("/api/upload-img", authMiddleware, async (req, res) => {
  const { imageBase64 } = req.body;
  
  // Image Size Validation
  if (imageBase64.length > 5 * 1024 * 1024) {
    return res.status(400).json({ message: "Image size exceeds 5MB" });
  }

  // Image Type Validation
  const allowedFormats = ['image/jpeg', 'image/png'];
  const imgType = imageBase64.split(';')[0].split('/')[1];
  if (!allowedFormats.includes(`image/${imgType}`)) {
    return res.status(400).json({ message: "Invalid image format. Only JPG and PNG allowed." });
  }

  try {
    const response = await axios.post(
      `https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`,
      { image: imageBase64 }
    );
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ message: "Image upload failed", error: err.message });
  }
});

 
// --- Auth Routes ---
app.get("/api/users", async (req, res) => {
  try {
    // Correct way to fetch workers
    const users = await User.find({ role: "Worker" }).limit(6);
    
    if (users.length === 0) {
      console.error("No workers found in database");
      return res.status(404).json({ message: "No workers found" });
    }

    console.log("Fetched users: ", users);
    res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching users:", error);  // Log detailed error
    res.status(500).json({ message: "Server error while fetching users" });
  }
});


// Users - Register
app.post("/api/users", async (req, res) => {
  let { name, photoURL, email, password, method, role } = req.body;
  if (!email || !name || !photoURL || !method) {
    return res.status(400).json({ message: "Missing required fields" });
  }
  if (!role) role = "Worker";

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const coinValue = role === "Buyer" ? 50 : 10;

    if (method === "google") {
      const user = { name, photo_url: photoURL, email, googleId: "", role, coin: coinValue };
      const result = await User.create(user);
      return res.status(201).json({ message: "Google user created", user: result });
    }

    if (method === "manual") {
      if (!password) return res.status(400).json({ message: "Password required" });
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = { name, photo_url: photoURL, email, password: hashedPassword, role, coin: coinValue };
      const result = await User.create(user);
      return res.status(201).json({ message: "Manual user created", user: result });
    }

    return res.status(400).json({ message: "Invalid method" });
  } catch (error) {
    console.error("User creation error:", error);
    res.status(500).json({ message: "User creation failed", error: error.message });
  }
});


// --- Stripe Integration for Payment ---
app.post("/api/payments", authMiddleware, roleMiddleware("Buyer"), async (req, res) => {
  const { coin, amount } = req.body;
  const buyer = await User.findById(req.user.id);
  buyer.coin += coin;
  await buyer.save();
  const payment = await Payment.create({ buyer_id: buyer._id, coin, amount });
  res.json(payment);
});

app.get('/users/role/:email', async (req, res) => {
  const { email } = req.params;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ role: user.role });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

 
// Google login (Firebase ID token verify)
app.post("/api/google-login", async (req, res) => {
  const { idToken, role } = req.body;
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { name, email, picture: photo_url, uid: googleId } = decodedToken;

    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ name, email, photo_url, googleId, role: role || "Worker", coin: 10 });
      await user.save();
    }

    res.status(200).json({ message: "Login success", user });
  } catch (error) {
    console.error("Google login error:", error);
    res.status(401).json({ message: "Invalid Firebase token" });
  }
});


// Users - Login
app.post("/login", async (req, res) => {
  try {
    const { email, method } = req.body;
    
    if (!email || !method) {
      return res.status(400).json({ message: "Email and method are required" });
    }

    // Handle Google login (or other methods)
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Logic to handle user login
    const token = generateToken(user); // Ensure this method exists and works
    res.status(200).json({ message: "Login successful", token });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error during login", error: error.message });
  }
});


// --- User Profile & Coin ---
app.get("/api/profile", authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.json(user);
});

 
// --- Task Routes ---

// Create task (Buyer)
app.post("/api/tasks", authMiddleware, roleMiddleware("Buyer"), async (req, res) => {
  console.log("Received task data:", req.body);

  try {
    const {
      task_title,
      task_detail,
      required_workers,
      payable_amount,
      completion_date,
      submission_info,
      task_image_url,
    } = req.body;

    // Create task in the database
    const task = await Task.create({
      task_title: task_title.trim(),
      task_detail: task_detail.trim(),
      required_workers: Number(required_workers),
      payable_amount: Number(payable_amount),
      completion_date: new Date(completion_date),
      submission_info: submission_info.trim(),
      task_image_url,
      buyer_id: req.user._id,
      buyer_name: req.user.name,
      buyer_email: req.user.email,
    });

    console.log("Task created in DB:", task);

    // Deduct coins from buyer
    const buyer = await User.findById(req.user._id);
    buyer.coin -= task.required_workers * task.payable_amount;
    await buyer.save();

    res.status(201).json(task);
  } catch (error) {
    console.error("Error creating task:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Get tasks (fetch all tasks)
app.get("/api/tasks", authMiddleware, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;  // Default to page 1 and limit 10 tasks
    
    const tasks = await Task.find()
      .sort({ completion_date: -1 })
      .skip((page - 1) * limit)  // Skip the previous pages
      .limit(Number(limit));  // Limit the number of tasks returned

    res.json(tasks);
  } catch (error) {
    console.error("Error fetching tasks:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Get available tasks for workers
app.get("/api/tasks/available", authMiddleware, async (req, res) => {
  try {
    // Find tasks that have required workers greater than 0
    const availableTasks = await Task.find({
      required_workers: { $gt: 0 },  // Only fetch tasks with required workers > 0
    }).sort({ completion_date: 1 });  // Sort by completion date in ascending order (earliest first)

    res.json(availableTasks);  // Return the available tasks
  } catch (error) {
    console.error("Error fetching available tasks:", error);
    res.status(500).json({ message: "Server error while fetching available tasks" });
  }
});

app.get("/api/tasks/available/:id", authMiddleware, async (req, res) => {
  const taskId = req.params.id;
  try {
    const task = await Task.findById(taskId);
    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }
    res.json(task);
  } catch (error) {
    console.error("Error fetching task by ID:", error);
    res.status(500).json({ message: "Server error while fetching task" });
  }
});

// Update task
app.put('/api/tasks/:id', async (req, res) => {
  const taskId = req.params.id;
  const updatedTaskData = req.body;
  console.log('Updating task with ID:', taskId); // Log taskId to ensure it's correct

  try {
    const task = await Task.findByIdAndUpdate(taskId, updatedTaskData, { new: true });
    if (!task) {
      return res.status(404).send('Task not found');
    }
    console.log('Updated task:', task);  // Log the updated task data
    res.status(200).send(task);  // Return the updated task data
  } catch (error) {
    console.error('Error updating task:', error);
    res.status(500).send('Server error');
  }
});

// Delete task
app.delete("/api/tasks/:id", authMiddleware, roleMiddleware("Buyer"), async (req, res) => {
  const taskId = req.params.id;

  try {
    // Fetch the task from the database using the provided task ID
    const task = await Task.findById(taskId);

    // If the task doesn't exist, return a 404 error
    if (!task) {
      return res.status(404).json({ message: "Task not found" });
    }

    // Log the task's buyer_id and the logged-in user's ID for debugging purposes
    console.log('Task Buyer ID:', task.buyer_id.toString());  
    console.log('Logged-in User ID:', req.user._id);  

    // Ownership check: Ensure the logged-in user is the task's owner (the buyer)
    if (task.buyer_id.toString() !== req.user._id.toString()) {
      console.log('User is not authorized to delete this task');
      return res.status(403).json({ message: "Forbidden: You do not own this task" });
    }

    // Refund coins if the task is not completed (check the completion date)
    if (task.completion_date > new Date()) {
      const refill = task.required_workers * task.payable_amount;
      const buyer = await User.findById(req.user.id);

      // Update the buyer's coin balance
      buyer.coin += refill;
      await buyer.save();
    }

    // Delete the task
    await task.deleteOne();  // Use deleteOne to delete the task

    // Respond with a success message
    res.json({ message: "Task deleted and coins refunded" });

  } catch (error) {
    // Handle any errors that occur during the process
    console.error('Error deleting task:', error);
    res.status(500).json({ message: "Server error while deleting task", error: error.message });
  }
});

app.post("/api/submissions", authMiddleware, roleMiddleware("Worker"), async (req, res) => {
  const { task_id, submission_details, worker_name, worker_email, buyer_name, buyer_email, status } = req.body;

  // Ensure worker_name is passed
  if (!worker_name) {
    return res.status(400).json({ message: "Worker name is required" });
  }

  // Ensure submission_details is provided
  if (!submission_details) {
    return res.status(400).json({ message: "Submission details are required" });
  }

  // Validate task_id as a valid ObjectId
  if (!mongoose.Types.ObjectId.isValid(task_id)) {
    return res.status(400).json({ message: "Invalid task ID" });
  }

  const taskObjectId = new mongoose.Types.ObjectId(task_id);

  try {
    console.log('Received Task ID:', task_id); // Debug log to check task ID

    // Fetch the task from the database using the task ID
    const task = await Task.findById(taskObjectId);
    if (!task) {
      console.error('Task not found');
      return res.status(400).json({ message: "Task not found" });
    }

    // Check if required workers are available
    if (task.required_workers <= 0) {
      console.error('No workers needed for this task');
      return res.status(400).json({ message: "No workers needed for this task" });
    }

    // Find the worker submitting the task using the firebase UID
    const worker = await User.findOne({ uid: req.user.id }); // Use uid instead of _id
    if (!worker) {
      console.error('Worker not found');
      return res.status(400).json({ message: "Worker not found" });
    }

    console.log('Worker found:', worker.name);

    // Create a new task submission
    const submission = await Submission.create({
      task_id: taskObjectId,
      task_title: task.task_title,
      payable_amount: task.payable_amount,
      worker_email,
      worker_name,
      buyer_name,
      buyer_email,
      submission_details,
      status: status || "pending", // Default to 'pending' if not provided
    });

    console.log('Task Submission Created:', submission);

    // Update task to reflect the new submission and decrement the required_workers
    task.submissions.push(submission._id);
    task.required_workers -= 1;
    await task.save(); // Save the task after updating it

    // Create a notification for the Buyer about the worker submission
    await Notification.create({
      message: `${worker.name} submitted for ${task.task_title}`,
      toEmail: task.buyer_email,
      actionRoute: "/dashboard/buyer-home",
    });

    // Send the submission data as a response
    res.status(201).json(submission); // Return the created submission

  } catch (error) {
    console.error("Error in task submission:", error);  // Log the error details for debugging
    res.status(500).json({ message: "Server error while submitting task", error: error.message });
  }
});






// Get submissions (Worker or Buyer)
app.get("/api/submissions", authMiddleware, async (req, res) => {
  let submissions;

  // Fetch submissions based on user role
  if (req.user.role === "Worker") {
    submissions = await Submission.find({ worker_email: req.user.email }).sort({ current_date: -1 });
  } else if (req.user.role === "Buyer") {
    submissions = await Submission.find({ buyer_email: req.user.email }).sort({ current_date: -1 });
  } else {
    submissions = await Submission.find().sort({ current_date: -1 });
  }

  res.json(submissions); // Return the list of submissions
});





// Approve/Reject Submission (Buyer)
app.post(
  "/api/submissions/:id/approve",
  authMiddleware,
  roleMiddleware("Buyer"),
  async (req, res) => {
    const submission = await Submission.findById(req.params.id);
    if (!submission)
      return res.status(404).json({ message: "Submission not found" });
    if (submission.buyer_email !== req.user.email)
      return res.status(403).json({ message: "Forbidden" });
    submission.status = "approved";
    await submission.save();
    // Increase worker coin
    const worker = await User.findOne({ email: submission.worker_email });
    worker.coin += submission.payable_amount;
    await worker.save();
    // Notification to Worker
    await Notification.create({
      message: `You have earned ${submission.payable_amount} from ${submission.buyer_name} for completing ${submission.task_title}`,
      toEmail: worker.email,
      actionRoute: "/dashboard/worker-home",
    });
    res.json(submission);
  }
);

// Reject Submission (Buyer)
app.post(
  "/api/submissions/:id/reject",
  authMiddleware,
  roleMiddleware("Buyer"),
  async (req, res) => {
    const submission = await Submission.findById(req.params.id);
    if (!submission)
      return res.status(404).json({ message: "Submission not found" });
    if (submission.buyer_email !== req.user.email)
      return res.status(403).json({ message: "Forbidden" });
    submission.status = "rejected";
    await submission.save();
    // Increase required_workers by 1
    const task = await Task.findById(submission.task_id);
    task.required_workers += 1;
    await task.save();
    // Notification to Worker
    await Notification.create({
      message: `Your submission for ${submission.task_title} was rejected by ${submission.buyer_name}`,
      toEmail: submission.worker_email,
      actionRoute: "/dashboard/worker-home",
    });
    res.json(submission);
  }
);

// --- Payment Routes (Buyer) ---
app.post("/api/payments", verifyFirebaseToken, checkRole("Buyer"), async (req, res) => {
  const { coin, amount } = req.body;
  try {
    // Create Stripe payment intent
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amount * 100,  // Convert to cents
      currency: 'usd',
      description: 'Coin Purchase',
      payment_method: req.body.payment_method,  // Payment method passed from frontend
      confirm: true,
    });

    const buyer = await User.findById(req.user.id);
    buyer.coin += coin;
    await buyer.save();

    // Create payment record
    const payment = await Payment.create({
      buyer_id: buyer._id,
      coin,
      amount,
      stripe_id: paymentIntent.id,  // Store the Stripe payment ID
    });

    res.json({ id: paymentIntent.id });
  } catch (error) {
    console.error("Stripe Payment Error:", error);
    res.status(500).json({ message: "Payment failed", error: error.message });
  }
});


// Get payments (Buyer)
app.get('/api/payments', verifyFirebaseToken, async (req, res) => {
  const { userId } = req.query; // Get the user ID from the query params
  try {
    const payments = await Payment.find({ buyer_id: userId }).sort({ payment_date: -1 }); // Fetch payments for the user
    res.json(payments); // Return the payments data
  } catch (error) {
    console.error('Error fetching payments:', error);
    res.status(500).json({ message: 'Error fetching payments' }); // Handle errors
  }
});


// --- Withdrawal Routes (Worker) ---
app.post(
  "/api/withdrawals",
  authMiddleware,
  roleMiddleware("Worker"),
  async (req, res) => {
    const { withdrawal_coin, payment_system, account_number } = req.body;
    const worker = await User.findById(req.user.id);
    if (worker.coin < withdrawal_coin || withdrawal_coin < 200)
      return res.status(400).json({ message: "Insufficient coin" });
    const withdrawal_amount = withdrawal_coin / 20;
    const withdrawal = await Withdrawal.create({
      worker_id: worker._id,
      worker_email: worker.email,
      worker_name: worker.name,
      withdrawal_coin,
      withdrawal_amount,
      payment_system,
      account_number,
      status: "pending",
    });
    // Notification to Admin
    await Notification.create({
      message: `${worker.name} requested withdrawal of ${withdrawal_amount}$`,
      toEmail: "mdmahfujhossen.pr@gmail.com",
      actionRoute: "/dashboard/admin-home",
    });
    res.json(withdrawal);
  }
);

app.get("/api/withdrawals", authMiddleware, async (req, res) => {
  let withdrawals;
  if (req.user.role === "Worker") {
    withdrawals = await Withdrawal.find({ worker_email: req.user.email }).sort({
      withdraw_date: -1,
    });
  } else if (req.user.role === "Admin") {
    withdrawals = await Withdrawal.find({ status: "pending" }).sort({
      withdraw_date: -1,
    });
  } else {
    withdrawals = [];
  }
  res.json(withdrawals);
});

// Admin approves withdrawal
app.post(
  "/api/withdrawals/:id/approve",
  authMiddleware,
  roleMiddleware("Admin"),
  async (req, res) => {
    const withdrawal = await Withdrawal.findById(req.params.id);
    if (!withdrawal)
      return res.status(404).json({ message: "Withdrawal not found" });
    withdrawal.status = "approved";
    await withdrawal.save();
    // Decrease worker coin
    const worker = await User.findById(withdrawal.worker_id);
    worker.coin -= withdrawal.withdrawal_coin;
    await worker.save();
    // Notification to Worker
    await Notification.create({
      message: `Your withdrawal of $${withdrawal.withdrawal_amount} is approved`,
      toEmail: worker.email,
      actionRoute: "/dashboard/worker-home",
    });
    res.json(withdrawal);
  }
);

// --- Notification Routes ---
app.get("/api/notifications", authMiddleware, async (req, res) => {
  const notifications = await Notification.find({
    toEmail: req.user.email,
  }).sort({ time: -1 });
  res.json(notifications);
});

// Backend route to fetch buyer stats
app.get("/api/buyer/stats/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;  // Access the userId from the URL parameter
  if (!userId) {
    return res.status(400).json({ message: "User ID is required" });
  }

  try {
    const stats = await getBuyerStatsFromDB(userId);  // Fetch stats from DB using userId
    res.json(stats);
  } catch (error) {
    console.error("Error fetching stats:", error);
    res.status(500).json({ message: "Error fetching stats" });
  }
});


// --- Admin Routes ---
app.get(
  "/api/admin/stats",
  authMiddleware,
  roleMiddleware("Admin"),
  async (req, res) => {
    const totalWorker = await User.countDocuments({ role: "Worker" });
    const totalBuyer = await User.countDocuments({ role: "Buyer" });
    const totalCoin = await User.aggregate([
      { $group: { _id: null, total: { $sum: "$coin" } } },
    ]);
    const totalPayments = await Payment.countDocuments();
    res.json({
      totalWorker,
      totalBuyer,
      totalCoin: totalCoin[0]?.total || 0,
      totalPayments,
    });
  }
);

// --- User Routes ---
app.get(
  "/api/admin/users",
  authMiddleware,
  roleMiddleware("Admin"),
  async (req, res) => {
    const users = await User.find();
    res.json(users);
  }
);

// Get user by ID
app.get(
  "/api/admin/users/:id",
  authMiddleware,
  roleMiddleware("Admin"),
  async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: "User deleted" });
  }
);

app.put(
  "/api/admin/users/:id/role",
  authMiddleware,
  roleMiddleware("Admin"),
  async (req, res) => {
    const { role } = req.body;
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    user.role = role;
    await user.save();
    res.json(user);
  }
);

app.get(
  "/api/admin/tasks",
  authMiddleware,
  roleMiddleware("Admin"),
  async (req, res) => {
    const tasks = await Task.find();
    res.json(tasks);
  }
);

app.delete(
  "/api/admin/tasks/:id",
  authMiddleware,
  roleMiddleware("Admin"),
  async (req, res) => {
    await Task.findByIdAndDelete(req.params.id);
    res.json({ message: "Task deleted" });
  }
);

// --- Pagination for Worker Submissions ---
app.get("/api/worker/submissions", authMiddleware, roleMiddleware("Worker"), async (req, res) => {
  const { page = 1, limit = 10 } = req.query;
  const submissions = await Submission.find({ worker_email: req.user.email })
    .sort({ current_date: -1 })
    .skip((page - 1) * limit)
    .limit(Number(limit));
  const total = await Submission.countDocuments({ worker_email: req.user.email });
  res.json({ submissions, total });
});


// --- imgBB Image Upload (registration/task) ---
app.post("/api/upload-img", authMiddleware, async (req, res) => {
  const { imageBase64 } = req.body;
  try {
    const response = await axios.post(
      `https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`,
      { image: imageBase64 }
    );
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ message: "Image upload failed", error: err.message });
  }
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: "Something went wrong", error: err.message });
});

app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  next();
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
