// === ENV SETUP ===
require("dotenv").config();

// === MODULES ===
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const path = require("path");
const admin = require("firebase-admin");

 

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

// User Schema
const userSchema = new Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  photo_url: String,
  role: { type: String, enum: ["Worker", "Buyer", "Admin"], default: "Worker" },
  coin: { type: Number, default: 0 },
  googleId: String,
  uid: { type: String, required: true, unique: true, index: true } // Firebase UID as String and Indexed
}, { timestamps: true });

const User = model("User", userSchema);

// Task Schema
const taskSchema = new Schema({
  task_title: String,
  task_detail: String,
  required_workers: Number,
  payable_amount: Number,
  completion_date: Date,
  submission_info: String,
  task_image_url: String,
  buyer_id: { type: String, required: true },  // Store buyer_id as String for Firebase UID
  buyer_name: String,
  buyer_email: String,
  submissions: [{ type: Schema.Types.ObjectId, ref: "Submission" }],
}, { timestamps: true });

const Task = model("Task", taskSchema);

// Submission Schema
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

// Payment Schema
const paymentSchema = new Schema({
  buyer_id: { type: String, required: true },  // Store buyer_id as String (Firebase UID)
  amount: { type: Number, required: true },
  coin: { type: Number, required: true },
  payment_date: { type: Date, default: Date.now },
  stripe_id: String,
}, { timestamps: true });

const Payment = model("Payment", paymentSchema);

module.exports = { User, Task, Submission, Payment };


  

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
    req.user = decodedUser;
    console.log("Decoded user from Firebase:", req.user);
    req.user.id = decodedUser.uid;
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
    // Check if the email already exists in Firebase
    let firebaseUser;
    try {
      firebaseUser = await admin.auth().getUserByEmail(email);  // Check if user exists in Firebase
    } catch (error) {
      // If error is thrown, it means the user doesn't exist
      if (error.code !== 'auth/user-not-found') {
        return res.status(500).json({ message: "Error checking Firebase user", error: error.message });
      }
    }

    if (!firebaseUser) {
      // If the user doesn't exist, create the user in Firebase
      if (method === "google") {
        firebaseUser = await admin.auth().createUser({
          email,
          displayName: name,
          photoURL,
        });
      } else if (method === "manual") {
        if (!password) return res.status(400).json({ message: "Password required" });
        const hashedPassword = await bcrypt.hash(password, 10);
        firebaseUser = await admin.auth().createUser({
          email,
          password: hashedPassword,
          displayName: name,
          photoURL,
        });
      } else {
        return res.status(400).json({ message: "Invalid method" });
      }
    }

    // Firebase UID
    const firebaseUid = firebaseUser.uid;

    // Check if the user already exists in MongoDB
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(200).json({ message: "User already exists", user: existingUser });
    }

    // Create the user in MongoDB
    const coinValue = role === "Buyer" ? 50 : 10;
    const user = {
      name,
      photo_url: photoURL,
      email,
      role,
      coin: coinValue,
      uid: firebaseUid,  // Firebase UID added
    };

    const result = await User.create(user);
    return res.status(201).json({ message: "User created", user: result });

  } catch (error) {
    console.error("User creation error:", error);
    res.status(500).json({ message: "User creation failed", error: error.message });
  }
});

app.get('/users/role/:email', async (req, res) => {
  const { email } = req.params;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });
    
    // Send both role and coin
    res.json({ role: user.role, coin: user.coin });
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

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

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

    // Task creation
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
    const totalDeduction = task.required_workers * task.payable_amount;
    console.log("Total Deduction (After Calculation):", totalDeduction);
    buyer.coin -= totalDeduction;
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

//Submissions Route 
app.post("/api/submissions", authMiddleware, roleMiddleware("Worker"), async (req, res) => {
  const { task_id, submission_details, worker_name, worker_email, buyer_name, buyer_email, status } = req.body;

  if (!worker_name) {
    return res.status(400).json({ message: "Worker name is required" });
  }

  if (!submission_details) {
    return res.status(400).json({ message: "Submission details are required" });
  }

  if (!mongoose.Types.ObjectId.isValid(task_id)) {
    return res.status(400).json({ message: "Invalid task ID" });
  }

  const taskObjectId = new mongoose.Types.ObjectId(task_id);

  try {
    // Check if the task exists
    const task = await Task.findById(taskObjectId);
    if (!task) {
      console.error('Task not found');
      return res.status(400).json({ message: "Task not found" });
    }

    // Check if the task requires workers
    if (task.required_workers <= 0) {
      console.error('No workers needed for this task');
      return res.status(400).json({ message: "No workers needed for this task" });
    }

    // Find the worker in the database
    const worker = await User.findOne({ email: worker_email });
    if (!worker) {
      console.error('Worker not found');
      return res.status(400).json({ message: "Worker not found" });
    }

    console.log('Task Submission Data:', req.body); // Debugging log for submission data

    // Create a new submission
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

    // Update the task's submission and required workers
    task.submissions.push(submission._id);
    task.required_workers -= 1;
    await task.save(); // Save the task after updating it

    // Create a notification for the Buyer
    await Notification.create({
      message: `${worker.name} submitted for ${task.task_title}`,
      toEmail: task.buyer_email,
      actionRoute: "/dashboard/buyer-home",
    });

    res.status(201).json(submission); // Return the created submission

  } catch (error) {
    console.error("Error in task submission:", error);
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
app.post("/api/submissions/:id/approve", authMiddleware, roleMiddleware("Buyer"), async (req, res) => {
  const submission = await Submission.findById(req.params.id); // Get submission by ID
  if (!submission) {
    return res.status(404).json({ message: "Submission not found" });
  }
  if (submission.buyer_email !== req.user.email) {
    return res.status(403).json({ message: "Forbidden" });
  }
  
  // Approve the submission
  submission.status = "approved";
  await submission.save();

  // Increase worker's coin balance
  const worker = await User.findOne({ email: submission.worker_email });
  worker.coin += submission.payable_amount;
  await worker.save();

  // Create notification for the worker
  await Notification.create({
    message: `You have earned ${submission.payable_amount} from ${submission.buyer_name} for completing ${submission.task_title}`,
    toEmail: worker.email,
    actionRoute: "/dashboard/worker-home",
  });
  // Respond with the approved submission
  res.json(submission);
});


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



const Stripe = require("stripe");
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
 
// Create Payment Intent
app.post("/api/payment/create", authMiddleware, async (req, res) => {
  const { amount, coin } = req.body;

  if (coin === undefined) {
    return res.status(400).json({ error: "Coin value is missing in the request body" });
  }

  try {
    const amountInCents = amount * 100;
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amountInCents,
      currency: "usd",
      description: "Coin purchase",
    });

    res.status(200).json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    console.error("Error creating payment intent:", error);
    res.status(500).json({ error: "Payment intent creation failed" });
  }
});

// Complete Payment and Update User Coins
app.post("/api/payments/complete-payment", authMiddleware, async (req, res) => {
  const { paymentMethodId, paymentIntentId, userId, coins } = req.body;

  console.log('Looking for user with Firebase UID:', userId);

  // Check if all required fields are provided
  if (!paymentMethodId || !paymentIntentId || !userId || !coins) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }

  try {
    const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);

    if (paymentIntent.status === 'succeeded') {
      console.log("Payment already succeeded, updating user coins.");

      // Ensure userId is always a string (Firebase UID is string)
      const userUid = userId && typeof userId === 'string' ? userId : String(userId);
      console.log("Firebase UID (converted):", userUid);

      // Fetch user using Firebase UID correctly
      const user = await User.findOne({ uid: userUid }); // Use Firebase UID for MongoDB query
      console.log("User from DB:", user);
      
      if (!user) {
        console.log("User not found");
        return res.status(404).json({ success: false, message: "User not found" });
      }

      // Update user coins after payment success
      user.coin = (user.coin || 0) + coins;
      await user.save();

      // Save payment information in MongoDB
      const payment = new Payment({
        buyer_id: user._id,  // Store MongoDB ObjectId
        amount: paymentIntent.amount_received / 100,  // Amount in dollars
        coin: coins,
        stripe_id: paymentIntent.id,
      });

      await payment.save();

      return res.json({ success: true, message: "Payment successful, coins added" });
    }

    // Confirm payment if it was not successful
    const confirmPaymentIntent = await stripe.paymentIntents.confirm(paymentIntentId, {
      payment_method: paymentMethodId,
    });

    if (confirmPaymentIntent.status !== "succeeded") {
      return res.status(400).json({ success: false, message: "Payment not completed" });
    }

    // Ensure userId is always a string (Firebase UID is string)
    const userUid = userId && typeof userId === 'string' ? userId : String(userId);  // Ensure the userId is a string

    const user = await User.findOne({ uid: userUid }); // Query by Firebase UID
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    user.coin = (user.coin || 0) + coins;
    await user.save();

    // Create and save payment info
    const payment = new Payment({
      buyer_id: user._id,  // MongoDB ObjectId
      amount: confirmPaymentIntent.amount_received / 100,  // Amount in dollars
      coin: coins,
      stripe_id: confirmPaymentIntent.id,
    });

    await payment.save();

    res.json({ success: true, message: "Payment successful, coins added" });
  } catch (error) {
    console.error("Error completing payment:", error); // Detailed logging
    res.status(500).json({ success: false, message: "Server error during payment", error: error.message });
  }
});

// Example of backend route querying Payments
app.get("/api/payments", authMiddleware, async (req, res) => {
  const { userId } = req.query;

  if (!userId) {
    return res.status(400).json({ error: "User ID is required" });
  }

  try {
    // Ensure userId is a valid ObjectId (though we are using Firebase UID here)
    const userPayments = await Payment.find({ buyer_id: userId });

    res.json(userPayments);  // Send payments back
  } catch (err) {
    console.error("Error fetching payments:", err);
    res.status(500).json({ error: "Failed to fetch payments" });
  }
});


// --- Withdrawal Routes (Worker) ---
app.post("/api/withdrawals", authMiddleware, async (req, res) => {
  try {
    const { worker_email, worker_name, withdrawal_coin, withdrawal_amount, payment_system, account_number } = req.body;

    // Ensure the worker has sufficient coins
    const worker = await User.findOne({ email: worker_email });
    if (!worker || worker.coin < withdrawal_coin) {
      return res.status(400).json({ message: "Insufficient coins for withdrawal" });
    }

    // Save the withdrawal request
    const withdrawal = new Withdrawal({
      worker_email,
      worker_name,
      withdrawal_coin,
      withdrawal_amount,
      payment_system,
      account_number,
      withdraw_date: new Date(),
      status: "pending"
    });

    await withdrawal.save();  // Save to DB
    worker.coin -= withdrawal_coin;  // Update worker's coin balance
    await worker.save();

    res.status(201).json(withdrawal);  // Respond with the saved withdrawal
  } catch (error) {
    console.error("Error in withdrawal process:", error);
    res.status(500).json({ message: "Error processing withdrawal", error: error.message });
  }
});

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

// Fetch withdrawal requests for workers and admin
app.get("/api/withdraw/requests", authMiddleware, roleMiddleware("Admin"), async (req, res) => {
  try {
    const requests = await Withdrawal.find({ status: "pending" }).populate("worker_id", "name email");
    res.status(200).json(requests);
  } catch (error) {
    console.error("Error fetching withdrawal requests:", error);
    res.status(500).json({ message: "Failed to fetch withdrawal requests" });
  }
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
app.get('/api/notifications', authMiddleware, async (req, res) => {
  const { email } = req.query;

  try {
    // Fetch notifications based on the user's email
    const notifications = await Notification.find({ toEmail: email }).sort({ time: -1 });

    // If no notifications found
    if (notifications.length === 0) {
      return res.status(200).json([]); // Return an empty array if no notifications
    }

    res.status(200).json(notifications); // Send notifications as JSON response
  } catch (err) {
    console.error("Error fetching notifications:", err);
    res.status(500).json({ message: "Failed to fetch notifications" });
  }
});

const getBuyerStatsFromDB = async (userId) => {
  try {
    console.log(`Fetching stats for userId: ${userId}`);

    // Use the string userId directly (no ObjectId conversion)
    const totalTasks = await Task.countDocuments({ buyer_id: userId });
    console.log(`Total tasks: ${totalTasks}`);

    const pendingTasks = await Task.countDocuments({
      buyer_id: userId,
      required_workers: { $gt: 0 },
    });
    console.log(`Pending tasks: ${pendingTasks}`);

    const totalPayments = await Payment.aggregate([
      { $match: { buyer_id: userId } },  // Use userId as a string
      { $group: { _id: null, totalPayments: { $sum: "$amount" } } },
    ]);
    console.log(`Total payments: ${totalPayments}`);

    return {
      totalTasks,
      pendingTasks,
      totalPayments: totalPayments[0] ? totalPayments[0].totalPayments : 0,
    };
  } catch (error) {
    console.error("Error in getBuyerStatsFromDB:", error);
    throw new Error("Error fetching stats from DB: " + error.message);
  }
};

// === API ENDPOINT TO GET BUYER STATS ===
app.get('/api/buyer/stats/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    if (!userId) {
      return res.status(400).json({ message: 'User ID is required.' });
    }

    // Log the received userId
    console.log(`Received userId: ${userId}`);

    // Fetch stats from DB
    const stats = await getBuyerStatsFromDB(userId);

    // Log the stats
    console.log(`Fetched stats: ${JSON.stringify(stats)}`);

    if (!stats) {
      return res.status(404).json({ message: 'No stats found for this user.' });
    }

    // Return the stats
    res.json(stats);
  } catch (error) {
    console.error("Error in getting buyer stats:", error);
    res.status(500).json({ message: 'Internal Server Error', error: error.message });
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


app.post("/api/upload-img", authMiddleware, async (req, res) => {
  const { imageBase64 } = req.body;

  if (!imageBase64) {
    return res.status(400).json({ message: "Image data is required" });
  }

  // Image Size Validation
  const imageSize = Buffer.byteLength(imageBase64, 'base64'); // Calculate base64 size
  if (imageSize > 5 * 1024 * 1024) {  // 5MB size limit
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
