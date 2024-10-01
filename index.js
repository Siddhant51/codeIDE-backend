require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

// Handle OPTIONS request (preflight requests for all routes)
app.options("*", cors());

// Allow only specific frontend URLs and allow credentials
app.use(
  cors({
    origin: "*", // Frontend URL(s)
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], // Allowed methods
    allowedHeaders: ["Content-Type", "Authorization"], // Allowed headers
    credentials: true, // Allow credentials (if using cookies or tokens)
  })
);

// Middleware to parse JSON
app.use(express.json());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((err) => {
    console.error("MongoDB connection failed:", err);
  });

const ProjectSchema = new mongoose.Schema({
  name: String,
  userId: String,
  htmlCode: String,
  cssCode: String,
  jsCode: String,
});

const Project = mongoose.model("Project", ProjectSchema);

const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
});

const User = mongoose.model("User", UserSchema);

// Register route
app.post("/register", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
    });
    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Login route
app.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isMatch = await bcrypt.compare(req.body.password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Protected route
app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "Access granted!" });
});

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.header("Authorization");
  const token = authHeader;

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Get all projects for authenticated user
app.get("/projects", authenticateToken, async (req, res) => {
  try {
    const projects = await Project.find({ userId: req.user.userId }).sort({
      createdAt: -1,
    });
    res.json(projects);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get project by ID
app.get("/project/:projectId", authenticateToken, async (req, res) => {
  try {
    const project = await Project.findById(req.params.projectId);
    res.json(project);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete project by ID
app.delete("/project/:projectId", authenticateToken, async (req, res) => {
  try {
    const project = await Project.findByIdAndDelete(req.params.projectId);

    if (!project) {
      return res.status(404).json({ message: "Project not found" });
    }

    res.json({ message: "Project deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create new project
app.post("/project", authenticateToken, async (req, res) => {
  try {
    const newProject = new Project({
      name: req.body.name,
      userId: req.user.userId,
      htmlCode: req.body.htmlCode,
      cssCode: req.body.cssCode,
      jsCode: req.body.jsCode,
    });
    await newProject.save();
    res.status(201).json(newProject);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Save project code
app.put("/project/:projectId", authenticateToken, async (req, res) => {
  try {
    const { htmlCode, cssCode, jsCode } = req.body;

    // Find the project document
    const project = await Project.findById(req.params.projectId);

    if (!project) {
      return res.status(404).json({ error: "Project not found" });
    }

    // Update the project with new code
    project.htmlCode = htmlCode || "";
    project.cssCode = cssCode || "";
    project.jsCode = jsCode || "";

    // Save the updated project
    await project.save();

    res.status(200).json(project);
  } catch (error) {
    console.error("Error saving project code:", error);
    res.status(500).json({ error: "Failed to save project code" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
