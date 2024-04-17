const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cors = require("cors");
const { S3Client } = require("@aws-sdk/client-s3");
const multer = require("multer");
const multerS3 = require("multer-s3");
const { authenticateToken, pool } = require("./utilities");

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});
const upload = multer({
  storage: multerS3({
    s3: s3,
    bucket: process.env.S3_BUCKET_NAME,
    key: function (req, file, cb) {
      cb(null, `resumes/${Date.now()}_${file.originalname}`);
    },
  }),
}).single("resume");

// User registration endpoint
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if user already exists
    const [rows] = await pool.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);
    if (rows.length > 0) {
      return res.status(409).json({ message: "User already exists" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    await pool.query("INSERT INTO users (username, password) VALUES (?, ?)", [
      username,
      hashedPassword,
    ]);

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// User login endpoint
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find the user by username
    const [rows] = await pool.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);
    const user = rows[0];

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Compare the provided password with the stored hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Generate a JWT token
    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET);

    res.json({ token });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/user-details", authenticateToken, async (req, res) => {
  try {
    // Fetch user by username to get the userID
    const [userRows] = await pool.query(
      "SELECT user_id, profile_category FROM users WHERE username = ?",
      [req.user.username]
    );
    if (userRows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const userId = userRows[0].user_id;
    const profileCategory = userRows[0].profile_category;

    // Retrieve general user information and check registration status
    const [rows] = await pool.query(
      "SELECT is_registered FROM users WHERE user_id = ?",
      [userId]
    );

    if (rows.length === 0 || !rows[0].is_registered) {
      res.json({ isRegistered: false });
    } else {
      // Additional query to get detailed information based on user profile category
      let detailsQuery = "";
      if (profileCategory === "employer") {
        detailsQuery =
          "SELECT companyName, address FROM emp_master WHERE user_id = ?";
      } else if (profileCategory === "jobSeeker") {
        detailsQuery =
          "SELECT firstName, lastName, skills, workExperience, resume_url FROM job_seeker_master WHERE user_id = ?";
      }

      const [details] = await pool.query(detailsQuery, [userId]);

      // Send back user details along with registration status
      res.json({
        isRegistered: true,
        userDetails:
          details.length > 0
            ? {
                ...details[0],
                username: req.user.username,
                profileType: profileCategory,
              }
            : null,
      });
    }
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/profile/:type", authenticateToken, upload, async (req, res) => {
  const type = req.params.type;
  const { firstName, lastName, companyName, address, skills, workExperience } =
    req.body;
  const resumeUrl = req.file ? req.file.location : null;

  try {
    const [userRows] = await pool.query(
      "SELECT user_id FROM users WHERE username = ?",
      [req.user.username]
    );
    const userId = userRows[0].user_id;

    // Insert into respective table based on profile type and update users table
    if (type === "employer") {
      await pool.query(
        "INSERT INTO emp_master (user_id, companyName, address) VALUES (?, ?, ?)",
        [userId, companyName, address]
      );
      await pool.query(
        "UPDATE users SET is_registered = TRUE, profile_category = 'employer' WHERE user_id = ?",
        [userId]
      );
    } else if (type === "jobSeeker") {
      await pool.query(
        "INSERT INTO job_seeker_master (user_id, firstName, lastName, skills, workExperience, resume_url) VALUES (?, ?, ?, ?, ?, ?)",
        [userId, firstName, lastName, skills, workExperience, resumeUrl]
      );
      await pool.query(
        "UPDATE users SET is_registered = TRUE, profile_category = 'jobSeeker' WHERE user_id = ?",
        [userId]
      );
    }

    res
      .status(201)
      .json({ message: "Profile created and user updated successfully" });
  } catch (error) {
    console.error("Error creating profile:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/api/update-user", authenticateToken, upload, async (req, res) => {
  try {
    console.log("req body", req.body);
    // Fetch user by username to get the userID
    const [userRows] = await pool.query(
      "SELECT user_id, profile_category FROM users WHERE username = ?",
      [req.user.username]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const userId = userRows[0].user_id;
    const profileCategory = userRows[0].profile_category;
    console.log("userId", userId);
    console.log("profileCategory", profileCategory);
    console.log("Incoming request body", req.body);

    // Update user details based on profile category
    if (profileCategory === "employer") {
      // Update employer details
      const { companyName, address } = req.body;
      await pool.query(
        "UPDATE emp_master SET companyName = ?, address = ? WHERE user_id = ?",
        [companyName, address, userId]
      );
    } else if (profileCategory === "jobSeeker") {
      // Update job seeker details
      const { firstName, lastName, skills, workExperience } = req.body;

      await pool.query(
        "UPDATE job_seeker_master SET firstName = ?, lastName = ?, skills = ?, workExperience = ? WHERE user_id = ?",
        [firstName, lastName, skills, workExperience, userId]
      );

      // Handle resume upload if provided
      if (req.file) {
        const resumeUrl = req.file.location;

        // Update the resume URL in the database
        await pool.query(
          "UPDATE job_seeker_master SET resume_url = ? WHERE user_id = ?",
          [resumeUrl, userId]
        );
      }
    }

    res.json({ message: "User details updated successfully" });
  } catch (error) {
    console.error("Error updating user details:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
// Start the server
app.listen(5002, () => {
  console.log("Server is running on port 5002");
});
