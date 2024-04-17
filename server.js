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
          "SELECT firstName, lastName, skills, workExperience, email, resume_url FROM job_seeker_master WHERE user_id = ?";
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
  const {
    firstName,
    lastName,
    companyName,
    address,
    skills,
    email,
    workExperience,
  } = req.body;
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
        "INSERT INTO job_seeker_master (user_id, firstName, lastName, skills, workExperience, email, resume_url) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [userId, firstName, lastName, skills, workExperience, email, resumeUrl]
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
      const { firstName, lastName, skills, workExperience, email } = req.body;

      await pool.query(
        "UPDATE job_seeker_master SET firstName = ?, lastName = ?, skills = ?, workExperience = ?, email = ? WHERE user_id = ?",
        [firstName, lastName, skills, workExperience, email, userId]
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

app.get("/api/job-seekers", authenticateToken, async (req, res) => {
  try {
    const { skills } = req.query;

    let query = `
      SELECT u.user_id, u.username, jsm.email, jsm.skills
      FROM users u
      JOIN job_seeker_master jsm ON u.user_id = jsm.user_id
      WHERE u.profile_category = 'jobSeeker'
    `;

    if (skills) {
      query += ` AND jsm.skills LIKE '%${skills}%'`;
    }

    const [jobSeekerRows] = await pool.query(query);

    const jobSeekers = jobSeekerRows.map((row) => ({
      username: row.username,
      email: row.email,
      user_id: row.user_id,
    }));

    res.json({ jobSeekers });
  } catch (error) {
    console.error("Error fetching job seekers:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/job-seeker/:username", authenticateToken, async (req, res) => {
  try {
    const { username } = req.params;

    // Retrieve job seeker details based on the provided username
    const [jobSeekerRows] = await pool.query(
      `
      SELECT u.username, jsm.firstName, jsm.lastName, jsm.email, jsm.skills, jsm.workExperience, jsm.resume_url
      FROM users u
      JOIN job_seeker_master jsm ON u.user_id = jsm.user_id
      WHERE u.username = ? AND u.profile_category = 'jobSeeker'
      `,
      [username]
    );

    if (jobSeekerRows.length === 0) {
      return res.status(404).json({ message: "Job seeker not found" });
    }

    const jobSeekerDetails = {
      username: jobSeekerRows[0].username,
      firstName: jobSeekerRows[0].firstName,
      lastName: jobSeekerRows[0].lastName,
      email: jobSeekerRows[0].email,
      skills: jobSeekerRows[0].skills,
      workExperience: jobSeekerRows[0].workExperience,
      resumeUrl: jobSeekerRows[0].resume_url,
    };

    res.json({ jobSeekerDetails });
  } catch (error) {
    console.error("Error fetching job seeker details:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Get jobs posted by the logged-in employer
app.get("/api/jobs_for_user", authenticateToken, async (req, res) => {
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

    const [jobs] = await pool.query("SELECT * FROM jobs WHERE user_id = ?", [
      userId,
    ]);

    res.json({ jobs });
  } catch (error) {
    console.error("Error fetching jobs:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Post a new job
app.post("/api/jobs", authenticateToken, async (req, res) => {
  try {
    const { jobTitle, jobDescription, tags, budget, duration } = req.body;
    // Fetch user by username to get the userID
    const [userRows] = await pool.query(
      "SELECT user_id, profile_category FROM users WHERE username = ?",
      [req.user.username]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const userId = userRows[0].user_id;

    await pool.query(
      "INSERT INTO jobs (user_id, job_title, job_description, tags, budget, duration) VALUES (?, ?, ?, ?, ?, ?)",
      [userId, jobTitle, jobDescription, tags, budget, duration]
    );

    res.json({ message: "Job posted successfully" });
  } catch (error) {
    console.error("Error posting job:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
// Get job details by ID
app.get("/api/jobs/:id", authenticateToken, async (req, res) => {
  try {
    const jobId = req.params.id;
    const [userRows] = await pool.query(
      "SELECT user_id, profile_category FROM users WHERE username = ?",
      [req.user.username]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const userId = userRows[0].user_id;

    const [job] = await pool.query(
      "SELECT * FROM jobs WHERE job_id = ? AND user_id = ?",
      [jobId, userId]
    );

    if (job.length === 0) {
      return res.status(404).json({ message: "Job not found" });
    }

    res.json({ job: job[0] });
  } catch (error) {
    console.error("Error fetching job details:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Update job details
app.put("/api/jobs/:id", authenticateToken, async (req, res) => {
  try {
    const jobId = req.params.id;
    const [userRows] = await pool.query(
      "SELECT user_id, profile_category FROM users WHERE username = ?",
      [req.user.username]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const userId = userRows[0].user_id;
    const { jobTitle, jobDescription, tags, budget, duration } = req.body;

    const [job] = await pool.query(
      "SELECT * FROM jobs WHERE job_id = ? AND user_id = ?",
      [jobId, userId]
    );

    if (job.length === 0) {
      return res.status(404).json({ message: "Job not found" });
    }

    await pool.query(
      "UPDATE jobs SET job_title = ?, job_description = ?, tags = ?, budget = ?, duration = ? WHERE job_id = ?",
      [jobTitle, jobDescription, tags, budget, duration, jobId]
    );

    res.json({ message: "Job updated successfully" });
  } catch (error) {
    console.error("Error updating job:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Get all jobs with tag filtering
app.get("/api/jobs", authenticateToken, async (req, res) => {
  try {
    const { job_title } = req.query;
    let query = "SELECT * FROM jobs";
    let values = [];

    if (job_title) {
      query += " WHERE job_title LIKE ?";
      values.push(`%${job_title}%`);
    }

    const [jobs] = await pool.query(query, values);
    res.json({ jobs });
  } catch (error) {
    console.error("Error fetching jobs:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Apply for a job
app.post("/api/apply-job", authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.body;
    const [userRows] = await pool.query(
      "SELECT user_id, profile_category FROM users WHERE username = ?",
      [req.user.username]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const userId = userRows[0].user_id;

    // Check if the user has already applied for the job
    const [existingApplication] = await pool.query(
      "SELECT * FROM job_applications WHERE user_id = ? AND job_id = ?",
      [userId, jobId]
    );

    if (existingApplication.length > 0) {
      return res
        .status(400)
        .json({ message: "You have already applied for this job" });
    }

    // Insert the job application into the database
    await pool.query(
      "INSERT INTO job_applications (user_id, job_id) VALUES (?, ?)",
      [userId, jobId]
    );

    res.json({ message: "Job application submitted successfully" });
  } catch (error) {
    console.error("Error applying for job:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Get applied jobs for the logged-in user
app.get("/api/applied-jobs", authenticateToken, async (req, res) => {
  try {
    const [userRows] = await pool.query(
      "SELECT user_id, profile_category FROM users WHERE username = ?",
      [req.user.username]
    );

    if (userRows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const userId = userRows[0].user_id;

    const [appliedJobs] = await pool.query(
      "SELECT job_id FROM job_applications WHERE user_id = ?",
      [userId]
    );

    const appliedJobIds = appliedJobs.map((application) => application.job_id);

    res.json({ appliedJobs: appliedJobIds });
  } catch (error) {
    console.error("Error fetching applied jobs:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Get applicants for a job
app.get("/api/jobs/:id/applicants", authenticateToken, async (req, res) => {
  try {
    const jobId = req.params.id;

    const [applicants] = await pool.query(
      `
      SELECT u.user_id, u.username
      FROM users u
      JOIN job_applications ja ON u.user_id = ja.user_id
      WHERE ja.job_id = ?
      `,
      [jobId]
    );

    res.json({ applicants });
  } catch (error) {
    console.error("Error fetching applicants:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
// Start the server
app.listen(process.env.PORT || 5002, () => {
  console.log("Server is running on port 5002");
});
