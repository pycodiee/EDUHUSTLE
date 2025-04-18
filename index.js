// Import required packages
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import fs from "fs";

// Environment setup
env.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

// Database connection setup
const { Client, Pool } = pg;
const db = new Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});
db.connect()
  .then(() => console.log("Connected to the database"))
  .catch((err) => console.error("Database connection error:", err));

// Create a connection pool for additional database operations
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

// App configuration
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Serve static files from the uploads directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/views', express.static(path.join(__dirname, 'views')));



// Passport Local Strategy for email/password login
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const isValid = await bcrypt.compare(password, user.password);
        return done(null, isValid ? user : false);
      } else {
        return done(null, false);
      }
    } catch (err) {
      done(err);
    }
  })
);

// Configure multer storage
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, 'uploads/videos/')) // Use path.join with _dirname
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname)) // Unique filename
    }
});

// File filter
const fileFilter = (req, file, cb) => {
    const allowedTypes = ['video/mp4', 'video/webm'];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Only MP4 and WebM are allowed.'), false);
    }
};

const upload = multer({ 
    storage: storage,
    fileFilter: fileFilter,
    limits: { fileSize: 500 * 1024 * 1024 } // 500MB
});

// Add this route after other routes, before the error handling middleware
app.post('/api/upload/video', upload.single('video'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded or file type not allowed' });
    }
    
    try {
        const { title, description } = req.body;
        const filePath = '/uploads/videos/' + req.file.filename; // Store relative path
        
        const result = await pool.query(
            'INSERT INTO videos (title, description, file_path, uploaded_by) VALUES ($1, $2, $3, $4) RETURNING *',
            [title, description, filePath, req.user.id]
        );
        
        res.json({ 
            message: 'Video uploaded successfully',
            video: result.rows[0]
        });
    } catch (error) {
        console.error('Error saving video details:', error);
        res.status(500).json({ error: 'Failed to save video details' });
    }
});

// Passport Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, full_name, password) VALUES ($1, $2, $3) RETURNING *",
            [profile.email, profile.displayName, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, result.rows[0]);
  } catch (err) {
    done(err);
  }
});

// Authentication middleware
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  req.session.returnTo = req.originalUrl;
  res.redirect("/login");
}

// Routes
app.get("/", (req, res) => res.redirect("/register"));
app.get("/login", (req, res) => res.render("login", { title: "Login" }));
app.get("/register", (req, res) => res.render("register", { title: "Register" }));
app.get("/home", ensureAuthenticated, (req, res) =>
  res.render("home", { user: req.user, title: "Home" })
);

// Google OAuth routes
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);
app.get(
  "/auth/google/hackathon",
  passport.authenticate("google", {
    failureRedirect: "/login",
  }),
  (req, res) => res.redirect("/home")
);

// Signup route
app.post("/api/signup", async (req, res) => {
  const { fullName, email, password } = req.body;
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (checkResult.rows.length > 0) {
      return res.status(400).json({ success: false, message: "Email already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await db.query(
      "INSERT INTO users (full_name, email, password) VALUES ($1, $2, $3)",
      [fullName, email, hashedPassword]
    );
    res.status(201).json({ success: true, message: "Account created successfully" });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ success: false, message: "Error creating account" });
  }
});

// Login route
app.post(
  "/api/login",
  passport.authenticate("local", { failureRedirect: "/login" }),
  (req, res) => {
    const redirectTo = req.session.returnTo || "/home";
    delete req.session.returnTo;
    res.json({ success: true, message: "Login successful", redirect: redirectTo });
  }
);

// Logout route
app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).send("Error during logout");
    }
    req.session.destroy((err) => {
      if (err) {
        console.error("Session destruction error:", err);
        return res.status(500).send("Error destroying session");
      }
      res.clearCookie("connect.sid");
      res.redirect("/login"); // Redirect to the login page after logout
    });
  });
});


// frontend routes
app.get("/user", ensureAuthenticated, (req, res) => {
  res.render("user", { user: req.user, title: "User Profile" });
});

app.get("/courses", ensureAuthenticated, (req, res) => {
  res.render("courses", { user: req.user, title: "My-Courses" });
});

app.get("/shedule", ensureAuthenticated, (req, res) => {
  res.render("shedule", { user: req.user, title: "Schedule" });
});

//frontend teacher routing
app.get("/admin", ensureAuthenticated, (req, res) => {
  res.render("admin", { user: req.user, title: "Admin Profile" });
});

app.get("/video", ensureAuthenticated, (req, res) => {
  res.render("video", { user: req.user, title: "videos" });
});

app.get("/quiz", ensureAuthenticated, (req, res) => {
  res.render("quiz", { user: req.user, title: "Technical Quiz" });
});

app.get("/chatbot", ensureAuthenticated, (req, res) => {
  res.render("chatbot", { user: req.user, title: "ChatBot" });
});

// Add this after other routes
app.get('/api/videos', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM videos ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching videos:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add this route for deleting videos
app.delete('/api/videos/:id', async (req, res) => {
    try {
        // First get the video details to get the file path
        const videoResult = await pool.query('SELECT file_path FROM videos WHERE id = $1', [req.params.id]);
        
        if (videoResult.rows.length === 0) {
            return res.status(404).json({ error: 'Video not found' });
        }

        const filePath = path.join(__dirname, videoResult.rows[0].file_path.replace('/uploads/', 'uploads/'));
        
        // Delete the file from filesystem
        fs.unlink(filePath, async (err) => {
            if (err) {
                console.error('Error deleting file:', err);
                // Continue with database deletion even if file deletion fails
            }
            
            // Delete from database
            await pool.query('DELETE FROM videos WHERE id = $1', [req.params.id]);
            
            res.json({ message: 'Video deleted successfully' });
        });
    } catch (error) {
        console.error('Error deleting video:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add these routes after other routes
app.post('/api/user/profile', async (req, res) => {
    try {
        const { fullName, email, linkedin, github, languages, tools } = req.body;
        const userId = req.user.id;

        // Convert arrays to JSON strings before storing
        const languagesJson = JSON.stringify(languages || []);
        const toolsJson = JSON.stringify(tools || []);

        const result = await pool.query(
            `UPDATE users 
             SET full_name = $1, 
                 email = $2, 
                 linkedin_url = $3, 
                 github_url = $4, 
                 languages = $5::jsonb, 
                 tools = $6::jsonb
             WHERE id = $7
             RETURNING *`,
            [fullName, email, linkedin, github, languagesJson, toolsJson, userId]
        );

        res.json({ success: true, user: result.rows[0] });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

app.get('/api/user/profile', async (req, res) => {
    try {
        const userId = req.user.id;
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Add these new routes for tracking progress

// Get user's learning track
app.get('/api/user/learning-track', async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get language progress
        const languageProgress = await pool.query(
            'SELECT language, progress FROM language_progress WHERE user_id = $1',
            [userId]
        );
        
        // Get course completion
        const courseProgress = await pool.query(
            `SELECT v.title, cc.completion_percentage, cc.completed_at 
             FROM course_completion cc 
             JOIN videos v ON cc.course_id = v.id 
             WHERE cc.user_id = $1`,
            [userId]
        );
        
        // Get skill development
        const skillProgress = await pool.query(
            'SELECT tool, proficiency_level, projects_completed FROM skill_development WHERE user_id = $1',
            [userId]
        );
        
        // Get recommended courses based on user's progress
        const recommendations = await pool.query(
            `SELECT DISTINCT v.* FROM videos v
             WHERE v.id NOT IN (
                 SELECT course_id FROM course_completion 
                 WHERE user_id = $1 AND completion_percentage = 100
             )
             LIMIT 3`,
            [userId]
        );

        res.json({
            languages: languageProgress.rows,
            courses: courseProgress.rows,
            skills: skillProgress.rows,
            recommendations: recommendations.rows
        });
    } catch (error) {
        console.error('Error fetching learning track:', error);
        res.status(500).json({ error: 'Failed to fetch learning track' });
    }
});

// Update progress for a specific language
app.post('/api/user/language-progress', async (req, res) => {
    try {
        const { language, progress } = req.body;
        const userId = req.user.id;
        
        const result = await pool.query(
            `INSERT INTO language_progress (user_id, language, progress)
             VALUES ($1, $2, $3)
             ON CONFLICT (user_id, language)
             DO UPDATE SET progress = $3, last_updated = CURRENT_TIMESTAMP
             RETURNING *`,
            [userId, language, progress]
        );
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error updating language progress:', error);
        res.status(500).json({ error: 'Failed to update progress' });
    }
});

// Update course completion status
app.post('/api/user/course-progress', async (req, res) => {
    try {
        const { courseId, completionPercentage } = req.body;
        const userId = req.user.id;
        
        const result = await pool.query(
            `INSERT INTO course_completion (user_id, course_id, completion_percentage)
             VALUES ($1, $2, $3)
             ON CONFLICT (user_id, course_id)
             DO UPDATE SET 
                completion_percentage = $3,
                completed_at = CASE WHEN $3 = 100 THEN CURRENT_TIMESTAMP ELSE NULL END,
                last_watched = CURRENT_TIMESTAMP
             RETURNING *`,
            [userId, courseId, completionPercentage]
        );
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error updating course progress:', error);
        res.status(500).json({ error: 'Failed to update progress' });
    }
});

// Add these new routes for progress tracking

// Get user's detailed progress
app.get('/api/user/detailed-progress', async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get language progress with detailed stats
        const languageProgress = await pool.query(`
            SELECT 
                language,
                proficiency_level,
                exercises_completed,
                last_practice_date,
                CASE 
                    WHEN proficiency_level >= 8 THEN 'Expert'
                    WHEN proficiency_level >= 5 THEN 'Intermediate'
                    ELSE 'Beginner'
                END as skill_level
            FROM user_language_progress
            WHERE user_id = $1
            ORDER BY proficiency_level DESC
        `, [userId]);

        // Get course progress with completion stats
        const courseProgress = await pool.query(`
            SELECT 
                v.title,
                ucp.watched_duration,
                ucp.total_duration,
                ucp.completed_exercises,
                ucp.completion_status,
                ROUND((ucp.watched_duration::float / NULLIF(ucp.total_duration, 0) * 100)::numeric, 2) as completion_percentage
            FROM user_course_progress ucp
            JOIN videos v ON v.id = ucp.course_id
            WHERE ucp.user_id = $1
            ORDER BY ucp.last_watched_at DESC
        `, [userId]);

        // Get progress history for the last 30 days
        const progressHistory = await pool.query(`
            SELECT 
                activity_type,
                SUM(progress_made) as total_progress,
                DATE(recorded_at) as date
            FROM progress_history
            WHERE user_id = $1
            AND recorded_at >= NOW() - INTERVAL '30 days'
            GROUP BY activity_type, DATE(recorded_at)
            ORDER BY date DESC
        `, [userId]);

        res.json({
            languages: languageProgress.rows,
            courses: courseProgress.rows,
            history: progressHistory.rows
        });
    } catch (error) {
        console.error('Error fetching detailed progress:', error);
        res.status(500).json({ error: 'Failed to fetch progress data' });
    }
});

// Update language progress
app.post('/api/user/language-progress/update', async (req, res) => {
    try {
        const { language, exercisesCompleted, timeSpent } = req.body;
        const userId = req.user.id;

        // Update language progress
        await pool.query(`
            INSERT INTO user_language_progress (user_id, language, exercises_completed)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id, language)
            DO UPDATE SET 
                exercises_completed = user_language_progress.exercises_completed + $3,
                proficiency_level = LEAST(user_language_progress.proficiency_level + 
                    CASE 
                        WHEN $3 >= 10 THEN 1
                        ELSE 0
                    END, 10),
                last_practice_date = CURRENT_TIMESTAMP
        `, [userId, language, exercisesCompleted]);

        // Record in history
        await pool.query(`
            INSERT INTO progress_history (user_id, activity_type, activity_id, progress_made)
            VALUES ($1, 'language', (
                SELECT id FROM user_language_progress 
                WHERE user_id = $1 AND language = $2
            ), $3)
        `, [userId, language, timeSpent]);

        res.json({ success: true, message: 'Progress updated successfully' });
    } catch (error) {
        console.error('Error updating language progress:', error);
        res.status(500).json({ error: 'Failed to update progress' });
    }
});

// Update course progress
app.post('/api/user/course-progress/update', async (req, res) => {
    try {
        const { courseId, watchedDuration, exercisesCompleted } = req.body;
        const userId = req.user.id;

        // Update course progress
        const result = await pool.query(`
            INSERT INTO user_course_progress (
                user_id, course_id, watched_duration, completed_exercises
            )
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, course_id)
            DO UPDATE SET 
                watched_duration = $3,
                completed_exercises = user_course_progress.completed_exercises + $4,
                last_watched_at = CURRENT_TIMESTAMP,
                completion_status = CASE 
                    WHEN $3 >= user_course_progress.total_duration THEN 'completed'
                    ELSE 'in_progress'
                END
            RETURNING *
        `, [userId, courseId, watchedDuration, exercisesCompleted]);

        // Record in history
        await pool.query(`
            INSERT INTO progress_history (user_id, activity_type, activity_id, progress_made)
            VALUES ($1, 'course', $2, $3)
        `, [userId, courseId, watchedDuration]);

        res.json({
            success: true,
            progress: result.rows[0]
        });
    } catch (error) {
        console.error('Error updating course progress:', error);
        res.status(500).json({ error: 'Failed to update progress' });
    }
});

// Get progress statistics
app.get('/api/user/progress-stats', async (req, res) => {
    try {
        const userId = req.user.id;

        const stats = await pool.query(`
            SELECT 
                (SELECT COUNT(*) FROM user_language_progress WHERE user_id = $1) as total_languages,
                (SELECT COUNT(*) FROM user_course_progress WHERE user_id = $1 AND completion_status = 'completed') as completed_courses,
                (SELECT ROUND(AVG(proficiency_level)::numeric, 1) FROM user_language_progress WHERE user_id = $1) as avg_proficiency,
                (SELECT SUM(progress_made) FROM progress_history WHERE user_id = $1 AND recorded_at >= NOW() - INTERVAL '7 days') as weekly_progress
        `, [userId]);

        res.json(stats.rows[0]);
    } catch (error) {
        console.error('Error fetching progress stats:', error);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

// Simplified skills tracker route
app.get('/api/user/skills-tracker', async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get user's selected languages and tools
        const result = await pool.query(
            'SELECT languages, tools FROM users WHERE id = $1',
            [userId]
        );

        const languages = result.rows[0].languages || [];
        const tools = result.rows[0].tools || [];

        // Create simple progress tracking for selected items
        const languageProgress = languages.map(lang => ({
            language: lang,
            progress: 0,  // Initial progress
            status: 'Not Started'
        }));

        const toolProgress = tools.map(tool => ({
            tool: tool,
            progress: 0,  // Initial progress
            status: 'Not Started'
        }));

        res.json({
            languages: languageProgress,
            tools: toolProgress
        });
    } catch (error) {
        console.error('Error fetching skills tracker:', error);
        res.status(500).json({ error: 'Failed to fetch skills tracker' });
    }
});

// Add or update these schedule routes
app.post('/api/schedule/add', async (req, res) => {
    try {
        const { className, instructor, date, startTime, endTime, roomNumber, notes } = req.body;
        const userId = req.user.id;

        // First check if a class already exists at this time
        const existingClass = await pool.query(
            `SELECT * FROM class_schedules 
             WHERE user_id = $1 
             AND date = $2 
             AND (
                 (start_time <= $3 AND end_time > $3) OR
                 (start_time < $4 AND end_time >= $4) OR
                 (start_time >= $3 AND end_time <= $4)
             )
             AND is_deleted = FALSE`,
            [userId, date, startTime, endTime]
        );

        if (existingClass.rows.length > 0) {
            return res.status(400).json({ 
                error: 'A class is already scheduled during this time slot' 
            });
        }

        // Insert the new class schedule
        const result = await pool.query(
            `INSERT INTO class_schedules 
            (user_id, class_name, instructor, date, start_time, end_time, room_number, notes)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *`,
            [userId, className, instructor, date, startTime, endTime, roomNumber, notes]
        );

        // Send back the created schedule
        res.json({ 
            success: true, 
            message: 'Class scheduled successfully',
            schedule: result.rows[0] 
        });
    } catch (error) {
        console.error('Error adding schedule:', error);
        res.status(500).json({ error: 'Failed to add schedule' });
    }
});

app.get('/api/schedule', async (req, res) => {
    try {
        const userId = req.user.id;
        // Get all active schedules for the user
        const result = await pool.query(
            `SELECT * FROM class_schedules 
             WHERE user_id = $1 
             AND is_deleted = FALSE 
             ORDER BY date ASC, start_time ASC`,
            [userId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching schedule:', error);
        res.status(500).json({ error: 'Failed to fetch schedule' });
    }
});

app.delete('/api/schedule/:id', async (req, res) => {
    try {
        const scheduleId = req.params.id;
        const userId = req.user.id;

        // Soft delete by updating is_deleted flag
        const result = await pool.query(
            `UPDATE class_schedules 
             SET is_deleted = TRUE 
             WHERE id = $1 AND user_id = $2 
             AND is_deleted = FALSE
             RETURNING *`,
            [scheduleId, userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ 
                error: 'Schedule not found or already deleted' 
            });
        }

        res.json({ 
            success: true, 
            message: 'Schedule deleted successfully',
            deletedSchedule: result.rows[0]
        });
    } catch (error) {
        console.error('Error deleting schedule:', error);
        res.status(500).json({ error: 'Failed to delete schedule' });
    }
});

// Add or update these routes for payment handling
app.get('/payment', ensureAuthenticated, async (req, res) => {
    try {
        const courseId = req.query.courseId;
        
        // Fetch course details
        const result = await pool.query(
            'SELECT * FROM courses WHERE id = $1',
            [courseId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).send('Course not found');
        }
        
        const course = result.rows[0];
        
        // Check if user already purchased the course
        const purchaseCheck = await pool.query(
            'SELECT * FROM course_purchases WHERE user_id = $1 AND course_id = $2',
            [req.user.id, courseId]
        );
        
        if (purchaseCheck.rows.length > 0) {
            return res.redirect(`/courses/${courseId}`);
        }
        
        res.render('payment', {
            course: course,
            user: req.user
        });
    } catch (error) {
        console.error('Error loading payment page:', error);
        res.status(500).send('Error loading payment page');
    }
});

// Process payment
app.post('/api/process-payment', ensureAuthenticated, async (req, res) => {
    try {
        const { courseId } = req.body;
        const userId = req.user.id;

        // Get course details
        const courseResult = await pool.query(
            'SELECT * FROM courses WHERE id = $1',
            [courseId]
        );

        if (courseResult.rows.length === 0) {
            return res.status(404).json({ error: 'Course not found' });
        }

        const course = courseResult.rows[0];

        // Record the purchase
        await pool.query(
            `INSERT INTO course_purchases (user_id, course_id, amount)
             VALUES ($1, $2, $3)`,
            [userId, courseId, course.price]
        );

        // Grant access to the course
        await pool.query(
            `INSERT INTO user_courses (user_id, course_id)
             VALUES ($1, $2)
             ON CONFLICT (user_id, course_id) DO NOTHING`,
            [userId, courseId]
        );

        res.json({
            success: true,
            message: 'Payment processed successfully',
            redirect: `/courses/${courseId}`
        });
    } catch (error) {
        console.error('Payment processing error:', error);
        res.status(500).json({ error: 'Failed to process payment' });
    }
});

// Get course details
app.get('/api/courses/:id', async (req, res) => {
    try {
        const courseId = parseInt(req.params.id);
        
        if (isNaN(courseId)) {
            return res.status(400).json({ error: 'Invalid course ID' });
        }

        const result = await pool.query(
            'SELECT * FROM courses WHERE id = $1',
            [courseId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Course not found' });
        }
        
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error fetching course:', error);
        res.status(500).json({ error: 'Failed to fetch course details' });
    }
});

// Add a route to get all courses
app.get('/api/courses', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM courses ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching courses:', error);
        res.status(500).json({ error: 'Failed to fetch courses' });
    }
});

// Add this route for the quiz
app.get('/quiz', ensureAuthenticated, (req, res) => {
    res.render('quiz', { user: req.user, title: 'Technical Quiz' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Error occurred:", err);
  res.status(500).send("Something broke!");
});

// Start server
if (process.env.NODE_ENV !== "production") {
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}

// Export for Vercel deployment
export default app;