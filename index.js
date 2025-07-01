import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import multer from "multer";
import fs from "fs";
import path from "path";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));

app.use(bodyParser.urlencoded({ extended: true}));
app.use(express.static("public"));
app.use('/uploads', express.static('uploads'));

app.use(passport.initialize());
app.use(passport.session());


// Storage config
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // Make sure this folder exists
  },
  filename: function (req, file, cb) {
    const uniqueName = Date.now() + path.extname(file.originalname);
    cb(null, uniqueName);
  },
});
const upload = multer({ storage: storage });


const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
  });
  db.connect();

let posts = [];
let users = [];

db.query("SELECT * FROM posts", (err, res) => {
    if (err) {
        console.error("Error fetching database", err.stack)
    }else {
        posts = res.rows;
    }
    console.log(posts);
});

db.query("SELECT * FROM users", (err, res) => {
    if (err) {
        console.error("Error fetching database", err.stack)
    }else {
        users = res.rows;
    }
    console.log(users);
});

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.get("/blogs", async (req, res) => {
    if (req.isAuthenticated()) {

        try {
            const result = await db.query("SELECT posts.id AS post_id, posts.content, posts.created_at, users.username, users.email, users.profile_picture FROM posts JOIN users ON posts.user_id = users.id ORDER BY posts.created_at DESC");

            const posts = result.rows;

            res.render("blogs.ejs", { posts });
        } catch (err) {
            console.error("Error fetching posts:", err);
            res.status.send("Failed to load posts");
        }
    } else {
        res.redirect("/login");
    }
});

 
app.get("/post", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("post.ejs");
    } else {
        res.redirect("/login");
    }
});
app.post("/submit", upload.single("file"), async (req, res) => {
    const userId = req.user.id;
    const content = req.body.content;

        console.log("Uploaded content:", content);
    try {
        await db.query("INSERT INTO posts (user_id, content) VALUES ($1, $2)", [userId, content]);
        res.redirect("/blogs");
    } catch (err) {
        console.error("Database insertion error", err);
        res.status(500).send("Error saving post");
    }
    
});

app.post("/login",
    passport.authenticate("local", {
        successRedirect: "/blogs",
        failureRedirect: "login",
    })
);

app.post("/register", upload.single("photo"), async (req, res) => {
    const userName = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    if (!req.file) {
        return res.status(400).send("No image uploaded");
    }

    const photoPath = req.file.path;
    console.log(userName, email, password, photoPath);
    try {

        const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (checkResult.rows.length > 0) {
            res.redirect("/login");
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.error("Error hashing password:", err);
                } else {
                    const result = await db.query("INSERT INTO users (username, email, password_hash, profile_picture) VALUES ($1, $2, $3, $4) RETURNING *", [userName, email, hash, photoPath]);
                    const user = result.rows[0];
                    req.login(user, (err) => {
                        if (err) {
                            console.error("Login error:", err);
                            return res.redirect("/login");
                        }
                        console.log("success!");
                        res.redirect("/blogs");
                    });
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
});


passport.use("local", 
    new Strategy(async function verify(email, password, cb) {
    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            const hashedPassword = user.password_hash;
            bcrypt.compare(password, hashedPassword, (err, 
            valid) => {
                if (err) {
                    console.error("Error compairing password:", err);
                    return cb(err);
                } else {
                    if (valid) {
                        return cb(null, user);
                    } else {
                        return cb(null, false);
                    }
                }
            });

        } else {
            return cb("User not found");
        }
    } catch (err) {
        console.log(err);
    }
    
}));
passport.serializeUser((user, cb) => {
  cb(null, user.id); // only store the user ID
});
passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = result.rows[0];
    cb(null, user);
  } catch (err) {
    cb(err);
  }
});


const uploadsDir = "./uploads";
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
  console.log("Created uploads folder");
}

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});