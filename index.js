const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
    session({
        secret: "replace_this_with_a_secure_key",
        resave: false,
        saveUninitialized: true,
    })
);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const USERS = [
    {
        id: 1,
        username: "AdminUser",
        email: "admin@example.com",
        password: bcrypt.hashSync("admin123", SALT_ROUNDS), //In a database, you'd just store the hashes, but for 
                                                            // our purposes we'll hash these existing users when the 
                                                            // app loads
        role: "admin",
    },
    {
        id: 2,
        username: "RegularUser",
        email: "user@example.com",
        password: bcrypt.hashSync("user123", SALT_ROUNDS),
        role: "user", // Regular user
    },
];

// GET /login - Render login form
app.get("/login", (request, response) => {
    const success = request.query.success ? "User successfully registered! Please log in." : null;
    response.render("login", { error: null, success });
});

// POST /login - Allows a user to login
app.post("/login", async (request, response) => {

    const { email, password } = request.body;

    // Find the user by their email 
    const user = USERS.find(user => user.email === email);
    if (!user) {
        return response.render('login', { error: 'Invalid credentials.' });
    }

    // Compare the hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return response.render('login', { error: 'Invalid credentials.' });
    }

    // Save user in session
    request.session.user = { id: user.id, username: user.username, role: user.role };

    // Redirect to landing page
    response.redirect("/landing");
});

// GET /signup - Render signup form
app.get("/signup", (request, response) => {
    response.render("signup", { error: null });
});

// POST /signup - Allows a user to signup
app.post("/signup", async (request, response) => {

    const { username, email, password } = request.body;

    // Validate user input
    if (!username || !email || !password) {
        return response.render('signup', { error: 'All fields are required.'});
    }

    // Check if email is already registered
    const existingEmail = USERS.find(user => user.email === email);
    if (existingEmail) {
        return response.render('signup', { error: "Email is already registered."});
    }

    // Check if username already exists
    const existingUsername = USERS.find(user => user.username === username);
    if (existingUsername) {
        return response.render('signup', { error: 'Username already exists.'})
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Create the new user and add them to USERS array
    const newUser = {
        id: USERS.length + 1,
        username,
        email,
        password: hashedPassword,
        role: 'user',
    };
    USERS.push(newUser);

    // Redirect user to login page with a success message
    response.redirect('/login?success=1');
});

// GET / - Render index page or redirect to landing if logged in
app.get("/", (request, response) => {
    if (request.session.user) {
        return response.redirect("/landing");
    }
    response.render("index");
});

// GET /landing - Shows a welcome page for users, shows the names of all users if an admin
app.get("/landing", (request, response) => {
    
    const user = request.session.user;

    // Redirect user to home if not logged in
    if (!user) {
        return response.redirect('/');
    }

    // Render landing page with role-based content restricting data exposure to admin only
    response.render('landing', { user, users: user.role === 'admin' ? USERS : null });
});

// GET /logout - Allows a user to log out by destroying session
app.get("/logout", (request, response) => {
    request.session.destroy(() => {
        response.redirect("/");
    });
});


// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
