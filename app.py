from flask import Flask, render_template, request, session, redirect
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

ADMIN_USERNAME = "shivkaradmin"
ADMIN_PASSWORD = "149209"

app = Flask(__name__)
app.secret_key = "supersecretkey"

#-----------------------
#ADMIN LOGIN
#-----------------------

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin-dashboard")
        else:
            return "Invalid Admin Credentials ❌"

    return """
        <h2>Admin Login 🔐</h2>
        <form method="POST">
            <input name="username" placeholder="Admin Username"><br><br>
            <input type="password" name="password" placeholder="Password"><br><br>
            <button type="submit">Login</button>
        </form>
    """
    
#-----------------------
#ADMIN DASHBOARD
#---------------------

@app.route("/admin-dashboard")
def admin_dashboard():

    if "admin" not in session:
        return redirect("/admin-login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id, username FROM users")
    users = cursor.fetchall()

    cursor.execute("SELECT id, user, content FROM notes")
    notes = cursor.fetchall()

    conn.close()

    return f"""
        <h1>Admin Panel 🚀</h1>

        <h2>All Users</h2>
        {users}

        <h2>All Notes</h2>
        {notes}

        <br><br>
        <a href='/admin-logout'>Logout</a>
    """

# --------------------
# ADMIN logout
# ------------------

@app.route("/admin-logout")
def admin_logout():
    session.pop("admin", None)
    return redirect("/admin-login")

# ----------------------
# DATABASE INITIALIZATION
# ----------------------
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    # Notes Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            content TEXT
        )
    """)

    conn.commit()
    conn.close()


# ----------------------
# HOME ROUTE
# ----------------------
@app.route("/")
def home():
    return render_template("index.html")


# ----------------------
# REGISTER
# ----------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password),
            )
            conn.commit()
        except:
            return "Username already exists ❌"
        finally:
            conn.close()

        return redirect("/login")

    return render_template("register.html")


# ----------------------
# LOGIN
# ----------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):
            session["user"] = username
            return redirect("/dashboard")
        else:
            return "Invalid credentials ❌"

    return render_template("login.html")


# ----------------------
# DASHBOARD
# ----------------------
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT content FROM notes WHERE user = ?",
        (session["user"],)
    )

    notes = cursor.fetchall()
    conn.close()

    return render_template(
        "dashboard.html",
        username=session["user"],
        notes=notes
    )


# ----------------------
# ADD NOTE
# ----------------------
@app.route("/add_note", methods=["GET", "POST"])
def add_note():

    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":
        content = request.form.get("content")

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO notes (user, content) VALUES (?, ?)",
            (session["user"], content)
        )

        conn.commit()
        conn.close()

        return redirect("/dashboard")

    return render_template("add_note.html")



# ----------------------
# LOGOUT
# ----------------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


# ----------------------
# MAIN
# ----------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
