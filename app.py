from flask import Flask, render_template, request, session, redirect
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "fallbacksecret")

# Admin credentials (SET THESE IN RENDER ENV VARIABLES)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")


# ----------------------
# DATABASE CONNECTION
# ----------------------
def get_db_connection():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn


# ----------------------
# DATABASE INITIALIZATION
# ----------------------
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

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
# HOME
# ----------------------
@app.route("/")
def home():
    return render_template("index.html")


# ----------------------
# REGISTER
# ----------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if "user" in session:
        return redirect("/dashboard")

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
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
    if "user" in session:
        return redirect("/dashboard")

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user"] = user["username"]
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

    conn = get_db_connection()
    notes = conn.execute(
        "SELECT * FROM notes WHERE user = ?",
        (session["user"],)
    ).fetchall()
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

        conn = get_db_connection()
        conn.execute(
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
    return redirect("/")


# ----------------------
# ADMIN LOGIN
# ----------------------
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

    return render_template("admin_login.html")


# ----------------------
# ADMIN DASHBOARD
# ----------------------
@app.route("/admin-dashboard")
def admin_dashboard():

    if "admin" not in session:
        return redirect("/admin-login")

    conn = get_db_connection()

    users = conn.execute("SELECT id, username FROM users").fetchall()
    notes = conn.execute("SELECT id, user, content FROM notes").fetchall()

    conn.close()

    return render_template(
        "admin_dashboard.html",
        users=users,
        notes=notes
    )


# ----------------------
# ADMIN LOGOUT
# ----------------------
@app.route("/admin-logout")
def admin_logout():
    session.pop("admin", None)
    return redirect("/admin-login")


# ----------------------
# MAIN
# ----------------------
if __name__ == "__main__":
    init_db()
    app.run()