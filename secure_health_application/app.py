#from flask import Flask
#app = Flask(__name__)

#@app.route('/')
#def home():
#    return "✅ Flask is working perfectly! Welcome to Secure Health Application."

#if __name__ == '__main__':
#    app.run(debug=True)
# from flask import Flask, render_template

# app = Flask(__name__)

# @app.route('/')
# def home():
#     return render_template('index.html')
# # I'm adding a very simple login page route so the navbar link works
# @app.route('/login')
# def login():
#     # I'm rendering a template called login.html (I'll create it next)
#     return render_template('login.html')

# if __name__ == '__main__':
#     app.run(debug=True)
# # I'm building the Flask app and adding simple, secure login logic
# from flask import Flask, render_template, request, redirect, url_for, flash, session
# from werkzeug.security import generate_password_hash, check_password_hash
# import os

# # I'm creating the Flask application instance
# app = Flask(__name__)

# # I'm setting a secret key so sessions and flash() work securely
# # (Later, for production, this MUST come from an environment variable)
# app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")

# # I'm defining a tiny in-memory "database" of users for now
# # (Later, we’ll replace this with a real data store)
# USERS = {
#     "demo": generate_password_hash("Password123!")
# }

# @app.route("/")
# def home():
#     # I'm rendering the homepage (extends base.html)
#     return render_template("index.html")

# @app.route("/login", methods=["GET", "POST"])
# def login():
#     # I show the form on GET; on POST I validate credentials
#     if request.method == "POST":
#         username = request.form.get("username", "").strip()
#         password = request.form.get("password", "")

#         # I'm doing minimal input validation first
#         if not username or not password:
#             flash("Please enter both username and password.", "error")
#             return render_template("login.html", username=username)

#         # I'm checking the stored hashed password securely
#         if username in USERS and check_password_hash(USERS[username], password):
#             session["user"] = username
#             flash(f"Welcome back, {username}!", "success")
#             return redirect(url_for("dashboard"))
#         else:
#             flash("Invalid username or password.", "error")
#             return render_template("login.html", username=username), 401

#     # If it's a GET request, I just show the form
#     return render_template("login.html")

# @app.route("/dashboard")
# def dashboard():
#     # I'm protecting this page: if you’re not logged in, I send you to /login
#     if "user" not in session:
#         flash("Please log in to access the dashboard.", "warning")
#         return redirect(url_for("login"))
#     return render_template("dashboard.html", user=session["user"])

# @app.route("/logout")
# def logout():
#     # I'm clearing the session to log the user out
#     session.clear()
#     flash("You have been logged out.", "success")
#     return redirect(url_for("home"))

# if __name__ == "__main__":
#     app.run(debug=True)


# now replacing my app.py a more secure version (an AI assisted code)
# app.py
# building the Flask app with CSRF protection, session hardening,
# basic auth flow, security headers, and a tiny rate-limit for login.

from datetime import timedelta, datetime
from collections import defaultdict, deque
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from werkzeug.security import check_password_hash, generate_password_hash

# CSRF
from flask_wtf import CSRFProtect

# My WTForms login form
from forms import LoginForm

app = Flask(__name__)

# --- Core security config (I'm keeping secrets out of code in real life) ---
app.config["SECRET_KEY"] = "change-me-in-real-project"  # I'm using this for sessions + CSRF
app.config["WTF_CSRF_ENABLED"] = True

# Session hardening (I'm making cookies stricter)
app.config["SESSION_COOKIE_SECURE"] = False  # set True when using HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.permanent_session_lifetime = timedelta(minutes=30)  # I'm expiring idle sessions sooner

# Enable CSRF protection
csrf = CSRFProtect(app)

# --- Fake user store (I'm hashing the password so I never store plain text) ---
USERS = {
    # username: password_hash for 'password123'
    "student": generate_password_hash("password123")
}

# I'm connecting both my local SQLite database (for users)
# and a MongoDB database (for patient stroke records)

from flask_sqlalchemy import SQLAlchemy
from pymongo import MongoClient

# I'm setting up SQLite for user authentication
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# I'm initialising SQLAlchemy
db = SQLAlchemy(app)

# I'm defining a simple User model for authentication data
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

# I'm connecting to my local MongoDB (patient records)
# Later, this will hold all stroke dataset records securely
mongo_client = MongoClient("mongodb://localhost:27017/")
mongo_db = mongo_client["secure_health_db"]
patients_collection = mongo_db["patients"]

# --- Tiny in-memory rate-limit for /login (I'm throttling repeated failures) ---
FAIL_WINDOW = 60          # seconds I'm looking back
FAIL_LIMIT = 5            # I'm allowing 5 failed attempts per window
fail_log = defaultdict(lambda: deque())  # ip -> deque[timestamps]

def too_many_failures(ip: str) -> bool:
    now = datetime.utcnow().timestamp()
    dq = fail_log[ip]
    # I'm dropping old entries outside my window
    while dq and now - dq[0] > FAIL_WINDOW:
        dq.popleft()
    return len(dq) >= FAIL_LIMIT

def note_failure(ip: str):
    now = datetime.utcnow().timestamp()
    dq = fail_log[ip]
    dq.append(now)

# --- Security headers (I'm adding a few safe-by-default headers) ---
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # I'm allowing only same-origin resources + my own inline styles (kept minimal).
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    return resp

# --- Helpers ---
def require_login():
    if not session.get("user"):
        abort(401)

# --- Routes ---
@app.route("/")
def home():
    # I'm showing the friendly home page (extends base.html).
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"

    # I'm blocking if this IP has too many recent failures
    if request.method == "POST" and too_many_failures(client_ip):
        flash("Too many failed attempts. Please wait a minute and try again.", "error")
        return render_template("login.html", form=form), 429

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # I'm looking up the user and verifying the hash
        stored_hash = USERS.get(username)
        if stored_hash and check_password_hash(stored_hash, password):
            session.clear()
            session.permanent = True      # uses my 30-min lifetime above
            session["user"] = username
            flash("You are now signed in.", "success")
            return redirect(url_for("dashboard"))

        # I'm logging the failed attempt and telling the user (without leaking detail)
        note_failure(client_ip)
        flash("Invalid username or password.", "error")
        return render_template("login.html", form=form), 401

    # GET or invalid POST falls through to here
    return render_template("login.html", form=form)

# --- Analytics helpers & dashboard route ------------------------------------
# I'm importing tools to count and summarise neatly
from collections import Counter
from statistics import mean

def _age_band(a):
    """I'm bucketing ages so I can chart them cleanly."""
    try:
        a = float(a)
    except (TypeError, ValueError):
        return "Unknown"
    if a < 18: return "0–17"
    if a < 36: return "18–35"
    if a < 51: return "36–50"
    if a < 66: return "51–65"
    return "66+"

@app.route("/dashboard")
def dashboard():
    # I'm protecting this page so only logged-in users can view analytics
    if not session.get("user"):
        flash("Please log in to see the dashboard.", "warning")
        return redirect(url_for("login"))

    # I'm pulling just the fields I need to keep this light and fast
    cursor = patients_collection.find({}, {
        "_id": 0,
        "age": 1,
        "gender": 1,
        "stroke": 1,
        "avg_glucose_level": 1,
        "bmi": 1,
        "hypertension": 1,
        "heart_disease": 1,
        "smoking_status": 1
    })
    docs = list(cursor)

    total = len(docs)
    stroke_yes = sum(1 for d in docs if int(d.get("stroke", 0)) == 1)
    stroke_no  = total - stroke_yes
    stroke_rate = round((stroke_yes / total) * 100, 2) if total else 0.0

    # I'm counting simple distributions for quick charts
    by_gender = Counter((d.get("gender") or "Unknown") for d in docs)
    by_age_band = Counter(_age_band(d.get("age")) for d in docs)

    # I'm showing a couple of simple risk-factor signals (means)
    # – keeping it clearly labelled as descriptive, not clinical advice.
    glucose_stroke = [float(d.get("avg_glucose_level")) for d in docs if d.get("avg_glucose_level") not in (None, "") and int(d.get("stroke",0))==1]
    glucose_no     = [float(d.get("avg_glucose_level")) for d in docs if d.get("avg_glucose_level") not in (None, "") and int(d.get("stroke",0))==0]
    bmi_stroke     = [float(d.get("bmi")) for d in docs if d.get("bmi") not in (None, "") and int(d.get("stroke",0))==1]
    bmi_no         = [float(d.get("bmi")) for d in docs if d.get("bmi") not in (None, "") and int(d.get("stroke",0))==0]

    stats = {
        "total": total,
        "stroke_yes": stroke_yes,
        "stroke_no": stroke_no,
        "stroke_rate": stroke_rate,
        "by_gender": by_gender,
        "by_age_band": by_age_band,
        "glucose_mean_stroke": round(mean(glucose_stroke), 1) if glucose_stroke else None,
        "glucose_mean_no": round(mean(glucose_no), 1) if glucose_no else None,
        "bmi_mean_stroke": round(mean(bmi_stroke), 1) if bmi_stroke else None,
        "bmi_mean_no": round(mean(bmi_no), 1) if bmi_no else None,
    }

    # I'm passing lists to the template so Chart.js can plot them
    gender_labels = list(stats["by_gender"].keys())
    gender_values = [stats["by_gender"][g] for g in gender_labels]

    age_labels = ["0–17", "18–35", "36–50", "51–65", "66+"]
    age_values = [stats["by_age_band"].get(lbl, 0) for lbl in age_labels]

    return render_template(
        "dashboard.html",
        user=session.get("user"),
        stats=stats,
        gender_labels=gender_labels, gender_values=gender_values,
        age_labels=age_labels, age_values=age_values
    )

# I'm exposing a tiny JSON API so the dashboard (or markers) can fetch stats if needed
@app.route("/api/stats")
def api_stats():
    if not session.get("user"):
        return {"error": "unauthorised"}, 401
    # I’m returning just the high-level numbers for now
    cursor = patients_collection.find({}, {"_id":0, "stroke":1})
    docs = list(cursor)
    total = len(docs)
    stroke_yes = sum(1 for d in docs if int(d.get("stroke",0))==1)
    return {"total": total, "stroke_yes": stroke_yes, "stroke_no": total-stroke_yes}
# I'm providing a proper /logout route so the nav link works
@app.route("/logout")
def logout():
    session.clear()                         # I'm clearing the session safely
    flash("You have been signed out.", "success")
    return redirect(url_for("home"))        # I'm sending the user back to home
# --- Dev runner ---
if __name__ == "__main__":
    app.run(debug=True)