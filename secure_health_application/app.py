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
# I'm building the Flask app and adding simple, secure login logic
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import os

# I'm creating the Flask application instance
app = Flask(__name__)

# I'm setting a secret key so sessions and flash() work securely
# (Later, for production, this MUST come from an environment variable)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")

# I'm defining a tiny in-memory "database" of users for now
# (Later, we’ll replace this with a real data store)
USERS = {
    "demo": generate_password_hash("Password123!")
}

@app.route("/")
def home():
    # I'm rendering the homepage (extends base.html)
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    # I show the form on GET; on POST I validate credentials
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # I'm doing minimal input validation first
        if not username or not password:
            flash("Please enter both username and password.", "error")
            return render_template("login.html", username=username)

        # I'm checking the stored hashed password securely
        if username in USERS and check_password_hash(USERS[username], password):
            session["user"] = username
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "error")
            return render_template("login.html", username=username), 401

    # If it's a GET request, I just show the form
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    # I'm protecting this page: if you’re not logged in, I send you to /login
    if "user" not in session:
        flash("Please log in to access the dashboard.", "warning")
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"])

@app.route("/logout")
def logout():
    # I'm clearing the session to log the user out
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True)