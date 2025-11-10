# tests/test_e2e_admin.py
# I'm writing an end-to-end test that proves an admin can:
# 1) log in  →  2) see the dashboard  →  3) open the admin settings  →  4) log out
# I also prove that non-admin users are blocked from the admin settings.

import pytest
from werkzeug.security import generate_password_hash

# I'm importing your Flask app + DB model so I can spin up a fresh test app/DB.
from app import app, db, User


@pytest.fixture
def client():
    # I'm putting the app into test mode and disabling CSRF ONLY for tests.
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    # I'm switching to an in-memory SQLite so tests don’t touch your real users.db
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

    with app.app_context():
        # I'm resetting the test DB cleanly before each test function
        db.drop_all()
        db.create_all()

        # I'm creating a real admin account in the test DB
        admin = User(
            username="admin",
            password_hash=generate_password_hash("AdminPass123!")
        )
        db.session.add(admin)
        db.session.commit()

        # I'm returning a Flask test client that keeps cookies (so sessions work)
        with app.test_client() as c:
            yield c


def _login(client, username, password):
    # I'm posting to /login just like a normal browser would
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def test_admin_e2e_login_dashboard_settings_logout(client):
    # 1) I'm logging in as the test admin
    res = _login(client, "admin", "AdminPass123!")
    assert res.status_code == 200
    # I expect to land on the dashboard
    assert b"Stroke Dataset Dashboard" in res.data

    # 2) I'm opening the admin settings page (admin-only)
    res = client.get("/settings", follow_redirects=True)
    assert res.status_code == 200
    # I'm checking that the page looks like the admin panel
    # (your admin_settings.html should contain "Admin" or "Settings")
    assert (b"Admin" in res.data) or (b"Settings" in res.data)

    # 3) I'm logging out and expecting to go back to home
    res = client.get("/logout", follow_redirects=True)
    assert res.status_code == 200
    # I'm checking for the exact flash text used in app.py
    assert b"You have been signed out." in res.data


def test_admin_guard_blocks_non_admin(client):
    # I'm creating a normal (non-admin) user in the test DB
    with app.app_context():
        u = User(
            username="student",
            password_hash=generate_password_hash("password123")
        )
        db.session.add(u)
        db.session.commit()

    # I'm logging in as the non-admin
    res = _login(client, "student", "password123")
    assert res.status_code == 200

    # I'm trying to open /settings; I expect a redirect/flash back to dashboard
    res = client.get("/settings", follow_redirects=True)
    assert res.status_code == 200
    # I should NOT see the admin panel; I should end up on the dashboard
    assert b"Stroke Dataset Dashboard" in res.data