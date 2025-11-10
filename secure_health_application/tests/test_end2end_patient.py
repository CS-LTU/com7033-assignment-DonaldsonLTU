# tests/test_e2e_patient.py
# I'm proving a real patient can:
# 1) log in → 2) see ONLY their own record (no charts/tables)
# 3) is blocked from admin settings → 4) can change password and re-login

import pytest
from werkzeug.security import generate_password_hash

from app import app, db, User, patients_collection

@pytest.fixture
def client():
    # I'm running the app in test mode and disabling CSRF ONLY for tests
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    # I'm switching to an in-memory SQLite so tests don’t touch your real users.db
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

    with app.app_context():
        # Fresh DB each test run
        db.drop_all()
        db.create_all()

        # I'm creating a patient user that maps to dataset id=101
        u = User(username="patient-101",
                 password_hash=generate_password_hash("password123"))
        db.session.add(u)
        db.session.commit()

        # I'm inserting the matching patient record into Mongo
        patients_collection.delete_many({"id": 101})
        patients_collection.insert_one({
            "id": 101,
            "gender": "Male",
            "age": 45.0,
            "hypertension": 0,
            "heart_disease": 0,
            "ever_married": "Yes",
            "work_type": "Private",
            "residence_type": "Urban",
            "avg_glucose_level": 89.4,
            "bmi": 26.2,
            "smoking_status": "never smoked",
            "stroke": 0,
        })

    # I'm yielding a client that keeps session cookies
    with app.test_client() as c:
        yield c

    # I'm cleaning up the Mongo doc after tests
    patients_collection.delete_many({"id": 101})


def _login(client, username, password):
    # I'm logging in like a browser would
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def test_patient_sees_only_their_record(client):
    # Login as the patient
    res = _login(client, "patient-101", "password123")
    assert res.status_code == 200
    # I expect the patient dashboard welcome
    assert b"Welcome, patient-101" in res.data
    # I should NOT see admin analytics title or charts
    assert b"Stroke Dataset Dashboard" not in res.data
    assert b"<canvas" not in res.data  # no charts for patients
    # I should see my own id in the table
    assert b">101<" in res.data


def test_patient_blocked_from_admin_settings(client):
    _ = _login(client, "patient-101", "password123")
    res = client.get("/settings", follow_redirects=True)
    assert res.status_code == 200
    # Should be redirected back (admins only)
    assert b"Admins only" in res.data or b"Stroke Dataset Dashboard" in res.data


def test_patient_can_change_password_and_relogin(client):
    # Login first
    res = _login(client, "patient-101", "password123")
    assert res.status_code == 200

    # Change password (CSRF disabled in tests)
    res = client.post(
        "/password",
        data={
            "current_password": "password123",
            "new_password": "NewPass888!",
            "confirm_password": "NewPass888!",
        },
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Password changed." in res.data

    # Logout
    res = client.get("/logout", follow_redirects=True)
    assert res.status_code == 200

    # Login with new password
    res = _login(client, "patient-101", "NewPass888!")
    assert res.status_code == 200
    assert b"Welcome, patient-101" in res.data