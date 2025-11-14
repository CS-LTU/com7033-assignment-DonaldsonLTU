# create_admin.py
# I'm (re)creating an admin user with a known password in the real users.db file.

from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    admin = User.query.filter_by(username="admin").first()

    if admin is None:
        # I'm creating a brand new admin user
        admin = User(
            username="admin",
            password_hash=generate_password_hash("AdminPass123!")
        )
        db.session.add(admin)
        print("Created new admin user.")
    else:
        # I'm resetting the admin password in case it changed
        admin.password_hash = generate_password_hash("AdminPass123!")
        print("Updated existing admin password.")

    db.session.commit()
    print("✅ Admin ready: username=admin, password=AdminPass123!")