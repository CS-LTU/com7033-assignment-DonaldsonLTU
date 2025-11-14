print(" Starting bulk patient-account creation…")

# I'm importing everything I need from my main Flask app
from app import app, db, User, patients_collection

# I'm using Werkzeug so I can hash passwords safely
from werkzeug.security import generate_password_hash

with app.app_context():
    # I'm choosing the default password for all patient logins
    default_pw = "password123"
    
    # I'm keeping track of how many new accounts I create
    created = 0

    # I'm counting how many patient records exist in the MongoDB collection
    total = patients_collection.count_documents({})
    print(f"📊 Found {total} patient records. Beginning account generation…")

    # I'm looping through every patient document, one by one
    for i, doc in enumerate(
            patients_collection.find({}, {"_id": 0, "id": 1}), start=1):

        pid = doc.get("id")
        if pid is None:
            # If somehow the document has no ID, I'm skipping it
            continue

        # I'm generating the username in the same style as the login system
        uname = f"patient-{int(pid)}"

        # I'm checking if this user already exists to avoid duplicates
        u = User.query.filter_by(username=uname).first()

        if not u:
            # I'm creating a brand-new user with the default password
            u = User(
                username=uname,
                password_hash=generate_password_hash(default_pw)
            )
            db.session.add(u)
            created += 1

        # I'm just printing progress every 50 records so I know the script is alive
        if i % 50 == 0:
            print(f"…processed {i}/{total}")

    # I'm saving everything into the database
    db.session.commit()

    # I'm printing a nice confirmation message at the end
    print(f"✅ Done! Successfully created {created} new patient accounts "
          f"(default password: {default_pw})")