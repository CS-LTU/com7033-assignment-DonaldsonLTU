print("Starting bulk create...")
from app import app, db, User, patients_collection
from werkzeug.security import generate_password_hash

with app.app_context():
    default_pw = "password123"
    created = 0
    total = patients_collection.count_documents({})
    print(f"Found {total} patient records to check...")
    for i, doc in enumerate(patients_collection.find({}, {"_id": 0, "id": 1}), start=1):
        pid = doc.get("id")
        if pid is None:
            continue
        uname = f"patient-{int(pid)}"
        u = User.query.filter_by(username=uname).first()
        if not u:
            u = User(username=uname, password_hash=generate_password_hash(default_pw))
            db.session.add(u)
            created += 1
        if i % 50 == 0:
            print(f"...processed {i}/{total}")
    db.session.commit()
    print(f"✅ Done! Created {created} new patient accounts (default password: {default_pw})")