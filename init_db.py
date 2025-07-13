import os
from app import db, app

# Elimina il vecchio database se esiste
if os.path.exists("db.sqlite3"):
    os.remove("db.sqlite3")
    print("🗑️ Vecchio database eliminato.")

# Crea un nuovo database con tutte le tabelle definite nei modelli
with app.app_context():
    db.create_all()
    print("✅ Nuovo database creato correttamente.")
