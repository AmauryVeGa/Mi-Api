import sqlite3

conexion = sqlite3.connect("database.db")
cursor = conexion.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'cliente'
)
""")

cursor.execute("""
CREATE TABLE historial_conversiones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    moneda_origen TEXT,
    moneda_destino TEXT,
    cantidad REAL,
    resultado REAL,
    fecha TEXT
)
""")

conexion.commit()
conexion.close()

print("Base de datos creada correctamente.")