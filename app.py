from flask import Flask, request, jsonify
import sqlite3
import bcrypt

app = Flask(__name__)

# Función para conectar a la BD
def get_db_connection():
    conexion = sqlite3.connect("database.db")
    conexion.row_factory = sqlite3.Row
    return conexion

@app.route('/registro', methods=['POST'])
def registro():

    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    # 1️⃣ Validar datos
    if not email or not password or len(password) <= 8 or len(password) >= 10:
        return jsonify({"error": "Credenciales Invalidas"}), 400

    conexion = get_db_connection()
    cursor = conexion.cursor()

    # 2️⃣ Verificar duplicados
    cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
    usuario_existente = cursor.fetchone()

    if usuario_existente:
        conexion.close()
        return jsonify({"error": "El usuario ya existe"}), 409

    # 3️⃣ Crear hash con bcrypt
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)

    # 4️⃣ Guardar usuario
    cursor.execute(
        "INSERT INTO usuarios (email, password) VALUES (?, ?)",
        (email, hashed_password.decode('utf-8'))
    )

    conexion.commit()
    conexion.close()

    return jsonify({"message": "Usuario Registrado"}), 201


if __name__ == '__main__':
    app.run(debug=True)