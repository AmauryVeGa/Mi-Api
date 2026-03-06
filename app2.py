from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import jwt
from datetime import datetime, timezone, timedelta
from config import Config

app = Flask(__name__)

# Conexión a BD
def get_db_connection():
    conexion = sqlite3.connect("database.db")
    conexion.row_factory = sqlite3.Row
    return conexion


# =========================
# REGISTRO DE USUARIO
# =========================
@app.route('/registro', methods=['POST'])
def registro():

    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email y contraseña son obligatorios"}), 400

    if len(password) < 8:
        return jsonify({"error": "La contraseña debe tener mínimo 8 caracteres"}), 400

    conexion = get_db_connection()
    cursor = conexion.cursor()

    # Verificar duplicados
    cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
    usuario_existente = cursor.fetchone()

    if usuario_existente:
        conexion.close()
        return jsonify({"error": "El usuario ya existe"}), 409

    # Hash bcrypt
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)

    # Insertar usuario (rol cliente por defecto)
    cursor.execute(
        "INSERT INTO usuarios (email, password, role) VALUES (?, ?, ?)",
        (email, hashed_password.decode('utf-8'), "cliente")
    )

    conexion.commit()
    conexion.close()

    return jsonify({"message": "Usuario registrado correctamente"}), 201


# =========================
# CAMBIAR CONTRASEÑA
# =========================
@app.route('/actualizar_password', methods=['PUT'])
def actualizar_password():

    data = request.get_json()

    email = data.get('email')
    nueva_password = data.get('password')

    if not email or not nueva_password:
        return jsonify({"error": "Email y nueva contraseña son requeridos"}), 400

    if len(nueva_password) < 8:
        return jsonify({"error": "La contraseña debe tener mínimo 8 caracteres"}), 400

    conexion = get_db_connection()
    cursor = conexion.cursor()

    cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
    usuario = cursor.fetchone()

    if not usuario:
        conexion.close()
        return jsonify({"error": "Usuario no encontrado"}), 404

    # Hash nueva contraseña
    password_bytes = nueva_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)

    cursor.execute(
        "UPDATE usuarios SET password = ? WHERE email = ?",
        (hashed_password.decode('utf-8'), email)
    )

    conexion.commit()
    conexion.close()

    return jsonify({"message": "Contraseña actualizada correctamente"}), 200


# =========================
# CAMBIAR ROL
# =========================
@app.route('/actualizar_role', methods=['PUT'])
def actualizar_role():

    data = request.get_json()

    email = data.get('email')
    nuevo_role = data.get('role')

    if not email or not nuevo_role:
        return jsonify({"error": "Email y rol son obligatorios"}), 400

    # Validar roles permitidos
    roles_validos = ["cliente", "admin"]

    if nuevo_role not in roles_validos:
        return jsonify({"error": "Rol inválido"}), 400

    conexion = get_db_connection()
    cursor = conexion.cursor()

    cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
    usuario = cursor.fetchone()

    if not usuario:
        conexion.close()
        return jsonify({"error": "Usuario no encontrado"}), 404

    cursor.execute(
        "UPDATE usuarios SET role = ? WHERE email = ?",
        (nuevo_role, email)
    )

    conexion.commit()
    conexion.close()

    return jsonify({"message": "Rol actualizado correctamente"}), 200

# =========================
# LOGIN
# =========================
@app.route('/login', methods=['POST'])
def login():

    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email y contraseña son obligatorios"}), 400

    conexion = get_db_connection()
    cursor = conexion.cursor()

    cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
    usuario = cursor.fetchone()

    conexion.close()

    if not usuario:
        return jsonify({"error": "Credenciales incorrectas"}), 401

    password_guardado = usuario["password"]

    # Comparar contraseña con bcrypt
    if bcrypt.checkpw(password.encode('utf-8'), password_guardado.encode('utf-8')):

        payload={
            "usuario": usuario["email"],
            "role": usuario["role"],
            "exp": datetime.now(tz=timezone.utc) + timedelta(hours=1)
        }

        token = jwt.encode(payload,Config.SECRET_KEY,algorithm=Config.JWT_ALGORITHM)

        return jsonify({
            "message": "Login exitoso",
            "token": token
        }), 200

    else:
        return jsonify({"error": "Credenciales incorrectas"}), 401
    
# =========================
# ELIMINAR USUARIO
# =========================
@app.route('/eliminar_usuario', methods=['DELETE'])
def eliminar_usuario():

    data = request.get_json()

    email = data.get('email')

    if not email:
        return jsonify({"error": "El email es obligatorio"}), 400

    conexion = get_db_connection()
    cursor = conexion.cursor()

    # Verificar si existe
    cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
    usuario = cursor.fetchone()

    if not usuario:
        conexion.close()
        return jsonify({"error": "Usuario no encontrado"}), 404

    # Eliminar usuario
    cursor.execute("DELETE FROM usuarios WHERE email = ?", (email,))
    conexion.commit()
    conexion.close()

    return jsonify({"message": "Usuario eliminado correctamente"}), 200

# =========================
# CONVERSION DE MONEDAS
# =========================
@app.route('/convertir', methods=['POST'])
def convertir_moneda():

    data = request.get_json()

    moneda_origen = data.get("from")
    moneda_destino = data.get("to")
    cantidad = data.get("amount")

    if not moneda_origen or not moneda_destino or not cantidad:
        return jsonify({"error": "from, to y amount son obligatorios"}), 400

    try:
        cantidad = float(cantidad)
    except:
        return jsonify({"error": "La cantidad debe ser un número"}), 400

    # No permitir 0 ni negativos
    if cantidad <= 0:
        return jsonify({"error": "La cantidad debe ser mayor a 0"}), 400

    # Tasas base respecto al USD
    tasas = {
        "USD": 1,
        "MXN": 17.68,
        "EUR": 0.86
    }

    if moneda_origen not in tasas or moneda_destino not in tasas:
        return jsonify({"error": "Moneda no soportada"}), 400

    # convertir primero a USD
    usd = cantidad / tasas[moneda_origen]

    # convertir a moneda destino
    resultado = usd * tasas[moneda_destino]

    # Guardar en historial
    conexion = get_db_connection()
    cursor = conexion.cursor()

    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
    INSERT INTO historial_conversiones
    (moneda_origen, moneda_destino, cantidad, resultado, fecha)
    VALUES (?, ?, ?, ?, ?)
    """, (
        moneda_origen,
        moneda_destino,
        cantidad,
        round(resultado,2),
        fecha
    ))

    conexion.commit()
    conexion.close()

    return jsonify({
        "origen": moneda_origen,
        "destino": moneda_destino,
        "cantidad": cantidad,
        "resultado": round(resultado, 2)
    }), 200

# =========================
# HISTORIAL DE CONVERSIONES
# =========================
@app.route('/historial_conversiones', methods=['GET'])
def historial_conversiones():

    conexion = get_db_connection()
    cursor = conexion.cursor()

    cursor.execute("SELECT * FROM historial_conversiones ORDER BY fecha DESC")

    historial = cursor.fetchall()

    conexion.close()

    lista = []

    for fila in historial:
        lista.append({
            "id": fila["id"],
            "origen": fila["moneda_origen"],
            "destino": fila["moneda_destino"],
            "cantidad": fila["cantidad"],
            "resultado": fila["resultado"],
            "fecha": fila["fecha"]
        })

    return jsonify(lista), 200

if __name__ == '__main__':
    app.run(debug=True)