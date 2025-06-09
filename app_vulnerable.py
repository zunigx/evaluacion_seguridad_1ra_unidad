from flask import Flask, request, jsonify
import sqlite3
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
# Clave secreta para JWT. En producción, usa una clave segura y guárdala en variables de entorno.
app.config['SECRET_KEY'] = 'your_super_secret_key_12345'

# --- INICIALIZACIÓN DE LA BASE DE DATOS ---
def init_db():
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        
        # Tabla de usuarios (ya existente en tu código)
        cursor.execute(""" 
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                correo TEXT NOT NULL,
                pregunta_secreta TEXT,
                respuesta_secreta TEXT,
                birth_date TEXT,
                is_deleted INTEGER DEFAULT 0
            )
        """)
        
        # Tabla de permisos (ejemplo: get_user, update_user)
        cursor.execute(""" 
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        """)
        
        # Tabla de roles (ejemplo: admin, common_user)
        cursor.execute(""" 
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        """)
        
        # Tabla para vincular roles con permisos (muchos a muchos)
        cursor.execute(""" 
            CREATE TABLE IF NOT EXISTS role_permissions (
                role_id INTEGER,
                permission_id INTEGER,
                PRIMARY KEY (role_id, permission_id),
                FOREIGN KEY (role_id) REFERENCES roles(id),
                FOREIGN KEY (permission_id) REFERENCES permissions(id)
            )
        """)
        
        # Tabla para vincular usuarios con roles (un usuario puede tener un rol)
        cursor.execute(""" 
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id INTEGER,
                role_id INTEGER,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (role_id) REFERENCES roles(id)
            )
        """)
        
        # Insertar datos iniciales solo si no existen
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password, correo, birth_date) "
            "VALUES (?, ?, ?, ?)",
            ('admin', '1234', 'admin@mail.com', '1990-01-01')
        )
        cursor.execute(
            "INSERT OR IGNORE INTO roles (name) VALUES (?)", ('admin',)
        )
        cursor.execute(
            "INSERT OR IGNORE INTO permissions (name) VALUES (?)", ('get_user',)
        )
        cursor.execute(
            "INSERT OR IGNORE INTO role_permissions (role_id, permission_id) "
            "VALUES ((SELECT id FROM roles WHERE name = 'admin'), (SELECT id FROM permissions WHERE name = 'get_user'))"
        )
        cursor.execute(
            "INSERT OR IGNORE INTO user_roles (user_id, role_id) "
            "VALUES ((SELECT id FROM users WHERE username = 'admin'), (SELECT id FROM roles WHERE name = 'admin'))"
        )
        
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error al inicializar la base de datos: {e}")
    finally:
        conn.close()

# --- DECORADOR PARA AUTENTICACIÓN CON JWT ---
def token_required(f):
    """
    Decorador que verifica si el token JWT es válido y no ha expirado.
    Se aplica a todas las rutas protegidas.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Busca el token en el encabezado 'Authorization' (formato: Bearer <token>)
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Extrae el token después de "Bearer"
            except IndexError:
                return jsonify({"message": "Token mal formado"}), 401
        if not token:
            return jsonify({"message": "Falta el token"}), 401
        
        try:
            # Decodifica el token y verifica su validez
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user = data['sub']  # Guarda el username en el objeto request
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expirado"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token inválido"}), 401
        
        return f(*args, **kwargs)
    return decorated

# --- LOGIN CON GENERACIÓN DE TOKEN JWT ---
@app.route('/login', methods=['POST'])
def login():
    """
    Autentica al usuario y genera un token JWT con 5 minutos de vida.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not all([username, password]):
        return jsonify({"message": "Faltan username o password"}), 400
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND password = ? AND is_deleted = 0",
        (username, password)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        # Genera el token con tiempo de vida de 5 minutos
        expiration_time = datetime.utcnow() + timedelta(minutes=5)
        payload = {
            'exp': expiration_time,
            'iat': datetime.utcnow(),
            'sub': username
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({"message": "Login exitoso", "token": token})
    else:
        return jsonify({"message": "Credenciales inválidas"}), 401

# --- REGISTRO DE USUARIOS (SIN TOKEN) ---
@app.route('/register', methods=['POST'])
def register():
    """
    Registra un nuevo usuario. No requiere token.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    correo = data.get('correo')
    birth_date = data.get('birth_date')
    
    if not all([username, password, correo]):
        return jsonify({"message": "Faltan campos requeridos"}), 400
    
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password, correo, birth_date) VALUES (?, ?, ?, ?)",
            (username, password, correo, birth_date)
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "Usuario registrado"})
    except sqlite3.IntegrityError:
        return jsonify({"message": "El username ya existe"}), 400
    except sqlite3.Error as e:
        return jsonify({"message": f"Error en la base de datos: {e}"}), 500

# --- CRUD DE PERMISOS ---
@app.route('/permissions', methods=['POST'])
@token_required
def create_permission():
    """
    Crea un nuevo permiso (ejemplo: 'update_user').
    Requiere token válido.
    """
    data = request.get_json()
    name = data.get('name')
    
    if not name:
        return jsonify({"message": "Falta el nombre del permiso"}), 400
    
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO permissions (name) VALUES (?)", (name,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Permiso creado"})
    except sqlite3.IntegrityError:
        return jsonify({"message": "El permiso ya existe"}), 400
    except sqlite3.Error as e:
        return jsonify({"message": f"Error: {e}"}), 500

@app.route('/permissions', methods=['GET'])
@token_required
def get_permissions():
    """
    Lista todos los permisos.
    Requiere token válido.
    """
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM permissions")
        permissions = cursor.fetchall()
        conn.close()
        return jsonify({"permissions": [{"id": p[0], "name": p[1]} for p in permissions]})
    except sqlite3.Error as e:
        return jsonify({"message": f"Error: {e}"}), 500

@app.route('/permissions/<int:permission_id>', methods=['PUT'])
@token_required
def update_permission(permission_id):
    """
    Actualiza un permiso existente.
    Requiere token válido.
    """
    data = request.get_json()
    name = data.get('name')
    
    if not name:
        return jsonify({"message": "Falta el nombre del permiso"}), 400
    
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE permissions SET name = ? WHERE id = ?", (name, permission_id))
        conn.commit()
        conn.close()
        if cursor.rowcount > 0:
            return jsonify({"message": "Permiso actualizado"})
        return jsonify({"message": "Permiso no encontrado"}), 404
    except sqlite3.IntegrityError:
        return jsonify({"message": "El nombre ya existe"}), 400
    except sqlite3.Error as e:
        return jsonify({"message": f"Error: {e}"}), 500

@app.route('/permissions/<int:permission_id>', methods=['DELETE'])
@token_required
def delete_permission(permission_id):
    """
    Elimina un permiso.
    Requiere token válido.
    """
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM permissions WHERE id = ?", (permission_id,))
        conn.commit()
        conn.close()
        if cursor.rowcount > 0:
            return jsonify({"message": "Permiso eliminado"})
        return jsonify({"message": "Permiso no encontrado"}), 404
    except sqlite3.Error as e:
        return jsonify({"message": f"Error: {e}"}), 500

# --- CRUD DE ROLES ---
@app.route('/roles', methods=['POST'])
@token_required
def create_role():
    """
    Crea un nuevo rol (ejemplo: 'seller').
    Requiere token válido.
    """
    data = request.get_json()
    name = data.get('name')
    
    if not name:
        return jsonify({"message": "Falta el nombre del rol"}), 400
    
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO roles (name) VALUES (?)", (name,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Rol creado"})
    except sqlite3.IntegrityError:
        return jsonify({"message": "El rol ya existe"}), 400
    except sqlite3.Error as e:
        return jsonify({"message": f"Error: {e}"}), 500

@app.route('/roles', methods=['GET'])
@token_required
def get_roles():
    """
    Lista todos los roles.
    Requiere token válido.
    """
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM roles")
        roles = cursor.fetchall()
        conn.close()
        return jsonify({"roles": [{"id": r[0], "name": r[1]} for r in roles]})
    except sqlite3.Error as e:
        return jsonify({"message": f"Error: {e}"}), 500

@app.route('/roles/<int:role_id>', methods=['PUT'])
@token_required
def update_role(role_id):
    """
    Actualiza un rol existente.
    Requiere token válido.
    """
    data = request.get_json()
    name = data.get('name')
    
    if not name:
        return jsonify({"message": "Falta el nombre del rol"}), 400
    
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE roles SET name = ? WHERE id = ?", (name, role_id))
        conn.commit()
        conn.close()
        if cursor.rowcount > 0:
            return jsonify({"message": "Rol actualizado"})
        return jsonify({"message": "Rol no encontrado"}), 404
    except sqlite3.IntegrityError:
        return jsonify({"message": "El nombre ya existe"}), 400
    except sqlite3.Error as e:
        return jsonify({"message": f"Error: {e}"}), 500

@app.route('/roles/<int:role_id>', methods=['DELETE'])
@token_required
def delete_role(role_id):
    """
    Elimina un rol.
    Requiere token válido.
    """
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM roles WHERE id = ?", (role_id,))
        conn.commit()
        conn.close()
        if cursor.rowcount > 0:
            return jsonify({"message": "Rol eliminado"})
        return jsonify({"message": "Rol no encontrado"}), 404
    except sqlite3.Error as e:
        return jsonify({"message": f"Error: {e}"}), 500

# --- VINCULACIÓN DE ROLES CON USUARIOS ---
@app.route('/user/<int:user_id>/role', methods=['POST'])
@token_required
def assign_role_to_user(user_id):
    """
    Asigna un rol a un usuario.
    Requiere token válido.
    """
    data = request.get_json()
    role_id = data.get('role_id')
    
    if not role_id:
        return jsonify({"message": "Falta el ID del rol"}), 400
    
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", (user_id, role_id))
        conn.commit()
        conn.close()
        return jsonify({"message": "Rol asignado al usuario"})
    except sqlite3.IntegrityError:
        return jsonify({"message": "El usuario ya tiene ese rol o no existe"}), 400
    except sqlite3.Error as e:
        return jsonify({"message": f"Error: {e}"}), 500

# --- INICIO DE LA APLICACIÓN ---
if __name__ == '__main__':
    init_db()
    app.run(debug=True)  # En producción, usa debug=False