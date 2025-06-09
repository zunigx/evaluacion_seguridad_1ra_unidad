# API REST - Gestión de Roles y Permisos con Seguridad JWT
Este proyecto es una API REST desarrollada con Flask y SQLite, diseñada para gestionar operaciones CRUD (Crear, Leer, Actualizar, Eliminar) sobre permisos y roles, con autenticación basada en JSON Web Tokens (JWT). Las rutas protegidas requieren un token JWT con una expiración de 5 minutos, asegurando un acceso seguro y controlado.

# Desarrollador
- Emmanuel Zuñiga Suarez

# Endpoints principales
# Autenticación

- 'POST /login' → Iniciar sesión y obtener un token JWT (expira en 5 minutos)
- 'POST /register' → Registrar un nuevo usuario

# Permisos

- 'POST /permissions' → Crear un permiso (Requiere token y rol autorizado)
- 'GET /permissions' → Listar todos los permisos (Requiere token y rol autorizado)
- 'PUT /permissions' → Actualizar un permiso (Requiere token y rol autorizado)
- 'DELETE /permissions' → Eliminar un permiso (Requiere token y rol autorizado)

# Roles

- 'POST /roles' → Crear un rol (Requiere token y rol autorizado)
- 'GET /roles' → Listar todos los roles (Requiere token y rol autorizado)
- 'PUT /roles' → Actualizar un rol (Requiere token y rol autorizado)
- 'DELETE /roles' → Eliminar un rol (Requiere token y rol autorizado)

# Asignación de Roles

- 'POST /assign_role' → Asignar un rol a un usuario (Requiere token y rol autorizado)

# Campos principales
# Usuarios

id: Identificador único (entero autoincremental)
username: Nombre de usuario
password: Contraseña (almacenada de forma segura)
role_id: Identificador del rol asignado

# Permisos

id: Identificador único (entero autoincremental)
name: Nombre del permiso
description: Descripción del permiso

# Roles

id: Identificador único (entero autoincremental)
name: Nombre del rol
permissions: Lista de permisos asociados al rol

# Seguridad

- Autenticación mediante JWT para rutas protegidas
- Tokens con expiración de 5 minutos para minimizar riesgos
- Decorador @token_required para validar tokens en cada solicitud
- Consultas parametrizadas en SQLite para prevenir inyecciones SQL
- Validación de datos para evitar entradas maliciosas

# Versión
Python 3.12.6
Crear entorno virtual
python -m venv venv

# En Windows:
venv\Scripts\activate.bat

# En Linux/Mac:
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar la API
python app.py

# Instalación

# Clonar el repositorio:
git clone https://github.com/tu_usuario/tu_repositorio.git
cd tu_repositorio


# Crear y activar el entorno virtual (ver instrucciones arriba).

Instalar las dependencias con pip install -r requirements.txt.
Ejecutar la API con python app.py.
