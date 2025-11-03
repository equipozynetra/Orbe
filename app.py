from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import sqlite3
import bcrypt
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- CONFIGURACIÓN DE SEGURIDAD (RATE LIMITER) ---
# Identifica a los usuarios por su dirección IP
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/register', methods=['POST'])
def register():
    # La lógica de registro no necesita rate limiting estricto, pero se beneficia de los límites por defecto
    data = request.get_json()
    name = data['name']
    email = data['email']
    plain_password = data['password']
    if not all([name, email, plain_password]):
        return jsonify({'error': 'Faltan datos'}), 400
    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed_password))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Usuario registrado con éxito'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'El correo electrónico ya está en uso'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- RUTA DE LOGIN PROTEGIDA CONTRA FUERZA BRUTA ---
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute") # Límite específico: 5 intentos por minuto por IP
def login():
    data = request.get_json()
    email = data['email']
    plain_password = data['password']
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        hashed_password_from_db = user[3]
        if bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password_from_db):
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            return jsonify({'message': 'Inicio de sesión exitoso', 'redirect_url': url_for('chat_page')}), 200
    return jsonify({'error': 'Correo o contraseña incorrectos'}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login_page')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('chat_page'))
    return render_template('login.html')

@app.route('/chat')
def chat_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    user = {'name': session['user_name']}
    return render_template('chat.html', user=user)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)