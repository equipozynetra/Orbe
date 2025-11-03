from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import psycopg2 # <- CAMBIO: Importamos la nueva librería
import bcrypt
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- CONFIGURACIONES (sin cambios) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# ... (el resto de la configuración de Mail, Serializer y Limiter se queda igual)
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# --- CONEXIÓN A LA BASE DE DATOS POSTGRES ---
def get_db_connection():
    conn = psycopg2.connect(os.getenv('POSTGRES_URL'))
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    # CAMBIO: La sintaxis para crear la tabla es ligeramente diferente
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(150) NOT NULL,
            email VARCHAR(150) NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_verified BOOLEAN NOT NULL DEFAULT FALSE
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()

# --- Funciones de correo (sin cambios) ---
def send_verification_email(email, name):
    # ... (código sin cambios)
    token = s.dumps(email, salt='email-confirm')
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('emails/verify_email.html', name=name, confirm_url=confirm_url)
    msg = Message('Activa tu cuenta de Orbe y protege tu acceso', sender=('Orbe', app.config['MAIL_USERNAME']), recipients=[email], html=html)
    mail.send(msg)

def send_login_notification_email(email, name):
    # ... (código sin cambios)
    html = render_template('emails/login_notification.html', name=name)
    msg = Message('Alerta de Seguridad: Nuevo inicio de sesión en tu cuenta de Orbe', sender=('Orbe', app.config['MAIL_USERNAME']), recipients=[email], html=html)
    mail.send(msg)

def send_password_reset_email(email, name):
    # ... (código sin cambios)
    token = s.dumps(email, salt='password-reset')
    reset_url = url_for('reset_password', token=token, _external=True)
    html = render_template('emails/reset_password_email.html', name=name, reset_url=reset_url)
    msg = Message('Instrucciones para restablecer tu contraseña de Orbe', sender=('Orbe', app.config['MAIL_USERNAME']), recipients=[email], html=html)
    mail.send(msg)


# --- RUTAS DE AUTENTICACIÓN (actualizadas para Postgres) ---
@app.route('/register', methods=['POST'])
def register():
    # ... (código actualizado)
    data = request.get_json()
    name, email, plain_password = data.get('name'), data.get('email'), data.get('password')
    if not all([name, email, plain_password]): return jsonify({'error': 'Faltan datos'}), 400
    
    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password.decode('utf-8')))
        conn.commit()
        send_verification_email(email, name)
        return jsonify({'message': 'Registro exitoso. Revisa tu correo para activar la cuenta.'}), 201
    except psycopg2.IntegrityError:
        return jsonify({'error': 'El correo electrónico ya está en uso'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            cur.close()
            conn.close()

@app.route('/confirm/<token>')
def confirm_email(token):
    # ... (código actualizado)
    try:
        email = s.loads(token, salt='email-confirm', max_age=900)
    except (SignatureExpired, BadTimeSignature):
        return render_template('message.html', title="Enlace Inválido o Expirado", message="El enlace de activación es inválido o ha expirado.")
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET is_verified = TRUE WHERE email = %s", (email,))
    conn.commit()
    cur.close()
    conn.close()
    return render_template('message.html', title="Cuenta Activada", message="¡Tu cuenta ha sido activada con éxito! Ya puedes iniciar sesión.", success=True)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # ... (código actualizado)
    data = request.get_json()
    email, plain_password = data.get('email'), data.get('password')
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, password, is_verified FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    
    if user:
        user_id, name, db_email, hashed_password_from_db, is_verified = user
        if not is_verified: return jsonify({'error': 'Tu cuenta no ha sido verificada. Por favor, revisa tu correo.'}), 403
        
        # bcrypt espera bytes, así que codificamos la contraseña de la DB
        if bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password_from_db.encode('utf-8')):
            session['user_id'], session['user_name'] = user_id, name
            send_login_notification_email(email, name)
            return jsonify({'message': 'Inicio de sesión exitoso', 'redirect_url': url_for('chat_page')}), 200
            
    return jsonify({'error': 'Correo o contraseña incorrectos'}), 401

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    # ... (código actualizado)
    email = request.get_json().get('email')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT name FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if user:
        send_password_reset_email(email, user[0])
    return jsonify({'message': 'Si tu correo está registrado, recibirás un enlace para restablecer tu contraseña.'}), 200

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # ... (código actualizado)
    try:
        email = s.loads(token, salt='password-reset', max_age=900)
    except (SignatureExpired, BadTimeSignature):
        return render_template('message.html', title="Enlace Inválido o Expirado", message="El enlace para restablecer la contraseña no es válido o ha expirado.")

    if request.method == 'POST':
        password = request.form['password']
        if password != request.form['confirm_password']:
            flash('Las contraseñas no coinciden.', 'error')
            return render_template('reset_password.html', token=token)
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password.decode('utf-8'), email))
        conn.commit()
        cur.close()
        conn.close()
        return render_template('message.html', title="Contraseña Actualizada", message="Tu contraseña ha sido actualizada con éxito.", success=True)
    
    return render_template('reset_password.html', token=token)

# --- RUTAS DE NAVEGACIÓN (sin cambios) ---
@app.route('/logout')
def logout():
    # ...
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/')
def index():
    # ...
    return render_template('index.html')

@app.route('/login_page')
def login_page():
    # ...
    if 'user_id' in session:
        return redirect(url_for('chat_page'))
    return render_template('login.html')

@app.route('/chat')
def chat_page():
    # ...
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    user = {'name': session.get('user_name')}
    return render_template('chat.html', user=user)

if __name__ == '__main__':
    # Al iniciar, crea la tabla si no existe
    init_db()
    app.run(debug=True)