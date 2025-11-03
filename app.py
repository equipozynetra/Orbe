from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import sqlite3
import bcrypt
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- CONFIGURACIONES ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_verified INTEGER NOT NULL DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

# --- Funciones de Ayuda para Enviar Correos ---
def send_verification_email(email, name):
    token = s.dumps(email, salt='email-confirm')
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('emails/verify_email.html', name=name, confirm_url=confirm_url)
    msg = Message('Activa tu cuenta de Orbe y protege tu acceso', sender=('Orbe', app.config['MAIL_USERNAME']), recipients=[email], html=html)
    mail.send(msg)

def send_login_notification_email(email, name):
    html = render_template('emails/login_notification.html', name=name)
    msg = Message('Alerta de Seguridad: Nuevo inicio de sesión en tu cuenta de Orbe', sender=('Orbe', app.config['MAIL_USERNAME']), recipients=[email], html=html)
    mail.send(msg)

def send_password_reset_email(email, name):
    token = s.dumps(email, salt='password-reset')
    reset_url = url_for('reset_password', token=token, _external=True)
    html = render_template('emails/reset_password_email.html', name=name, reset_url=reset_url)
    msg = Message('Instrucciones para restablecer tu contraseña de Orbe', sender=('Orbe', app.config['MAIL_USERNAME']), recipients=[email], html=html)
    mail.send(msg)


# --- RUTAS PRINCIPALES DE AUTENTICACIÓN ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name, email, plain_password = data.get('name'), data.get('email'), data.get('password')
    
    if not all([name, email, plain_password]):
        return jsonify({'error': 'Faltan datos'}), 400

    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), bcrypt.gensalt())
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed_password))
        conn.commit()
        conn.close()
        send_verification_email(email, name)
        return jsonify({'message': 'Registro exitoso. Revisa tu correo para activar la cuenta.'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'El correo electrónico ya está en uso'}), 409
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=900)
    except SignatureExpired:
        return render_template('message.html', title="Enlace Expirado", message="El enlace de activación ha expirado. Por favor, regístrate de nuevo.")
    except (BadTimeSignature, Exception):
        return render_template('message.html', title="Enlace Inválido", message="El enlace de activación es inválido o ya ha sido utilizado.")

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
    conn.commit()
    conn.close()
    
    return render_template('message.html', title="Cuenta Activada", message="¡Tu cuenta ha sido activada con éxito! Ya puedes iniciar sesión.", success=True)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    email, plain_password = data.get('email'), data.get('password')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        user_id, name, db_email, hashed_password_from_db, is_verified = user
        if not is_verified:
            return jsonify({'error': 'Tu cuenta no ha sido verificada. Por favor, revisa tu correo.'}), 403
        if bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password_from_db):
            session['user_id'] = user_id
            session['user_name'] = name
            send_login_notification_email(email, name)
            return jsonify({'message': 'Inicio de sesión exitoso', 'redirect_url': url_for('chat_page')}), 200
            
    return jsonify({'error': 'Correo o contraseña incorrectos'}), 401

# --- RUTAS PARA RECUPERAR CONTRASEÑA ---
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        send_password_reset_email(email, user[0])
        
    return jsonify({'message': 'Si tu correo está registrado, recibirás un enlace para restablecer tu contraseña.'}), 200

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=900)
    except (SignatureExpired, BadTimeSignature):
        return render_template('message.html', title="Enlace Inválido o Expirado", message="El enlace para restablecer la contraseña no es válido o ha expirado. Por favor, solicita uno nuevo.")

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            # Usamos flash para mostrar mensajes en la página renderizada
            flash('Las contraseñas no coinciden.', 'error')
            return render_template('reset_password.html', token=token)
        
        # Aquí se añadiría la validación de contraseña fuerte en el backend si se desea
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
        conn.commit()
        conn.close()
        return render_template('message.html', title="Contraseña Actualizada", message="Tu contraseña ha sido actualizada con éxito. Ya puedes iniciar sesión.", success=True)
    
    return render_template('reset_password.html', token=token)


# --- RUTAS DE NAVEGACIÓN ---
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
    user = {'name': session.get('user_name')}
    return render_template('chat.html', user=user)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)