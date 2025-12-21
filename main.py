from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import flask_mail 
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from email.header import Header
from datetime import datetime, timedelta
import random 
import threading 
from whitenoise import WhiteNoise
import os

# --- CONFIGURACIÓN DEL SISTEMA ---
app = Flask(__name__)
app.wsgi_app = WhiteNoise(app.wsgi_app, root='static/')

app.config['SECRET_KEY'] = 'orbe_core_system_key_v1'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///orbe.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- CONFIGURACIÓN DE EMAIL (GMAIL) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'equipozynetra@gmail.com' 
app.config['MAIL_PASSWORD'] = 'klttyzyvuqvfcsai' 
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = ('Orbe System', app.config['MAIL_USERNAME'])
app.config['MAIL_DEBUG'] = True 

db = SQLAlchemy(app)
mail = flask_mail.Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# --- TIERS ---
TIERS = {
    'free':  {'limit': 3,      'name': 'FREE',  'color': '#888888', 'price': 0},
    'gold':  {'limit': 10,     'name': 'GOLD',  'color': '#ffd700', 'price': 9},
    'elite': {'limit': 50,     'name': 'ELITE', 'color': '#00ffff', 'price': 29},
    'omega': {'limit': 999999, 'name': 'OMEGA', 'color': '#ff003c', 'price': 99},
    'support': {'limit': 999999, 'name': 'SOPORTE', 'color': '#00ff00', 'price': 0},
    'admin':   {'limit': 999999, 'name': 'ADMIN',   'color': '#9d00ff', 'price': 0},
    'owner':   {'limit': 999999, 'name': 'DUEÑO',   'color': '#ffffff', 'price': 0}
}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alias = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    plan = db.Column(db.String(20), default='free') 
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    otp_code = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    chats = db.relationship('Chat', backref='author', lazy=True)

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), default="Nueva Conversación")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('Message', backref='chat_parent', lazy=True, cascade="all, delete")

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=False)
    sender = db.Column(db.String(10), nullable=False) 
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Changelog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(20), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

@app.before_request
def update_last_active():
    if 'user_id' in session:
        try:
            user = User.query.get(session['user_id'])
            if user:
                user.last_active = datetime.utcnow()
                db.session.commit()
            else: session.pop('user_id', None)
        except: pass

# --- FUNCIÓN EMAIL ASÍNCRONA (SOLUCIÓN A LA LENTITUD) ---
def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
            print(f"--- [EMAIL] Enviado correctamente a {msg.recipients[0]} ---")
        except Exception as e:
            print(f"--- [EMAIL ERROR] Falló el envío: {e} ---")

def send_email(to, subject, body_html):
    try:
        # Preparamos el mensaje
        safe_subject = Header(subject, 'utf-8').encode()
        msg = flask_mail.Message(
            subject=safe_subject,
            recipients=[to],
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        msg.html = body_html
        
        # Enviamos en un HILO SEPARADO para que la página cargue rápido
        thr = threading.Thread(target=send_async_email, args=[app, msg])
        thr.start()
        
        return True
    except Exception as e:
        print(f"--- [EMAIL CRITICAL] {e} ---")
        return False

# --- RUTAS ---
@app.route('/')
def home(): return render_template('index.html')

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            if not user.is_verified:
                # Reenviar OTP si intenta entrar sin verificar
                otp = str(random.randint(100000, 999999))
                user.otp_code = otp
                user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
                db.session.commit()
                
                html_body = f"<h1>Código ORBE</h1><h2>{otp}</h2>"
                send_email(email, 'Tu Código de Acceso', html_body)
                
                session['temp_email'] = email
                flash('Cuenta no verificada. Hemos enviado un nuevo código.', 'error')
                return redirect(url_for('verify_otp'))
            
            session['user_id'] = user.id; session['user_name'] = user.alias
            
            # Alerta de login (opcional, asíncrona)
            if user.plan != 'owner':
                html_login = f"<p>Nuevo inicio de sesión detectado en tu cuenta {user.alias}.</p>"
                send_email(user.email, 'ORBE - Nueva Conexión', html_login)

            return redirect(url_for('dashboard'))
        else: flash('Credenciales incorrectas.', 'error')
    return render_template('auth.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.form.get('captcha_solved') != 'true': flash('Captcha incorrecto.', 'error'); return redirect(url_for('register'))
        
        alias = request.form.get('alias').strip()
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        
        if password != request.form.get('confirm_password'): flash('Passwords no coinciden.', 'error'); return redirect(url_for('register'))
        if User.query.filter_by(email=email).first(): flash('Email en uso.', 'error'); return redirect(url_for('register'))
        
        # Dueño Auto-Verificado
        target_plan = 'free'; is_verified_status = False
        if email == 'equipozynetra@gmail.com': target_plan = 'owner'; is_verified_status = True

        otp = str(random.randint(100000, 999999))
        expiry = datetime.utcnow() + timedelta(minutes=5)

        new_user = User(alias=alias, email=email, password_hash=generate_password_hash(password, method='pbkdf2:sha256'), plan=target_plan, is_verified=is_verified_status, otp_code=otp, otp_expiry=expiry)
        db.session.add(new_user); db.session.commit()
        
        if target_plan == 'owner': 
            flash('Bienvenido Creador.', 'success'); return redirect(url_for('auth'))
        
        session['temp_email'] = email
        
        # Enviar Correo OTP Asíncrono
        html_body = f"""
        <div style="background:#000; color:#fff; padding:30px; font-family:monospace; text-align:center;">
            <h1 style="color:#888;">ORBE SECURITY</h1>
            <p>Introduce este código para activar tu nodo:</p>
            <h2 style="color:#00ff9d; font-size:40px; letter-spacing:8px; margin:20px 0;">{otp}</h2>
            <p>Este código expira en 5 minutos.</p>
        </div>
        """
        send_email(email, 'ORBE - Tu Código de Verificación', html_body)
        
        # Redirección inmediata (no espera al correo)
        return redirect(url_for('verify_otp'))
    return render_template('register.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'temp_email' not in session: return redirect(url_for('auth'))
    
    if request.method == 'POST':
        code = request.form.get('otp_code')
        email = session['temp_email']
        user = User.query.filter_by(email=email).first()
        
        if not user: session.pop('temp_email', None); return redirect(url_for('register'))
            
        if user.otp_code == code and user.otp_expiry > datetime.utcnow():
            user.is_verified = True; user.otp_code = None; db.session.commit()
            session.pop('temp_email', None)
            flash('Verificación exitosa. Entrando...', 'success')
            return redirect(url_for('auth'))
        else:
            flash('Código incorrecto o expirado.', 'error')
            
    return render_template('verify_otp.html')

@app.route('/logout')
def logout(): session.pop('user_id', None); return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('auth'))
    user = User.query.get(session['user_id'])
    logs = Changelog.query.order_by(Changelog.date.desc()).limit(5).all()
    current_tier = TIERS.get(user.plan, TIERS['free'])
    return render_template('dashboard.html', user=user, logs=logs, tier=current_tier)

@app.route('/chat')
@app.route('/chat/<int:chat_id>')
def chat(chat_id=None):
    if 'user_id' not in session: return redirect(url_for('auth'))
    user = User.query.get(session['user_id'])
    my_chats = Chat.query.filter_by(user_id=user.id).order_by(Chat.created_at.desc()).all()
    active_chat = None; messages = []
    if chat_id:
        active_chat = Chat.query.get_or_404(chat_id)
        if active_chat.user_id != user.id: return redirect(url_for('chat'))
        messages = active_chat.messages
    current_tier = TIERS.get(user.plan, TIERS['free'])
    return render_template('chat.html', user=user.alias, chats=my_chats, active_chat=active_chat, messages=messages, tier=current_tier, user_plan=user.plan, limit=current_tier['limit'])

@app.route('/new_chat')
def new_chat():
    if 'user_id' not in session: return redirect(url_for('auth'))
    user = User.query.get(session['user_id'])
    limit = TIERS.get(user.plan, TIERS['free'])['limit']
    if Chat.query.filter_by(user_id=user.id).count() >= limit: flash(f'Límite alcanzado.', 'premium_error'); return redirect(url_for('chat'))
    new_chat = Chat(user_id=user.id, title=f"Conversación {Chat.query.filter_by(user_id=user.id).count() + 1}")
    db.session.add(new_chat); db.session.commit()
    return redirect(url_for('chat', chat_id=new_chat.id))

@app.route('/delete_chat/<int:chat_id>')
def delete_chat(chat_id):
    if 'user_id' not in session: return redirect(url_for('auth'))
    chat = Chat.query.get_or_404(chat_id)
    if chat.user_id != session['user_id']: flash('Acceso denegado.', 'error'); return redirect(url_for('chat'))
    db.session.delete(chat); db.session.commit()
    return redirect(url_for('chat'))

@app.route('/pricing')
def pricing():
    if 'user_id' not in session: return redirect(url_for('auth'))
    user = User.query.get(session['user_id'])
    return render_template('pricing.html', user=user.alias, current_plan=user.plan)

@app.route('/api/process_payment', methods=['POST'])
def process_payment():
    if 'user_id' not in session: return jsonify({'error': 'Unauthorized'}), 401
    data = request.json; plan_name = data.get('plan'); order_id = data.get('orderID')
    if plan_name in ['gold', 'elite', 'omega']:
        user = User.query.get(session['user_id'])
        user.plan = plan_name; db.session.commit()
        price = TIERS[plan_name]['price']
        
        # Enviar recibo asíncrono
        html_receipt = f"<h1>Recibo Orbe</h1><p>Plan: {plan_name.upper()}</p><p>Precio: {price}€</p><p>ID: {order_id}</p>"
        send_email(user.email, f'Recibo Orbe: Plan {plan_name.upper()}', html_receipt)
        
        return jsonify({'success': True})
    return jsonify({'error': 'Invalid'}), 400

@app.route('/api/status')
def api_status(): return {'cpu': random.randint(10, 95), 'ram': random.randint(20, 85)}

@app.route('/admin_panel', methods=['GET', 'POST'])
def admin_panel():
    if 'user_id' not in session: return redirect(url_for('auth'))
    current_user = User.query.get(session['user_id'])
    if current_user.plan != 'owner': return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        target_email = request.form.get('target_email'); new_plan = request.form.get('new_plan')
        target_user = User.query.filter_by(email=target_email).first()
        if target_user: target_user.plan = new_plan; db.session.commit(); flash(f'Usuario actualizado', 'success')
        else: flash('Usuario no encontrado', 'error')
    
    all_users = User.query.all()
    return render_template('admin.html', user=current_user, all_users=all_users, now=datetime.utcnow(), timedelta=timedelta)

@app.route('/admin/reset_db_danger', methods=['POST'])
def reset_db_danger():
    if 'user_id' not in session: return redirect(url_for('auth'))
    current_user = User.query.get(session['user_id'])
    if current_user.plan != 'owner': return "ACCESO DENEGADO"
    db.drop_all(); db.create_all()
    owner = User(alias=current_user.alias, email=current_user.email, password_hash=current_user.password_hash, plan='owner', is_verified=True)
    db.session.add(owner); db.session.commit(); session['user_id'] = owner.id
    flash('♻ BASE DE DATOS REINICIADA.', 'success')
    return redirect(url_for('admin_panel'))

# --- INIT ---
with app.app_context():
    try:
        db.create_all()
        if not Changelog.query.first():
            db.session.add(Changelog(version="v1.0.0", description="Lanzamiento Oficial"))
            db.session.commit()
    except Exception as e: print(f"DB Init Error: {e}")

if __name__ == '__main__':
    app.run(debug=True, port=5000)