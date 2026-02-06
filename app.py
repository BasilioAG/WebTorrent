import os
import platform
import subprocess
import secrets
import re
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import send_from_directory
from werkzeug.utils import secure_filename
import qbittorrentapi
from werkzeug.security import generate_password_hash, check_password_hash

# --- CONFIGURACIÓN ---

app = Flask(__name__)
# --- CONFIGURACIÓN DE SUBIDAS ---
UPLOAD_FOLDER = 'static/profile_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Crear la carpeta si no existe al arrancar
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'clave_secreta_super_segura')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///torrents.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- QBITTORRENT CONF ---
QBIT_HOST = os.getenv('QBIT_HOST', 'localhost')
QBIT_PORT = int(os.getenv('QBIT_PORT', 8080))
QBIT_USER = os.getenv('QBIT_USER', 'admin')
QBIT_PASS = os.getenv('QBIT_PASS', 'adminadmin')

IS_HEADLESS = True if platform.system() == 'Linux' and os.environ.get('DISPLAY') is None else False

# --- TABLA DE ASOCIACIÓN (Muchos a Muchos: Usuarios <-> Rutas) ---
user_paths = db.Table('user_paths',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('path_id', db.Integer, db.ForeignKey('allowed_path.id'), primary_key=True)
)

# --- MODELOS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(150), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    profile_pic = db.Column(db.String(255), default="https://ui-avatars.com/api/?background=random&name=User")
    
    # Relación: Qué rutas tiene permitidas este usuario
    allowed_paths = db.relationship('AllowedPath', secondary=user_paths, lazy='subquery',
                                    backref=db.backref('users', lazy=True))

class AllowedPath(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alias = db.Column(db.String(50), nullable=False)
    full_path = db.Column(db.String(255), nullable=False)

class Download(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    magnet = db.Column(db.Text, nullable=False)
    path_id = db.Column(db.Integer, db.ForeignKey('allowed_path.id'), nullable=False)
    info_hash = db.Column(db.String(40), nullable=True)
    status = db.Column(db.String(50), default="Pending")
    progress = db.Column(db.Float, default=0.0)
    filename = db.Column(db.String(255), nullable=True)

@app.context_processor
def inject_os_info():
    return dict(is_headless=IS_HEADLESS)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def sync_torrents_logic(user_downloads):
    active_hashes = [d.info_hash for d in user_downloads if d.info_hash]
    if not active_hashes: return
    try:
        qbt = qbittorrentapi.Client(host=QBIT_HOST, port=QBIT_PORT, username=QBIT_USER, password=QBIT_PASS)
        qbt.auth_log_in()
        torrents_info = qbt.torrents_info(torrent_hashes=active_hashes)
        for t_info in torrents_info:
            dl = Download.query.filter_by(info_hash=t_info.hash).first()
            if dl:
                dl.progress = t_info.progress * 100
                dl.status = t_info.state
                dl.filename = t_info.name
        db.session.commit()
    except Exception as e: print(f"Error Sync: {e}")

# --- RUTAS ---
@app.route('/')
@login_required
def index():
    downloads = Download.query.all() if current_user.is_admin else Download.query.filter_by(user_id=current_user.id).all()
    sync_torrents_logic(downloads)
    
    # LÓGICA DE RESTRICCIÓN: Admin ve todas, Usuario solo las suyas asignadas
    if current_user.is_admin:
        paths = AllowedPath.query.all()
    else:
        paths = current_user.allowed_paths

    return render_template('dashboard.html', downloads=downloads, paths=paths)

@app.route('/api/updates')
@login_required
def api_updates():
    downloads = Download.query.all() if current_user.is_admin else Download.query.filter_by(user_id=current_user.id).all()
    sync_torrents_logic(downloads)
    data = [{'id': dl.id, 'progress': round(dl.progress, 1), 'status': dl.status, 'filename': dl.filename or "Cargando..."} for dl in downloads]
    return jsonify(data)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Credenciales inválidas.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # 1. Actualizar datos de texto
        current_user.email = request.form.get('email')
        current_user.phone = request.form.get('phone')
        
        if request.form.get('password'):
            current_user.password = generate_password_hash(request.form.get('password'))
        
        # 2. GESTIÓN DE FOTO DE PERFIL
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename != '' and allowed_file(file.filename):
                # Generamos un nombre único: user_ID.extension (ej: user_1.jpg)
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = secure_filename(f"user_{current_user.id}.{ext}")
                
                # Guardamos el archivo
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # Guardamos la ruta en la base de datos (añadimos versión ?v=... para evitar caché del navegador)
                current_user.profile_pic = f"/static/profile_pics/{filename}?v={secrets.token_hex(2)}"

        db.session.commit()
        flash("Perfil actualizado correctamente.", "success")
        return redirect(url_for('profile'))
        
    return render_template('profile.html', user=current_user)

@app.route('/download', methods=['POST'])
@login_required
def start_download():
    magnet = request.form.get('magnet')
    path_id = request.form.get('path_id')
    if not magnet or not path_id:
        flash("Faltan datos.", "error")
        return redirect(url_for('index'))

    path_obj = AllowedPath.query.get(path_id)
    # Seguridad extra: verificar si el usuario tiene permiso para esta ruta
    if not current_user.is_admin and path_obj not in current_user.allowed_paths:
        flash("No tienes permiso para usar esta ruta.", "error")
        return redirect(url_for('index'))

    try:
        qbt = qbittorrentapi.Client(host=QBIT_HOST, port=QBIT_PORT, username=QBIT_USER, password=QBIT_PASS)
        qbt.auth_log_in()
        qbt.torrents_add(urls=magnet, save_path=path_obj.full_path)
        hash_search = re.search(r'xt=urn:btih:([a-zA-Z0-9]+)', magnet)
        info_hash = hash_search.group(1).lower() if hash_search else None
        db.session.add(Download(user_id=current_user.id, magnet=magnet, path_id=path_id, info_hash=info_hash))
        db.session.commit()
        flash("Descarga iniciada.", "success")
    except Exception as e: flash(f"Error: {e}", "error")
    return redirect(url_for('index'))

@app.route('/delete_download/<int:dl_id>', methods=['POST'])
@login_required
def delete_download(dl_id):
    dl = Download.query.get_or_404(dl_id)
    if not current_user.is_admin and dl.user_id != current_user.id: return abort(403)
    try:
        qbt = qbittorrentapi.Client(host=QBIT_HOST, port=QBIT_PORT, username=QBIT_USER, password=QBIT_PASS)
        qbt.auth_log_in()
        if dl.info_hash: qbt.torrents_delete(delete_files=True, torrent_hashes=dl.info_hash)
    except: pass
    db.session.delete(dl)
    db.session.commit()
    return redirect(url_for('index'))

# --- ADMIN ROUTES ---
@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin: return abort(403)
    users = User.query.all()
    paths = AllowedPath.query.all() # Para el select del formulario
    return render_template('admin_users.html', users=users, paths=paths)

@app.route('/admin/create_user', methods=['POST'])
@login_required
def create_user():
    if not current_user.is_admin: return abort(403)
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    is_admin = True if request.form.get('is_admin') == 'on' else False
    
    # Obtener rutas seleccionadas (Lista de IDs)
    selected_paths_ids = request.form.getlist('allowed_paths')

    if User.query.filter_by(username=username).first():
        flash("Usuario ya existe.", "error")
        return redirect(url_for('admin_users'))

    hashed_pw = generate_password_hash(password)
    new_user = User(username=username, password=hashed_pw, email=email, is_admin=is_admin)
    
    # Asignar rutas permitidas
    if selected_paths_ids:
        for pid in selected_paths_ids:
            path = AllowedPath.query.get(pid)
            if path: new_user.allowed_paths.append(path)
    
    db.session.add(new_user)
    db.session.commit()
    flash("Usuario creado con rutas asignadas.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin: return abort(403)
    user = User.query.get_or_404(user_id)
    # Cargamos todas las rutas posibles para el checkbox
    paths = AllowedPath.query.all()
    
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        
        # Cambio de password opcional
        if request.form.get('password'):
            user.password = generate_password_hash(request.form.get('password'))
            
        # Evitar quitarse admin a uno mismo
        if user.id != current_user.id:
            user.is_admin = True if request.form.get('is_admin') == 'on' else False
        
        # Actualizar Rutas Permitidas (Checkbox logic)
        selected_paths_ids = request.form.getlist('allowed_paths')
        # Limpiamos las rutas anteriores y asignamos las nuevas
        user.allowed_paths = [] 
        for pid in selected_paths_ids:
            path_obj = AllowedPath.query.get(pid)
            if path_obj:
                user.allowed_paths.append(path_obj)

        db.session.commit()
        flash("Usuario actualizado correctamente.", "success")
        return redirect(url_for('admin_users'))
        
    return render_template('edit_user.html', user=user, paths=paths)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin: return abort(403)
    u = User.query.get(user_id)
    if u.id != current_user.id:
        db.session.delete(u)
        db.session.commit()
    return redirect(url_for('admin_users'))

@app.route('/admin/paths', methods=['GET', 'POST'])
@login_required
def admin_paths():
    if not current_user.is_admin: return abort(403)
    if request.method == 'POST':
        alias = request.form.get('alias')
        full_path = request.form.get('full_path')
        if alias and full_path:
            db.session.add(AllowedPath(alias=alias, full_path=full_path))
            db.session.commit()
            flash("Ruta creada.", "success")
    return render_template('admin_paths.html', paths=AllowedPath.query.all())

@app.route('/admin/open_path/<int:path_id>')
@login_required
def open_path_sys(path_id):
    if not current_user.is_admin or IS_HEADLESS: return abort(403)
    p = AllowedPath.query.get(path_id)
    try:
        if platform.system() == "Windows": os.startfile(p.full_path)
        else: subprocess.Popen(["xdg-open", p.full_path])
        return "", 204
    except: return "", 404

@app.route('/admin/delete_path/<int:path_id>', methods=['POST'])
@login_required
def delete_path(path_id):
    if not current_user.is_admin: return abort(403)
    db.session.delete(AllowedPath.query.get(path_id))
    db.session.commit()
    return redirect(url_for('admin_paths'))

if __name__ == '__main__':
    if not os.path.exists('torrents.db'):
        with app.app_context():
            db.create_all()
            if not User.query.filter_by(username='admin').first():
                pw = generate_password_hash('admin123')
                db.session.add(User(username='admin', password=pw, is_admin=True, email="admin@local"))
                db.session.commit()
    app.run(debug=True, host='0.0.0.0', port=5000)