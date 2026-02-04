import os
import platform
import subprocess
import secrets
import re
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import qbittorrentapi
from werkzeug.security import generate_password_hash, check_password_hash

# --- CONFIGURACIÓN ---
app = Flask(__name__)
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

# --- DETECCIÓN DE SISTEMA OPERATIVO ---
IS_HEADLESS = False
if platform.system() == 'Linux' and os.environ.get('DISPLAY') is None:
    IS_HEADLESS = True

# --- MODELOS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(150), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    profile_pic = db.Column(db.String(255), default="https://ui-avatars.com/api/?background=random&name=User")

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

# --- FUNCIÓN AUXILIAR DE SINCRONIZACIÓN ---
def sync_torrents_logic(user_downloads):
    """Sincroniza una lista de descargas con qBittorrent"""
    active_hashes = [d.info_hash for d in user_downloads if d.info_hash]
    if not active_hashes:
        return
    
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
    except Exception as e:
        print(f"Error Sync qBit: {e}")

# --- RUTAS ---

@app.route('/')
@login_required
def index():
    # Cargar descargas
    downloads = Download.query.all() if current_user.is_admin else Download.query.filter_by(user_id=current_user.id).all()
    
    # Sincronizar al cargar la página (por si acaso el JS falla)
    sync_torrents_logic(downloads)
    
    paths = AllowedPath.query.all()
    return render_template('dashboard.html', downloads=downloads, paths=paths)

# --- NUEVA RUTA API (MAGIA PARA LIVE UPDATE) ---
@app.route('/api/updates')
@login_required
def api_updates():
    downloads = Download.query.all() if current_user.is_admin else Download.query.filter_by(user_id=current_user.id).all()
    
    # Sincronizamos con qBit
    sync_torrents_logic(downloads)
    
    # Devolvemos JSON para que Javascript lo lea
    data = []
    for dl in downloads:
        data.append({
            'id': dl.id,
            'progress': round(dl.progress, 1),
            'status': dl.status,
            'filename': dl.filename or "Cargando..."
        })
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
        flash('Usuario o contraseña incorrectos.', 'error')
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
        current_user.email = request.form.get('email')
        current_user.phone = request.form.get('phone')
        new_pass = request.form.get('password')
        if new_pass:
            current_user.password = generate_password_hash(new_pass)
        db.session.commit()
        flash("Perfil actualizado.", "success")
        return redirect(url_for('profile'))
    return render_template('profile.html', user=current_user)

@app.route('/download', methods=['POST'])
@login_required
def start_download():
    magnet = request.form.get('magnet')
    path_id = request.form.get('path_id')

    if not magnet:
        flash("¡Error! Introduce un enlace Magnet.", "error")
        return redirect(url_for('index'))
    if not path_id:
        flash("¡Error! Selecciona una ruta.", "error")
        return redirect(url_for('index'))

    path_obj = AllowedPath.query.get(path_id)
    
    try:
        qbt = qbittorrentapi.Client(host=QBIT_HOST, port=QBIT_PORT, username=QBIT_USER, password=QBIT_PASS)
        qbt.auth_log_in()
        qbt.torrents_add(urls=magnet, save_path=path_obj.full_path)
        
        # Intentar sacar el hash del magnet
        hash_search = re.search(r'xt=urn:btih:([a-zA-Z0-9]+)', magnet)
        info_hash = hash_search.group(1).lower() if hash_search else None

        new_dl = Download(user_id=current_user.id, magnet=magnet, path_id=path_id, info_hash=info_hash)
        db.session.add(new_dl)
        db.session.commit()
        flash("Descarga añadida.", "success")
    except Exception as e:
        flash(f"Error qBittorrent: {str(e)}", "error")

    return redirect(url_for('index'))

@app.route('/delete_download/<int:dl_id>', methods=['POST'])
@login_required
def delete_download(dl_id):
    dl = Download.query.get_or_404(dl_id)
    if not current_user.is_admin and dl.user_id != current_user.id:
        return abort(403)
    try:
        if dl.info_hash:
            qbt = qbittorrentapi.Client(host=QBIT_HOST, port=QBIT_PORT, username=QBIT_USER, password=QBIT_PASS)
            qbt.auth_log_in()
            qbt.torrents_delete(delete_files=True, torrent_hashes=dl.info_hash)
    except: pass
    db.session.delete(dl)
    db.session.commit()
    flash("Descarga eliminada.", "success")
    return redirect(url_for('index'))

# --- ADMIN RUTAS ---
@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin: return abort(403)
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/create_user', methods=['POST'])
@login_required
def create_user():
    if not current_user.is_admin: return abort(403)
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email')
    phone = request.form.get('phone')
    is_admin = True if request.form.get('is_admin') == 'on' else False

    if User.query.filter_by(username=username).first():
        flash("Usuario ya existe.", "error")
        return redirect(url_for('admin_users'))

    hashed_pw = generate_password_hash(password) # CORREGIDO: Sin method='sha256'
    avatar = f"https://ui-avatars.com/api/?background=random&name={username}"
    new_user = User(username=username, password=hashed_pw, email=email, phone=phone, is_admin=is_admin, profile_pic=avatar)
    db.session.add(new_user)
    db.session.commit()
    flash("Usuario creado.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin: return abort(403)
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        user.phone = request.form.get('phone')
        if request.form.get('password'):
            user.password = generate_password_hash(request.form.get('password'))
        if user.id != current_user.id:
            user.is_admin = True if request.form.get('is_admin') == 'on' else False
        db.session.commit()
        flash("Usuario actualizado.", "success")
        return redirect(url_for('admin_users'))
    return render_template('edit_user.html', user=user)

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
            flash("Ruta añadida.", "success")
    paths = AllowedPath.query.all()
    return render_template('admin_paths.html', paths=paths)

@app.route('/admin/open_path/<int:path_id>')
@login_required
def open_path_sys(path_id):
    if not current_user.is_admin or IS_HEADLESS: return abort(403)
    path = AllowedPath.query.get_or_404(path_id)
    try:
        if platform.system() == "Windows": os.startfile(path.full_path)
        elif platform.system() == "Darwin": subprocess.Popen(["open", path.full_path])
        else: subprocess.Popen(["xdg-open", path.full_path])
        return "", 204
    except: return "", 404

@app.route('/admin/delete_path/<int:path_id>', methods=['POST'])
@login_required
def delete_path(path_id):
    if not current_user.is_admin: return abort(403)
    p = AllowedPath.query.get(path_id)
    db.session.delete(p)
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