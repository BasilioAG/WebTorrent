import os
import threading
import time
import qbittorrentapi
import subprocess
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'tu_clave_secreta_aqui'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///torrents.db'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Ahora lee la configuración desde Docker, si no la encuentra usa los valores por defecto
QBIT_HOST = os.getenv('QBIT_HOST', 'localhost')
QBIT_PORT = int(os.getenv('QBIT_PORT', 8080))
QBIT_USER = os.getenv('QBIT_USER', 'admin')
QBIT_PASS = os.getenv('QBIT_PASS', 'adminadmin')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'clave_por_defecto_insegura')

# --- MODELOS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class AllowedPath(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alias = db.Column(db.String(50))
    full_path = db.Column(db.String(300), nullable=False)

class Download(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    status = db.Column(db.String(50), default="Pending")
    progress = db.Column(db.Integer, default=0)
    info_hash = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    path_id = db.Column(db.Integer, db.ForeignKey('allowed_path.id'))

def monitor_downloads():
    """Pregunta a qBittorrent el estado de las descargas cada 5s"""
    while True:
        try:
            qbt = qbittorrentapi.Client(host=QBIT_HOST, port=QBIT_PORT, username=QBIT_USER, password=QBIT_PASS)
            qbt.auth_log_in()
            
            with app.app_context():
                active_downloads = Download.query.filter(Download.status != 'Completado').all()
                
                if active_downloads:
                    for dl in active_downloads:
                        if dl.info_hash:
                            torrents = qbt.torrents_info(torrent_hashes=dl.info_hash)
                            
                            if torrents:
                                t = torrents[0] 
                                dl.filename = t.name
                                dl.progress = int(t.progress * 100)
                                
                                state = t.state
                                
                                if state == "downloading":
                                    speed = t.dlspeed / 1000
                                    dl.status = f"Descargando ({speed:.1f} KB/s)"
                                elif state == "pausedDL":
                                    dl.status = "Pausado"
                                elif state == "metaDL":
                                    dl.status = "Buscando Metadatos..."
                                elif state in ["uploading", "stalledUP", "queuedUP", "checkingUP"]:
                                    dl.status = "Completado" 
                                    dl.progress = 100
                                else:
                                    dl.status = state
                                
                                db.session.commit()
        except Exception as e:
            print(f"Error en monitor: {e}")
        
        time.sleep(5)

monitor_thread = threading.Thread(target=monitor_downloads, daemon=True)
monitor_thread.start()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    my_downloads = Download.query.filter_by(user_id=current_user.id).order_by(Download.id.desc()).all()
    paths = AllowedPath.query.all()
    return render_template('dashboard.html', downloads=my_downloads, paths=paths)

@app.route('/admin/delete_path/<int:path_id>', methods=['POST'])
@login_required
def delete_path(path_id):
    if not current_user.is_admin: return "No", 403
    path_to_delete = AllowedPath.query.get_or_404(path_id)
    db.session.delete(path_to_delete)
    db.session.commit()
    flash(f"Ruta '{path_to_delete.alias}' eliminada.")
    return redirect(url_for('admin_paths'))

@app.route('/admin/open_path/<int:path_id>')
@login_required
def open_path(path_id):
    if not current_user.is_admin: return "No", 403
    path_obj = AllowedPath.query.get_or_404(path_id)
    try:
        subprocess.Popen(f'explorer "{path_obj.full_path}"')
        return '', 204
    except Exception as e:
        return str(e), 500

@app.route('/delete_download/<int:dl_id>', methods=['POST'])
@login_required
def delete_download(dl_id):
    dl = Download.query.get_or_404(dl_id)
    
    if not current_user.is_admin and dl.user_id != current_user.id:
        return "No tienes permiso", 403

    try:
        qbt = qbittorrentapi.Client(host=QBIT_HOST, port=QBIT_PORT, username=QBIT_USER, password=QBIT_PASS)
        qbt.auth_log_in()
        
        if dl.info_hash:
            qbt.torrents_delete(delete_files=True, torrent_hashes=dl.info_hash)
            
        db.session.delete(dl)
        db.session.commit()
        flash("Descarga eliminada correctamente.")
        
    except Exception as e:
        flash(f"Error al borrar: {str(e)}")
        
    return redirect(url_for('index'))

@app.route('/download', methods=['POST'])
@login_required
def add_download():
    magnet = request.form.get('magnet')
    path_id = request.form.get('path_id')
    
    target_path = AllowedPath.query.get(path_id)
    if not target_path: return redirect(url_for('index'))

    try:
        info_hash = magnet.split('btih:')[1].split('&')[0]
    except:
        info_hash = None

    new_dl = Download(user_id=current_user.id, path_id=path_id, filename="Iniciando...", status="Enviando...", info_hash=info_hash)
    db.session.add(new_dl)
    db.session.commit()

    try:
        qbt = qbittorrentapi.Client(host=QBIT_HOST, port=QBIT_PORT, username=QBIT_USER, password=QBIT_PASS)
        qbt.auth_log_in()
        qbt.torrents_add(urls=magnet, save_path=target_path.full_path)
    except Exception as e:
        new_dl.status = "Error Conexión"
        db.session.commit()

    return redirect(url_for('index'))

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin: return "Acceso Denegado", 403
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/create_user', methods=['POST'])
@login_required
def create_user():
    if not current_user.is_admin: return "No", 403
    username = request.form.get('username')
    password = request.form.get('password')
    is_admin = 'is_admin' in request.form
    
    hashed_pw = generate_password_hash(password)
    new_user = User(username=username, password=hashed_pw, is_admin=is_admin)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('admin_users'))

@app.route('/admin/paths', methods=['GET', 'POST'])
@login_required
def admin_paths():
    if not current_user.is_admin: return "Acceso Denegado", 403
    if request.method == 'POST':
        alias = request.form.get('alias')
        full_path = request.form.get('full_path')
        new_path = AllowedPath(alias=alias, full_path=full_path)
        db.session.add(new_path)
        db.session.commit()
    paths = AllowedPath.query.all()
    return render_template('admin_paths.html', paths=paths)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash('Credenciales incorrectas')
    return render_template('login.html')

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin: return "Acceso Denegado", 403
    
    user = User.query.get(user_id)
    if user:
        if user.id == current_user.id:
            flash("¡No puedes borrarte a ti mismo!")
        else:
            Download.query.filter_by(user_id=user.id).delete()
            db.session.delete(user)
            db.session.commit()
            flash("Usuario eliminado correctamente.")
            
    return redirect(url_for('admin_users'))

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin: return "Acceso Denegado", 403
    
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.username = request.form.get('username')
        
        new_pass = request.form.get('password')
        if new_pass:
            user.password = generate_password_hash(new_pass)
            
        user.is_admin = 'is_admin' in request.form
        
        db.session.commit()
        flash(f"Usuario {user.username} actualizado.")
        return redirect(url_for('admin_users'))
        
    return render_template('edit_user.html', user=user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', password=generate_password_hash('admin123'), is_admin=True)
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)