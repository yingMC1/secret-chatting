# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, make_response
from flask_socketio import SocketIO, emit, join_room, leave_room
from functools import wraps
import sqlite3
import hashlib
import json
import os
import time
from datetime import datetime
from flask_cors import CORS
import uuid
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
CORS(app)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", logger=False, engineio_logger=False)

DB_PATH = 'chatroom.db'

# 防CC攻击（原生实现，无第三方库）
ip_request_counter = defaultdict(int)
ip_last_clean = defaultdict(int)
MAX_REQUEST_PER_MINUTE = 120

# 消息发送频率限制
user_send_time = {}
RATE_LIMIT_SECONDS = 1.5

# WebSocket单IP连接限制
ws_conn = defaultdict(int)
MAX_WS_PER_IP = 8

def init_db():
    if os.path.exists(DB_PATH):
        return
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room TEXT NOT NULL,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_name TEXT UNIQUE NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS ban_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            device_id TEXT,
            reason TEXT,
            ban_time TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    admin_pwd = hashlib.sha256('admin123'.encode()).hexdigest()
    try:
        c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)', ('yingMC', admin_pwd))
    except:
        pass

    try:
        c.execute('INSERT INTO rooms (room_name, created_by) VALUES (?, ?)', ('public', 'system'))
    except:
        pass

    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def get_real_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr

# 原生IP请求频率限制（防CC）
def check_cc():
    ip = get_real_ip()
    now = time.time()
    if now - ip_last_clean[ip] > 60:
        ip_request_counter[ip] = 0
        ip_last_clean[ip] = now
    ip_request_counter[ip] += 1
    return ip_request_counter[ip] <= MAX_REQUEST_PER_MINUTE

def is_ip_or_device_banned():
    device_id = request.cookies.get("device_id", "")
    ip = get_real_ip()
    conn = get_db()
    res = conn.execute("SELECT id FROM ban_list WHERE ip=? OR device_id=?", (ip, device_id)).fetchone()
    conn.close()
    return res is not None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not check_cc():
            return "请求过于频繁", 429
        if is_ip_or_device_banned():
            return "你的设备或IP已被封禁", 403
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated

def owner_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('username') != 'yingMC':
            return jsonify({"error": "仅yingMC可执行"}), 403
        return f(*args, **kwargs)
    return decorated

# ====================== 路由 ======================
@app.route('/')
def index():
    if not check_cc():
        return "请求频繁", 429
    if is_ip_or_device_banned():
        return "你的设备或IP已被封禁", 403

    if 'user_id' not in session:
        resp = make_response(redirect(url_for('login_page')))
        if not request.cookies.get("device_id"):
            resp.set_cookie("device_id", str(uuid.uuid4()), max_age=365*86400, httponly=True)
        return resp

    conn = get_db()
    user = conn.execute("SELECT username, is_banned FROM users WHERE id=?", (session['user_id'],)).fetchone()
    rooms = conn.execute("SELECT room_name FROM rooms").fetchall()
    conn.close()

    if user and user['is_banned']:
        session.clear()
        return "您已被封禁", 403

    resp = make_response(render_template("index.html",
        username=user['username'],
        is_admin=(user['username'] == "yingMC"),
        rooms=[r['room_name'] for r in rooms]
    ))

    if not request.cookies.get("device_id"):
        resp.set_cookie("device_id", str(uuid.uuid4()), max_age=365*86400, httponly=True)
    return resp

@app.route('/login')
def login_page():
    if not check_cc():
        return "请求频繁", 429
    resp = make_response(render_template("login.html"))
    if not request.cookies.get("device_id"):
        resp.set_cookie("device_id", str(uuid.uuid4()), max_age=365*86400, httponly=True)
    return resp

@app.route('/api/login', methods=['POST'])
def login():
    if not check_cc():
        return jsonify({"error": "请求频繁"}), 429
    if is_ip_or_device_banned():
        return jsonify({"error": "设备或IP被封禁"}), 403

    data = request.get_json()
    username = data.get('username')
    password = hash_password(data.get('password', ''))
    conn = get_db()
    user = conn.execute("SELECT id, username, is_banned FROM users WHERE username=? AND password=?", (username, password)).fetchone()
    conn.close()

    if not user:
        return jsonify({'error': '用户名或密码错误'}), 401
    if user['is_banned']:
        return jsonify({'error': '账号已封禁'}), 403

    session['user_id'] = user['id']
    session['username'] = user['username']
    return jsonify({'success': True, 'is_admin': user['username'] == 'yingMC'})

@app.route('/api/register', methods=['POST'])
def register():
    if not check_cc():
        return jsonify({"error": "请求频繁"}), 429
    if is_ip_or_device_banned():
        return jsonify({"error": "设备或IP被封禁"}), 403

    data = request.get_json()
    username = data.get('username')
    password = hash_password(data.get('password', ''))
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': '用户名已存在'}), 400

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/messages/<room>')
@login_required
def get_messages(room):
    conn = get_db()
    msgs = conn.execute("SELECT username, content, timestamp FROM messages WHERE room=? ORDER BY id DESC LIMIT 50", (room,)).fetchall()
    conn.close()
    return jsonify([dict(m) for m in reversed(msgs)])

@app.route('/api/users')
@login_required
@owner_required
def get_users():
    conn = get_db()
    users = conn.execute("SELECT id, username, is_admin, is_banned, created_at FROM users").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route("/api/ban_ip", methods=["POST"])
@login_required
@owner_required
def ban_ip():
    data = request.get_json()
    ip = data.get("ip", "")
    dev = data.get("device_id", "")
    reason = data.get("reason", "恶意攻击")
    conn = get_db()
    if ip:
        if not conn.execute("SELECT id FROM ban_list WHERE ip=?", (ip,)).fetchone():
            conn.execute("INSERT INTO ban_list (ip, device_id, reason) VALUES (?,?,?)", (ip, dev, reason))
    if dev:
        if not conn.execute("SELECT id FROM ban_list WHERE device_id=?", (dev,)).fetchone():
            conn.execute("INSERT INTO ban_list (ip, device_id, reason) VALUES (?,?,?)", (ip, dev, reason))
    conn.commit()
    conn.close()
    socketio.emit("kick_by_ban")
    return jsonify({"success": True})

@app.route("/api/unban_ip", methods=["POST"])
@login_required
@owner_required
def unban_ip():
    data = request.get_json()
    ip = data.get("ip", "")
    dev = data.get("device_id", "")
    conn = get_db()
    if ip:
        conn.execute("DELETE FROM ban_list WHERE ip=?", (ip,))
    if dev:
        conn.execute("DELETE FROM ban_list WHERE device_id=?", (dev,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route("/api/get_banlist")
@login_required
@owner_required
def get_banlist():
    conn = get_db()
    items = conn.execute("SELECT * FROM ban_list").fetchall()
    conn.close()
    return jsonify([dict(i) for i in items])

@app.route('/api/ban/<int:user_id>', methods=['POST'])
@login_required
@owner_required
def ban_user(user_id):
    conn = get_db()
    user = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if user and user["username"] == "yingMC":
        conn.close()
        return jsonify({"error": "不能封禁自己"}), 400
    conn.execute("UPDATE users SET is_banned=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    socketio.emit("force_logout", room=str(user_id))
    return jsonify({"success": True})

@app.route('/api/unban/<int:user_id>', methods=['POST'])
@login_required
@owner_required
def unban_user(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET is_banned=0 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/api/delete_message/<int:msg_id>', methods=['DELETE'])
@login_required
@owner_required
def delete_message(msg_id):
    conn = get_db()
    conn.execute("DELETE FROM messages WHERE id=?", (msg_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/api/clear_messages/<room>', methods=['DELETE'])
@login_required
@owner_required
def clear_messages(room):
    conn = get_db()
    conn.execute("DELETE FROM messages WHERE room=?", (room,))
    conn.commit()
    conn.close()
    socketio.emit("clear_room", room=room)
    return jsonify({"success": True})

@app.route('/api/rooms')
@login_required
@owner_required
def get_rooms():
    conn = get_db()
    rs = conn.execute("SELECT room_name, created_by, created_at FROM rooms").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rs])

@app.route('/admin')
@login_required
@owner_required
def admin_panel():
    return render_template("admin.html")

# ====================== SocketIO ======================
@socketio.on("connect")
def on_connect():
    ip = get_real_ip()
    if is_ip_or_device_banned():
        return False
    if ws_conn[ip] >= MAX_WS_PER_IP:
        return False
    ws_conn[ip] += 1

@socketio.on("disconnect")
def on_disconnect():
    ip = get_real_ip()
    if ws_conn[ip] > 0:
        ws_conn[ip] -= 1

@socketio.on('join')
def on_join(data):
    if is_ip_or_device_banned():
        emit("ban_close", {"msg": "已被封禁"})
        return
    room = data.get('room', 'public')
    username = session.get('username', '匿名')
    join_room(room)
    emit("system_message", {"content": f"{username} 加入了房间"}, room=room)

@socketio.on('leave')
def on_leave(data):
    room = data.get('room', 'public')
    username = session.get('username', '匿名')
    leave_room(room)
    emit("system_message", {"content": f"{username} 离开了房间"}, room=room)

@socketio.on('message')
def on_message(data):
    sid = request.sid
    now = time.time()
    if is_ip_or_device_banned():
        emit("ban_close", {"msg": "已被封禁"})
        return

    if sid in user_send_time and now - user_send_time[sid] < RATE_LIMIT_SECONDS:
        emit("system_message", {"content": "发送太快，请稍后再发"}, room=sid)
        return
    user_send_time[sid] = now

    room = data.get('room', 'public')
    username = session.get('username', '匿名')
    content = data.get('content', '').strip()
    if not content:
        return

    conn = get_db()
    banned = conn.execute("SELECT is_banned FROM users WHERE username=?", (username,)).fetchone()
    if banned and banned['is_banned']:
        conn.close()
        emit("system_message", {"content": "您已被封禁，无法发言"}, room=sid)
        return

    try:
        c = conn.execute("INSERT INTO messages (room, username, content) VALUES (?,?,?)", (room, username, content))
        msg_id = c.lastrowid
        conn.commit()
        conn.close()
        emit("new_message", {
            "id": msg_id,
            "username": username,
            "content": content,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }, room=room)
    except:
        emit("system_message", {"content": "发送失败"}, room=sid)

@socketio.on('admin_message')
def admin_msg(data):
    if session.get('username') == 'yingMC':
        room = data.get('room', 'public')
        content = data.get('content', '')
        emit("system_message", {"content": f"[管理员] {content}"}, room=room)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
