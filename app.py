# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, make_response
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import sqlite3
import hashlib
import json
import os
import time
from datetime import datetime
from flask_cors import CORS
import uuid

app = Flask(__name__)
# 优先读取Railway环境变量，生产务必设置真实SECRET_KEY
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
CORS(app)

# ========== 全局HTTP限流 ==========
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["120 per minute"],  # 全局每分钟最多120次请求
    storage_uri="memory://",
)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", logger=False, engineio_logger=False)

# ============ 数据库初始化：新增ban_ip黑名单表 ============
DB_PATH = 'chatroom.db'

# 消息发送限速缓存
user_send_time = {}
RATE_LIMIT_SECONDS = 1.5
# WebSocket连接计数限制
ws_conn_count = {}
MAX_WS_PER_IP = 8

def init_db():
    if os.path.exists(DB_PATH):
        return
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # 用户表
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
    # 消息表
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room TEXT NOT NULL,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # 房间表
    c.execute('''
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_name TEXT UNIQUE NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # 新增：IP和设备指纹黑名单表
    c.execute('''
        CREATE TABLE IF NOT EXISTS ban_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            device_id TEXT,
            reason TEXT,
            ban_time TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 默认管理员
    admin_pwd = hashlib.sha256('admin123'.encode()).hexdigest()
    try:
        c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)', ('yingMC', admin_pwd))
    except:
        pass
    # 默认房间
    try:
        c.execute('INSERT INTO rooms (room_name, created_by) VALUES (?, ?)', ('public', 'system'))
    except:
        pass
    
    conn.commit()
    conn.close()

init_db()

# ============ 辅助函数 ============
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

# Railway获取真实用户IP（关键）
def get_real_ip():
    if request.headers.get("X-Forwarded-For"):
        ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()
    else:
        ip = request.remote_addr
    return ip

# 检查IP或者设备ID是否被封禁
def is_ip_or_device_banned():
    device_id = request.cookies.get("device_id","")
    ip = get_real_ip()
    conn = get_db()
    row = conn.execute('''
        SELECT id FROM ban_list WHERE ip = ? OR device_id = ?
    ''', (ip, device_id)).fetchone()
    conn.close()
    return row is not None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if is_ip_or_device_banned():
            return "你的设备或IP已被管理员封禁",403
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated

def owner_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session or session.get("username") != "yingMC":
            return jsonify({"error":"仅yingMC可执行本操作"}),403
        return f(*args,**kwargs)
    return decorated

# ============ 路由 ============
@app.route('/')
@limiter.limit("60 per minute")
def index():
    device_id = request.cookies.get("device_id")
    resp = None
    if is_ip_or_device_banned():
        return "你的设备或IP已被管理员封禁",403

    if 'user_id' not in session:
        resp = make_response(redirect(url_for('login_page')))
        if not device_id:
            device_id = str(uuid.uuid4())
            resp.set_cookie("device_id", device_id, max_age=365*24*3600, httponly=True, samesite='Lax')
        return resp
    
    conn = get_db()
    user = conn.execute('SELECT username, is_admin, is_banned FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    rooms = conn.execute('SELECT room_name FROM rooms').fetchall()
    conn.close()
    if user and user['is_banned']:
        session.clear()
        return '您账号已被封禁', 403
    resp = make_response(render_template('index.html', username=user['username'], is_admin=user['username'] == 'yingMC', rooms=[r['room_name'] for r in rooms]))
    if not device_id:
        new_id = str(uuid.uuid4())
        resp.set_cookie("device_id", new_id, max_age=365*24*3600, httponly=True, samesite='Lax')
    return resp

@app.route('/login')
@limiter.limit("30 per minute")
def login_page():
    resp = make_response(render_template('login.html'))
    device_id = request.cookies.get("device_id")
    if not device_id:
        new_id = str(uuid.uuid4())
        resp.set_cookie("device_id", new_id, max_age=365*24*3600, httponly=True, samesite='Lax')
    return resp

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    if is_ip_or_device_banned():
        return jsonify({"error": "设备或IP被封禁"}),403
    data = request.get_json()
    username = data.get('username')
    password = hash_password(data.get('password', ''))
    conn = get_db()
    user = conn.execute('SELECT id, username, is_admin, is_banned FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
    conn.close()
    if user:
        if user['is_banned']:
            return jsonify({'error': '该账号已被封禁'}), 403
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['is_admin'] = (user['username'] == "yingMC")
        return jsonify({'success': True, 'is_admin': session['is_admin']})
    return jsonify({'error': '用户名或密码错误'}), 401

@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    if is_ip_or_device_banned():
        return jsonify({"error": "设备或IP被封禁"}),403
    data = request.get_json()
    username = data.get('username')
    password = hash_password(data.get('password', ''))
    conn = get_db()
    try:
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
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
@limiter.limit("60 per minute")
def get_messages(room):
    conn = get_db()
    messages = conn.execute('SELECT username, content, timestamp FROM messages WHERE room = ? ORDER BY id DESC LIMIT 50', (room,)).fetchall()
    conn.close()
    return jsonify([dict(m) for m in messages[::-1]])

@app.route('/api/users')
@login_required
@owner_required
def get_users():
    conn = get_db()
    users = conn.execute('SELECT id, username, is_admin, is_banned, created_at FROM users').fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route("/api/ban_ip", methods=["POST"])
@login_required
@owner_required
def ban_ip():
    data = request.get_json()
    ip = data.get("ip","")
    dev_id = data.get("device_id","")
    reason = data.get("reason","恶意刷屏/攻击")
    conn = get_db()
    if ip:
        exist = conn.execute("SELECT id FROM ban_list WHERE ip = ?",(ip,)).fetchone()
        if not exist:
            conn.execute("INSERT INTO ban_list(ip,device_id,reason) VALUES (?,?,?)",(ip,dev_id,reason))
    if dev_id:
        exist = conn.execute("SELECT id FROM ban_list WHERE device_id = ?",(dev_id,)).fetchone()
        if not exist:
            conn.execute("INSERT INTO ban_list(ip,device_id,reason) VALUES (?,?,?)",(ip,dev_id,reason))
    conn.commit()
    conn.close()
    socketio.emit("kick_by_ban")
    return jsonify({"success":True})

@app.route("/api/unban_ip", methods=["POST"])
@login_required
@owner_required
def unban_ip():
    data = request.get_json()
    ip = data.get("ip","")
    dev_id = data.get("device_id","")
    conn = get_db()
    if ip:
        conn.execute("DELETE FROM ban_list WHERE ip = ?",(ip,))
    if dev_id:
        conn.execute("DELETE FROM ban_list WHERE device_id = ?",(dev_id,))
    conn.commit()
    conn.close()
    return jsonify({"success":True})

@app.route("/api/get_banlist")
@login_required
@owner_required
def get_banlist():
    conn = get_db()
    items = conn.execute("SELECT * FROM ban_list").fetchall()
    conn.close()
    return jsonify([dict(r) for r in items])

@app.route('/api/ban/<int:user_id>', methods=['POST'])
@login_required
@owner_required
def ban_user(user_id):
    conn = get_db()
    user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if user and user["username"] == "yingMC":
        conn.close()
        return jsonify({'error': '不能封禁自己'}), 400
    conn.execute('UPDATE users SET is_banned = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    socketio.emit('force_logout', room=str(user_id))
    return jsonify({'success': True})

@app.route('/api/unban/<int:user_id>', methods=['POST'])
@login_required
@owner_required
def unban_user(user_id):
    conn = get_db()
    conn.execute('UPDATE users SET is_banned = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/delete_message/<int:msg_id>', methods=['DELETE'])
@login_required
@owner_required
def delete_message(msg_id):
    conn = get_db()
    conn.execute('DELETE FROM messages WHERE id = ?', (msg_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/clear_messages/<room>', methods=['DELETE'])
@login_required
@owner_required
def clear_messages(room):
    conn = get_db()
    conn.execute('DELETE FROM messages WHERE room = ?', (room,))
    conn.commit()
    conn.close()
    socketio.emit('clear_room', room, room=room)
    return jsonify({'success': True})

@app.route('/api/rooms')
@login_required
@owner_required
def get_rooms():
    conn = get_db()
    rooms = conn.execute('SELECT room_name, created_by, created_at FROM rooms').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rooms])

@app.route('/admin')
@login_required
@owner_required
def admin_panel():
    return render_template('admin.html')

# ============ SocketIO 事件 ============
@socketio.on('connect')
def handle_connect():
    ip = get_real_ip()
    # 黑名单校验
    if is_ip_or_device_banned():
        return False
    # 单IP最大WebSocket连接数限制
    if ip not in ws_conn_count:
        ws_conn_count[ip] = 0
    ws_conn_count[ip] +=1
    if ws_conn_count[ip] > MAX_WS_PER_IP:
        ws_conn_count[ip] -=1
        return False

@socketio.on('disconnect')
def handle_disconnect():
    ip = get_real_ip()
    if ip in ws_conn_count and ws_conn_count[ip] > 0:
        ws_conn_count[ip] -=1

@socketio.on('join')
def handle_join(data):
    if is_ip_or_device_banned():
        emit("ban_close",{"msg":"设备被封禁"})
        return
    room = data.get('room', 'public')
    username = session.get('username', '匿名')
    join_room(room)
    emit('system_message', {'content': f'{username} 加入了房间'}, room=room)
    emit('room_joined', {'room': room})

@socketio.on('leave')
def handle_leave(data):
    room = data.get('room', 'public')
    username = session.get('username', '匿名')
    leave_room(room)
    emit('system_message', {'content': f'{username} 离开了房间'}, room=room)

@socketio.on('message')
def handle_message(data):
    sid = request.sid
    now = time.time()
    if is_ip_or_device_banned():
        emit("ban_close",{"msg":"设备被封禁"})
        return
    if sid in user_send_time:
        last_time = user_send_time[sid]
        if now - last_time < RATE_LIMIT_SECONDS:
            emit('system_message', {'content': '发送太快，请稍后再发'}, room=sid)
            return
    user_send_time[sid] = now

    room = data.get('room', 'public')
    username = session.get('username', '匿名')
    content = data.get('content', '').strip()
    if not content:
        return
    conn = get_db()
    user = conn.execute('SELECT is_banned FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user and user['is_banned']:
        emit('system_message', {'content': '您已被封禁，无法发送消息'}, room=request.sid)
        return
    try:
        conn = get_db()
        cursor = conn.execute('INSERT INTO messages (room, username, content) VALUES (?, ?, ?)', (room, username, content))
        msg_id = cursor.lastrowid
        conn.commit()
        conn.close()
        emit('new_message', {
            'id': msg_id,
            'username': username,
            'content': content,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }, room=room)
    except Exception as e:
        print("数据库写入异常:", str(e))
        emit('system_message', {'content': '消息发送失败'}, room=sid)

@socketio.on('admin_message')
def handle_admin_message(data):
    if session.get("username") == "yingMC":
        room = data.get('room', 'public')
        content = data.get('content', '')
        emit('system_message', {'content': f'[管理员] {content}'}, room=room)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8080))
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
