# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, make_response
from flask_socketio import SocketIO, send, emit, join_room, leave_room
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
import traceback

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "your-secret-key-change-this-in-production")
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
CORS(app)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", logger=False, engineio_logger=False)

# 数据库路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'chatroom.db')

print(f"📁 数据库路径: {DB_PATH}")

user_send_time = {}
RATE_LIMIT_SECONDS = 1.5
register_ip_limit = defaultdict(int)
register_ip_reset = defaultdict(float)
REGISTER_LIMIT = 1
REGISTER_LIMIT_SEC = 60

# ============================================================
#  数据库初始化 + 修复（强制清理）
# ============================================================
def init_db():
    """初始化数据库，修复所有用户问题"""
    print("🔧 正在初始化/修复数据库...")
    
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    
    # ===== 1. 创建所有表 =====
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
    
    # ===== 2. 删除所有非法用户 =====
    # 删除 admin 用户
    c.execute("DELETE FROM users WHERE username = 'admin'")
    print("🗑️ 已删除 admin 用户")
    
    # 删除空用户名
    c.execute("DELETE FROM users WHERE username IS NULL OR username = ''")
    print("🗑️ 已删除空用户名用户")
    
    # 删除重复的 yingMC（保留第一个）
    c.execute('''
        DELETE FROM users 
        WHERE username = 'yingMC' 
        AND id NOT IN (SELECT MIN(id) FROM users WHERE username = 'yingMC')
    ''')
    
    # ===== 3. 确保 yingMC 存在且是管理员 =====
    admin_pwd = hashlib.sha256('admin123'.encode()).hexdigest()
    
    # 检查 yingMC 是否存在
    yingmc = c.execute("SELECT id FROM users WHERE username = 'yingMC'").fetchone()
    
    if yingmc:
        # 存在，设置为管理员
        c.execute("UPDATE users SET is_admin = 1, is_banned = 0 WHERE username = 'yingMC'")
        print("✅ yingMC 已设置为管理员")
    else:
        # 不存在，创建
        c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)', ('yingMC', admin_pwd))
        print("✅ 已创建 yingMC 管理员用户")
    
    # ===== 4. 所有其他用户取消管理员权限 =====
    c.execute("UPDATE users SET is_admin = 0 WHERE username != 'yingMC'")
    
    # ===== 5. 确保 public 房间存在 =====
    room_exists = c.execute("SELECT id FROM rooms WHERE room_name = 'public'").fetchone()
    if not room_exists:
        c.execute('INSERT INTO rooms (room_name, created_by) VALUES (?, ?)', ('public', 'system'))
        print("🏠 已创建 public 房间")
    
    conn.commit()
    conn.close()
    
    # ===== 6. 打印当前用户列表 =====
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    users = c.execute("SELECT id, username, is_admin, is_banned FROM users").fetchall()
    print("📋 当前用户列表:")
    for u in users:
        print(f"   ID: {u[0]}, 用户名: {u[1]}, 管理员: {u[2]}, 封禁: {u[3]}")
    conn.close()
    
    print("✅ 数据库初始化/修复完成")

# 运行数据库修复
init_db()

def get_db():
    """获取数据库连接"""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=20)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"❌ 数据库连接失败: {e}")
        traceback.print_exc()
        raise

def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def get_real_ip():
    if request.headers.get("X-Forwarded-For"):
        ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()
    else:
        ip = request.remote_addr
    return ip

def is_ip_or_device_banned():
    """检查IP或设备是否被封禁"""
    device_id = request.cookies.get("device_id", "")
    ip = get_real_ip()
    try:
        conn = get_db()
        row = conn.execute('SELECT id FROM ban_list WHERE ip = ? OR device_id = ?', (ip, device_id)).fetchone()
        conn.close()
        return row is not None
    except Exception as e:
        print(f"ban check error: {e}")
        return False

def check_register_limit(ip):
    now = time.time()
    if now - register_ip_reset[ip] > REGISTER_LIMIT_SEC:
        register_ip_limit[ip] = 0
        register_ip_reset[ip] = now
    register_ip_limit[ip] += 1
    return register_ip_limit[ip] <= REGISTER_LIMIT

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if is_ip_or_device_banned():
            return "你的设备或IP已被管理员封禁", 403
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated

def owner_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session or session.get("username") != "yingMC":
            return jsonify({"error": "仅yingMC可执行本操作"}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    """首页 - 修复 user 为 None 的问题"""
    device_id = request.cookies.get("device_id")
    
    if is_ip_or_device_banned():
        return "你的设备或IP已被管理员封禁", 403

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
    
    if user is None:
        session.clear()
        resp = make_response(redirect(url_for('login_page')))
        if not device_id:
            device_id = str(uuid.uuid4())
            resp.set_cookie("device_id", device_id, max_age=365*24*3600, httponly=True, samesite='Lax')
        return resp
    
    if user['is_banned']:
        session.clear()
        return '您账号已被封禁', 403
    
    try:
        resp = make_response(render_template(
            'index.html',
            username=user['username'],
            is_admin=(user['username'] == 'yingMC'),
            rooms=[r['room_name'] for r in rooms] if rooms else ['public']
        ))
    except Exception as e:
        print(f"❌ 渲染模板错误: {e}")
        return f"聊天室运行中，但模板文件缺失。错误: {e}", 500
    
    if not device_id:
        new_id = str(uuid.uuid4())
        resp.set_cookie("device_id", new_id, max_age=365*24*3600, httponly=True, samesite='Lax')
    
    return resp

@app.route('/login')
def login_page():
    if is_ip_or_device_banned():
        return "你的设备或IP已被管理员封禁", 403
    resp = make_response(render_template('login.html'))
    device_id = request.cookies.get("device_id")
    if not device_id:
        new_id = str(uuid.uuid4())
        resp.set_cookie("device_id", new_id, max_age=365*24*3600, httponly=True, samesite='Lax')
    return resp

@app.route('/api/login', methods=['POST'])
def login():
    if is_ip_or_device_banned():
        return jsonify({"error": "设备或IP被封禁"}), 403
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
def register():
    ip = get_real_ip()
    if is_ip_or_device_banned():
        return jsonify({"error": "该设备/IP已被封禁，禁止注册"}), 403
    if not check_register_limit(ip):
        return jsonify({"error": "注册过于频繁，请稍后再试"}), 429
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
def get_messages(room):
    try:
        conn = get_db()
        messages = conn.execute('SELECT id, username, content, timestamp FROM messages WHERE room = ? ORDER BY id DESC LIMIT 50', (room,)).fetchall()
        conn.close()
        return jsonify([dict(m) for m in messages[::-1]])
    except Exception as e:
        print("获取消息错误:", e)
        traceback.print_exc()
        return jsonify([])

@app.route('/api/users')
@login_required
@owner_required
def get_users():
    try:
        conn = get_db()
        users = conn.execute('SELECT id, username, is_admin, is_banned, created_at FROM users').fetchall()
        conn.close()
        return jsonify([dict(u) for u in users])
    except Exception as e:
        print("获取用户错误:", e)
        traceback.print_exc()
        return jsonify([])

@app.route("/api/ban_ip", methods=["POST"])
@login_required
@owner_required
def ban_ip():
    data = request.get_json()
    ip = data.get("ip", "")
    dev_id = data.get("device_id", "")
    reason = data.get("reason", "恶意小号攻击")
    conn = get_db()
    if ip:
        exist = conn.execute("SELECT id FROM ban_list WHERE ip = ?", (ip,)).fetchone()
        if not exist:
            conn.execute("INSERT INTO ban_list(ip,device_id,reason) VALUES (?,?,?)", (ip, dev_id, reason))
    if dev_id:
        exist = conn.execute("SELECT id FROM ban_list WHERE device_id = ?", (dev_id,)).fetchone()
        if not exist:
            conn.execute("INSERT INTO ban_list(ip,device_id,reason) VALUES (?,?,?)", (ip, dev_id, reason))
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
    dev_id = data.get("device_id", "")
    conn = get_db()
    if ip:
        conn.execute("DELETE FROM ban_list WHERE ip = ?", (ip,))
    if dev_id:
        conn.execute("DELETE FROM ban_list WHERE device_id = ?", (dev_id,))
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
    banned_user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if banned_user:
        socketio.emit('system_message', {'content': f'🚫 用户 "{banned_user["username"]}" 已被管理员封禁！'})
        socketio.emit('user_banned', {'username': banned_user["username"]})
    
    socketio.emit('force_logout', room=str(user_id))
    return jsonify({'success': True})

@app.route('/api/unban/<int:user_id>', methods=['POST'])
@login_required
@owner_required
def unban_user(user_id):
    conn = get_db()
    user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.execute('UPDATE users SET is_banned = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    if user:
        socketio.emit('system_message', {'content': f'✅ 用户 "{user["username"]}" 已被管理员解封'})
        socketio.emit('user_unbanned', {'username': user["username"]})
    
    return jsonify({'success': True})

@app.route('/api/delete_message/<int:msg_id>', methods=['DELETE'])
@login_required
@owner_required
def delete_message(msg_id):
    try:
        print(f"🗑️ 删除消息: {msg_id}")
        
        conn = get_db()
        
        msg = conn.execute('SELECT id, username, content, room FROM messages WHERE id = ?', (msg_id,)).fetchone()
        
        if not msg:
            conn.close()
            return jsonify({'error': '消息不存在'}), 404
        
        conn.execute('DELETE FROM messages WHERE id = ?', (msg_id,))
        conn.commit()
        conn.close()
        
        socketio.emit('system_message', {'content': f'🗑️ 管理员删除了 "{msg["username"]}" 的消息'})
        socketio.emit('message_deleted', {'id': msg_id, 'room': msg["room"]})
        
        return jsonify({'success': True, 'message': f'消息 {msg_id} 已删除'})
        
    except sqlite3.Error as e:
        print(f"❌ 数据库错误: {e}")
        traceback.print_exc()
        return jsonify({'error': f'数据库错误: {str(e)}'}), 500
    except Exception as e:
        print(f"❌ 删除错误: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/clear_messages/<room>', methods=['DELETE'])
@login_required
@owner_required
def clear_messages(room):
    try:
        conn = get_db()
        conn.execute('DELETE FROM messages WHERE room = ?', (room,))
        conn.commit()
        conn.close()
        socketio.emit('clear_room', room, room=room)
        return jsonify({'success': True})
    except Exception as e:
        print("清空消息错误:", str(e))
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

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
    try:
        return render_template('admin.html')
    except Exception as e:
        return f"管理后台模板缺失: {e}", 500

# ============================================================
#  Socket.IO 事件
# ============================================================
@socketio.on('connect')
def handle_connect():
    print(f"🔌 客户端连接: {request.sid}")
    if is_ip_or_device_banned():
        return False

@socketio.on('join')
def handle_join(data):
    if is_ip_or_device_banned():
        emit("ban_close", {"msg": "设备/IP已被封禁"})
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
        emit("ban_close", {"msg": "设备/IP已被封禁"})
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
        emit('system_message', {'content': '您已被封禁，无法发言'}, room=request.sid)
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
        print("message error:", e)
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
