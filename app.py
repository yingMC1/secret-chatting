# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from functools import wraps
import sqlite3
import hashlib
import json
import os
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
CORS(app)
# 匹配 gevent worker
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

# ============ 数据库初始化 ============
DB_PATH = 'chatroom.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # 用户表（包含管理员）
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
    
    # 创建默认管理员（admin / admin123）
    admin_pwd = hashlib.sha256('admin123'.encode()).hexdigest()
    try:
        c.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)', ('admin', admin_pwd))
    except:
        pass
    
    # 创建默认房间
    try:
        c.execute('INSERT INTO rooms (room_name, created_by) VALUES (?, ?)', ('public', 'system'))
    except:
        pass
    
    conn.commit()
    conn.close()

init_db()

# ============ 辅助函数 ============
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': '请先登录'}), 401
        conn = get_db()
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        if not user or not user['is_admin']:
            return jsonify({'error': '需要管理员权限'}), 403
        return f(*args, **kwargs)
    return decorated

# ============ 路由 ============
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    conn = get_db()
    user = conn.execute('SELECT username, is_admin, is_banned FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    rooms = conn.execute('SELECT room_name FROM rooms').fetchall()
    conn.close()
    if user and user['is_banned']:
        session.clear()
        return '您已被封禁', 403
    return render_template('index.html', username=user['username'], is_admin=user['is_admin'], rooms=[r['room_name'] for r in rooms])

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = hash_password(data.get('password', ''))
    
    conn = get_db()
    user = conn.execute('SELECT id, username, is_admin, is_banned FROM users WHERE username = ? AND password = ?', 
                        (username, password)).fetchone()
    conn.close()
    
    if user:
        if user['is_banned']:
            return jsonify({'error': '该账号已被封禁'}), 403
        session['user_id'] = user['id']
        session['username'] = user['username']
        return jsonify({'success': True, 'is_admin': user['is_admin']})
    return jsonify({'error': '用户名或密码错误'}), 401

@app.route('/api/register', methods=['POST'])
def register():
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
    conn = get_db()
    messages = conn.execute('''
        SELECT username, content, timestamp FROM messages 
        WHERE room = ? ORDER BY id DESC LIMIT 100
    ''', (room,)).fetchall()
    conn.close()
    return jsonify([dict(m) for m in messages[::-1]])

@app.route('/api/users')
@admin_required
def get_users():
    conn = get_db()
    users = conn.execute('SELECT id, username, is_admin, is_banned, created_at FROM users').fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/api/rooms')
@admin_required
def get_rooms():
    conn = get_db()
    rooms = conn.execute('SELECT room_name, created_by, created_at FROM rooms').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rooms])

@app.route('/api/ban/<int:user_id>', methods=['POST'])
@admin_required
def ban_user(user_id):
    conn = get_db()
    user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    if user and user['is_admin']:
        conn.close()
        return jsonify({'error': '不能封禁管理员'}), 400
    conn.execute('UPDATE users SET is_banned = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    # 踢出被禁用户（通过socketio强制断开）
    socketio.emit('force_logout', room=str(user_id))
    return jsonify({'success': True})

@app.route('/api/unban/<int:user_id>', methods=['POST'])
@admin_required
def unban_user(user_id):
    conn = get_db()
    conn.execute('UPDATE users SET is_banned = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/delete_message/<int:msg_id>', methods=['DELETE'])
@admin_required
def delete_message(msg_id):
    conn = get_db()
    conn.execute('DELETE FROM messages WHERE id = ?', (msg_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/clear_messages/<room>', methods=['DELETE'])
@admin_required
def clear_messages(room):
    conn = get_db()
    conn.execute('DELETE FROM messages WHERE room = ?', (room,))
    conn.commit()
    conn.close()
    socketio.emit('clear_room', room, room=room)
    return jsonify({'success': True})

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html')

# ============ SocketIO 事件 ============
@socketio.on('join')
def handle_join(data):
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
    room = data.get('room', 'public')
    username = session.get('username', '匿名')
    content = data.get('content', '')
    
    if not content.strip():
        return
    
    # 检查用户是否被禁
    conn = get_db()
    user = conn.execute('SELECT is_banned FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user and user['is_banned']:
        emit('system_message', {'content': '您已被封禁，无法发送消息'}, room=request.sid)
        return
    
    # 保存消息
    conn = get_db()
    cursor = conn.execute('INSERT INTO messages (room, username, content) VALUES (?, ?, ?)', 
                          (room, username, content))
    msg_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # 广播消息
    emit('new_message', {
        'id': msg_id,
        'username': username,
        'content': content,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }, room=room)

@socketio.on('admin_message')
def handle_admin_message(data):
    if session.get('is_admin'):
        room = data.get('room', 'public')
        content = data.get('content', '')
        emit('system_message', {'content': f'[管理员] {content}'}, room=room)

# ============ 启动 ============
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
