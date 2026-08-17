from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import sqlite3
import os
import hashlib
import json

app = Flask(__name__)
app.secret_key = "super_secret_chat_key_2026"

# 全部写死PythonAnywhere绝对路径
PROJECT_ROOT = "/home/yingMC/secret-chatting"
# 服务器实际文件夹名是【数据】
DATA_FOLDER = os.path.join(PROJECT_ROOT, "数据")
# 使用服务器真实数据库 chatroom.db
DB_FILE = os.path.join(PROJECT_ROOT, "chatroom.db")


def init_db():
    os.makedirs(DATA_FOLDER, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute("SELECT * FROM users WHERE username = ?", ("admin",))
    if not c.fetchone():
        raw_pwd = "admin123"
        hash_pwd = hashlib.sha256(raw_pwd.encode("utf8")).hexdigest()
        c.execute("INSERT INTO users(username,password,is_admin) VALUES (?,?,?)",
                  ("admin", hash_pwd, 1))

    conn.commit()
    conn.close()


first_run = True


@app.before_request
def before_req():
    global first_run
    if first_run:
        init_db()
        first_run = False
    g.user = None
    if "username" in session:
        g.user = session["username"]


def get_db():
    db = sqlite3.connect(DB_FILE)
    db.row_factory = sqlite3.Row
    return db


# ========== 原有表单路由（保留不动） ==========
@app.route("/")
def index():
    if g.user is None:
        return redirect(url_for("login"))
    db = get_db()
    msgs = db.execute("SELECT * FROM messages ORDER BY created_at DESC LIMIT 100").fetchall()
    db.close()
    return render_template("index.html", user=g.user, messages=msgs)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        un = request.form["username"]
        pw = hashlib.sha256(request.form["password"].encode("utf8")).hexdigest()
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username=? AND password=?", (un, pw)).fetchone()
        db.close()
        if row:
            session["username"] = un
            return redirect(url_for("index"))
        flash("账号密码错误")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        un = request.form["username"]
        pw_raw = request.form["password"]
        pw_hash = hashlib.sha256(pw_raw.encode("utf8")).hexdigest()
        db = get_db()
        try:
            db.execute("INSERT INTO users(username,password) VALUES (?,?)", (un, pw_hash))
            db.commit()
            flash("注册成功，请登录")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("用户名已存在")
        finally:
            db.close()
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/send", methods=["POST"])
def send_msg():
    if g.user is None:
        return redirect(url_for("login"))
    content = request.form.get("content", "").strip()
    if content:
        db = get_db()
        db.execute("INSERT INTO messages(username,content) VALUES (?,?)", (g.user, content))
        db.commit()
        db.close()
    return redirect(url_for("index"))


@app.route("/admin")
def admin_panel():
    if g.user is None:
        return redirect(url_for("login"))
    db = get_db()
    uinfo = db.execute("SELECT is_admin FROM users WHERE username=?", (g.user,)).fetchone()
    if not uinfo or uinfo["is_admin"] != 1:
        db.close()
        flash("无管理员权限")
        return redirect(url_for("index"))
    users = db.execute("SELECT id,username,is_admin FROM users").fetchall()
    msgs = db.execute("SELECT * FROM messages ORDER BY created_at DESC").fetchall()
    db.close()
    return render_template("admin.html", users=users, messages=msgs)


@app.route("/admin/del_msg/<int:mid>")
def del_msg(mid):
    if g.user is None:
        return redirect(url_for("login"))
    db = get_db()
    uinfo = db.execute("SELECT is_admin FROM users WHERE username=?", (g.user,)).fetchone()
    if uinfo and uinfo["is_admin"] == 1:
        db.execute("DELETE FROM messages WHERE id=?", (mid,))
        db.commit()
    db.close()
    return redirect(url_for("admin"))


# ========== 新增API接口，给前端fetch调用 ==========
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    if not data:
        return json.dumps({"ok": False, "msg": "参数错误"}), 400
    un = data.get("username", "").strip()
    pw_raw = data.get("password", "")
    if not un or not pw_raw:
        return json.dumps({"ok": False, "msg": "用户名密码不能为空"}), 400
    pw_hash = hashlib.sha256(pw_raw.encode("utf8")).hexdigest()
    db = get_db()
    try:
        db.execute("INSERT INTO users(username,password) VALUES (?,?)", (un, pw_hash))
        db.commit()
        return json.dumps({"ok": True, "msg": "注册成功"})
    except sqlite3.IntegrityError:
        return json.dumps({"ok": False, "msg": "用户名已存在"}), 400
    finally:
        db.close()


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    if not data:
        return json.dumps({"ok": False, "msg": "参数错误"}), 400
    un = data.get("username", "").strip()
    pw_raw = data.get("password", "")
    pw_hash = hashlib.sha256(pw_raw.encode("utf8")).hexdigest()
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username=? AND password=?", (un, pw_hash)).fetchone()
    db.close()
    if row:
        session["username"] = un
        return json.dumps({"ok": True, "msg": "登录成功"})
    else:
        return json.dumps({"ok": False, "msg": "账号密码错误"}), 400


if __name__ == "__main__":
    init_db()
    app.run(debug=False)
