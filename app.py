# 1. 导入需要的工具
from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import hashlib  # 密码加密用
from flask import session  # 保持登录状态用

# 2. 初始化Flask应用
app = Flask(__name__)
app.secret_key = "abc123"  # 用于flash消息


# 3. 创建数据库表
def init_db():
    conn = sqlite3.connect('user.db')  # 连接数据库（没有则自动创建）
    cursor = conn.cursor()
    # 创建users表
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS users
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       phone
                       TEXT
                       UNIQUE
                       NOT
                       NULL, -- 手机号唯一，不能重复注册
                       nickname
                       TEXT
                       NOT
                       NULL,
                       tags
                       TEXT
                       NOT
                       NULL, -- 3个标签用逗号分隔（比如“电影,运动,读书”）
                       password
                       TEXT
                       NOT
                       NULL
                   )
                   ''')
    conn.commit()  # 保存操作
    conn.close()  # 关闭连接


# 4. 启动时自动创建数据库表
init_db()


# 5. 密码加密函数
def encrypt_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


# 注册页面的路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    # 如果是GET请求，显示注册页面
    if request.method == 'GET':
        return render_template('register.html')
    # 如果是POST请求，处理注册数据
    else:
        # 获取用户输入
        phone = request.form.get('phone')
        nickname = request.form.get('nickname')
        tag1 = request.form.get('tag1')
        tag2 = request.form.get('tag2')
        tag3 = request.form.get('tag3')
        password = request.form.get('password')
        confirm_pwd = request.form.get('confirm_pwd')

        # 校验输入
        errors = []
        if not (phone.isdigit() and len(phone) == 11):
            errors.append("手机号必须是11位数字")
        if not (2 <= len(nickname) <= 8):
            errors.append("昵称必须是2-8个字符")

        # 校验标签是2-4个汉字
        import re
        tag_pattern = re.compile(r'^[\u4e00-\u9fa5]{2,4}$')
        for tag in [tag1, tag2, tag3]:
            if not tag_pattern.match(tag):
                errors.append("每个兴趣标签必须是2-4个汉字")

        if not (6 <= len(password) <= 12):
            errors.append("密码必须是6-12位")
        if password != confirm_pwd:
            errors.append("两次密码不一致")

        # 如果没错误，保存数据到数据库
        if not errors:
            tags = f"{tag1},{tag2},{tag3}"
            encrypted_pwd = encrypt_password(password)

            conn = sqlite3.connect('user.db')
            cursor = conn.cursor()
            try:
                cursor.execute('''
                               INSERT INTO users (phone, nickname, tags, password)
                               VALUES (?, ?, ?, ?)
                               ''', (phone, nickname, tags, encrypted_pwd))
                conn.commit()
                flash("注册成功！快去登录")
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                errors.append("该手机号已注册，直接登录吧")
            finally:
                conn.close()

        # 如果有错误，显示错误信息
        for error in errors:
            flash(error)
        return render_template('register.html')


# 登录页面的路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    # 如果用户已登录，跳转到个人中心
    if 'phone' in session:
        return redirect(url_for('profile'))

    # 如果是GET请求，显示登录页
    if request.method == 'GET':
        return render_template('login.html')

    # 如果是POST请求，处理登录数据
    else:
        phone = request.form.get('phone')
        password = request.form.get('password')

        # 简单校验格式
        if not (phone.isdigit() and len(phone) == 11):
            flash("手机号必须是11位数字")
            return render_template('login.html')
        if not (6 <= len(password) <= 12):
            flash("密码必须是6-12位")
            return render_template('login.html')

        # 校验手机号和密码
        encrypted_pwd = encrypt_password(password)
        conn = sqlite3.connect('user.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE phone = ?', (phone,))
        user = cursor.fetchone()
        conn.close()

        # 判断登录是否成功
        if user and user[4] == encrypted_pwd:
            session['phone'] = phone  # 记录登录状态
            flash("登录成功！")
            return redirect(url_for('index'))
        else:
            flash("手机号或密码错了，再试试")
            return render_template('login.html')


# 个人中心路由
@app.route('/profile')
def profile():
    # 如果没登录，跳转到登录页
    if 'phone' not in session:
        flash("请先登录")
        return redirect(url_for('login'))

    # 查询当前用户信息
    phone = session['phone']
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    cursor.execute('SELECT nickname, tags FROM users WHERE phone = ?', (phone,))
    user_info = cursor.fetchone()
    conn.close()

    # 处理标签数据
    nickname = user_info[0]
    tags = user_info[1].split(',')

    # 显示个人中心页面
    return render_template('profile.html', nickname=nickname, tags=tags)


# 修改密码路由
@app.route('/change_pwd', methods=['POST'])
def change_pwd():
    if 'phone' not in session:
        flash("请先登录")
        return redirect(url_for('login'))

    # 获取表单数据
    old_pwd = request.form.get('old_pwd')
    new_pwd = request.form.get('new_pwd')
    confirm_new_pwd = request.form.get('confirm_new_pwd')

    # 校验输入
    errors = []
    if not (6 <= len(old_pwd) <= 12 and 6 <= len(new_pwd) <= 12):
        errors.append("密码必须是6-12位")
    if new_pwd != confirm_new_pwd:
        errors.append("两次新密码不一致")
    if old_pwd == new_pwd:
        errors.append("新密码不能和原密码一样")

    if errors:
        for error in errors:
            flash(error)
        return redirect(url_for('profile'))

    # 校验原密码是否正确
    phone = session['phone']
    encrypted_old = encrypt_password(old_pwd)
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE phone = ?', (phone,))
    stored_pwd = cursor.fetchone()[0]

    if stored_pwd != encrypted_old:
        flash("原密码错了，改不了")
        conn.close()
        return redirect(url_for('profile'))

    # 更新新密码
    encrypted_new = encrypt_password(new_pwd)
    cursor.execute('UPDATE users SET password = ? WHERE phone = ?', (encrypted_new, phone))
    conn.commit()
    conn.close()

    flash("密码改成功了！下次登录用新密码")
    return redirect(url_for('profile'))


# 退出登录路由
@app.route('/logout')
def logout():
    session.pop('phone', None)  # 清除登录状态
    flash("已退出登录")
    return redirect(url_for('login'))


# 首页路由
@app.route('/')
def index():
    # 如果没登录，跳转到登录页
    if 'phone' not in session:
        flash("请先登录")
        return redirect(url_for('login'))

    # 查询当前用户昵称
    phone = session['phone']
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    cursor.execute('SELECT nickname FROM users WHERE phone = ?', (phone,))
    nickname = cursor.fetchone()[0]
    conn.close()

    # 显示首页
    return render_template('index.html', nickname=nickname)


# 启动应用
if __name__ == '__main__':
    app.run(debug=True)
