import re
import logging
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, session, jsonify
from flask_socketio import SocketIO, emit# 移除 socket_request 导入

app = Flask(__name__)
app.secret_key = 'your_secure_secret_key_here'  # 实际部署需更换为安全密钥
app.permanent_session_lifetime = 3600  # 会话有效期1小时
socketio = SocketIO(app, cors_allowed_origins="*")

# 全局存储在线用户（socket_id -> user_id）
online_users = {}

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# ---------------------- 数据库工具函数 ----------------------
def get_db_connection():
    """获取数据库连接，使用上下文管理器确保连接正确关闭"""
    try:
        conn = sqlite3.connect('chat_system.db', check_same_thread=False)
        conn.row_factory = sqlite3.Row  # 支持按列名获取数据
        return conn
    except sqlite3.Error as e:
        logging.error(f"数据库连接失败：{str(e)}")
        raise  # 确保有返回值或正确抛出异常


# ---------------------- 安全相关函数 ----------------------
def encrypt_password(password):
    """使用bcrypt进行密码加密（需先安装bcrypt：pip install bcrypt）"""
    import bcrypt  # 移至函数内导入，确保安装后可用
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(plain_password, hashed_password):
    """验证密码"""
    import bcrypt  # 移至函数内导入
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


# ---------------------- 页面路由 ----------------------
@app.route('/')
def index():
    """首页（跳转登录页）"""
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """登录接口（修复SQL注入风险和密码验证方式）"""
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        data = request.form
        phone = data.get('phone')
        password = data.get('password')

        # 校验输入格式
        if not re.match(r'^\d{11}$', phone):
            return jsonify({'code': 0, 'msg': '请输入11位手机号'})
        if not (6 <= len(password) <= 12):
            return jsonify({'code': 0, 'msg': '密码长度需为6-12位'})

        # 验证用户信息（使用参数化查询防SQL注入）
        conn = get_db_connection()
        try:
            # 先获取用户信息
            user = conn.execute(
                'SELECT id, nickname, password FROM users WHERE phone = ?',
                (phone,)
            ).fetchone()

            if not user or not verify_password(password, user['password']):
                return jsonify({'code': 0, 'msg': '手机号或密码错误'})

            # 登录成功，创建会话
            session['user_id'] = user['id']
            session['nickname'] = user['nickname']
            session.permanent = True
            return jsonify({
                'code': 1,
                'msg': '登录成功',
                'data': {'user_id': user['id'], 'nickname': user['nickname']}
            })
        except sqlite3.Error as e:
            logging.error(f"登录数据库错误：{str(e)}")
            return jsonify({'code': 0, 'msg': '登录失败，请重试'})
        finally:
            conn.close()
    return render_template('login.html')


@app.route('/logout')
def logout():
    """退出登录"""
    session.clear()
    return render_template('login.html')


@app.route('/chat')
def chat_page():
    """聊天首页（需登录才能访问）"""
    if 'user_id' not in session:
        return render_template('login.html', msg='请先登录')

    user_id = session['user_id']
    nickname = session['nickname']

    # 获取当前用户的好友列表及状态
    with get_db_connection() as conn:  # 使用with语句自动管理连接
        try:
            friends = conn.execute('''
                SELECT u.id AS friend_id, u.nickname AS friend_nickname, us.status 
                FROM friend_relations fr
                JOIN users u ON fr.friend_id = u.id
                JOIN user_status us ON u.id = us.user_id
                WHERE fr.user_id = ? AND fr.status = 'accepted'
            ''', (user_id,)).fetchall()
            friends_list = [dict(friend) for friend in friends]
        except sqlite3.Error as e:
            logging.error(f"获取好友列表错误：{str(e)}")
            friends_list = []

    return render_template('chat.html',
                           user_id=user_id,
                           nickname=nickname,
                           friends=friends_list)


# ---------------------- SocketIO事件处理 ----------------------
@socketio.on('connect')
def handle_connect():
    """用户建立Socket连接"""
    if 'user_id' not in session:
        emit('connect_failed', {'msg': '请先登录'})
        return
    user_id = session['user_id']
    socket_id = request.sid  # 使用flask的request获取sid

    # 更新用户状态为在线
    with get_db_connection() as conn:
        try:
            # 检查用户是否已存在于状态表
            existing = conn.execute('SELECT * FROM user_status WHERE user_id = ?', (user_id,)).fetchone()
            if existing:
                conn.execute('''
                    UPDATE user_status 
                    SET status = 'online', socket_id = ?, last_active = ? 
                    WHERE user_id = ?
                ''', (socket_id, datetime.now(), user_id))
            else:
                conn.execute('''
                    INSERT INTO user_status (user_id, status, socket_id, last_active) 
                    VALUES (?, ?, ?, ?)
                ''', (user_id, 'online', socket_id, datetime.now()))

            # 添加到在线用户映射
            online_users[socket_id] = user_id
            conn.commit()

            # 通知该用户的所有好友：当前用户上线
            notify_friend_status_change(user_id, 'online')
            emit('connect_success', {'msg': '成功连接聊天服务器'})
            logging.info(f"用户 {user_id}（SocketID: {socket_id}）上线")
        except sqlite3.Error as e:
            logging.error(f"用户 {user_id} 连接失败：{str(e)}")
            emit('connect_failed', {'msg': '连接聊天服务器失败，请重试'})


@socketio.on('disconnect')
def handle_disconnect():
    """用户断开Socket连接（关闭页面/离线时触发）"""
    socket_id = request.sid  # 使用flask的request获取sid
    if socket_id not in online_users:
        return
    user_id = online_users[socket_id]

    # 更新用户状态为离线
    with get_db_connection() as conn:
        try:
            conn.execute('''
                UPDATE user_status 
                SET status = 'offline', last_active = ? 
                WHERE user_id = ?
            ''', (datetime.now(), user_id))
            conn.commit()

            # 从在线用户映射中移除
            del online_users[socket_id]

            # 通知该用户的所有好友：当前用户离线
            notify_friend_status_change(user_id, 'offline')
            logging.info(f"用户 {user_id}（SocketID: {socket_id}）离线")
        except sqlite3.Error as e:
            logging.error(f"用户 {user_id} 断开连接处理失败：{str(e)}")


@socketio.on('send_message')
def handle_send_message(data):
    """处理用户发送消息（文字/表情）"""
    # 校验登录状态
    if 'user_id' not in session:
        emit('message_error', {'msg': '请先登录'})
        return
    sender_id = session['user_id']

    # 校验参数完整性
    required_fields = ['receiver_id', 'content', 'message_type']
    if not all(field in data for field in required_fields):
        emit('message_error', {'msg': '消息参数不完整'})
        return

    receiver_id = data['receiver_id']
    content = data['content'].strip()
    message_type = data['message_type']

    # 校验消息内容合法性
    if message_type == 'text':
        if len(content) == 0 or len(content) > 200:
            emit('message_error', {'msg': '文字消息需1-200字符'})
            return
    elif message_type == 'emoji':
        # 校验表情编码（预设10种：emoji_1 ~ emoji_10）
        if not re.match(r'^emoji_\d{1,2}$', content) or int(content.split('_')[1]) not in range(1, 11):
            emit('message_error', {'msg': '表情不合法'})
            return
    else:
        emit('message_error', {'msg': '消息类型错误'})
        return

    # 存储消息到数据库并处理历史记录清理
    message_id = None
    with get_db_connection() as conn:
        try:
            # 1. 插入新消息
            cursor = conn.execute('''
                INSERT INTO chat_records 
                (sender_id, receiver_id, content, message_type, send_time)
                VALUES (?, ?, ?, ?, ?)
            ''', (sender_id, receiver_id, content, message_type, datetime.now()))
            message_id = cursor.lastrowid

            # 2. 清理历史记录：仅保留当前会话（sender-receiver）最近100条
            record_count = conn.execute('''
                SELECT COUNT(*) FROM chat_records
                WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
            ''', (sender_id, receiver_id, receiver_id, sender_id)).fetchone()[0]

            if record_count > 100:
                # 获取第100条记录的ID（倒序取第100条）
                keep_id = conn.execute('''
                    SELECT id FROM chat_records
                    WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
                    ORDER BY id DESC LIMIT 1 OFFSET 99
                ''', (sender_id, receiver_id, receiver_id, sender_id)).fetchone()[0]

                # 删除更早的记录
                conn.execute('''
                    DELETE FROM chat_records
                    WHERE id < ? AND 
                    ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
                ''', (keep_id, sender_id, receiver_id, receiver_id, sender_id))

            conn.commit()
        except sqlite3.Error as e:
            logging.error(f"存储消息失败：{str(e)}")
            emit('message_error', {'msg': '消息发送失败，请重试'})
            return

    # 构建消息数据
    message_data = {
        'message_id': message_id,
        'sender_id': sender_id,
        'sender_nickname': session['nickname'],
        'receiver_id': receiver_id,
        'content': content,
        'message_type': message_type,
        'send_time': datetime.now().strftime('%H:%M:%S'),
    }

    # 发送给接收者（如果在线）
    receiver_socket_id = next(
        (sid for sid, uid in online_users.items() if uid == receiver_id),
        None
    )
    if receiver_socket_id:
        emit('new_message', message_data, to=receiver_socket_id)
        emit('message_delivered', {
            'message_id': message_id,
            'msg': '已送达'
        })
    else:
        emit('message_delivered', {
            'message_id': message_id,
            'msg': '对方离线，稍后送达'
        })

    # 发送给自己
    emit('new_message', message_data)


def notify_friend_status_change(user_id, status):
    """通知好友用户状态变化"""
    with get_db_connection() as conn:
        try:
            # 获取该用户的所有好友
            friends = conn.execute('''
                SELECT u.id, u.nickname, us.socket_id 
                FROM friend_relations fr
                JOIN users u ON fr.user_id = u.id
                LEFT JOIN user_status us ON u.id = us.user_id
                WHERE fr.friend_id = ? AND fr.status = 'accepted'
            ''', (user_id,)).fetchall()

            # 获取当前用户昵称
            user_info = conn.execute(
                'SELECT nickname FROM users WHERE id = ?',
                (user_id,)
            ).fetchone()
            user_nickname = user_info['nickname'] if user_info else '未知用户'

            # 向每个在线好友发送状态更新
            for friend in friends:
                friend_socket_id = friend['socket_id']
                if friend_socket_id and friend_socket_id in online_users:
                    emit('friend_status_change', {
                        'user_id': user_id,
                        'nickname': user_nickname,
                        'status': status
                    }, to=friend_socket_id)
        except sqlite3.Error as e:
            logging.error(f"通知好友状态变化失败：{str(e)}")


@socketio.on('get_chat_history')
def handle_get_chat_history(data):
    """获取聊天历史记录"""
    if 'user_id' not in session:
        emit('history_error', {'msg': '请先登录'})
        return

    user_id = session['user_id']
    friend_id = data.get('friend_id')
    if not friend_id:
        emit('history_error', {'msg': '缺少好友ID'})
        return

    try:
        with get_db_connection() as conn:
            # 获取双方聊天记录（按时间倒序，取最近100条）
            records = conn.execute('''
                SELECT cr.id, cr.sender_id, cr.receiver_id, cr.content, 
                       cr.message_type, cr.send_time, u.nickname as sender_nickname
                FROM chat_records cr
                JOIN users u ON cr.sender_id = u.id
                WHERE (cr.sender_id = ? AND cr.receiver_id = ?) OR 
                      (cr.sender_id = ? AND cr.receiver_id = ?)
                ORDER BY cr.send_time DESC LIMIT 100
            ''', (user_id, friend_id, friend_id, user_id)).fetchall()

            # 转换为列表并反转（按时间正序）
            history = []
            for record in reversed(records):
                history.append({
                    'message_id': record['id'],
                    'sender_id': record['sender_id'],
                    'sender_nickname': record['sender_nickname'],
                    'receiver_id': record['receiver_id'],
                    'content': record['content'],
                    'message_type': record['message_type'],
                    'send_time': record['send_time'].strftime('%H:%M:%S'),
                    'is_read': record['is_read']
                })

            # 标记未读消息为已读
            conn.execute('''
                UPDATE chat_records 
                SET is_read = 1 
                WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
            ''', (friend_id, user_id))
            conn.commit()

            emit('chat_history', {'history': history})
    except sqlite3.Error as e:
        logging.error(f"获取聊天历史失败：{str(e)}")
        emit('history_error', {'msg': '获取聊天记录失败'})


@socketio.on('mark_message_read')
def handle_mark_message_read(message_id):
    """标记消息为已读"""
    if 'user_id' not in session:
        return

    user_id = session['user_id']
    try:
        with get_db_connection() as conn:
            # 更新消息状态
            conn.execute('''
                UPDATE chat_records 
                SET is_read = 1 
                WHERE id = ? AND receiver_id = ?
            ''', (message_id, user_id))
            conn.commit()

            # 获取发送者ID
            record = conn.execute(
                'SELECT sender_id FROM chat_records WHERE id = ?',
                (message_id,)
            ).fetchone()
            if record:
                sender_id = record['sender_id']
                # 通知发送者消息已读
                sender_socket_id = next(
                    (sid for sid, uid in online_users.items() if uid == sender_id),
                    None
                )
                if sender_socket_id:
                    emit('message_read', {
                        'message_id': message_id,
                        'msg': '已读'
                    }, to=sender_socket_id)
    except sqlite3.Error as e:
        logging.error(f"标记消息已读失败：{str(e)}")


@socketio.on('search_friend')
def handle_search_friend(keyword):
    """搜索好友"""
    if 'user_id' not in session:
        emit('search_error', {'msg': '请先登录'})
        return

    user_id = session['user_id']
    try:
        with get_db_connection() as conn:
            # 搜索昵称包含关键词的用户（排除自己和已添加的好友）
            friends = conn.execute('''
                SELECT u.id, u.nickname, u.tag1, u.tag2, u.tag3
                FROM users u
                WHERE u.id != ? 
                AND u.nickname LIKE ?
                AND u.id NOT IN (
                    SELECT friend_id FROM friend_relations 
                    WHERE user_id = ? AND status IN ('pending', 'accepted')
                )
                LIMIT 10
            ''', (user_id, f'%{keyword}%', user_id)).fetchall()

            result = [dict(friend) for friend in friends]
            emit('search_result', {'friends': result})
    except sqlite3.Error as e:
        logging.error(f"搜索好友失败：{str(e)}")
        emit('search_error', {'msg': '搜索失败，请重试'})


@socketio.on('add_friend')
def handle_add_friend(friend_id):
    """添加好友"""
    if 'user_id' not in session:
        emit('add_friend_error', {'msg': '请先登录'})
        return

    user_id = session['user_id']
    if user_id == friend_id:
        emit('add_friend_error', {'msg': '不能添加自己为好友'})
        return

    try:
        with get_db_connection() as conn:
            # 检查是否已发送过请求
            existing = conn.execute('''
                SELECT * FROM friend_relations 
                WHERE user_id = ? AND friend_id = ?
            ''', (user_id, friend_id)).fetchone()

            if existing:
                emit('add_friend_error', {'msg': '已发送过好友请求'})
                return

            # 获取好友昵称
            friend = conn.execute(
                'SELECT nickname FROM users WHERE id = ?',
                (friend_id,)
            ).fetchone()
            if not friend:
                emit('add_friend_error', {'msg': '用户不存在'})
                return
            friend_nickname = friend['nickname']

            # 插入好友请求
            conn.execute('''
                INSERT INTO friend_relations 
                (user_id, friend_id, status)
                VALUES (?, ?, 'pending')
            ''', (user_id, friend_id))
            conn.commit()

            # 通知对方有新的好友请求
            friend_socket_id = next(
                (sid for sid, uid in online_users.items() if uid == friend_id),
                None
            )
            if friend_socket_id:
                emit('new_friend_request', {
                    'from_user_id': user_id,
                    'from_nickname': session['nickname']
                }, to=friend_socket_id)

            emit('add_friend_success', {'msg': f'已向{friend_nickname}发送好友请求'})
    except sqlite3.Error as e:
        logging.error(f"添加好友失败：{str(e)}")
        emit('add_friend_error', {'msg': '添加好友失败，请重试'})


@socketio.on('accept_friend')
def handle_accept_friend(from_user_id):
    """接受好友请求"""
    if 'user_id' not in session:
        return

    user_id = session['user_id']
    try:
        with get_db_connection() as conn:
            # 更新好友关系状态
            conn.execute('''
                UPDATE friend_relations 
                SET status = 'accepted' 
                WHERE user_id = ? AND friend_id = ?
            ''', (from_user_id, user_id))

            # 插入反向关系
            conn.execute('''
                INSERT INTO friend_relations 
                (user_id, friend_id, status)
                VALUES (?, ?, 'accepted')
            ''', (user_id, from_user_id))

            conn.commit()

            # 获取双方昵称
            from_user = conn.execute(
                'SELECT nickname FROM users WHERE id = ?',
                (from_user_id,)
            ).fetchone()
            from_nickname = from_user['nickname'] if from_user else '未知用户'

            # 通知对方好友请求已通过
            from_user_socket_id = next(
                (sid for sid, uid in online_users.items() if uid == from_user_id),
                None
            )
            if from_user_socket_id:
                emit('friend_request_accepted', {
                    'friend_id': user_id,
                    'friend_nickname': session['nickname']
                }, to=from_user_socket_id)

            emit('add_friend_success', {'msg': f'已成功添加{from_nickname}为好友'})
    except sqlite3.Error as e:
        logging.error(f"接受好友请求失败：{str(e)}")


@socketio.on('refresh_friend_status')
def handle_refresh_friend_status():
    """刷新好友状态"""
    if 'user_id' not in session:
        emit('status_error', {'msg': '请先登录'})
        return

    user_id = session['user_id']
    try:
        with get_db_connection() as conn:
            friends = conn.execute('''
                SELECT u.id AS friend_id, u.nickname AS friend_nickname, us.status 
                FROM friend_relations fr
                JOIN users u ON fr.friend_id = u.id
                JOIN user_status us ON u.id = us.user_id
                WHERE fr.user_id = ? AND fr.status = 'accepted'
            ''', (user_id,)).fetchall()

            friends_list = [dict(friend) for friend in friends]
            emit('friend_status_list', {'friends': friends_list})
    except sqlite3.Error as e:
        logging.error(f"刷新好友状态失败：{str(e)}")
        emit('status_error', {'msg': '刷新好友状态失败'})


if __name__ == '__main__':
    socketio.run(app, debug=True)