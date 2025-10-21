import sqlite3
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def init_database():
    """初始化聊天系统数据库表结构"""
    conn=None
    try:
        # 连接数据库（不存在则自动创建）
        conn = sqlite3.connect('chat_system.db')
        cursor = conn.cursor()
        logging.info("开始初始化数据库表结构...")

        # 1. 用户表（存储用户基本信息）
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,  -- 手机号（登录账号）
            password TEXT NOT NULL,      -- 加密后的密码
            nickname TEXT NOT NULL,      -- 用户昵称
            tag1 TEXT,                   -- 标签1（可选）
            tag2 TEXT,                   -- 标签2（可选）
            tag3 TEXT,                   -- 标签3（可选）
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- 创建时间
        )
        ''')

        # 2. 用户状态表（存储在线状态、Socket连接信息）
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_status (
            user_id INTEGER PRIMARY KEY,
            status TEXT NOT NULL,               -- 状态：online/offline
            socket_id TEXT,                     -- Socket连接ID（在线时有效）
            last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- 最后活跃时间
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
        ''')

        # 3. 好友关系表（存储用户间的好友关系）
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS friend_relations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,           -- 发起关系的用户ID
            friend_id INTEGER NOT NULL,         -- 好友用户ID
            status TEXT NOT NULL,               -- 关系状态：pending/accepted
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- 关系创建时间
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (friend_id) REFERENCES users (id) ON DELETE CASCADE,
            UNIQUE (user_id, friend_id)         -- 避免重复添加好友
        )
        ''')

        # 4. 聊天记录表（存储用户间的聊天消息）
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,         -- 发送者ID
            receiver_id INTEGER NOT NULL,       -- 接收者ID
            content TEXT NOT NULL,              -- 消息内容
            message_type TEXT NOT NULL,         -- 消息类型：text/emoji
            send_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- 发送时间
            is_read INTEGER DEFAULT 0,          -- 已读状态：0-未读，1-已读
            FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (receiver_id) REFERENCES users (id) ON DELETE CASCADE
        )
        ''')

        # 添加索引提升查询性能
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_chat_sender ON chat_records (sender_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_chat_receiver ON chat_records (receiver_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_friend_user ON friend_relations (user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_status ON user_status (status)')

        conn.commit()
        logging.info("数据库表结构初始化成功")

    except sqlite3.Error as e:
        logging.error(f"数据库初始化失败：{str(e)}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    init_database()