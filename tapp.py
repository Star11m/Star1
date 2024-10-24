from flask import Flask, request, render_template, redirect, url_for, flash
import sqlite3
from bcrypt import hashpw, gensalt, checkpw

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# إنشاء قاعدة البيانات
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )''')
    conn.commit()
    conn.close()

# صفحة تسجيل الدخول
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE username=?', (username,))
        user = c.fetchone()

        if user and checkpw(password, user[0].encode('utf-8')):
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'danger')
        conn.close()

    return render_template('login.html')

# صفحة إنشاء حساب جديد
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        hashed_password = hashpw(password, gensalt())

        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password.decode('utf-8')))
            conn.commit()
            conn.close()
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')

    return render_template('register.html')

# صفحة نسيت كلمة المرور
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password'].encode('utf-8')
        hashed_password = hashpw(new_password, gensalt())

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('UPDATE users SET password=? WHERE username=?', (hashed_password.decode('utf-8'), username))
        conn.commit()
        conn.close()

        flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

# الصفحة الرئيسية بعد تسجيل الدخول
@app.route('/')
def home():
    return 'Welcome to your dashboard!'

if __name__ == '__main__':
    init_db()  # إنشاء قاعدة البيانات عند بدء السيرفر
    app.run(debug=True)