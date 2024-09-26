from flask import Flask, request, jsonify, render_template
import sqlite3
import bcrypt
import secrets
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT UNIQUE NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        username = data['username']
        password = data['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            return jsonify({"message": "Login successful"}), 200
        else:
            return jsonify({"message": "Invalid credentials"}), 401
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.json
        username = data['username']
        password = data['password']
        email = data['email']

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                      (username, hashed_password.decode('utf-8'), email))
            conn.commit()
            return jsonify({"message": "User created successfully"}), 201
        except sqlite3.IntegrityError:
            return jsonify({"message": "Username or email already exists"}), 409
        finally:
            conn.close()
    return render_template('login.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        data = request.json
        email = data['email']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()

        if user:
            new_password = secrets.token_urlsafe(12)
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password.decode('utf-8'), email))
            conn.commit()
            conn.close()

            # Send email with new password
            send_password_reset_email(email, new_password)

            return jsonify({"message": "Password reset. Check your email for the new password"}), 200
        else:
            return jsonify({"message": "Email not found"}), 404
    return render_template('login.html')

def send_password_reset_email(email, new_password):
    sender_email = "tdlxusa@gmail.com"  # Replace with your email
    sender_password = "$InFlames1231!TDLGG"  # Replace with your email password

    msg = MIMEText(f"Your new password is: {new_password}")
    msg['Subject'] = "Password Reset"
    msg['From'] = sender_email
    msg['To'] = email

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
        smtp_server.login(sender_email, sender_password)
        smtp_server.sendmail(sender_email, email, msg.as_string())

if __name__ == '__main__':
    app.run(debug=True)