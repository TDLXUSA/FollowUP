from flask import Flask, request, jsonify, render_template
import sqlite3
import bcrypt
import secrets
import string

app = Flask(__name__)

# Database initialization and migration
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Create the users table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT UNIQUE NOT NULL)''')
    
    # Check if reset_token column exists, if not, add it
    c.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in c.fetchall()]
    if 'reset_token' not in columns:
        c.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
    
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

        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = c.fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
                return jsonify({"message": "Login successful"}), 200
            else:
                return jsonify({"message": "Invalid credentials"}), 401
        except Exception as e:
            return jsonify({"message": f"An error occurred: {str(e)}"}), 500
        finally:
            conn.close()
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.json
        username = data['username']
        password = data['password']
        email = data['email']

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                      (username, hashed_password.decode('utf-8'), email))
            conn.commit()
            return jsonify({"message": "User created successfully"}), 201
        except sqlite3.IntegrityError:
            return jsonify({"message": "Username or email already exists"}), 409
        except Exception as e:
            return jsonify({"message": f"An error occurred: {str(e)}"}), 500
        finally:
            conn.close()
    return render_template('login.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        data = request.json
        email = data['email']

        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = c.fetchone()

            if user:
                # Generate a secure reset token
                reset_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
                
                # Store the reset token in the database
                c.execute("UPDATE users SET reset_token = ? WHERE email = ?", (reset_token, email))
                conn.commit()

                # In a real-world scenario, you would send this token to the user's email
                # For this example, we'll just return it in the response
                return jsonify({"message": "Password reset initiated. Use this token to reset your password", "reset_token": reset_token}), 200
            else:
                return jsonify({"message": "Email not found"}), 404
        except Exception as e:
            return jsonify({"message": f"An error occurred: {str(e)}"}), 500
        finally:
            conn.close()
        
    return render_template('login.html')

@app.route('/confirm_reset', methods=['POST'])
def confirm_reset():
    data = request.json
    email = data['email']
    reset_token = data['reset_token']
    new_password = data['new_password']

    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ? AND reset_token = ?", (email, reset_token))
        user = c.fetchone()

        if user:
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            c.execute("UPDATE users SET password = ?, reset_token = NULL WHERE email = ?", (hashed_password.decode('utf-8'), email))
            conn.commit()
            return jsonify({"message": "Password reset successful"}), 200
        else:
            return jsonify({"message": "Invalid or expired reset token"}), 400
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)