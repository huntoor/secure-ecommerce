import os
from flask import Flask, render_template, request, jsonify, session
import sqlite3
import hashlib
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'

current_directory = os.path.dirname(os.path.abspath(__file__))
database_path = os.path.join(current_directory, 'test.db')
templates = os.path.join(current_directory, 'register.html')
print(templates+"\\register")

def create_connection():
    return sqlite3.connect(database_path)

def create_user_table(conn):
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS User (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
    )
    ''')
    conn.commit()

def create_product_table(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Product (
            id INTEGER PRIMARY KEY,
            product_name TEXT NOT NULL,
            price REAL NOT NULL
        )
    ''')
    conn.commit()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate_user(username, password):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM User WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and user[2] == hash_password(password):
        return user
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' in session:
            user_id = session['user_id']
            conn = create_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM User WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            conn.close()

            if user and user[3] == 1:  # Check if the user is an admin (is_admin == 1)
                return f(*args, **kwargs)
        return jsonify({'error': 'Admin privileges required'}), 403  # Forbidden
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # data = request.get_json()
        # username = data['username']
        # password = hash_password(data['password'])

        username = request.form['username']
        password = hash_password(request.form['password'])

        conn = create_connection()
        create_user_table(conn)
        cursor = conn.cursor()
        query = "INSERT INTO User (username, password) VALUES (?, ?)"
        try:
            cursor.execute(query, (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Username already exists'}), 409
        conn.close()
        return jsonify({'message': 'User registered successfully'}), 201
    elif request.method == 'GET':
        return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    
    user = authenticate_user(username, password)
    if user:
        session['user_id'] = user[0]  # Store user ID in session upon successful login
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/add_product', methods=['POST'])
@admin_required
def add_product():
    data = request.get_json()
    product_name = data['product_name']
    price = data['price']
    
    conn = create_connection()
    create_product_table(conn)
    cursor = conn.cursor()
    query = "INSERT INTO Product (product_name, price) VALUES (?, ?)"
    try:
        cursor.execute(query, (product_name, price))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'message': 'Product added successfully'}), 201

@app.route('/products', methods=['GET'])
def list_products():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Product")
    products = cursor.fetchall()
    conn.close()

    product_list = []
    for product in products:
        product_dict = {
            'product_id': product[0],
            'product_name': product[1],
            'price': product[2]
        }
        product_list.append(product_dict)

    # Render the template with the product list
    return render_template('products.html', products=product_list)


@app.route('/promote_to_admin', methods=['POST'])
@admin_required
def promote_to_admin():
    data = request.get_json()
    username = data['username']
    
    conn = create_connection()
    cursor = conn.cursor()
    query = "UPDATE User SET is_admin = 1 WHERE username = ?"
    try:
        cursor.execute(query, (username,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'message': f'{username} promoted to admin successfully'}), 200

# Dummy route for admin login (replace with actual authentication mechanism)
@app.route('/admin_login', methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    
    user = authenticate_user(username, password)
    if user and user[3] == 1:  # Check if the user is an admin (is_admin == 1)
        session['user_id'] = user[0]  # Store user ID in session upon successful login
        return jsonify({'message': 'Admin login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials or not an admin'}), 401
    
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)  # Remove the user's ID from the session
    return jsonify({'message': 'You have been logged out successfully'}), 200


if __name__ == '__main__':
    app.run(debug=True)
