import os
from flask import Flask, redirect, render_template, request, jsonify, session
import sqlite3
import hashlib
from functools import wraps
import re
# from cryptography.fernet import Fernet
from Crypto.Cipher import AES
import hashlib

app = Flask(__name__)
app.secret_key = '5kh6tuPxap'
key = 'C2y<]UcS2yBuNK8'

current_directory = os.path.dirname(os.path.abspath(__file__))
database_path = os.path.join(current_directory, 'test.db')
# templates = os.path.join(current_directory, 'register.html')
# print(templates+"\\register")

# key = Fernet.generate_key()
# cipher_suite = Fernet(key)


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

def validate_username(username):
    # Validate username format (alphanumeric characters and underscore, 3-20 characters)
    return re.match(r'^[a-zA-Z0-9_]{3,20}$', username)

def validate_password(password):
    # Validate password format (at least 8 characters including lowercase, uppercase, and digits)
    return re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$', password)

# def encrypt_text(plain_text):
#     if plain_text is not None:
#         encrypted_text = cipher_suite.encrypt(plain_text.encode())
#         return encrypted_text
#     return None

# def decrypt_text(encrypted_text):
#     if encrypted_text is not None:
#         decrypted_text = cipher_suite.decrypt(encrypted_text).decode()
#         return decrypted_text
#     return None

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

def encrypt_text(plain_text):
    key_hash = hashlib.sha256(key.encode()).digest()[:16]  # Ensure the key is 16 bytes
    cipher = AES.new(key_hash, AES.MODE_ECB)
    padded_text = pad(plain_text)
    encrypted_text = cipher.encrypt(padded_text.encode())
    return encrypted_text.hex()

def decrypt_text(encrypted_text):
    key_hash = hashlib.sha256(key.encode()).digest()[:16]  # Ensure the key is 16 bytes
    cipher = AES.new(key_hash, AES.MODE_ECB)
    padded_plaintext = cipher.decrypt(bytes.fromhex(encrypted_text))
    return unpad(padded_plaintext.decode())

def authenticate_user(username, password):
    conn = create_connection()
    cursor = conn.cursor()
    encrypted_username = encrypt_text(username)
    cursor.execute("SELECT * FROM User WHERE username = ?", (encrypted_username,))
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
            conn = None
            try:
                conn = create_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM User WHERE id = ?", (user_id,))
                user = cursor.fetchone()

                if user:
                    if user[3] == 1:  # Check if the user is an admin
                        return f(*args, **kwargs)
                    else:
                        return jsonify({'error': 'Admin privileges required'}), 403
                else:
                    return jsonify({'error': 'User not found'}), 404  # User ID not found
            except Exception as e:
                return jsonify({'error': 'Server error', 'message': str(e)}), 500  # Handle unexpected errors gracefully
            finally:
                if conn:
                    conn.close()
        else:
            return jsonify({'error': 'Authentication required'}), 401  # No user_id in session

    return decorated_function


def is_logged_in():
    return 'user_id' in session


@app.route('/')
def index():
    if is_logged_in():
        return redirect('/products')
    else:
        return redirect('/login')
    

@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect('/products')
    
    if request.method == 'GET':
        return render_template('register.html')
    
    # data = request.get_json()
    # username = data['username']
    # password = hash_password(data['password'])

    username = request.form['username']
    password = request.form['password']

    if not validate_username(username):
        return jsonify({'error': 'Invalid username format'}), 400
    
    if not validate_password(password):
        return jsonify({'error': 'Invalid password format'}), 400
    
    encrypted_username = encrypt_text(username)
    hashed_password = hash_password(password)


    conn = create_connection()
    create_user_table(conn)
    cursor = conn.cursor()
    query = "INSERT INTO User (username, password) VALUES (?, ?)"
    try:
        cursor.execute(query, (encrypted_username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Username already exists'}), 409
    conn.close()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect('/products')
    
    if request.method == 'GET':
        return render_template('login.html')
    
    # data = request.get_json()
    # username = data['username']
    # password = data['password']

    username = request.form['username']
    password = request.form['password']

    if not validate_username(username):
        return jsonify({'error': 'Invalid username format'}), 400

    if not validate_password(password):
        return jsonify({'error': 'Invalid password format'}), 400
    
    user = authenticate_user(username, password)

    if user:
        session['user_id'] = user[0]  # Store user ID in session upon successful login
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401
    
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if is_logged_in():
        return redirect('/products')
    
    if request.method == 'GET':
        return render_template('adminLogin.html')
    
    # data = request.get_json()
    # username = data['username']
    # password = data['password']
    username = request.form['username']
    password = request.form['password']

    if not validate_username(username):
        return jsonify({'error': 'Invalid username format'}), 400

    if not validate_password(password):
        return jsonify({'error': 'Invalid password format'}), 400
    

    user = authenticate_user(username, password)
    if user and user[3] == 1:  # Check if the user is an admin (is_admin == 1)
        session['user_id'] = user[0]  # Store user ID in session upon successful login
        return jsonify({'message': 'Admin login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials or not an admin'}), 401
    
@app.route('/admin_page', methods=['GET'])
@admin_required
def admin_page():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, is_admin FROM User")
    users = cursor.fetchall()
    conn.close()

    decrypted_users = []
    for user in users:
        decrypted_user = (
            user[0],
            decrypt_text(user[1]),  # Decrypting the username
            user[2]
        )
        decrypted_users.append(decrypted_user)

    return render_template('adminPage.html', users=decrypted_users)

@app.route('/promote_to_admin', methods=['POST'])
def promote_to_admin():
    # data = request.get_json()
    # username = data['username']

    username = request.form['username']
    encrypted_username = encrypt_text(username)
    
    conn = create_connection()
    cursor = conn.cursor()
    query = "UPDATE User SET is_admin = 1 WHERE username = ?"
    try:
        cursor.execute(query, (encrypted_username,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'message': f'{username} promoted to admin successfully'}), 200

@app.route('/demote_from_admin', methods=['POST'])
@admin_required
def demote_from_admin():
    username = request.form['username']
    encrypted_username = encrypt_text(username)
    
    conn = create_connection()
    cursor = conn.cursor()
    query = "UPDATE User SET is_admin = 0 WHERE username = ?"
    try:
        cursor.execute(query, (encrypted_username,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'message': f'{username} demoted from admin successfully'}), 200

@app.route('/add_product', methods=['GET', 'POST'])
@admin_required
def add_product():
    # if request.method == 'GET':
    #     return render_template('addProducts.html')
    
    # data = request.get_json()
    # product_name = data['product_name']
    # price = data['price']
    product_name = request.form['product_name']
    price = request.form['price']

    encrypted_product_name = encrypt_text(product_name)
    
    conn = create_connection()
    create_product_table(conn)
    cursor = conn.cursor()
    query = "INSERT INTO Product (product_name, price) VALUES (?, ?)"
    try:
        cursor.execute(query, (encrypted_product_name, price))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'message': 'Product added successfully'}), 201

@app.route('/products', methods=['GET'])
def list_products():
    if not is_logged_in():
        return redirect('/login')
    conn = create_connection()
    cursor = conn.cursor()
    create_product_table(conn)
    cursor.execute("SELECT * FROM Product")
    products = cursor.fetchall()
    conn.close()

    product_list = []
    for product in products:
        product_dict = {
            'product_id': product[0],
            'product_name': decrypt_text(product[1]),
            'price': product[2]
        }
        product_list.append(product_dict)

    # Render the template with the product list
    return render_template('products.html', products=product_list)
    
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('user_id', None)  # Remove the user's ID from the session
    return jsonify({'message': 'You have been logged out successfully'}), 200

# Cart
@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    if not is_logged_in():
        return redirect('/login')
    
    product_id = request.form.get('product_id')
    quantity = int(request.form.get('quantity', 1))  # Default to 1 if not specified
    
    if not product_id or quantity < 1:
        return jsonify({'error': 'Invalid product or quantity'}), 400
    
    cart = session.get('cart', {})
    if product_id in cart:
        cart[product_id] += quantity
    else:
        cart[product_id] = quantity
    
    session['cart'] = cart
    return jsonify({'message': 'Product added to cart'}), 200

@app.route('/cart', methods=['GET'])
def view_cart():
    if not is_logged_in():
        return redirect('/login')
    
    cart = session.get('cart', {})
    conn = create_connection()
    cursor = conn.cursor()
    products = []
    total_cost = 0
    
    for product_id, quantity in cart.items():
        cursor.execute("SELECT id, product_name, price FROM Product WHERE id = ?", (product_id,))
        product_data = cursor.fetchone()
        if product_data:
            total = product_data[2] * quantity
            products.append({
                'product_id': product_data[0],
                'product_name': decrypt_text(product_data[1]),
                'price': product_data[2],
                'quantity': quantity,
                'total': total
            })
            total_cost += total

    conn.close()
    return render_template('cart.html', products=products, total_cost=total_cost)

@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    if not is_logged_in():
        return redirect('/login')
    
    product_id = request.form.get('product_id')
    if not product_id or product_id not in session.get('cart', {}):
        return jsonify({'error': 'Product not in cart'}), 400
    
    del session['cart'][product_id]
    return jsonify({'message': 'Product removed from cart'}), 200

# Checkout
@app.route('/checkout')
def checkout():
    if not is_logged_in():
        return redirect('/login')
    
    cart = session.get('cart', {})
    if not cart:
        return redirect('/cart')  # Redirect to cart if empty

    conn = create_connection()
    cursor = conn.cursor()
    products = []
    total_cost = 0
    
    for product_id, quantity in cart.items():
        cursor.execute("SELECT id, product_name, price FROM Product WHERE id = ?", (product_id,))
        product_data = cursor.fetchone()
        if product_data:
            total = product_data[2] * quantity
            products.append({
                'product_id': product_data[0],
                'product_name': decrypt_text(product_data[1]),
                'price': product_data[2],
                'quantity': quantity,
                'total': total
            })
            total_cost += total

    conn.close()
    
    return render_template('checkout.html', products=products, total_cost=total_cost)

@app.route('/confirm', methods=['POST'])
def confirm():
    if not is_logged_in():
        return redirect('/login')

    # real payment processing with validation should be added
    # For now, we'll assume payment is always successful

    session.pop('cart', None)  # Clear the cart

    return jsonify({'message': 'Payment confirmed. Thank you for your purchase!'}), 200


if __name__ == '__main__':
    app.run(debug=True)
