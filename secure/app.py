from flask import Flask, jsonify, request, render_template, session
from flask_cors import CORS
from flask_seasurf import SeaSurf
import sqlite3
import secrets
import logging
import html
import bcrypt
from flask_talisman import Talisman

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
secret = secrets.token_urlsafe(32)

#CSRF protections
app.secret_key = secret
csrf = SeaSurf(app)
csrf.init_app(app)

# Configure CORS to allow cookies
CORS(app, supports_credentials=True)

#more csrf protections
Talisman(app, strict_transport_security=True, content_security_policy=None)

#require csrf token for get requests too
csrf._csrf_disable_on_get = False


# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Database setup
DATABASE = 'storefront.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row 
    return conn

def add_user(conn, username, password, salt, answer):
    if len(get_user(conn, username)) != 0:
        print("User already exists")
        return False
    sql = "INSERT INTO users(name, password, salt, email) VALUES(?,?,?,?)"
    cur = conn.cursor()
    cur.execute(sql, (username, password, salt, answer))
    conn.commit()
    return True

def get_user(conn, username):
    sql = "SELECT * FROM users WHERE name=?"
    cur = conn.cursor()
    cur.execute(sql, (username,))
    rows = cur.fetchall()
    # for row in rows:
    #     print(row)
    return rows

@app.errorhandler(403)
def csrf_error(e):
    # Log details about the CSRF validation failure
    app.logger.error("CSRF validation failed.")
    app.logger.error(f"Request method: {request.method}")
    app.logger.error(f"Request headers: {request.headers}")
    app.logger.error(f"Request cookies: {request.cookies}")
    app.logger.error(f"X-CSRFToken header: {request.headers.get('X-CSRFToken')}")
    return jsonify({'error': 'CSRF token missing or incorrect.'}), 403

@app.route('/')
def serve_frontend():
    # Serve the updated storefront HTML file
    return render_template('storefront.html')  



@app.route('/csrf-token', methods=['GET'])
def get_csrf_token():
    csrf_token = csrf._get_token()
    
    return jsonify({'csrf_token': html.escape(csrf_token)})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        csrf_token = csrf._get_token()
        app.logger.debug(f"Generated CSRF Token (from /register GET): {csrf_token}")
        return render_template('register.html', csrf_token=csrf_token)

    if request.method == 'POST':

        # Get the CSRF token from the headers
        received_csrf_token = request.headers.get('X-CSRFToken')

        expected_csrf_token = csrf._get_token()

        # Validate the CSRF token
        if received_csrf_token != expected_csrf_token:
            return jsonify({'error': 'CSRF token missing or incorrect.'}), 403

        username = request.json.get('username')
        password = request.json.get('password')
        confirm_password = request.json.get('confirm_password')

        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        salt = bcrypt.gensalt()

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO users (username, password, salt) VALUES (?, ?, ?)',
                (username, hashed_password, salt)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username already exists'}), 400
        finally:
            conn.close()

        return jsonify({'message': 'Registration successful'}), 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        csrf_token = csrf._get_token()
        app.logger.debug(f"Generated CSRF Token (from /login GET): {csrf_token}")
        return render_template('login.html', csrf_token=csrf_token)

    if request.method == 'POST':
        # Log the request headers
        app.logger.debug(f"Request Headers: {request.headers}")

        # Get the CSRF token from the headers
        received_csrf_token = request.headers.get('X-CSRFToken')
        app.logger.debug(f"Received CSRF Token (from /login POST): {received_csrf_token}")

        # Log the expected CSRF token
        expected_csrf_token = csrf._get_token()
        app.logger.debug(f"Expected CSRF Token (from /login POST): {expected_csrf_token}")

        # Validate the CSRF token
        if received_csrf_token != expected_csrf_token:
            return jsonify({'error': 'CSRF token missing or incorrect.'}), 403

        # Login logic continues here...
        username = request.json.get('username')
        password = request.json.get('password')

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user is None:
            return jsonify({'error': 'Invalid username or password'}), 401

        hashed_password = user['password']
        if not bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            return jsonify({'error': 'Invalid username or password'}), 401

        session['user_id'] = user['id']
        session['username'] = user['username']

        return jsonify({'message': 'Login successful'}), 200


@app.route('/products', methods=['GET'])
def fetch_products():
    #get all products from the database
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()

    #ensure all products have safe values, no stored xss
    sanitized_products = []
    for product in products:
        try:
            sanitized_products.append({
                'id': int(product['id']),
                'product_name': html.escape(product['product_name']),
                'description': html.escape(product['description']),
                'price': float(product['price']),
                'stock': int(product['stock'])
            })
        except ValueError as e:
            app.logger.error("Invalid product "+ str(e))

    return jsonify(sanitized_products)

@app.route('/purchase/<int:product_id>', methods=['POST'])
def purchase_product(product_id):
    id = str(product_id)
    conn = get_db_connection()
    
    try:
        # Fetch the product by ID
        #validate the prodcut_id first just in case
        if not id.isdigit():
            app.logger.error(f"Invalid product_id: {id}")
            return jsonify({'error': 'Invalid product ID'}), 400

        product_id = int(id)

        #get the product from the database
        product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
        
        if product is None:
            return jsonify({'error': 'Product not found'}), 404
        
        #ensure all the data is safe
        sanitized_product = {
            'id': int(product['id']),
            'product_name': html.escape(product['product_name']),
            'description': html.escape(product['description']),
            'price': float(product['price']),
            'stock': int(product['stock'])
        }

        # Check if stock is available
        if sanitized_product['stock'] <= 0:
            return jsonify({'error': 'Product is out of stock'}), 400

        # Reduce stock by 1
        new_stock = sanitized_product['stock'] - 1
        conn.execute('UPDATE products SET stock = ? WHERE id = ?', (new_stock, product_id))
        conn.commit()

        # Prepare the response
        response = jsonify({
            'message': 'Purchase successful',
            'product': {
                'id': sanitized_product['id'],
                'product_name': sanitized_product['product_name'],
                'description': sanitized_product['description'],
                'price': sanitized_product['price'],
                'stock': new_stock
            }
        })
        response.status_code = 200

        return response

    except Exception as e:
        app.logger.error(f"Error in purchase_product: {e}")
        return jsonify({'error': str(e)}), 500

    finally:
        conn.close()

@app.after_request
def add_header(response):
    #add secure headers to responses
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response



if __name__ == '__main__':
    # Create the database and add sample data if it doesn't exist
    conn = sqlite3.connect(DATABASE)
    conn.execute("""CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY, 
        product_name TEXT NOT NULL, 
        description TEXT, 
        price REAL NOT NULL, 
        stock INTEGER NOT NULL
    );""")
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, 
        username TEXT NOT NULL, 
        password BLOB NOT NULL, 
        salt BLOB NOT NULL
    );""")
    conn.commit()
    conn.close()

    #run app
    app.run(debug=False, ssl_context='adhoc')
