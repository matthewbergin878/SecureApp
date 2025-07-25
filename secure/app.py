from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from flask_seasurf import SeaSurf
import sqlite3
import secrets
import logging

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
secret = secrets.token_urlsafe(32)

app.secret_key = secret
csrf = SeaSurf(app)
csrf.init_app(app)

# Configure CORS to allow cookies
CORS(app, supports_credentials=True)

csrf._csrf_disable_on_get = False


# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Database setup
DATABASE = 'storefront.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row 
    return conn

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
    # Log all cookies received in the request
    app.logger.debug(f"Cookies received: {request.cookies}")
    
    # Log the CSRF token specifically
    csrf_token = request.cookies.get('_csrf_token')
    app.logger.debug(f"CSRF Token from cookie: {csrf_token}")
    
    return jsonify({'csrf_token': csrf_token})


@app.route('/products', methods=['GET'])
def fetch_products():
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()

    product_list = [dict(product) for product in products]
    return jsonify(product_list)

@app.route('/purchase/<int:product_id>', methods=['POST'])
def purchase_product(product_id):
    conn = get_db_connection()
    
    try:
        # Log the request method
        app.logger.debug(f"Request method: {request.method}")
        
        # Log the request headers
        app.logger.debug(f"Request headers: {request.headers}")
        
        # Log the request body
        app.logger.debug(f"Request body: {request.get_data(as_text=True)}")
        
        # Log the CSRF token received in the request header
        csrf_token_header = request.headers.get('X-CSRFToken')
        app.logger.debug(f"CSRF Token from header: {csrf_token_header}")

        # Log the CSRF token from the cookie
        csrf_token_cookie = request.cookies.get('_csrf_token')
        app.logger.debug(f"CSRF Token from cookie: {csrf_token_cookie}")

        # Fetch the product by ID
        product = conn.execute('SELECT * FROM products WHERE id = ?', (product_id,)).fetchone()
        
        if product is None:
            return jsonify({'error': 'Product not found'}), 404

        # Check if stock is available
        if product['stock'] <= 0:
            return jsonify({'error': 'Product is out of stock'}), 400

        # Reduce stock by 1
        new_stock = product['stock'] - 1
        conn.execute('UPDATE products SET stock = ? WHERE id = ?', (new_stock, product_id))
        conn.commit()

        # Prepare the response
        response = jsonify({
            'message': 'Purchase successful',
            'product': {
                'id': product['id'],
                'product_name': product['product_name'],
                'description': product['description'],
                'price': product['price'],
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



# Main entry point
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
    conn.commit()
    conn.close()

    # Run the Flask app
    app.run(debug=False)
