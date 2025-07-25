from flask import Flask, jsonify, request
from flask_cors import CORS, cross_origin
import sqlite3

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Database setup
DATABASE = 'storefront.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row 
    return conn

# Route to fetch all products
@app.route('/products', methods=['GET'])
def fetch_products():
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products').fetchall()
    conn.close()

    product_list = [dict(product) for product in products]
    return jsonify(product_list)

# Route to fetch a specific product by ID
@app.route('/product/<int:product_id>', methods=['GET'])
def fetch_product(product_id):
    id = 0
    try:
        id = int(product_id)
    except ValueError as e:
        return jsonify({'error': 'Product not found'}), 404
    
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ?', (id,)).fetchone()
    conn.close()

    if product is None:
        return jsonify({'error': 'Product not found'}), 404

    return jsonify(dict(product))

# Route to add a new product
@app.route('/product', methods=['POST'])
def add_product():
    new_product = request.get_json()
    product_name = new_product.get('product_name')
    description = new_product.get('description')
    price = new_product.get('price')
    stock = new_product.get('stock')

    if not all([product_name, price, stock]):
        return jsonify({'error': 'Missing required fields'}), 400

    conn = get_db_connection()
    conn.execute(
        'INSERT INTO products (product_name, description, price, stock) VALUES (?, ?, ?, ?)',
        (product_name, description, price, stock)
    )
    conn.commit()
    conn.close()

    return jsonify({'message': 'Product added successfully'}), 201

# Route to update a product
@app.route('/product/<int:product_id>', methods=['PUT'])
def update_product(product_id):
    updated_product = request.get_json()
    product_name = updated_product.get('product_name')
    description = updated_product.get('description')
    price = updated_product.get('price')
    stock = updated_product.get('stock')

    conn = get_db_connection()
    conn.execute(
        'UPDATE products SET product_name = ?, description = ?, price = ?, stock = ? WHERE id = ?',
        (product_name, description, price, stock, product_id)
    )
    conn.commit()
    conn.close()

    return jsonify({'message': 'Product updated successfully'})

# Route to delete a product
@app.route('/product/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM products WHERE id = ?', (product_id,))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Product deleted successfully'})

@app.route('/purchase/<int:product_id>', methods=['POST'])
def purchase_product(product_id):
    conn = get_db_connection()
    
    try:
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

        # Add CORS headers manually
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "*")
        response.headers.add("Access-Control-Allow-Methods", "*")

        return response

    except Exception as e:
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
    # conn.execute('INSERT INTO products (product_name, description, price, stock) VALUES (?, ?, ?, ?)', ('Laptop', 'A high-performance laptop', 999.99, 10))
    # conn.execute('INSERT INTO products (product_name, description, price, stock) VALUES (?, ?, ?, ?)', ('Smartphone', 'A latest-gen smartphone', 699.99, 25))
    # conn.execute('INSERT INTO products (product_name, description, price, stock) VALUES (?, ?, ?, ?)', ('Headphones', 'Noise-cancelling headphones', 199.99, 50))
    conn.commit()
    conn.close()

    # Run the Flask app
    app.run(debug=False)