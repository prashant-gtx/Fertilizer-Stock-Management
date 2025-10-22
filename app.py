from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key_change_this_in_production'

DATABASE = 'fertilizer_stock.db'

# Database initialization with triggers
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            business_name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            address TEXT,
            created_date TEXT NOT NULL
        )
    ''')
    
    # Create products table with user_id
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_name TEXT NOT NULL,
            product_type TEXT NOT NULL,
            category TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            unit TEXT NOT NULL,
            manufacturing_date TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            price REAL NOT NULL,
            supplier_name TEXT,
            batch_number TEXT,
            storage_location TEXT,
            date_added TEXT NOT NULL,
            last_updated TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    # Create alerts table for low stock notifications
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stock_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            product_name TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            message TEXT NOT NULL,
            alert_date TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
        )
    ''')
    
    # Create deleted products log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS deleted_products_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER,
            product_name TEXT,
            product_type TEXT,
            quantity INTEGER,
            deleted_date TEXT NOT NULL,
            deleted_by TEXT
        )
    ''')
    
    # Create activity log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            description TEXT,
            action_date TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    # TRIGGER 1A: Low stock alert on INSERT (when adding new products)
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS low_stock_alert_insert
        AFTER INSERT ON products
        WHEN NEW.quantity < 50
        BEGIN
            INSERT INTO stock_alerts (user_id, product_id, product_name, alert_type, message, alert_date)
            VALUES (
                NEW.user_id,
                NEW.id,
                NEW.product_name,
                'LOW_STOCK',
                'Stock level is low (' || NEW.quantity || ' ' || NEW.unit || ' remaining)',
                datetime('now')
            );
        END;
    ''')
    
    # TRIGGER 1B: Low stock alert on UPDATE (when updating quantity)
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS low_stock_alert_update
        AFTER UPDATE ON products
        WHEN NEW.quantity < 50 AND NEW.quantity != OLD.quantity
        BEGIN
            INSERT INTO stock_alerts (user_id, product_id, product_name, alert_type, message, alert_date)
            VALUES (
                NEW.user_id,
                NEW.id,
                NEW.product_name,
                'LOW_STOCK',
                'Stock level is low (' || NEW.quantity || ' ' || NEW.unit || ' remaining)',
                datetime('now')
            );
        END;
    ''')
    
    # TRIGGER 2: Expiry warning alert (products expiring in 30 days)
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS expiry_warning_on_insert
        AFTER INSERT ON products
        WHEN date(NEW.expiry_date) <= date('now', '+30 days') AND date(NEW.expiry_date) > date('now')
        BEGIN
            INSERT INTO stock_alerts (user_id, product_id, product_name, alert_type, message, alert_date)
            VALUES (
                NEW.user_id,
                NEW.id,
                NEW.product_name,
                'EXPIRY_WARNING',
                'Product expiring soon on ' || NEW.expiry_date,
                datetime('now')
            );
        END;
    ''')
    
    # TRIGGER 3: Prevent adding expired products
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS prevent_expired_products
        BEFORE INSERT ON products
        WHEN date(NEW.expiry_date) < date('now')
        BEGIN
            SELECT RAISE(ABORT, 'Cannot add expired products. Expiry date must be in the future.');
        END;
    ''')
    
    # TRIGGER 4: Log product deletions
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS log_product_deletion
        BEFORE DELETE ON products
        BEGIN
            INSERT INTO deleted_products_log (user_id, product_id, product_name, product_type, quantity, deleted_date)
            VALUES (
                OLD.user_id,
                OLD.id,
                OLD.product_name,
                OLD.product_type,
                OLD.quantity,
                datetime('now')
            );
        END;
    ''')
    
    # TRIGGER 5: Auto-update last_updated timestamp
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS update_timestamp
        AFTER UPDATE ON products
        BEGIN
            UPDATE products SET last_updated = datetime('now')
            WHERE id = NEW.id;
        END;
    ''')
    
    # TRIGGER 6: Log user activity on product addition
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS log_product_addition
        AFTER INSERT ON products
        BEGIN
            INSERT INTO activity_log (user_id, action, description, action_date)
            VALUES (
                NEW.user_id,
                'ADD_PRODUCT',
                'Added product: ' || NEW.product_name || ' (Qty: ' || NEW.quantity || ' ' || NEW.unit || ')',
                datetime('now')
            );
        END;
    ''')
    
    # TRIGGER 7: Check for negative quantity
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS prevent_negative_quantity
        BEFORE INSERT ON products
        WHEN NEW.quantity < 0
        BEGIN
            SELECT RAISE(ABORT, 'Quantity cannot be negative');
        END;
    ''')
    
    # TRIGGER 8: Check for negative price
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS prevent_negative_price
        BEFORE INSERT ON products
        WHEN NEW.price < 0
        BEGIN
            SELECT RAISE(ABORT, 'Price cannot be negative');
        END;
    ''')
    
    conn.commit()
    conn.close()

# Get database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['business_name'] = user['business_name']
            flash(f'Welcome back, {user["business_name"]}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'danger')
    
    return render_template('login.html')

# Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        business_name = request.form['business_name']
        email = request.form.get('email', '')
        phone = request.form.get('phone', '')
        address = request.form.get('address', '')
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        created_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        conn = get_db_connection()
        try:
            conn.execute('''INSERT INTO users 
                         (username, password, business_name, email, phone, address, created_date)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                         (username, hashed_password, business_name, email, phone, address, created_date))
            conn.commit()
            conn.close()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            flash('Username already exists! Please choose another.', 'danger')
            return redirect(url_for('register'))
    
    return render_template('register.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

# Home page - Display user's products only
@app.route('/')
@login_required
def index():
    user_id = session['user_id']
    conn = get_db_connection()
    products = conn.execute('SELECT * FROM products WHERE user_id = ? ORDER BY id DESC', 
                           (user_id,)).fetchall()
    
    # Get unread alerts count
    alerts_count = conn.execute('SELECT COUNT(*) as count FROM stock_alerts WHERE user_id = ? AND is_read = 0',
                                (user_id,)).fetchone()['count']
    conn.close()
    
    return render_template('index.html', products=products, alerts_count=alerts_count)

# View alerts
@app.route('/alerts')
@login_required
def view_alerts():
    user_id = session['user_id']
    conn = get_db_connection()
    alerts = conn.execute('SELECT * FROM stock_alerts WHERE user_id = ? ORDER BY alert_date DESC LIMIT 50',
                         (user_id,)).fetchall()
    
    # Mark alerts as read
    conn.execute('UPDATE stock_alerts SET is_read = 1 WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    return render_template('alerts.html', alerts=alerts)

# Add new product
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        user_id = session['user_id']
        product_name = request.form['product_name']
        product_type = request.form['product_type']
        category = request.form['category']
        quantity = request.form['quantity']
        unit = request.form['unit']
        manufacturing_date = request.form['manufacturing_date']
        expiry_date = request.form['expiry_date']
        price = request.form['price']
        supplier_name = request.form['supplier_name']
        batch_number = request.form['batch_number']
        storage_location = request.form['storage_location']
        date_added = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        conn = get_db_connection()
        try:
            conn.execute('''INSERT INTO products 
                         (user_id, product_name, product_type, category, quantity, unit, 
                          manufacturing_date, expiry_date, price, supplier_name, 
                          batch_number, storage_location, date_added)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                         (user_id, product_name, product_type, category, quantity, unit,
                          manufacturing_date, expiry_date, price, supplier_name,
                          batch_number, storage_location, date_added))
            conn.commit()
            conn.close()
            flash('Product added successfully!', 'success')
            return redirect(url_for('index'))
        except sqlite3.IntegrityError as e:
            conn.close()
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('add_product'))
    
    return render_template('add_product.html')

# View single product details
@app.route('/view/<int:id>')
@login_required
def view_product(id):
    user_id = session['user_id']
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ? AND user_id = ?', 
                          (id, user_id)).fetchone()
    conn.close()
    
    if product is None:
        flash('Product not found or access denied!', 'danger')
        return redirect(url_for('index'))
    
    return render_template('view_product.html', product=product)

# Update product
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update_product(id):
    user_id = session['user_id']
    conn = get_db_connection()
    product = conn.execute('SELECT * FROM products WHERE id = ? AND user_id = ?', 
                          (id, user_id)).fetchone()
    
    if product is None:
        flash('Product not found or access denied!', 'danger')
        conn.close()
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        product_name = request.form['product_name']
        product_type = request.form['product_type']
        category = request.form['category']
        quantity = request.form['quantity']
        unit = request.form['unit']
        manufacturing_date = request.form['manufacturing_date']
        expiry_date = request.form['expiry_date']
        price = request.form['price']
        supplier_name = request.form['supplier_name']
        batch_number = request.form['batch_number']
        storage_location = request.form['storage_location']
        
        try:
            conn.execute('''UPDATE products SET 
                         product_name=?, product_type=?, category=?, quantity=?, unit=?,
                         manufacturing_date=?, expiry_date=?, price=?, supplier_name=?,
                         batch_number=?, storage_location=?
                         WHERE id=? AND user_id=?''',
                         (product_name, product_type, category, quantity, unit,
                          manufacturing_date, expiry_date, price, supplier_name,
                          batch_number, storage_location, id, user_id))
            conn.commit()
            conn.close()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('index'))
        except sqlite3.IntegrityError as e:
            conn.close()
            flash(f'Error: {str(e)}', 'danger')
            return redirect(url_for('update_product', id=id))
    
    conn.close()
    return render_template('update_product.html', product=product)

# Delete product
@app.route('/delete/<int:id>')
@login_required
def delete_product(id):
    user_id = session['user_id']
    conn = get_db_connection()
    
    # Verify product belongs to user
    product = conn.execute('SELECT * FROM products WHERE id = ? AND user_id = ?', 
                          (id, user_id)).fetchone()
    
    if product is None:
        conn.close()
        flash('Product not found or access denied!', 'danger')
        return redirect(url_for('index'))
    
    conn.execute('DELETE FROM products WHERE id = ? AND user_id = ?', (id, user_id))
    conn.commit()
    conn.close()
    
    flash('Product deleted successfully!', 'warning')
    return redirect(url_for('index'))

# Search functionality
@app.route('/search', methods=['GET'])
@login_required
def search():
    user_id = session['user_id']
    query = request.args.get('query', '')
    conn = get_db_connection()
    products = conn.execute('''SELECT * FROM products 
                            WHERE user_id = ? AND (product_name LIKE ? OR category LIKE ? OR supplier_name LIKE ?)
                            ORDER BY id DESC''',
                            (user_id, '%' + query + '%', '%' + query + '%', '%' + query + '%')).fetchall()
    
    # Get unread alerts count
    alerts_count = conn.execute('SELECT COUNT(*) as count FROM stock_alerts WHERE user_id = ? AND is_read = 0',
                                (user_id,)).fetchone()['count']
    conn.close()
    return render_template('index.html', products=products, search_query=query, alerts_count=alerts_count)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
