from flask import Flask, render_template, request, jsonify, session, redirect, url_for, make_response, Response
from datetime import timedelta
import os
import sqlite3
import time
import uuid
import json
import csv
import io

from database import get_db_connection, init_db
from auth_utils import hash_password, verify_password, is_password_complex, generate_totp_secret, verify_totp

app = Flask(__name__)

# Configure secure session settings
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key_readymade_shop_2026_9f8d7e6c')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# Configure upload settings for product images
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads', 'products')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB limit
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Initialize database on startup
init_db()

# Helper function to log security/admin audit events
def log_audit_event(user_id, username, role, action, ip_address, details=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_logs (user_id, username, role, action, ip_address, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, username, role, action, ip_address, details))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging audit event: {e}")

# Helper decorator for checking authentication and roles
def login_required(allowed_role=None):
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'message': 'Authentication required.'}), 401
                return redirect(url_for('cashier_login_page'))
            
            # If a specific role is required, verify it
            if allowed_role and session.get('role') != allowed_role:
                if request.path.startswith('/api/'):
                    return jsonify({'success': False, 'message': 'Forbidden: Access denied for your role.'}), 403
                if session.get('role') == 'CASHIER':
                    return "Forbidden: Cashiers are not authorized to view this page.", 403
                return redirect(url_for('cashier_login_page'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Page Routes

@app.route('/')
def index():
    if 'user_id' in session:
        role = session.get('role')
        if role == 'ADMIN':
            return redirect(url_for('admin_dashboard'))
        elif role == 'CASHIER':
            return redirect(url_for('cashier_dashboard'))
    return redirect(url_for('cashier_login_page'))

@app.route('/login')
@app.route('/cashier/login')
def cashier_login_page():
    if 'user_id' in session:
        if session.get('role') == 'ADMIN':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('cashier_dashboard'))
    return render_template('cashier_login.html')

@app.route('/admin/login')
def admin_login_page():
    if 'user_id' in session:
        if session.get('role') == 'CASHIER':
            return redirect(url_for('cashier_dashboard'))
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@login_required(allowed_role='ADMIN')
def admin_dashboard():
    return render_template('admin_dashboard.html', admin_name=session.get('name'))

@app.route('/cashier/dashboard')
@login_required(allowed_role='CASHIER')
def cashier_dashboard():
    return render_template('cashier_dashboard.html', cashier_name=session.get('name'))

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_audit_event(session['user_id'], session['username'], session['role'], 'LOGOUT', request.remote_addr)
    session.clear()
    return redirect(url_for('cashier_login_page'))


# Authentication API Endpoints

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    identifier = data.get('username', '').strip()
    password = data.get('password', '')
    requested_role = data.get('role', 'CASHIER').upper()
    remember_me = data.get('remember_me', False)
    
    if not identifier or not password:
        return jsonify({'success': False, 'message': 'Username/Email/Mobile and Password are required.'}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # User can log in with username, email, or mobile
    cursor.execute('''
        SELECT * FROM users 
        WHERE (username = ? OR email = ? OR mobile = ?) AND role = ?
    ''', (identifier, identifier, identifier, requested_role))
    
    user = cursor.fetchone()
    conn.close()
    
    # Generic credential error to protect against username enumeration
    if not user:
        log_audit_event(None, identifier, requested_role, 'LOGIN_FAILED', request.remote_addr, 'User not found or role mismatch')
        return jsonify({'success': False, 'message': 'Invalid username or password.'}), 401
        
    # Check account status
    if user['status'] == 'INACTIVE':
        log_audit_event(user['id'], user['username'], user['role'], 'LOGIN_BLOCKED_INACTIVE', request.remote_addr, 'Blocked attempt on deactivated account')
        return jsonify({'success': False, 'message': 'Your account has been deactivated. Contact the administrator.'}), 403
        
    # Verify password hash
    if not verify_password(user['password_hash'], password):
        log_audit_event(user['id'], user['username'], user['role'], 'LOGIN_FAILED', request.remote_addr, 'Password verification failed')
        return jsonify({'success': False, 'message': 'Invalid username or password.'}), 401
        
    # Handle 2FA check
    if user['two_factor_secret']:
        # Store temporary credentials in session to complete verification in step 2
        session.clear()
        session['temp_2fa_user_id'] = user['id']
        session['temp_2fa_username'] = user['username']
        session['temp_2fa_role'] = user['role']
        session['temp_2fa_name'] = user['name']
        session['temp_2fa_remember_me'] = remember_me
        return jsonify({
            'success': True,
            'requires_2fa': True,
            'message': 'Two-factor verification required.'
        })
        
    # Establish standard session
    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    session['name'] = user['name']
    
    # Persist session if remember_me is selected
    if remember_me:
        session.permanent = True
    else:
        session.permanent = False
        
    log_audit_event(user['id'], user['username'], user['role'], 'LOGIN_SUCCESS', request.remote_addr)
        
    redirect_url = url_for('admin_dashboard') if user['role'] == 'ADMIN' else url_for('cashier_dashboard')
    return jsonify({
        'success': True,
        'message': 'Login successful!',
        'redirect': redirect_url
    })

@app.route('/api/auth/verify-2fa', methods=['POST'])
def api_verify_2fa():
    data = request.get_json() or {}
    token = data.get('token', '').strip()
    
    if 'temp_2fa_user_id' not in session:
        return jsonify({'success': False, 'message': 'Session expired or invalid. Please log in again.'}), 401
        
    user_id = session['temp_2fa_user_id']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not user['two_factor_secret']:
        return jsonify({'success': False, 'message': 'Two-factor setup not found.'}), 400
        
    if not verify_totp(user['two_factor_secret'], token):
        log_audit_event(user['id'], user['username'], user['role'], 'LOGIN_2FA_FAILED', request.remote_addr, 'Incorrect 2FA token submitted')
        return jsonify({'success': False, 'message': 'Invalid authentication code.'}), 401
        
    # Finalize login session
    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    session['name'] = user['name']
    
    # Check original remember me setting
    remember_me = session.get('temp_2fa_remember_me', False)
    if remember_me:
        session.permanent = True
        
    log_audit_event(user['id'], user['username'], user['role'], 'LOGIN_SUCCESS', request.remote_addr, 'Authenticated using 2FA')
    
    redirect_url = url_for('admin_dashboard') if user['role'] == 'ADMIN' else url_for('cashier_dashboard')
    return jsonify({
        'success': True,
        'message': 'Login successful!',
        'redirect': redirect_url
    })

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    if 'user_id' in session:
        log_audit_event(session['user_id'], session['username'], session['role'], 'LOGOUT', request.remote_addr)
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully.'})


# Admin Cashier Management API Endpoints

@app.route('/api/admin/cashiers', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_get_cashiers():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, username, email, mobile, status, created_at FROM users WHERE role = "CASHIER" ORDER BY id DESC')
    cashiers = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(cashiers)

@app.route('/api/admin/cashiers', methods=['POST'])
@login_required(allowed_role='ADMIN')
def api_create_cashier():
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    username = data.get('username', '').strip().lower()
    email = data.get('email', '').strip().lower()
    mobile = data.get('mobile', '').strip()
    password = data.get('password', '')
    
    # Server side validations
    if not name or not username or not email or not password:
        return jsonify({'success': False, 'message': 'Name, username, email, and password are required.'}), 400
        
    if not is_password_complex(password):
        return jsonify({
            'success': False, 
            'message': 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
        }), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if username or email is already taken
    cursor.execute('SELECT id, username, email FROM users WHERE username = ? OR email = ?', (username, email))
    existing = cursor.fetchone()
    if existing:
        conn.close()
        if existing['username'] == username:
            return jsonify({'success': False, 'message': 'Username is already registered.'}), 409
        return jsonify({'success': False, 'message': 'Email is already registered.'}), 409
        
    # Check mobile uniqueness if provided
    if mobile:
        cursor.execute('SELECT id FROM users WHERE mobile = ?', (mobile,))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Mobile number is already registered.'}), 409
            
    # Hash password and insert
    hashed_pwd = hash_password(password)
    try:
        cursor.execute('''
            INSERT INTO users (name, username, email, mobile, password_hash, role, status)
            VALUES (?, ?, ?, ?, ?, 'CASHIER', 'ACTIVE')
        ''', (name, username, email, mobile or None, hashed_pwd))
        conn.commit()
        conn.close()
        
        log_audit_event(session['user_id'], session['username'], session['role'], 'CASHIER_CREATED', request.remote_addr, f"Created cashier: {username}")
        return jsonify({'success': True, 'message': 'Cashier account created successfully.'}), 201
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/admin/cashiers/<int:cashier_id>', methods=['PUT'])
@login_required(allowed_role='ADMIN')
def api_update_cashier(cashier_id):
    data = request.get_json() or {}
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    mobile = data.get('mobile', '').strip()
    status = data.get('status', 'ACTIVE').upper()
    password = data.get('password', '')
    
    if not name or not email:
        return jsonify({'success': False, 'message': 'Name and email are required.'}), 400
        
    if status not in ('ACTIVE', 'INACTIVE'):
        return jsonify({'success': False, 'message': 'Invalid status value.'}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify cashier exists
    cursor.execute('SELECT id, username, status FROM users WHERE id = ? AND role = "CASHIER"', (cashier_id,))
    cashier = cursor.fetchone()
    if not cashier:
        conn.close()
        return jsonify({'success': False, 'message': 'Cashier not found.'}), 404
        
    # Verify email uniqueness
    cursor.execute('SELECT id FROM users WHERE email = ? AND id != ?', (email, cashier_id))
    if cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Email is already in use by another user.'}), 409
        
    # Verify mobile uniqueness if provided
    if mobile:
        cursor.execute('SELECT id FROM users WHERE mobile = ? AND id != ?', (mobile, cashier_id))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Mobile number is already in use.'}), 409
            
    # Compile updates
    update_fields = ['name = ?', 'email = ?', 'mobile = ?', 'status = ?', 'updated_at = CURRENT_TIMESTAMP']
    params = [name, email, mobile or None, status]
    
    if password:
        if not is_password_complex(password):
            conn.close()
            return jsonify({
                'success': False, 
                'message': 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
            }), 400
        update_fields.append('password_hash = ?')
        params.append(hash_password(password))
        
    params.append(cashier_id)
    query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
    
    try:
        cursor.execute(query, params)
        conn.commit()
        conn.close()
        
        status_detail = f" Status set to {status}." if status != cashier['status'] else ""
        password_detail = " Password reset." if password else ""
        log_audit_event(
            session['user_id'], 
            session['username'], 
            session['role'], 
            'CASHIER_UPDATED', 
            request.remote_addr, 
            f"Updated cashier: {cashier['username']}.{status_detail}{password_detail}"
        )
        return jsonify({'success': True, 'message': 'Cashier account updated successfully.'})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/admin/cashiers/<int:cashier_id>', methods=['DELETE'])
@login_required(allowed_role='ADMIN')
def api_delete_cashier(cashier_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify cashier exists
    cursor.execute('SELECT id, username FROM users WHERE id = ? AND role = "CASHIER"', (cashier_id,))
    cashier = cursor.fetchone()
    if not cashier:
        conn.close()
        return jsonify({'success': False, 'message': 'Cashier not found.'}), 404
        
    try:
        cursor.execute('DELETE FROM users WHERE id = ?', (cashier_id,))
        conn.commit()
        conn.close()
        
        log_audit_event(session['user_id'], session['username'], session['role'], 'CASHIER_DELETED', request.remote_addr, f"Deleted cashier: {cashier['username']}")
        return jsonify({'success': True, 'message': 'Cashier account deleted successfully.'})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500


# Product Registration CRUD API Endpoints (Admin access only)

@app.route('/api/admin/products', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_get_products():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT p.*,
               COALESCE((SELECT SUM(st.quantity) FROM stock_transactions st WHERE (st.product_id = p.id OR st.product_code = p.product_code) AND st.transaction_type = 'RESTOCK'), 0) as restocked_qty,
               COALESCE((SELECT SUM(st.quantity) FROM stock_transactions st WHERE (st.product_id = p.id OR st.product_code = p.product_code) AND st.transaction_type = 'SALE'), 0) as sold_qty,
               COALESCE((SELECT SUM(st.quantity) FROM stock_transactions st WHERE (st.product_id = p.id OR st.product_code = p.product_code) AND st.transaction_type = 'DAMAGE'), 
                        (SELECT SUM(dr.quantity) FROM damage_records dr WHERE dr.product_id = p.id OR dr.product_code = p.product_code), 0) as damaged_qty,
               COALESCE((SELECT SUM(st.quantity) FROM stock_transactions st WHERE (st.product_id = p.id OR st.product_code = p.product_code) AND st.transaction_type = 'RETURN'), 0) as returned_qty,
               COALESCE((SELECT SUM(dr.net_loss) FROM damage_records dr WHERE dr.product_id = p.id OR dr.product_code = p.product_code), 0) as damage_loss
        FROM products p
        ORDER BY p.id DESC
    ''')
    products = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(products)

@app.route('/api/admin/products', methods=['POST'])
@login_required(allowed_role='ADMIN')
def api_create_product():
    # Retrieve form data
    product_code = request.form.get('product_code', '').strip().upper()
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    sizes = request.form.get('sizes', 'Free Size').strip()
    category = request.form.get('category', 'General').strip()
    
    # Validate numbers safely
    try:
        stock = int(request.form.get('stock', '0'))
        quantity = int(request.form.get('quantity', '1'))
        selling_price = float(request.form.get('selling_price', '0.0'))
        mrp = float(request.form.get('mrp', '0.0'))
        discount = float(request.form.get('discount', '0.0'))
        gst = float(request.form.get('gst', '0.0'))
    except ValueError:
        return jsonify({'success': False, 'message': 'Stock, quantity, prices, discount, and GST must be valid numbers.'}), 400

    # Business logic validations
    if not name or selling_price <= 0 or mrp <= 0:
        return jsonify({'success': False, 'message': 'Product Name, Selling Price, and MRP are required and must be positive.'}), 400

    if selling_price > mrp:
        return jsonify({'success': False, 'message': 'Selling Price cannot be greater than MRP.'}), 400
        
    if stock < 0 or quantity <= 0 or discount < 0 or gst < 0:
        return jsonify({'success': False, 'message': 'Stock, quantities, discount, and GST percentages cannot be negative.'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Auto-generate unique product barcode if left empty
    if not product_code:
        cursor.execute('SELECT MAX(id) FROM products')
        max_id = cursor.fetchone()[0] or 0
        product_code = f"RMG-{max_id + 1001}"

    # Check uniqueness of product code
    cursor.execute('SELECT id FROM products WHERE product_code = ?', (product_code,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': f'Product code / Barcode "{product_code}" is already registered.'}), 409

    # Handle file upload securely
    image_path = None
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename != '':
            if not allowed_file(file.filename):
                conn.close()
                return jsonify({'success': False, 'message': 'Invalid file format. Allowed: PNG, JPG, JPEG, GIF, WEBP.'}), 400
            
            # Secure rename using UUID to prevent directory traversal
            extension = file.filename.rsplit('.', 1)[1].lower()
            secure_name = f"{uuid.uuid4()}.{extension}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_name))
            image_path = f"/static/uploads/products/{secure_name}"

    # Parse cost price safely (defaults to 65% of selling price if not provided)
    try:
        cost_price = float(request.form.get('cost_price', '0.0') or 0.0)
    except ValueError:
        cost_price = 0.0
    if cost_price <= 0:
        cost_price = round(selling_price * 0.65, 2)
    initial_stock = stock

    try:
        cursor.execute('''
            INSERT INTO products (product_code, name, description, image_path, stock, initial_stock, cost_price, quantity, selling_price, mrp, discount, gst, sizes, category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (product_code, name, description or None, image_path, stock, initial_stock, cost_price, quantity, selling_price, mrp, discount, gst, sizes or 'Free Size', category))
        new_id = cursor.lastrowid
        
        # Log opening initial stock transaction
        cursor.execute('''
            INSERT INTO stock_transactions (product_id, product_code, product_name, transaction_type, quantity, cost_price, selling_price, stock_before, stock_after, notes, operator)
            VALUES (?, ?, ?, 'INITIAL', ?, ?, ?, 0, ?, 'Initial opening stock registered', ?)
        ''', (new_id, product_code, name, stock, cost_price, selling_price, stock, session.get('username')))
        
        conn.commit()
        conn.close()
        
        log_audit_event(session['user_id'], session['username'], session['role'], 'PRODUCT_CREATED', request.remote_addr, f"Registered product: {product_code} ({name}) with Initial Stock: {stock}, Cost Price: ₹{cost_price}")
        return jsonify({
            'success': True, 
            'message': f'Product registered successfully with barcode {product_code}.',
            'product': {
                'id': new_id,
                'product_code': product_code,
                'name': name,
                'selling_price': selling_price,
                'cost_price': cost_price,
                'initial_stock': initial_stock,
                'mrp': mrp,
                'stock': stock,
                'sizes': sizes or 'Free Size',
                'category': category
            }
        }), 201
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/admin/generate-barcode', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_generate_barcode():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT MAX(id) FROM products')
    max_id = cursor.fetchone()[0] or 0
    conn.close()
    
    # Generate sequential unique barcode tag
    barcode = f"RMG-{max_id + 1001}"
    return jsonify({'success': True, 'barcode': barcode})

@app.route('/api/admin/products/<int:product_id>', methods=['POST', 'PUT'])  # Allow POST to support file upload emulation
@login_required(allowed_role='ADMIN')
def api_update_product(product_id):
    # Retrieve form data
    product_code = request.form.get('product_code', '').strip().upper()
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    sizes = request.form.get('sizes', 'Free Size').strip()
    category = request.form.get('category', 'General').strip()
    
    try:
        stock = int(request.form.get('stock', '0'))
        quantity = int(request.form.get('quantity', '1'))
        selling_price = float(request.form.get('selling_price', '0.0'))
        cost_price = float(request.form.get('cost_price', '0.0') or 0.0)
        mrp = float(request.form.get('mrp', '0.0'))
        discount = float(request.form.get('discount', '0.0'))
        gst = float(request.form.get('gst', '0.0'))
    except ValueError:
        return jsonify({'success': False, 'message': 'Stock, quantity, prices, discount, and GST must be valid numbers.'}), 400

    if not product_code or not name or selling_price <= 0 or mrp <= 0:
        return jsonify({'success': False, 'message': 'Product Code, Name, Selling Price, and MRP are required.'}), 400

    if cost_price <= 0:
        cost_price = round(selling_price * 0.65, 2)

    if selling_price > mrp:
        return jsonify({'success': False, 'message': 'Selling Price cannot be greater than MRP.'}), 400
        
    if stock < 0 or quantity <= 0 or discount < 0 or gst < 0 or cost_price < 0:
        return jsonify({'success': False, 'message': 'Values cannot be negative.'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify product exists
    cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    if not product:
        conn.close()
        return jsonify({'success': False, 'message': 'Product not found.'}), 404
        
    # Check uniqueness of product code
    cursor.execute('SELECT id FROM products WHERE product_code = ? AND id != ?', (product_code, product_id))
    if cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': f'Product code "{product_code}" is already in use.'}), 409

    # Handle image update
    image_path = product['image_path']
    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename != '':
            if not allowed_file(file.filename):
                conn.close()
                return jsonify({'success': False, 'message': 'Invalid file format.'}), 400
                
            # Delete old image if it exists
            if product['image_path']:
                old_file_path = os.path.join(app.root_path, product['image_path'].lstrip('/'))
                if os.path.exists(old_file_path):
                    try:
                        os.remove(old_file_path)
                    except Exception:
                        pass
                        
            # Save new image
            extension = file.filename.rsplit('.', 1)[1].lower()
            secure_name = f"{uuid.uuid4()}.{extension}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], secure_name))
            image_path = f"/static/uploads/products/{secure_name}"

    try:
        cursor.execute('''
            UPDATE products 
            SET product_code = ?, name = ?, description = ?, image_path = ?, stock = ?, quantity = ?, selling_price = ?, cost_price = ?, mrp = ?, discount = ?, gst = ?, sizes = ?, category = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (product_code, name, description or None, image_path, stock, quantity, selling_price, cost_price, mrp, discount, gst, sizes or 'Free Size', category, product_id))
        conn.commit()
        conn.close()
        
        log_audit_event(session['user_id'], session['username'], session['role'], 'PRODUCT_UPDATED', request.remote_addr, f"Updated product: {product_code}")
        return jsonify({'success': True, 'message': 'Product updated successfully.'})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

@app.route('/api/admin/products/<int:product_id>', methods=['DELETE'])
@login_required(allowed_role='ADMIN')
def api_delete_product(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify product exists
    cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    if not product:
        conn.close()
        return jsonify({'success': False, 'message': 'Product not found.'}), 404
        
    # Delete image file from disk
    if product['image_path']:
        file_path = os.path.join(app.root_path, product['image_path'].lstrip('/'))
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass
                
    try:
        cursor.execute('DELETE FROM products WHERE id = ?', (product_id,))
        conn.commit()
        conn.close()
        
        log_audit_event(session['user_id'], session['username'], session['role'], 'PRODUCT_DELETED', request.remote_addr, f"Deleted product: {product['product_code']}")
        return jsonify({'success': True, 'message': 'Product deleted successfully.'})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500


# Cashier Product Catalog API (Read-only access)

@app.route('/api/cashier/products', methods=['GET'])
@login_required(allowed_role='CASHIER')
def api_cashier_get_products():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, product_code, name, description, image_path, stock, quantity, selling_price, mrp, discount, gst, sizes, category FROM products ORDER BY id DESC')
    products = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(products)

@app.route('/api/settings', methods=['GET'])
@login_required()
def api_get_settings():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT key, value FROM settings')
    settings = {row['key']: row['value'] for row in cursor.fetchall()}
    conn.close()
    return jsonify(settings)

@app.route('/api/admin/settings', methods=['POST'])
@login_required(allowed_role='ADMIN')
def api_update_settings():
    low_stock_threshold = request.json.get('low_stock_threshold', '5').strip()
    try:
        val = int(low_stock_threshold)
        if val <= 0:
            raise ValueError()
    except ValueError:
        return jsonify({'success': False, 'message': 'Low stock threshold must be a positive integer.'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', ('low_stock_threshold', str(val)))
    conn.commit()
    conn.close()
    
    log_audit_event(session['user_id'], session['username'], session['role'], 'SETTINGS_UPDATED', request.remote_addr, f"Updated low stock threshold to {val}")
    return jsonify({'success': True, 'message': 'Settings updated successfully.'})


# Admin Metrics, Security and Audit Log API Endpoints

@app.route('/api/admin/metrics', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_admin_metrics():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM users WHERE role = "CASHIER"')
    total_cashiers = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM users WHERE role = "CASHIER" AND status = "ACTIVE"')
    active_cashiers = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM users WHERE role = "CASHIER" AND status = "INACTIVE"')
    inactive_cashiers = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE action = 'LOGIN_FAILED' AND timestamp >= datetime('now', '-1 day')")
    failed_logins_24h = cursor.fetchone()[0]
    
    cursor.execute("SELECT two_factor_secret FROM users WHERE id = ?", (session['user_id'],))
    row = cursor.fetchone()
    mfa_status = "Enabled" if row and row['two_factor_secret'] else "Disabled"
    
    conn.close()
    
    return jsonify({
        'total_cashiers': total_cashiers,
        'active_cashiers': active_cashiers,
        'inactive_cashiers': inactive_cashiers,
        'failed_logins_24h': failed_logins_24h,
        'mfa_status': mfa_status
    })

@app.route('/api/admin/audit-logs', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_admin_audit_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, username, role, action, ip_address, details FROM audit_logs ORDER BY timestamp DESC LIMIT 100')
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(logs)

@app.route('/api/admin/security/2fa/setup', methods=['POST'])
@login_required(allowed_role='ADMIN')
def api_setup_2fa():
    secret = generate_totp_secret()
    session['temp_totp_secret'] = secret
    return jsonify({'success': True, 'secret': secret})

@app.route('/api/admin/security/2fa/verify', methods=['POST'])
@login_required(allowed_role='ADMIN')
def api_verify_setup_2fa():
    data = request.get_json() or {}
    token = data.get('token', '').strip()
    
    secret = session.get('temp_totp_secret')
    if not secret:
        return jsonify({'success': False, 'message': '2FA setup session expired. Please request a new secret.'}), 400
        
    if not verify_totp(secret, token):
        return jsonify({'success': False, 'message': 'Invalid verification code. Please check your authenticator app.'}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET two_factor_secret = ? WHERE id = ?', (secret, session['user_id']))
    conn.commit()
    conn.close()
    
    session.pop('temp_totp_secret', None)
    log_audit_event(session['user_id'], session['username'], session['role'], '2FA_ENABLED', request.remote_addr, 'Admin enabled two-factor authentication')
    return jsonify({'success': True, 'message': 'Two-factor authentication successfully enabled!'})

@app.route('/api/admin/security/2fa/disable', methods=['POST'])
@login_required(allowed_role='ADMIN')
def api_disable_2fa():
    data = request.get_json() or {}
    password = data.get('password', '')
    
    if not password:
        return jsonify({'success': False, 'message': 'Password is required to disable 2FA.'}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    
    if not user or not verify_password(user['password_hash'], password):
        conn.close()
        log_audit_event(session['user_id'], session['username'], session['role'], '2FA_DISABLE_FAILED', request.remote_addr, 'Incorrect password attempt to disable 2FA')
        return jsonify({'success': False, 'message': 'Incorrect password.'}), 401
        
    cursor.execute('UPDATE users SET two_factor_secret = NULL WHERE id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    
    log_audit_event(session['user_id'], session['username'], session['role'], '2FA_DISABLED', request.remote_addr, 'Admin disabled two-factor authentication')
    return jsonify({'success': True, 'message': 'Two-factor authentication successfully disabled.'})

@app.route('/api/admin/security/change-password', methods=['POST'])
@login_required(allowed_role='ADMIN')
def api_admin_change_password():
    data = request.get_json() or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not current_password or not new_password:
        return jsonify({'success': False, 'message': 'Current and new passwords are required.'}), 400
        
    if not is_password_complex(new_password):
        return jsonify({
            'success': False, 
            'message': 'New password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
        }), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    
    if not user or not verify_password(user['password_hash'], current_password):
        conn.close()
        log_audit_event(session['user_id'], session['username'], session['role'], 'PASSWORD_CHANGE_FAILED', request.remote_addr, 'Admin incorrect current password attempt')
        return jsonify({'success': False, 'message': 'Incorrect current password.'}), 401
        
    cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hash_password(new_password), session['user_id']))
    conn.commit()
    conn.close()
    
    log_audit_event(session['user_id'], session['username'], session['role'], 'PASSWORD_CHANGED', request.remote_addr, 'Admin password changed')
    return jsonify({'success': True, 'message': 'Password updated successfully.'})


# Cashier Dashboard and Actions API Endpoints

@app.route('/api/cashier/change-password', methods=['POST'])
@login_required(allowed_role='CASHIER')
def api_cashier_change_password():
    data = request.get_json() or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not current_password or not new_password:
        return jsonify({'success': False, 'message': 'Current and new passwords are required.'}), 400
        
    if not is_password_complex(new_password):
        return jsonify({
            'success': False, 
            'message': 'New password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
        }), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    
    if not user or not verify_password(user['password_hash'], current_password):
        conn.close()
        log_audit_event(session['user_id'], session['username'], session['role'], 'PASSWORD_CHANGE_FAILED', request.remote_addr, 'Cashier incorrect current password attempt')
        return jsonify({'success': False, 'message': 'Incorrect current password.'}), 401
        
    cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hash_password(new_password), session['user_id']))
    conn.commit()
    conn.close()
    
    log_audit_event(session['user_id'], session['username'], session['role'], 'PASSWORD_CHANGED', request.remote_addr, 'Cashier password changed')
    return jsonify({'success': True, 'message': 'Password updated successfully.'})

@app.route('/api/cashier/mock-stats', methods=['GET'])
@login_required(allowed_role='CASHIER')
def api_cashier_mock_stats():
    import random
    
    # Use user_id as seed to make shift stats consistent per user, but dynamic
    random.seed(session['user_id'])
    transactions_count = random.randint(12, 45)
    total_sales = round(sum(random.uniform(15.0, 95.0) for _ in range(transactions_count)), 2)
    
    items = [
        "Slim Fit Jeans", "Denim Jacket", "Formal Cotton Shirt", "Summer Floral Dress",
        "Polo T-Shirt", "Chino Trousers", "Leather Belt", "Sneaker Shoes",
        "Printed Kurti", "Casual Blazer", "Cargo Pants", "Socks (Pair)"
    ]
    payment_methods = ["Cash", "Card", "UPI"]
    
    # Generate mock transactions based on dynamic window
    mock_sales = []
    # Seed based on current hour to rotate list throughout the day
    random.seed(int(time.time()) // 3600 + session['user_id'])
    for i in range(6):
        tid = f"TXN{random.randint(100000, 999999)}"
        item = random.choice(items)
        amt = round(random.uniform(10.0, 120.0), 2)
        pm = random.choice(payment_methods)
        ts = time.time() - (i * random.randint(300, 2400))
        formatted_ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
        mock_sales.append({
            'txn_id': tid,
            'item': item,
            'amount': amt,
            'payment_method': pm,
            'timestamp': formatted_ts
        })
        
    return jsonify({
        'transactions_count': transactions_count,
        'total_sales': total_sales,
        'mock_sales': mock_sales
    })

# Customer CRM Lookup Endpoint (with Auto-Detected Store Credit Notes & VIP Tier)
@app.route('/api/pos/customer-lookup', methods=['GET'])
@login_required()
def api_customer_lookup():
    mobile = request.args.get('mobile', '').strip()
    if not mobile:
        return jsonify({'found': False, 'message': 'Mobile number required.'}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM customers WHERE mobile = ?', (mobile,))
    cust = cursor.fetchone()
    
    # Check for active store credit notes for this customer phone
    cursor.execute('SELECT code, balance, amount AS original_amount FROM credit_notes WHERE customer_mobile = ? AND balance > 0 AND status = "ACTIVE" ORDER BY id DESC', (mobile,))
    active_credits = [dict(r) for r in cursor.fetchall()]

    if cust:
        cursor.execute('SELECT bill_no, total, timestamp FROM sales WHERE customer_mobile = ? ORDER BY id DESC LIMIT 3', (mobile,))
        recent_bills = [dict(r) for r in cursor.fetchall()]
        
        # Calculate Membership Tier
        spent = cust['total_spent'] or 0.0
        visits = cust['visit_count'] or 0
        if spent >= 5000 or visits >= 5:
            tier = '👑 VIP Gold Member'
        elif spent >= 2000 or visits >= 2:
            tier = '🥈 Silver Member'
        else:
            tier = '✨ Welcome Member'

        conn.close()
        return jsonify({
            'found': True,
            'customer': {
                'id': cust['id'],
                'name': cust['name'],
                'mobile': cust['mobile'],
                'loyalty_points': cust['loyalty_points'],
                'total_spent': spent,
                'visit_count': visits,
                'tier': tier
            },
            'recent_bills': recent_bills,
            'active_credit_notes': active_credits
        })
    else:
        conn.close()
        return jsonify({
            'found': False, 
            'message': 'New Customer',
            'active_credit_notes': active_credits
        })

# POS Real Database Checkout and Stock Deduction Endpoint
@app.route('/api/pos/checkout', methods=['POST'])
@login_required()
def api_pos_checkout():
    data = request.get_json() or {}
    cart = data.get('cart', [])
    payment_mode = str(data.get('payment_mode') or 'CASH').strip().upper()
    split_payment = data.get('split_payment')
    customer_name = str(data.get('customer_name') or '').strip() or 'Walk-in Customer'
    customer_mobile = str(data.get('customer_mobile') or '').strip() or None
    coupon_code = str(data.get('coupon_code') or '').strip().upper() or None
    salesperson = str(data.get('salesperson') or '').strip() or 'General Staff'
    redeem_loyalty_points = int(data.get('redeem_loyalty_points') or 0)
    credit_note_code = str(data.get('credit_note_code') or '').strip().upper() or None
    
    if not cart:
        return jsonify({'success': False, 'message': 'Cart is empty.'}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Validate stock count availability for all items first
    resolved_cart = []
    for item in cart:
        product_id = item.get('id')
        product_code = item.get('product_code')
        qty = int(item.get('qty', 1))
        
        if product_id:
            cursor.execute('SELECT id, stock, name, product_code, selling_price FROM products WHERE id = ?', (product_id,))
        elif product_code:
            cursor.execute('SELECT id, stock, name, product_code, selling_price FROM products WHERE product_code = ?', (product_code,))
        else:
            conn.close()
            return jsonify({'success': False, 'message': 'Product identifier missing.'}), 400

        prod = cursor.fetchone()
        if not prod:
            conn.close()
            return jsonify({'success': False, 'message': f"Product '{product_code or product_id}' not found in system."}), 404
            
        if prod['stock'] < qty:
            conn.close()
            return jsonify({'success': False, 'message': f"Insufficient stock for '{prod['name']}'. Only {prod['stock']} available."}), 400

        resolved_cart.append({
            'id': prod['id'],
            'product_code': prod['product_code'],
            'name': prod['name'],
            'price': float(item.get('price', prod['selling_price'])),
            'qty': qty,
            'selectedSize': item.get('selectedSize', 'Free Size')
        })
            
    # 2. Compute prices and apply discounts
    subtotal = 0.0
    for item in resolved_cart:
        subtotal += item['price'] * item['qty']
        
    discount_percent = float(data.get('discount_percent', 0) or 0)
    discount_amount = 0.0
    if discount_percent > 0:
        discount_amount = round(subtotal * (min(100.0, discount_percent) / 100.0), 2)
    elif coupon_code == 'FESTIVE10':
        discount_amount = round(subtotal * 0.10, 2)
    elif coupon_code == 'WELCOME500':
        if subtotal >= 1000:
            discount_amount = 500.0
        else:
            conn.close()
            return jsonify({'success': False, 'message': 'WELCOME500 requires a minimum order subtotal of ₹1000.'}), 400
            
    taxable_amount = max(0.0, subtotal - discount_amount)
    tax = round(taxable_amount * 0.05, 2) # 5% GST
    gross_total = round(taxable_amount + tax, 2)
    
    # 3. Handle Loyalty Points discount (1 pt = ₹1)
    loyalty_discount = 0.0
    customer_rec = None
    if customer_mobile:
        cursor.execute('SELECT * FROM customers WHERE mobile = ?', (customer_mobile,))
        customer_rec = cursor.fetchone()
        if redeem_loyalty_points > 0 and customer_rec:
            available_pts = customer_rec['loyalty_points']
            usable_pts = min(available_pts, redeem_loyalty_points, int(gross_total))
            loyalty_discount = float(usable_pts)
            
    # 4. Handle Credit Note discount
    credit_amount_used = 0.0
    if credit_note_code:
        cursor.execute('SELECT * FROM credit_notes WHERE code = ? AND status = "ACTIVE"', (credit_note_code,))
        cn_row = cursor.fetchone()
        if cn_row:
            rem_after_loyalty = gross_total - loyalty_discount
            credit_amount_used = min(float(cn_row['balance']), rem_after_loyalty)
        else:
            conn.close()
            return jsonify({'success': False, 'message': f"Credit Note '{credit_note_code}' is invalid or expired."}), 400

    total = round(gross_total - loyalty_discount - credit_amount_used, 2)
    if total < 0:
        total = 0.0
        
    points_earned = int(subtotal // 100)
    bill_no = f"INV-{time.strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
    
    try:
        # Deduct stock for all items and log SALE transaction in stock_transactions
        for item in resolved_cart:
            cursor.execute('SELECT stock, cost_price, name, product_code FROM products WHERE id = ?', (item['id'],))
            prod_info = cursor.fetchone()
            curr_stock = prod_info['stock'] if prod_info else 0
            c_price = prod_info['cost_price'] if prod_info else 0.0
            new_stock = curr_stock - item['qty']
            
            cursor.execute('UPDATE products SET stock = ? WHERE id = ?', (new_stock, item['id']))
            cursor.execute('''
                INSERT INTO stock_transactions (product_id, product_code, product_name, transaction_type, quantity, cost_price, selling_price, stock_before, stock_after, notes, operator)
                VALUES (?, ?, ?, 'SALE', ?, ?, ?, ?, ?, ?, ?)
            ''', (item['id'], item['product_code'], item['name'], item['qty'], c_price, item['price'], curr_stock, new_stock, f"POS Bill: {bill_no}", session.get('username')))
            
        # Insert sale record
        split_json_str = json.dumps(split_payment) if split_payment else None
        cursor.execute('''
            INSERT INTO sales (bill_no, customer_name, customer_mobile, payment_mode, subtotal, tax, discount_amount, coupon_code, total, operator, split_payment_json, salesperson, loyalty_points_earned, loyalty_points_used, credit_note_used, credit_amount_used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (bill_no, customer_name, customer_mobile, payment_mode, subtotal, tax, discount_amount + loyalty_discount + credit_amount_used, coupon_code, total, session.get('username'), split_json_str, salesperson, points_earned, int(loyalty_discount), credit_note_code, credit_amount_used))
        
        sale_id = cursor.lastrowid
        
        # Insert sale items
        for item in cart:
            cursor.execute('''
                INSERT INTO sale_items (sale_id, product_code, product_name, size, price, qty)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (sale_id, item.get('product_code'), item.get('name'), item.get('selectedSize', 'Free Size'), float(item.get('price', 0)), int(item.get('qty', 1))))
            
        # Update or create Customer CRM profile
        if customer_mobile:
            if customer_rec:
                new_points = customer_rec['loyalty_points'] - int(loyalty_discount) + points_earned
                new_spent = customer_rec['total_spent'] + total
                new_visits = customer_rec['visit_count'] + 1
                cursor.execute('''
                    UPDATE customers 
                    SET name = ?, loyalty_points = ?, total_spent = ?, visit_count = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (customer_name or customer_rec['name'], new_points, new_spent, new_visits, customer_rec['id']))
            else:
                cursor.execute('''
                    INSERT INTO customers (name, mobile, loyalty_points, total_spent, visit_count)
                    VALUES (?, ?, ?, ?, 1)
                ''', (customer_name, customer_mobile, points_earned, total))

        # Update Credit Note balance if used
        if credit_note_code and credit_amount_used > 0:
            cursor.execute('UPDATE credit_notes SET balance = balance - ? WHERE code = ?', (credit_amount_used, credit_note_code))
            cursor.execute('UPDATE credit_notes SET status = "REDEEMED" WHERE code = ? AND balance <= 0', (credit_note_code,))
            
        conn.commit()
        conn.close()
        
        log_audit_event(session['user_id'], session['username'], session['role'], 'POS_TRANSACTION_COMPLETED', request.remote_addr, f"Completed checkout: {bill_no} (Total: ₹{total}, Mode: {payment_mode})")
        return jsonify({
            'success': True,
            'message': 'Transaction completed successfully.',
            'bill_no': bill_no,
            'customer_name': customer_name,
            'customer_mobile': customer_mobile,
            'subtotal': subtotal,
            'tax': tax,
            'discount': discount_amount,
            'loyalty_discount': loyalty_discount,
            'credit_discount': credit_amount_used,
            'points_earned': points_earned,
            'total': total,
            'payment_mode': payment_mode,
            'split_payment': split_payment,
            'salesperson': salesperson,
            'cart': cart,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'success': False, 'message': f'Server error processing transaction: {str(e)}'}), 500

# Sales & Return Lookup Endpoint
@app.route('/api/pos/sales-lookup', methods=['GET'])
@login_required()
def api_sales_lookup():
    query = request.args.get('query', '').strip()
    if not query:
        return jsonify({'success': False, 'message': 'Invoice number or mobile required.'}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.*, 
               (SELECT json_group_array(json_object('product_code', si.product_code, 'product_name', si.product_name, 'size', si.size, 'price', si.price, 'qty', si.qty)) FROM sale_items si WHERE si.sale_id = s.id) as items_json
        FROM sales s 
        WHERE s.bill_no = ? OR s.customer_mobile = ?
        ORDER BY s.id DESC LIMIT 5
    ''', (query, query))
    rows = cursor.fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d['items'] = json.loads(d['items_json']) if d.get('items_json') else []
        results.append(d)
    conn.close()
    return jsonify({'success': True, 'sales': results})

# Return / Exchange Processing Endpoint
@app.route('/api/pos/return-item', methods=['POST'])
@login_required()
def api_process_return():
    data = request.get_json() or {}
    original_bill_no = str(data.get('bill_no') or '').strip()
    product_code = str(data.get('product_code') or '').strip()
    qty = int(data.get('qty') or 1)
    size = str(data.get('size') or 'Free Size').strip()
    reason = str(data.get('reason') or 'Size Exchange').strip()
    refund_mode = str(data.get('refund_mode') or 'CREDIT_NOTE').strip().upper()
    
    if not original_bill_no or not product_code or qty <= 0:
        return jsonify({'success': False, 'message': 'Original bill, product, and valid qty required.'}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM sales WHERE bill_no = ?', (original_bill_no,))
    sale = cursor.fetchone()
    if not sale:
        conn.close()
        return jsonify({'success': False, 'message': 'Original sale not found.'}), 404
        
    cursor.execute('SELECT * FROM sale_items WHERE sale_id = ? AND product_code = ?', (sale['id'], product_code))
    item = cursor.fetchone()
    if not item:
        conn.close()
        return jsonify({'success': False, 'message': 'Item not found in this sale invoice.'}), 404
        
    item_price = float(item['price'])
    refund_amount = round(item_price * qty, 2)
    return_no = f"RET-{time.strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
    credit_note_code = None
    
    try:
        # Fetch current product details
        cursor.execute('SELECT id, stock, cost_price, name FROM products WHERE product_code = ?', (product_code,))
        prod_row = cursor.fetchone()
        curr_stk = prod_row['stock'] if prod_row else 0
        c_price = prod_row['cost_price'] if prod_row else 0.0
        p_id = prod_row['id'] if prod_row else None
        p_name = prod_row['name'] if prod_row else item['product_name']
        new_stk = curr_stk + qty

        # Restock product into catalog
        cursor.execute('UPDATE products SET stock = ? WHERE product_code = ?', (new_stk, product_code))
        
        # Log stock transaction for return
        cursor.execute('''
            INSERT INTO stock_transactions (product_id, product_code, product_name, transaction_type, quantity, cost_price, selling_price, stock_before, stock_after, notes, operator)
            VALUES (?, ?, ?, 'RETURN', ?, ?, ?, ?, ?, ?, ?)
        ''', (p_id, product_code, p_name, qty, c_price, item_price, curr_stk, new_stk, f"Customer Return: {return_no} (Bill: {original_bill_no})", session.get('username')))
        
        # Issue Credit Note if chosen
        if refund_mode == 'CREDIT_NOTE':
            credit_note_code = f"CR-{uuid.uuid4().hex[:6].upper()}"
            cursor.execute('''
                INSERT INTO credit_notes (code, amount, balance, customer_mobile, customer_name, reason)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (credit_note_code, refund_amount, refund_amount, sale['customer_mobile'], sale['customer_name'], reason))
            
        cursor.execute('''
            INSERT INTO returns (return_no, original_bill_no, customer_name, customer_mobile, product_code, product_name, size, qty, refund_amount, refund_mode, credit_note_code, reason, operator)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (return_no, original_bill_no, sale['customer_name'], sale['customer_mobile'], product_code, item['product_name'], size, qty, refund_amount, refund_mode, credit_note_code, reason, session.get('username')))
        
        conn.commit()
        conn.close()
        
        log_audit_event(session['user_id'], session['username'], session['role'], 'RETURN_PROCESSED', request.remote_addr, f"Processed return {return_no} for {original_bill_no}: ₹{refund_amount}")
        return jsonify({
            'success': True,
            'message': 'Return processed successfully and stock replenished.',
            'return_no': return_no,
            'refund_amount': refund_amount,
            'refund_mode': refund_mode,
            'credit_note_code': credit_note_code
        })
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

# Validate Credit Note Endpoint
@app.route('/api/pos/validate-credit-note', methods=['GET'])
@login_required()
def api_validate_credit_note():
    code = request.args.get('code', '').strip().upper()
    if not code:
        return jsonify({'valid': False, 'message': 'Code required.'}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM credit_notes WHERE code = ? AND status = "ACTIVE"', (code,))
    cn = cursor.fetchone()
    conn.close()
    if cn and cn['balance'] > 0:
        return jsonify({
            'valid': True,
            'code': cn['code'],
            'balance': cn['balance'],
            'customer_name': cn['customer_name'],
            'customer_mobile': cn['customer_mobile']
        })
    return jsonify({'valid': False, 'message': 'Credit note is invalid or fully redeemed.'})

# Expenses Endpoints
@app.route('/api/admin/expenses', methods=['GET', 'POST'])
@login_required(allowed_role='ADMIN')
def api_admin_expenses():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        data = request.get_json() or {}
        category = data.get('category', 'Miscellaneous').strip()
        try:
            amount = float(data.get('amount', 0))
            if amount <= 0: raise ValueError()
        except ValueError:
            conn.close()
            return jsonify({'success': False, 'message': 'Valid positive expense amount required.'}), 400
            
        description = data.get('description', '').strip()
        expense_date = data.get('expense_date', '').strip() or time.strftime('%Y-%m-%d')
        
        cursor.execute('''
            INSERT INTO expenses (category, amount, description, expense_date, recorded_by)
            VALUES (?, ?, ?, ?, ?)
        ''', (category, amount, description, expense_date, session.get('username')))
        conn.commit()
        conn.close()
        
        log_audit_event(session['user_id'], session['username'], session['role'], 'EXPENSE_RECORDED', request.remote_addr, f"Recorded expense {category}: ₹{amount}")
        return jsonify({'success': True, 'message': 'Expense recorded successfully.'}), 201
        
    cursor.execute('SELECT * FROM expenses ORDER BY expense_date DESC, id DESC')
    expenses = [dict(r) for r in cursor.fetchall()]
    
    cursor.execute('SELECT SUM(amount) FROM expenses')
    total_expenses = cursor.fetchone()[0] or 0.0
    
    cursor.execute('SELECT category, SUM(amount) FROM expenses GROUP BY category')
    cat_summary = {r[0]: r[1] for r in cursor.fetchall()}
    
    conn.close()
    return jsonify({
        'expenses': expenses,
        'total_expenses': total_expenses,
        'category_summary': cat_summary
    })

@app.route('/api/admin/expenses/<int:expense_id>', methods=['DELETE'])
@login_required(allowed_role='ADMIN')
def api_delete_expense(expense_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM expenses WHERE id = ?', (expense_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Expense deleted.'})

# Suppliers Endpoints
@app.route('/api/admin/suppliers', methods=['GET', 'POST'])
@login_required(allowed_role='ADMIN')
def api_admin_suppliers():
    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == 'POST':
        data = request.get_json() or {}
        name = data.get('name', '').strip()
        contact_person = data.get('contact_person', '').strip()
        phone = data.get('phone', '').strip()
        email = data.get('email', '').strip()
        city = data.get('city', '').strip()
        gstin = data.get('gstin', '').strip()
        
        if not name:
            conn.close()
            return jsonify({'success': False, 'message': 'Supplier company name is required.'}), 400
            
        cursor.execute('''
            INSERT INTO suppliers (name, contact_person, phone, email, city, gstin)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, contact_person, phone, email, city, gstin))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Supplier registered successfully.'}), 201
        
    cursor.execute('SELECT * FROM suppliers WHERE status = "ACTIVE" ORDER BY id DESC')
    suppliers = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(suppliers)

# Purchases & Stock Inward Endpoints
@app.route('/api/admin/purchases', methods=['GET', 'POST'])
@login_required(allowed_role='ADMIN')
def api_admin_purchases():
    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == 'POST':
        data = request.get_json() or {}
        invoice_no = data.get('invoice_no', '').strip()
        supplier_id = data.get('supplier_id')
        supplier_name = data.get('supplier_name', '').strip()
        purchase_date = data.get('purchase_date', '').strip() or time.strftime('%Y-%m-%d')
        notes = data.get('notes', '').strip()
        items = data.get('items', [])
        
        if not invoice_no or not supplier_name or not items:
            conn.close()
            return jsonify({'success': False, 'message': 'Invoice No, Supplier, and at least 1 item are required.'}), 400
            
        total_amount = sum(float(it.get('cost_price', 0)) * int(it.get('quantity', 1)) for it in items)
        
        try:
            cursor.execute('''
                INSERT INTO purchases (invoice_no, supplier_id, supplier_name, total_amount, purchase_date, notes)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (invoice_no, supplier_id, supplier_name, total_amount, purchase_date, notes))
            purchase_id = cursor.lastrowid
            
            for it in items:
                p_code = it.get('product_code', '').strip().upper()
                p_name = it.get('product_name', '').strip()
                qty = int(it.get('quantity', 1))
                cost = float(it.get('cost_price', 0))
                
                cursor.execute('''
                    INSERT INTO purchase_items (purchase_id, product_code, product_name, quantity, cost_price)
                    VALUES (?, ?, ?, ?, ?)
                ''', (purchase_id, p_code, p_name, qty, cost))
                
                # Auto-increment product stock in inventory or create catalog item if new style
                cursor.execute('SELECT id, stock, cost_price, name, selling_price FROM products WHERE product_code = ?', (p_code,))
                existing_p = cursor.fetchone()
                if existing_p:
                    curr_stk = existing_p['stock']
                    c_price = cost if cost > 0 else (existing_p['cost_price'] or 0.0)
                    new_stk = curr_stk + qty
                    cursor.execute('UPDATE products SET stock = ?, cost_price = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (new_stk, c_price, existing_p['id']))
                    cursor.execute('''
                        INSERT INTO stock_transactions (product_id, product_code, product_name, transaction_type, quantity, cost_price, selling_price, stock_before, stock_after, supplier_name, notes, operator)
                        VALUES (?, ?, ?, 'RESTOCK', ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (existing_p['id'], p_code, p_name or existing_p['name'], qty, c_price, existing_p['selling_price'], curr_stk, new_stk, supplier_name, f"Wholesale Purchase Inv: {invoice_no}", session.get('username')))
                else:
                    selling = round(cost * 1.35, 2) if cost > 0 else 999.0
                    mrp = round(cost * 1.50, 2) if cost > 0 else 1299.0
                    cursor.execute('''
                        INSERT INTO products (product_code, name, description, stock, initial_stock, cost_price, quantity, selling_price, mrp, discount, gst, sizes, category)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (p_code, p_name or 'Ready-made Garment', 'Imported from Wholesale Purchase', qty, qty, cost, 1, selling, mrp, 0.0, 12.0, 'Free Size, S, M, L, XL', 'General'))
                    new_pid = cursor.lastrowid
                    cursor.execute('''
                        INSERT INTO stock_transactions (product_id, product_code, product_name, transaction_type, quantity, cost_price, selling_price, stock_before, stock_after, supplier_name, notes, operator)
                        VALUES (?, ?, ?, 'INITIAL', ?, ?, ?, 0, ?, ?, ?, ?)
                    ''', (new_pid, p_code, p_name or 'Ready-made Garment', qty, cost, selling, qty, supplier_name, f"Wholesale Purchase Inv: {invoice_no}", session.get('username')))
                
            conn.commit()
            conn.close()
            
            log_audit_event(session['user_id'], session['username'], session['role'], 'STOCK_INWARD_PURCHASE', request.remote_addr, f"Purchased stock from {supplier_name} (Invoice: {invoice_no}, Total: ₹{total_amount})")
            return jsonify({'success': True, 'message': 'Stock inward recorded and inventory updated successfully.'}), 201
        except Exception as e:
            conn.rollback()
            conn.close()
            return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500
            
    cursor.execute('''
        SELECT p.*,
               (SELECT json_group_array(json_object('product_code', pi.product_code, 'product_name', pi.product_name, 'quantity', pi.quantity, 'cost_price', pi.cost_price)) FROM purchase_items pi WHERE pi.purchase_id = p.id) as items_json
        FROM purchases p
        ORDER BY p.id DESC
    ''')
    rows = cursor.fetchall()
    purchases = []
    for r in rows:
        d = dict(r)
        d['items'] = json.loads(d['items_json']) if d.get('items_json') else []
        purchases.append(d)
    conn.close()
    return jsonify(purchases)

# Customers CRM Endpoint
@app.route('/api/admin/customers', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_admin_customers():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM customers ORDER BY total_spent DESC')
    custs = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(custs)

# Admin Sales Analytics and Net Profit Reports
@app.route('/api/admin/sales-analytics', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_sales_analytics():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Total Revenue
    cursor.execute('SELECT SUM(total) FROM sales')
    row = cursor.fetchone()
    total_revenue = row[0] if row and row[0] is not None else 0.0
    
    # 2. Total Expenses & Net Profit
    cursor.execute('SELECT SUM(amount) FROM expenses')
    row_exp = cursor.fetchone()
    total_expenses = row_exp[0] if row_exp and row_exp[0] is not None else 0.0
    net_profit = round(total_revenue - total_expenses, 2)
    
    # 3. Payment Methods counts
    cursor.execute('SELECT payment_mode, COUNT(*) FROM sales GROUP BY payment_mode')
    pm_rows = cursor.fetchall()
    payment_methods = {row[0]: row[1] for row in pm_rows}
    if 'CASH' not in payment_methods: payment_methods['CASH'] = 0
    if 'UPI' not in payment_methods: payment_methods['UPI'] = 0
    if 'CARD' not in payment_methods: payment_methods['CARD'] = 0
    if 'SPLIT' not in payment_methods: payment_methods['SPLIT'] = 0
    
    # 4. Top Selling Products
    cursor.execute('SELECT product_name, SUM(qty) as total_qty FROM sale_items GROUP BY product_name ORDER BY total_qty DESC LIMIT 5')
    ts_rows = cursor.fetchall()
    top_selling = [{'name': row[0], 'qty': row[1]} for row in ts_rows]
    
    # 5. Staff Sales Performance
    cursor.execute('SELECT salesperson, COUNT(*), SUM(total) FROM sales GROUP BY salesperson ORDER BY SUM(total) DESC')
    staff_rows = cursor.fetchall()
    staff_performance = [{'salesperson': r[0] or 'General Staff', 'count': r[1], 'total': round(r[2], 2)} for r in staff_rows]
    
    # 6. Recent Sales
    cursor.execute('SELECT bill_no, total, payment_mode, salesperson, timestamp FROM sales ORDER BY id DESC LIMIT 5')
    rs_rows = cursor.fetchall()
    recent_sales = [{'bill_no': row[0], 'total': row[1], 'payment_mode': row[2], 'salesperson': row[3] or 'General Staff', 'timestamp': row[4]} for row in rs_rows]
    
    # 7. Low Stock alerts (under threshold items)
    cursor.execute("SELECT value FROM settings WHERE key = 'low_stock_threshold'")
    setting_row = cursor.fetchone()
    threshold = int(setting_row[0]) if setting_row else 5
    
    cursor.execute('SELECT name, stock FROM products WHERE stock <= ?', (threshold,))
    ls_rows = cursor.fetchall()
    low_stock = [{'name': row[0], 'stock': row[1]} for row in ls_rows]
    
    conn.close()
    
    return jsonify({
        'total_revenue': total_revenue,
        'total_expenses': total_expenses,
        'net_profit': net_profit,
        'payment_methods': payment_methods,
        'top_selling': top_selling,
        'staff_performance': staff_performance,
        'recent_sales': recent_sales,
        'low_stock': low_stock
    })

# CSV Export: Sales and GST Tax
@app.route('/api/admin/export/sales-csv', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_export_sales_csv():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT bill_no, customer_name, customer_mobile, payment_mode, subtotal, tax, discount_amount, total, operator, salesperson, timestamp FROM sales ORDER BY id DESC')
    rows = cursor.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Invoice No', 'Customer Name', 'Mobile', 'Payment Mode', 'Taxable Subtotal (Rs)', 'GST 12% (Rs)', 'Discount (Rs)', 'Net Total (Rs)', 'Operator', 'Salesperson', 'Timestamp'])
    for r in rows:
        writer.writerow([r['bill_no'], r['customer_name'], r['customer_mobile'] or 'N/A', r['payment_mode'], r['subtotal'], r['tax'], r['discount_amount'], r['total'], r['operator'], r['salesperson'] or 'N/A', r['timestamp']])
        
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=Garments_Sales_Report_{time.strftime("%Y%m%d")}.csv'
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    return response

# CSV Export: Expenses
@app.route('/api/admin/export/expenses-csv', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_export_expenses_csv():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, category, amount, description, expense_date, recorded_by FROM expenses ORDER BY expense_date DESC')
    rows = cursor.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Expense ID', 'Category', 'Amount (Rs)', 'Description', 'Date', 'Recorded By'])
    for r in rows:
        writer.writerow([r['id'], r['category'], r['amount'], r['description'], r['expense_date'], r['recorded_by']])
        
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=Shop_Expenses_Report_{time.strftime("%Y%m%d")}.csv'
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    return response

# -------------------------------------------------------------
# Billing Management & Sales Reports Endpoints
# -------------------------------------------------------------

@app.route('/api/admin/billing-reports', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_admin_billing_reports():
    filter_type = request.args.get('filter', 'all').strip().lower()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    search = request.args.get('search', '').strip()
    payment_mode = request.args.get('payment_mode', '').strip().upper()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Today's Summary
    cursor.execute('''
        SELECT 
            COUNT(*) as count,
            COALESCE(SUM(total), 0) as total,
            COALESCE(SUM(subtotal), 0) as subtotal,
            COALESCE(SUM(tax), 0) as tax,
            COALESCE(SUM(discount_amount), 0) as discount,
            COALESCE(SUM(CASE WHEN payment_mode = 'CASH' THEN total ELSE 0 END), 0) as cash_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'UPI' THEN total ELSE 0 END), 0) as upi_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'CARD' THEN total ELSE 0 END), 0) as card_total
        FROM sales 
        WHERE date(timestamp) = date('now', 'localtime') OR date(timestamp) = date('now')
    ''')
    today_row = dict(cursor.fetchone())
    
    # 2. Yesterday's Summary
    cursor.execute('''
        SELECT 
            COUNT(*) as count,
            COALESCE(SUM(total), 0) as total,
            COALESCE(SUM(subtotal), 0) as subtotal,
            COALESCE(SUM(tax), 0) as tax,
            COALESCE(SUM(discount_amount), 0) as discount,
            COALESCE(SUM(CASE WHEN payment_mode = 'CASH' THEN total ELSE 0 END), 0) as cash_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'UPI' THEN total ELSE 0 END), 0) as upi_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'CARD' THEN total ELSE 0 END), 0) as card_total
        FROM sales 
        WHERE date(timestamp) = date('now', 'localtime', '-1 day') OR date(timestamp) = date('now', '-1 day')
    ''')
    yesterday_row = dict(cursor.fetchone())

    # 3. All-Time Total Summary
    cursor.execute('''
        SELECT 
            COUNT(*) as count,
            COALESCE(SUM(total), 0) as total,
            COALESCE(SUM(subtotal), 0) as subtotal,
            COALESCE(SUM(tax), 0) as tax,
            COALESCE(SUM(discount_amount), 0) as discount,
            COALESCE(SUM(CASE WHEN payment_mode = 'CASH' THEN total ELSE 0 END), 0) as cash_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'UPI' THEN total ELSE 0 END), 0) as upi_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'CARD' THEN total ELSE 0 END), 0) as card_total
        FROM sales
    ''')
    all_time_row = dict(cursor.fetchone())
    all_time_row['avg_bill'] = round(all_time_row['total'] / all_time_row['count'], 2) if all_time_row['count'] > 0 else 0.0

    today_sales_amt = float(today_row.get('total', 0) or 0)
    yest_sales_amt = float(yesterday_row.get('total', 0) or 0)
    growth_percent = round(((today_sales_amt - yest_sales_amt) / yest_sales_amt) * 100, 1) if yest_sales_amt > 0 else (100.0 if today_sales_amt > 0 else 0.0)
    
    # 4. Dynamic filter conditions
    query_conditions = []
    params = []
    
    if filter_type == 'today':
        query_conditions.append("(date(timestamp) = date('now', 'localtime') OR date(timestamp) = date('now'))")
    elif filter_type == 'yesterday':
        query_conditions.append("(date(timestamp) = date('now', 'localtime', '-1 day') OR date(timestamp) = date('now', '-1 day'))")
    elif filter_type in ('this_week', 'week', '7days', 'last_7_days'):
        query_conditions.append("date(timestamp) >= date('now', 'localtime', '-7 days')")
    elif filter_type in ('this_month', 'month'):
        query_conditions.append("strftime('%Y-%m', timestamp) = strftime('%Y-%m', 'now', 'localtime')")
    elif filter_type == 'custom' and start_date and end_date:
        query_conditions.append("date(timestamp) BETWEEN ? AND ?")
        params.extend([start_date, end_date])
    elif start_date and end_date:
        query_conditions.append("date(timestamp) BETWEEN ? AND ?")
        params.extend([start_date, end_date])
    elif start_date:
        query_conditions.append("date(timestamp) >= ?")
        params.append(start_date)
    elif end_date:
        query_conditions.append("date(timestamp) <= ?")
        params.append(end_date)
        
    if payment_mode and payment_mode != 'ALL':
        query_conditions.append("payment_mode = ?")
        params.append(payment_mode)
        
    if search:
        search_pattern = f"%{search}%"
        query_conditions.append("(bill_no LIKE ? OR customer_name LIKE ? OR customer_mobile LIKE ? OR operator LIKE ? OR salesperson LIKE ?)")
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern, search_pattern])
        
    where_clause = f"WHERE {' AND '.join(query_conditions)}" if query_conditions else ""
    
    # Period Summary
    period_summary_sql = f'''
        SELECT 
            COUNT(*) as count,
            COALESCE(SUM(total), 0) as total,
            COALESCE(SUM(subtotal), 0) as subtotal,
            COALESCE(SUM(tax), 0) as tax,
            COALESCE(SUM(discount_amount), 0) as discount,
            COALESCE(SUM(CASE WHEN payment_mode = 'CASH' THEN total ELSE 0 END), 0) as cash_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'UPI' THEN total ELSE 0 END), 0) as upi_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'CARD' THEN total ELSE 0 END), 0) as card_total
        FROM sales
        {where_clause}
    '''
    cursor.execute(period_summary_sql, params)
    period_summary = dict(cursor.fetchone())
    period_summary['avg_bill'] = round(period_summary['total'] / period_summary['count'], 2) if period_summary['count'] > 0 else 0.0
    
    # Detailed bills query
    bills_sql = f'''
        SELECT 
            s.*,
            (SELECT json_group_array(json_object('product_name', si.product_name, 'product_code', si.product_code, 'size', si.size, 'price', si.price, 'qty', si.qty)) FROM sale_items si WHERE si.sale_id = s.id) as items_json,
            (SELECT COUNT(*) FROM sale_items si WHERE si.sale_id = s.id) as item_count,
            (SELECT COALESCE(SUM(si.qty), 0) FROM sale_items si WHERE si.sale_id = s.id) as total_units
        FROM sales s
        {where_clause}
        ORDER BY s.id DESC
    '''
    cursor.execute(bills_sql, params)
    rows = cursor.fetchall()
    bills = []
    for r in rows:
        d = dict(r)
        d['items'] = json.loads(d['items_json']) if d.get('items_json') else []
        bills.append(d)
        
    conn.close()
    
    return jsonify({
        'success': True,
        'today_summary': today_row,
        'yesterday_summary': yesterday_row,
        'all_time_summary': all_time_row,
        'growth_percent': growth_percent,
        'period_summary': period_summary,
        'filter': filter_type,
        'bills': bills
    })

@app.route('/api/pos/bill-details/<bill_no>', methods=['GET'])
@login_required()
def api_pos_bill_details(bill_no):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM sales WHERE bill_no = ?', (bill_no,))
    sale = cursor.fetchone()
    if not sale:
        conn.close()
        return jsonify({'success': False, 'message': 'Bill not found.'}), 404
        
    cursor.execute('SELECT * FROM sale_items WHERE sale_id = ?', (sale['id'],))
    items = [dict(r) for r in cursor.fetchall()]
    conn.close()
    
    sale_dict = dict(sale)
    sale_dict['items'] = items
    return jsonify({'success': True, 'bill': sale_dict})

@app.route('/api/cashier/bills-history', methods=['GET'])
@login_required(allowed_role='CASHIER')
def api_cashier_bills_history():
    filter_type = request.args.get('filter', 'today').strip().lower()
    search = request.args.get('search', '').strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Today's Summary
    cursor.execute('''
        SELECT 
            COUNT(*) as count,
            COALESCE(SUM(total), 0) as total,
            COALESCE(SUM(subtotal), 0) as subtotal,
            COALESCE(SUM(tax), 0) as tax,
            COALESCE(SUM(discount_amount), 0) as discount,
            COALESCE(SUM(CASE WHEN payment_mode = 'CASH' THEN total ELSE 0 END), 0) as cash_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'UPI' THEN total ELSE 0 END), 0) as upi_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'CARD' THEN total ELSE 0 END), 0) as card_total
        FROM sales 
        WHERE date(timestamp) = date('now', 'localtime') OR date(timestamp) = date('now')
    ''')
    today_row = dict(cursor.fetchone())
    
    # 2. Yesterday's Summary
    cursor.execute('''
        SELECT 
            COUNT(*) as count,
            COALESCE(SUM(total), 0) as total,
            COALESCE(SUM(subtotal), 0) as subtotal,
            COALESCE(SUM(tax), 0) as tax,
            COALESCE(SUM(discount_amount), 0) as discount,
            COALESCE(SUM(CASE WHEN payment_mode = 'CASH' THEN total ELSE 0 END), 0) as cash_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'UPI' THEN total ELSE 0 END), 0) as upi_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'CARD' THEN total ELSE 0 END), 0) as card_total
        FROM sales 
        WHERE date(timestamp) = date('now', 'localtime', '-1 day') OR date(timestamp) = date('now', '-1 day')
    ''')
    yesterday_row = dict(cursor.fetchone())

    # 3. All-time summary
    cursor.execute('''
        SELECT 
            COUNT(*) as count,
            COALESCE(SUM(total), 0) as total,
            COALESCE(SUM(subtotal), 0) as subtotal,
            COALESCE(SUM(tax), 0) as tax,
            COALESCE(SUM(discount_amount), 0) as discount,
            COALESCE(SUM(CASE WHEN payment_mode = 'CASH' THEN total ELSE 0 END), 0) as cash_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'UPI' THEN total ELSE 0 END), 0) as upi_total,
            COALESCE(SUM(CASE WHEN payment_mode = 'CARD' THEN total ELSE 0 END), 0) as card_total
        FROM sales
    ''')
    all_time_row = dict(cursor.fetchone())
    all_time_row['avg_bill'] = round(all_time_row['total'] / all_time_row['count'], 2) if all_time_row['count'] > 0 else 0.0

    query_conditions = []
    params = []
    
    if filter_type == 'today':
        query_conditions.append("(date(timestamp) = date('now', 'localtime') OR date(timestamp) = date('now'))")
    elif filter_type == 'yesterday':
        query_conditions.append("(date(timestamp) = date('now', 'localtime', '-1 day') OR date(timestamp) = date('now', '-1 day'))")
    elif filter_type == 'all':
        pass
    else:
        query_conditions.append("(date(timestamp) = date('now', 'localtime') OR date(timestamp) = date('now'))")
        
    if search:
        search_pattern = f"%{search}%"
        query_conditions.append("(bill_no LIKE ? OR customer_name LIKE ? OR customer_mobile LIKE ?)")
        params.extend([search_pattern, search_pattern, search_pattern])
        
    where_clause = f"WHERE {' AND '.join(query_conditions)}" if query_conditions else ""
    
    cursor.execute(f'''
        SELECT 
            s.*,
            (SELECT json_group_array(json_object('product_name', si.product_name, 'product_code', si.product_code, 'size', si.size, 'price', si.price, 'qty', si.qty)) FROM sale_items si WHERE si.sale_id = s.id) as items_json,
            (SELECT COUNT(*) FROM sale_items si WHERE si.sale_id = s.id) as item_count,
            (SELECT COALESCE(SUM(si.qty), 0) FROM sale_items si WHERE si.sale_id = s.id) as total_units
        FROM sales s
        {where_clause}
        ORDER BY s.id DESC
    ''', params)
    
    rows = cursor.fetchall()
    bills = []
    for r in rows:
        d = dict(r)
        d['items'] = json.loads(d['items_json']) if d.get('items_json') else []
        bills.append(d)
        
    conn.close()
    return jsonify({
        'success': True,
        'today_summary': today_row,
        'yesterday_summary': yesterday_row,
        'all_time_summary': all_time_row,
        'shift_stats': today_row,
        'bills': bills
    })

@app.route('/api/admin/export/billing-csv', methods=['GET'])
@app.route('/api/cashier/export/bills-csv', methods=['GET'])
@login_required()
def api_export_billing_csv():
    filter_type = request.args.get('filter', 'all').strip().lower()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query_conditions = []
    params = []
    
    if filter_type == 'today':
        query_conditions.append("(date(timestamp) = date('now', 'localtime') OR date(timestamp) = date('now'))")
    elif filter_type == 'yesterday':
        query_conditions.append("(date(timestamp) = date('now', 'localtime', '-1 day') OR date(timestamp) = date('now', '-1 day'))")
    elif filter_type in ('this_week', 'week', '7days', 'last_7_days'):
        query_conditions.append("date(timestamp) >= date('now', 'localtime', '-7 days')")
    elif filter_type in ('this_month', 'month'):
        query_conditions.append("strftime('%Y-%m', timestamp) = strftime('%Y-%m', 'now', 'localtime')")
    elif start_date and end_date:
        query_conditions.append("date(timestamp) BETWEEN ? AND ?")
        params.extend([start_date, end_date])
        
    where_clause = f"WHERE {' AND '.join(query_conditions)}" if query_conditions else ""
    
    cursor.execute(f'''
        SELECT bill_no, timestamp, customer_name, customer_mobile, payment_mode, subtotal, tax, discount_amount, total, operator, salesperson
        FROM sales
        {where_clause}
        ORDER BY id DESC
    ''', params)
    rows = cursor.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Invoice No', 'Date & Time', 'Customer Name', 'Customer Mobile', 'Payment Mode', 'Subtotal (Rs)', 'GST 5% (Rs)', 'Discount (Rs)', 'Grand Total (Rs)', 'Operator / Cashier', 'Salesperson'])
    for r in rows:
        writer.writerow([
            r['bill_no'],
            r['timestamp'],
            r['customer_name'] or 'Walk-in Customer',
            r['customer_mobile'] or 'N/A',
            r['payment_mode'],
            r['subtotal'],
            r['tax'],
            r['discount_amount'],
            r['total'],
            r['operator'],
            r['salesperson'] or 'N/A'
        ])
        
    filename = f"Garments_Billing_Report_{filter_type}_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    return response


# ==========================================
# Stock Valuation, Damages & ROI Analytics APIs
# ==========================================

@app.route('/api/admin/stock/valuation', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_admin_stock_valuation():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Fetch low stock threshold setting
    cursor.execute("SELECT value FROM settings WHERE key = 'low_stock_threshold'")
    row = cursor.fetchone()
    low_stock_threshold = int(row['value']) if row else 5
    
    # 2. Fetch all products with movement breakdown (Inward, Sold, Damaged)
    cursor.execute('''
        SELECT p.*,
               COALESCE((SELECT SUM(st.quantity) FROM stock_transactions st WHERE st.product_id = p.id AND st.transaction_type = 'RESTOCK'), 0) as restocked_qty,
               COALESCE((SELECT SUM(st.quantity) FROM stock_transactions st WHERE st.product_id = p.id AND st.transaction_type = 'SALE'), 0) as sold_qty,
               COALESCE((SELECT SUM(dr.quantity) FROM damage_records dr WHERE dr.product_id = p.id), 0) as damaged_qty,
               COALESCE((SELECT SUM(dr.net_loss) FROM damage_records dr WHERE dr.product_id = p.id), 0) as damage_loss,
               (SELECT MAX(s.timestamp) FROM sale_items si JOIN sales s ON si.sale_id = s.id WHERE si.product_code = p.product_code) as last_sale_date
        FROM products p
        ORDER BY p.id DESC
    ''')
    raw_products = cursor.fetchall()
    
    products = []
    total_stock_units = 0
    total_cost_val = 0.0
    total_retail_val = 0.0
    total_mrp_val = 0.0
    total_damaged_units = 0
    total_damage_loss = 0.0
    low_stock_list = []
    out_of_stock_list = []
    dead_stock_list = []
    categories = {}
    
    for r in raw_products:
        p = dict(r)
        c_price = float(p.get('cost_price') or round(p['selling_price'] * 0.65, 2))
        s_price = float(p.get('selling_price') or 0.0)
        mrp_price = float(p.get('mrp') or 0.0)
        stock_qty = int(p.get('stock') or 0)
        init_stock = int(p.get('initial_stock') or stock_qty)
        restocked_qty = int(p.get('restocked_qty') or 0)
        sold_qty = int(p.get('sold_qty') or 0)
        damaged_qty = int(p.get('damaged_qty') or 0)
        damage_loss = float(p.get('damage_loss') or 0.0)
        
        cost_val = round(stock_qty * c_price, 2)
        retail_val = round(stock_qty * s_price, 2)
        mrp_val = round(stock_qty * mrp_price, 2)
        profit = round(retail_val - cost_val, 2)
        margin_pct = round((profit / cost_val * 100), 1) if cost_val > 0 else 0.0
        
        status = 'OUT_OF_STOCK' if stock_qty <= 0 else ('LOW_STOCK' if stock_qty <= low_stock_threshold else 'IN_STOCK')
        
        # Stock aging & movement velocity
        if sold_qty >= 5:
            aging_status = 'FAST_MOVING'
        elif sold_qty >= 1:
            aging_status = 'SLOW_MOVING'
        else:
            aging_status = 'DEAD_STOCK'
            if stock_qty > 0:
                dead_stock_list.append(p)
                
        p['cost_price'] = c_price
        p['initial_stock'] = init_stock
        p['restocked_qty'] = restocked_qty
        p['sold_qty'] = sold_qty
        p['damaged_qty'] = damaged_qty
        p['damage_loss'] = damage_loss
        p['cost_valuation'] = cost_val
        p['retail_valuation'] = retail_val
        p['mrp_valuation'] = mrp_val
        p['potential_profit'] = profit
        p['margin_pct'] = margin_pct
        p['stock_status'] = status
        p['aging_status'] = aging_status
        
        total_stock_units += stock_qty
        total_cost_val += cost_val
        total_retail_val += retail_val
        total_mrp_val += mrp_val
        total_damaged_units += damaged_qty
        total_damage_loss += damage_loss
        
        if stock_qty <= 0:
            out_of_stock_list.append(p)
        elif stock_qty <= low_stock_threshold:
            low_stock_list.append(p)
            
        cat = p.get('category') or 'General'
        if cat not in categories:
            categories[cat] = {'category': cat, 'count': 0, 'stock': 0, 'cost_val': 0.0, 'retail_val': 0.0, 'profit': 0.0, 'damaged_qty': 0, 'damage_loss': 0.0}
        categories[cat]['count'] += 1
        categories[cat]['stock'] += stock_qty
        categories[cat]['cost_val'] += cost_val
        categories[cat]['retail_val'] += retail_val
        categories[cat]['profit'] += profit
        categories[cat]['damaged_qty'] += damaged_qty
        categories[cat]['damage_loss'] += damage_loss
        
        products.append(p)
        
    for cat in categories:
        categories[cat]['cost_val'] = round(categories[cat]['cost_val'], 2)
        categories[cat]['retail_val'] = round(categories[cat]['retail_val'], 2)
        categories[cat]['profit'] = round(categories[cat]['profit'], 2)
        categories[cat]['damage_loss'] = round(categories[cat]['damage_loss'], 2)
        
    total_cost_val = round(total_cost_val, 2)
    total_retail_val = round(total_retail_val, 2)
    total_mrp_val = round(total_mrp_val, 2)
    total_damage_loss = round(total_damage_loss, 2)
    potential_profit = round(total_retail_val - total_cost_val, 2)
    overall_margin = round((potential_profit / total_cost_val * 100), 1) if total_cost_val > 0 else 0.0
    net_asset_valuation = round(total_cost_val - total_damage_loss, 2)
    
    conn.close()
    
    return jsonify({
        'success': True,
        'summary': {
            'total_products': len(products),
            'total_stock_units': total_stock_units,
            'total_cost_valuation': total_cost_val,
            'total_retail_valuation': total_retail_val,
            'total_mrp_valuation': total_mrp_val,
            'potential_profit': potential_profit,
            'overall_margin_pct': overall_margin,
            'total_damaged_units': total_damaged_units,
            'total_damage_loss': total_damage_loss,
            'net_asset_valuation': net_asset_valuation,
            'low_stock_count': len(low_stock_list),
            'out_of_stock_count': len(out_of_stock_list),
            'dead_stock_count': len(dead_stock_list),
            'low_stock_threshold': low_stock_threshold
        },
        'category_valuation': list(categories.values()),
        'low_stock_items': low_stock_list,
        'out_of_stock_items': out_of_stock_list,
        'dead_stock_items': dead_stock_list,
        'products': products
    })

@app.route('/api/admin/stock/restock', methods=['POST'])
@login_required(allowed_role='ADMIN')
def api_admin_stock_restock():
    data = request.get_json() or {}
    product_id = data.get('product_id')
    product_code = data.get('product_code', '').strip().upper()
    
    try:
        added_qty = int(data.get('quantity', 0))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Added quantity must be a positive integer.'}), 400
        
    if added_qty <= 0:
        return jsonify({'success': False, 'message': 'Added quantity must be at least 1 unit.'}), 400
        
    try:
        cost_price = float(data.get('cost_price', 0.0) or 0.0)
    except (ValueError, TypeError):
        cost_price = 0.0
        
    try:
        selling_price = float(data.get('selling_price', 0.0) or 0.0) if data.get('selling_price') else None
    except (ValueError, TypeError):
        selling_price = None
        
    supplier_name = data.get('supplier_name', '').strip() or 'Direct Purchase'
    notes = data.get('notes', '').strip() or 'Stock Inward / Batch Restock'
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if product_id:
        cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    elif product_code:
        cursor.execute('SELECT * FROM products WHERE product_code = ?', (product_code,))
    else:
        conn.close()
        return jsonify({'success': False, 'message': 'Product ID or Product Code is required.'}), 400
        
    product = cursor.fetchone()
    if not product:
        conn.close()
        return jsonify({'success': False, 'message': 'Product not found.'}), 404
        
    curr_stock = product['stock']
    new_stock = curr_stock + added_qty
    
    # Update cost price if specified, otherwise maintain existing
    new_cost_price = cost_price if cost_price > 0 else (product['cost_price'] or round(product['selling_price'] * 0.65, 2))
    new_selling_price = selling_price if (selling_price and selling_price > 0) else product['selling_price']
    
    cursor.execute('''
        UPDATE products 
        SET stock = ?, cost_price = ?, selling_price = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (new_stock, new_cost_price, new_selling_price, product['id']))
    
    # Record in stock_transactions audit table
    cursor.execute('''
        INSERT INTO stock_transactions (product_id, product_code, product_name, transaction_type, quantity, cost_price, selling_price, stock_before, stock_after, supplier_name, notes, operator)
        VALUES (?, ?, ?, 'RESTOCK', ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (product['id'], product['product_code'], product['name'], added_qty, new_cost_price, new_selling_price, curr_stock, new_stock, supplier_name, notes, session.get('username')))
    
    conn.commit()
    conn.close()
    
    log_audit_event(session['user_id'], session['username'], session['role'], 'STOCK_RESTOCKED', request.remote_addr, f"Restocked {product['product_code']} ({product['name']}): +{added_qty} pcs. Stock: {curr_stock} -> {new_stock}")
    
    return jsonify({
        'success': True,
        'message': f"Successfully added +{added_qty} pcs to '{product['name']}'. Available stock is now {new_stock} pcs.",
        'product': {
            'id': product['id'],
            'product_code': product['product_code'],
            'name': product['name'],
            'previous_stock': curr_stock,
            'new_stock': new_stock,
            'cost_price': new_cost_price,
            'selling_price': new_selling_price
        }
    })

# ==========================================
# Damaged Stock & Loss Write-off API
# ==========================================

@app.route('/api/admin/stock/damage', methods=['POST'])
@login_required(allowed_role='ADMIN')
def api_admin_log_damage():
    data = request.get_json() or {}
    product_id = data.get('product_id')
    product_code = (data.get('product_code') or '').strip().upper()
    
    try:
        qty = int(data.get('quantity', 0))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Damaged quantity must be a positive integer.'}), 400
        
    if qty <= 0:
        return jsonify({'success': False, 'message': 'Damaged quantity must be at least 1 piece.'}), 400
        
    reason = (data.get('reason') or '').strip() or 'Fabric Torn / Manufacturing Defect'
    action_taken = (data.get('action_taken') or '').strip() or 'SCRAPPED'
    try:
        recovery_amount = float(data.get('recovery_amount', 0.0) or 0.0)
    except (ValueError, TypeError):
        recovery_amount = 0.0
    notes = (data.get('notes') or '').strip() or 'Damaged stock write-off'
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if product_id:
        cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    elif product_code:
        cursor.execute('SELECT * FROM products WHERE product_code = ?', (product_code,))
    else:
        conn.close()
        return jsonify({'success': False, 'message': 'Product ID or Code is required.'}), 400
        
    product = cursor.fetchone()
    if not product:
        conn.close()
        return jsonify({'success': False, 'message': 'Product not found.'}), 404
        
    curr_stock = product['stock']
    if qty > curr_stock:
        conn.close()
        return jsonify({'success': False, 'message': f"Cannot write-off {qty} pcs. Available stock is only {curr_stock} pcs."}), 400
        
    c_price = float(product['cost_price'] or round(product['selling_price'] * 0.65, 2))
    s_price = float(product['selling_price'] or 0.0)
    loss_amount = round(qty * c_price, 2)
    net_loss = max(0.0, round(loss_amount - recovery_amount, 2))
    new_stock = curr_stock - qty
    
    # 1. Update product stock
    cursor.execute('UPDATE products SET stock = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', (new_stock, product['id']))
    
    # 2. Insert into damage_records
    cursor.execute('''
        INSERT INTO damage_records (product_id, product_code, product_name, quantity, cost_price, selling_price, loss_amount, reason, action_taken, recovery_amount, net_loss, notes, operator)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (product['id'], product['product_code'], product['name'], qty, c_price, s_price, loss_amount, reason, action_taken, recovery_amount, net_loss, notes, session.get('username')))
    damage_id = cursor.lastrowid
    
    # 3. Log stock transaction
    cursor.execute('''
        INSERT INTO stock_transactions (product_id, product_code, product_name, transaction_type, quantity, cost_price, selling_price, stock_before, stock_after, supplier_name, notes, operator)
        VALUES (?, ?, ?, 'DAMAGE', ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (product['id'], product['product_code'], product['name'], qty, c_price, s_price, curr_stock, new_stock, None, f"Damage Write-off: {reason} ({action_taken})", session.get('username')))
    
    conn.commit()
    conn.close()
    
    log_audit_event(session['user_id'], session['username'], session['role'], 'STOCK_DAMAGED', request.remote_addr, f"Damaged write-off for {product['product_code']} ({product['name']}): -{qty} pcs. Loss: ₹{net_loss:,.2f}. Reason: {reason}")
    
    return jsonify({
        'success': True,
        'message': f"Successfully recorded {qty} pcs damaged for '{product['name']}'. Loss write-off: ₹{net_loss:,.2f}. Remaining stock: {new_stock} pcs.",
        'damage_record': {
            'id': damage_id,
            'product_id': product['id'],
            'product_code': product['product_code'],
            'name': product['name'],
            'damaged_quantity': qty,
            'cost_price': c_price,
            'loss_amount': loss_amount,
            'recovery_amount': recovery_amount,
            'net_loss': net_loss,
            'previous_stock': curr_stock,
            'new_stock': new_stock,
            'reason': reason,
            'action_taken': action_taken
        }
    })

@app.route('/api/admin/stock/damages', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_admin_get_damages():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM damage_records ORDER BY id DESC')
    records = [dict(r) for r in cursor.fetchall()]
    
    total_qty = sum(r['quantity'] for r in records)
    total_loss = sum(r['loss_amount'] for r in records)
    total_recovery = sum(r['recovery_amount'] for r in records)
    total_net_loss = sum(r['net_loss'] for r in records)
    
    reasons = {}
    for r in records:
        re = r['reason']
        if re not in reasons:
            reasons[re] = {'reason': re, 'count': 0, 'quantity': 0, 'loss': 0.0}
        reasons[re]['count'] += 1
        reasons[re]['quantity'] += r['quantity']
        reasons[re]['loss'] += r['net_loss']
        
    conn.close()
    return jsonify({
        'success': True,
        'records': records,
        'summary': {
            'total_incidents': len(records),
            'total_damaged_units': total_qty,
            'total_loss_amount': round(total_loss, 2),
            'total_recovery_amount': round(total_recovery, 2),
            'total_net_loss': round(total_net_loss, 2)
        },
        'reasons_breakdown': list(reasons.values())
    })

# ==========================================
# Purchase vs. Sales vs. Profit ROI Engine
# ==========================================

@app.route('/api/admin/stock/purchase-vs-sales', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_admin_purchase_vs_sales():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Products breakdown with inward and sales calculations
    cursor.execute('''
        SELECT p.id, p.product_code, p.name, p.category, p.initial_stock, p.stock, p.cost_price, p.selling_price, p.mrp,
               COALESCE((SELECT SUM(st.quantity) FROM stock_transactions st WHERE st.product_id = p.id AND st.transaction_type = 'RESTOCK'), 0) as restocked_qty,
               COALESCE((SELECT SUM(st.quantity * st.cost_price) FROM stock_transactions st WHERE st.product_id = p.id AND st.transaction_type = 'RESTOCK'), 0) as restock_cost,
               COALESCE((SELECT SUM(si.qty) FROM sale_items si WHERE si.product_code = p.product_code), 0) as sold_qty,
               COALESCE((SELECT SUM(si.qty * si.price) FROM sale_items si WHERE si.product_code = p.product_code), 0) as realized_revenue,
               COALESCE((SELECT SUM(dr.quantity) FROM damage_records dr WHERE dr.product_id = p.id), 0) as damaged_qty,
               COALESCE((SELECT SUM(dr.net_loss) FROM damage_records dr WHERE dr.product_id = p.id), 0) as damage_loss,
               (SELECT MAX(s.timestamp) FROM sale_items si JOIN sales s ON si.sale_id = s.id WHERE si.product_code = p.product_code) as last_sale_date
        FROM products p
        ORDER BY p.id DESC
    ''')
    raw_products = cursor.fetchall()
    
    # 2. Total Sales summary from sales table
    cursor.execute("SELECT COALESCE(SUM(total), 0) as total_sales, COALESCE(SUM(subtotal), 0) as total_subtotal, COALESCE(SUM(tax), 0) as total_tax, COALESCE(SUM(discount_amount), 0) as total_discount, COUNT(id) as total_bills FROM sales")
    sales_sum = dict(cursor.fetchone())
    
    # 3. Total damages summary
    cursor.execute("SELECT COALESCE(SUM(quantity), 0) as total_damaged_qty, COALESCE(SUM(net_loss), 0) as total_damage_loss, COUNT(id) as damage_incidents FROM damage_records")
    damages_sum = dict(cursor.fetchone())
    
    conn.close()
    
    total_initial_cost = 0.0
    total_restock_cost = 0.0
    total_cogs = 0.0
    total_realized_sales = float(sales_sum['total_sales'] or 0.0)
    total_unsold_cost = 0.0
    total_unsold_retail = 0.0
    
    products_breakdown = []
    dead_stock_items = []
    fast_moving_items = []
    category_analytics = {}
    
    for r in raw_products:
        p = dict(r)
        c_price = float(p.get('cost_price') or round(p['selling_price'] * 0.65, 2))
        s_price = float(p.get('selling_price') or 0.0)
        stock_qty = int(p.get('stock') or 0)
        init_stock = int(p.get('initial_stock') or stock_qty)
        restock_qty = int(p.get('restocked_qty') or 0)
        restock_cost = float(p.get('restock_cost') or (restock_qty * c_price))
        sold_qty = int(p.get('sold_qty') or 0)
        revenue = float(p.get('realized_revenue') or (sold_qty * s_price))
        dam_qty = int(p.get('damaged_qty') or 0)
        dam_loss = float(p.get('damage_loss') or (dam_qty * c_price))
        
        init_cost = round(init_stock * c_price, 2)
        total_inward_qty = init_stock + restock_qty
        total_prod_purchase_cost = round(init_cost + restock_cost, 2)
        cogs = round(sold_qty * c_price, 2)
        gross_profit = round(revenue - cogs, 2)
        net_profit = round(gross_profit - dam_loss, 2)
        roi_pct = round((gross_profit / cogs * 100), 1) if cogs > 0 else 0.0
        
        unsold_cost = round(stock_qty * c_price, 2)
        unsold_retail = round(stock_qty * s_price, 2)
        
        # Velocity & Aging
        if sold_qty >= 5:
            aging_status = 'FAST_MOVING'
            aging_label = 'Fast Moving'
            discount_rec = '0%'
        elif sold_qty >= 1:
            aging_status = 'SLOW_MOVING'
            aging_label = 'Slow Moving'
            discount_rec = '10%'
        else:
            aging_status = 'DEAD_STOCK'
            aging_label = 'Dead Stock (0 Sales)'
            discount_rec = '25% - 35% Clearance'
            
        p_data = {
            'id': p['id'],
            'product_code': p['product_code'],
            'name': p['name'],
            'category': p.get('category') or 'General',
            'cost_price': c_price,
            'selling_price': s_price,
            'initial_stock': init_stock,
            'restocked_qty': restock_qty,
            'total_inward_qty': total_inward_qty,
            'total_purchase_cost': total_prod_purchase_cost,
            'sold_qty': sold_qty,
            'realized_revenue': revenue,
            'cogs': cogs,
            'gross_profit': gross_profit,
            'damaged_qty': dam_qty,
            'damage_loss': dam_loss,
            'net_profit': net_profit,
            'roi_pct': roi_pct,
            'available_stock': stock_qty,
            'unsold_cost': unsold_cost,
            'unsold_retail': unsold_retail,
            'aging_status': aging_status,
            'aging_label': aging_label,
            'clearance_recommendation': discount_rec,
            'last_sale_date': p.get('last_sale_date') or 'Never'
        }
        
        products_breakdown.append(p_data)
        
        total_initial_cost += init_cost
        total_restock_cost += restock_cost
        total_cogs += cogs
        total_unsold_cost += unsold_cost
        total_unsold_retail += unsold_retail
        
        if aging_status == 'DEAD_STOCK' and stock_qty > 0:
            dead_stock_items.append(p_data)
        elif aging_status == 'FAST_MOVING':
            fast_moving_items.append(p_data)
            
        cat = p.get('category') or 'General'
        if cat not in category_analytics:
            category_analytics[cat] = {
                'category': cat,
                'total_purchase_investment': 0.0,
                'total_sales_revenue': 0.0,
                'cogs': 0.0,
                'gross_profit': 0.0,
                'damage_loss': 0.0,
                'net_profit': 0.0,
                'available_stock': 0,
                'unsold_retail': 0.0
            }
        category_analytics[cat]['total_purchase_investment'] += total_prod_purchase_cost
        category_analytics[cat]['total_sales_revenue'] += revenue
        category_analytics[cat]['cogs'] += cogs
        category_analytics[cat]['gross_profit'] += gross_profit
        category_analytics[cat]['damage_loss'] += dam_loss
        category_analytics[cat]['net_profit'] += net_profit
        category_analytics[cat]['available_stock'] += stock_qty
        category_analytics[cat]['unsold_retail'] += unsold_retail

    total_purchase_investment = round(total_initial_cost + total_restock_cost, 2)
    total_gross_profit = round(total_realized_sales - total_cogs, 2)
    total_damage_loss = round(float(damages_sum.get('total_damage_loss') or 0.0), 2)
    total_net_trading_profit = round(total_gross_profit - total_damage_loss, 2)
    
    breakeven_recovery_pct = round((total_realized_sales / total_purchase_investment * 100), 1) if total_purchase_investment > 0 else 0.0
    breakeven_recovery_pct = min(100.0, breakeven_recovery_pct)
    remaining_to_breakeven = max(0.0, round(total_purchase_investment - total_realized_sales, 2))
    overall_roi_pct = round((total_gross_profit / total_cogs * 100), 1) if total_cogs > 0 else 0.0
    
    projected_clearance_profit = round((total_realized_sales + total_unsold_retail) - total_purchase_investment - total_damage_loss, 2)
    
    for cat in category_analytics:
        category_analytics[cat]['total_purchase_investment'] = round(category_analytics[cat]['total_purchase_investment'], 2)
        category_analytics[cat]['total_sales_revenue'] = round(category_analytics[cat]['total_sales_revenue'], 2)
        category_analytics[cat]['cogs'] = round(category_analytics[cat]['cogs'], 2)
        category_analytics[cat]['gross_profit'] = round(category_analytics[cat]['gross_profit'], 2)
        category_analytics[cat]['damage_loss'] = round(category_analytics[cat]['damage_loss'], 2)
        category_analytics[cat]['net_profit'] = round(category_analytics[cat]['net_profit'], 2)
        category_analytics[cat]['unsold_retail'] = round(category_analytics[cat]['unsold_retail'], 2)
        
    return jsonify({
        'success': True,
        'summary': {
            'total_purchase_investment': total_purchase_investment,
            'total_initial_investment': round(total_initial_cost, 2),
            'total_restock_investment': round(total_restock_cost, 2),
            'total_realized_sales': round(total_realized_sales, 2),
            'total_bills_count': sales_sum.get('total_bills', 0),
            'cost_of_goods_sold': round(total_cogs, 2),
            'realized_gross_profit': total_gross_profit,
            'total_damage_loss': total_damage_loss,
            'total_damaged_units': damages_sum.get('total_damaged_qty', 0),
            'net_trading_profit': total_net_trading_profit,
            'realized_roi_pct': overall_roi_pct,
            'breakeven_recovery_pct': breakeven_recovery_pct,
            'remaining_to_breakeven': remaining_to_breakeven,
            'unsold_stock_cost': round(total_unsold_cost, 2),
            'unsold_stock_retail': round(total_unsold_retail, 2),
            'projected_full_clearance_profit': projected_clearance_profit,
            'dead_stock_count': len(dead_stock_items),
            'fast_moving_count': len(fast_moving_items)
        },
        'category_analytics': list(category_analytics.values()),
        'dead_stock_items': dead_stock_items,
        'fast_moving_items': fast_moving_items,
        'products': products_breakdown
    })

@app.route('/api/admin/stock/transactions', methods=['GET'])
@app.route('/api/admin/stock/transactions/<product_code>', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_admin_stock_transactions(product_code=None):
    if not product_code:
        product_code = (request.args.get('product_code') or '').strip().upper() or None
        
    filter_type = (request.args.get('filter_type') or request.args.get('date_preset') or 'all').strip().lower()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    tx_type = (request.args.get('transaction_type') or request.args.get('type') or 'ALL').strip().upper()
    search = request.args.get('search', '').strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # -------------------------------------------------------------
    # Scenario A: Per-Product Comprehensive Passbook & History
    # -------------------------------------------------------------
    if product_code:
        cursor.execute('SELECT * FROM products WHERE product_code = ?', (product_code,))
        prod = cursor.fetchone()
        if not prod and product_code.isdigit():
            cursor.execute('SELECT * FROM products WHERE id = ?', (int(product_code),))
            prod = cursor.fetchone()
            
        prod_dict = dict(prod) if prod else None
        p_code = prod_dict['product_code'] if prod_dict else product_code
        
        cursor.execute('''
            SELECT st.* 
            FROM stock_transactions st 
            WHERE st.product_code = ? OR (st.product_id IS NOT NULL AND st.product_id = ?)
            ORDER BY st.created_at ASC, st.id ASC
        ''', (p_code, prod_dict['id'] if prod_dict else -1))
        
        raw_txs = [dict(r) for r in cursor.fetchall()]
        conn.close()
        
        # Build chronological passbook with running balance
        running_bal = 0
        timeline = []
        tot_initial = 0
        tot_restocked = 0
        tot_sold = 0
        tot_damaged = 0
        tot_returned = 0
        tot_sales_val = 0.0
        tot_cost_inv = 0.0
        
        for t in raw_txs:
            ttype = t['transaction_type']
            qty = int(t['quantity'] or 0)
            cp = float(t['cost_price'] or (prod_dict.get('cost_price') if prod_dict else 0.0) or 0.0)
            sp = float(t['selling_price'] or (prod_dict.get('selling_price') if prod_dict else 0.0) or 0.0)
            
            if ttype == 'INITIAL':
                running_bal += qty
                tot_initial += qty
                tot_cost_inv += (qty * cp)
                qty_badge = f"+{qty}"
                flow_dir = 'INWARD'
                flow_icon = '📦'
                flow_label = 'Opening Initial Stock'
            elif ttype == 'RESTOCK':
                running_bal += qty
                tot_restocked += qty
                tot_cost_inv += (qty * cp)
                qty_badge = f"+{qty}"
                flow_dir = 'INWARD'
                flow_icon = '➕'
                flow_label = 'Restock / Stock Inward'
            elif ttype == 'SALE':
                running_bal -= qty
                tot_sold += qty
                tot_sales_val += (qty * sp)
                qty_badge = f"-{qty}"
                flow_dir = 'OUTWARD'
                flow_icon = '🛍️'
                flow_label = 'POS Sale Checkout'
            elif ttype == 'DAMAGE':
                running_bal -= qty
                tot_damaged += qty
                qty_badge = f"-{qty}"
                flow_dir = 'OUTWARD'
                flow_icon = '💥'
                flow_label = 'Damage / Defect Write-off'
            elif ttype == 'RETURN':
                running_bal += qty
                tot_returned += qty
                qty_badge = f"+{qty}"
                flow_dir = 'INWARD'
                flow_icon = '🔄'
                flow_label = 'Customer Return / Restock'
            else:
                running_bal = t['stock_after']
                qty_badge = f"{qty}"
                flow_dir = 'ADJUSTMENT'
                flow_icon = '📝'
                flow_label = 'Stock Adjustment'
                
            t['running_balance'] = t['stock_after'] if t.get('stock_after') is not None else running_bal
            t['qty_badge'] = qty_badge
            t['flow_dir'] = flow_dir
            t['flow_icon'] = flow_icon
            t['flow_label'] = flow_label
            t['total_value'] = round(qty * (sp if ttype == 'SALE' else cp), 2)
            timeline.append(t)
            
        summary = {
            'initial_stock': tot_initial or (prod_dict['initial_stock'] if prod_dict else 0),
            'total_restocked': tot_restocked,
            'total_inward': tot_initial + tot_restocked,
            'total_sold': tot_sold,
            'total_damaged': tot_damaged,
            'total_returned': tot_returned,
            'total_outward': tot_sold + tot_damaged,
            'current_available_stock': prod_dict['stock'] if prod_dict else running_bal,
            'total_sales_value': round(tot_sales_val, 2),
            'total_cost_invested': round(tot_cost_inv, 2),
            'total_transactions': len(timeline)
        }
        
        return jsonify({
            'success': True,
            'product': prod_dict,
            'summary': summary,
            'transactions': list(reversed(timeline)),
            'chronological_timeline': timeline
        })

    # -------------------------------------------------------------
    # Scenario B: Shop-wide Multi-Product Stock Movement Ledger
    # -------------------------------------------------------------
    query_conditions = []
    params = []
    
    if filter_type == 'today':
        query_conditions.append("(date(st.created_at) = date('now', 'localtime') OR date(st.created_at) = date('now'))")
    elif filter_type == 'yesterday':
        query_conditions.append("(date(st.created_at) = date('now', 'localtime', '-1 day') OR date(st.created_at) = date('now', '-1 day'))")
    elif filter_type in ('this_week', 'week', '7days', 'last_7_days'):
        query_conditions.append("date(st.created_at) >= date('now', 'localtime', '-7 days')")
    elif filter_type in ('this_month', 'month'):
        query_conditions.append("strftime('%Y-%m', st.created_at) = strftime('%Y-%m', 'now', 'localtime')")
    elif filter_type == 'custom' and start_date and end_date:
        query_conditions.append("date(st.created_at) BETWEEN ? AND ?")
        params.extend([start_date, end_date])
    elif start_date and end_date:
        query_conditions.append("date(st.created_at) BETWEEN ? AND ?")
        params.extend([start_date, end_date])
    elif start_date:
        query_conditions.append("date(st.created_at) >= ?")
        params.append(start_date)
    elif end_date:
        query_conditions.append("date(st.created_at) <= ?")
        params.append(end_date)
        
    if tx_type and tx_type != 'ALL':
        query_conditions.append("st.transaction_type = ?")
        params.append(tx_type)
        
    if search:
        search_pattern = f"%{search}%"
        query_conditions.append("(st.product_code LIKE ? OR st.product_name LIKE ? OR st.supplier_name LIKE ? OR st.notes LIKE ? OR st.operator LIKE ?)")
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern, search_pattern])
        
    where_clause = f"WHERE {' AND '.join(query_conditions)}" if query_conditions else ""
    
    sql = f'''
        SELECT st.*, p.category, p.image_path, p.sizes
        FROM stock_transactions st
        LEFT JOIN products p ON st.product_id = p.id OR st.product_code = p.product_code
        {where_clause}
        ORDER BY st.created_at DESC, st.id DESC
    '''
    cursor.execute(sql, params)
    raw_rows = cursor.fetchall()
    conn.close()
    
    enriched_rows = []
    tot_initial_u = 0
    tot_restock_u = 0
    tot_sold_u = 0
    tot_damaged_u = 0
    tot_returned_u = 0
    tot_sales_val = 0.0
    tot_cost_val = 0.0
    
    for r in raw_rows:
        t = dict(r)
        ttype = t['transaction_type']
        qty = int(t['quantity'] or 0)
        cp = float(t['cost_price'] or 0.0)
        sp = float(t['selling_price'] or 0.0)
        
        if ttype == 'INITIAL':
            tot_initial_u += qty
            tot_cost_val += (qty * cp)
            qty_badge = f"+{qty}"
            flow_dir = 'INWARD'
            flow_icon = '📦'
            flow_label = 'Opening Initial Stock'
        elif ttype == 'RESTOCK':
            tot_restock_u += qty
            tot_cost_val += (qty * cp)
            qty_badge = f"+{qty}"
            flow_dir = 'INWARD'
            flow_icon = '➕'
            flow_label = 'Restock / Stock Inward'
        elif ttype == 'SALE':
            tot_sold_u += qty
            tot_sales_val += (qty * sp)
            qty_badge = f"-{qty}"
            flow_dir = 'OUTWARD'
            flow_icon = '🛍️'
            flow_label = 'POS Sale Checkout'
        elif ttype == 'DAMAGE':
            tot_damaged_u += qty
            qty_badge = f"-{qty}"
            flow_dir = 'OUTWARD'
            flow_icon = '💥'
            flow_label = 'Damage Write-off'
        elif ttype == 'RETURN':
            tot_returned_u += qty
            qty_badge = f"+{qty}"
            flow_dir = 'INWARD'
            flow_icon = '🔄'
            flow_label = 'Customer Return'
        else:
            qty_badge = f"{qty}"
            flow_dir = 'ADJUSTMENT'
            flow_icon = '📝'
            flow_label = 'Stock Adjustment'
            
        t['qty_badge'] = qty_badge
        t['flow_dir'] = flow_dir
        t['flow_icon'] = flow_icon
        t['flow_label'] = flow_label
        t['total_value'] = round(qty * (sp if ttype == 'SALE' else cp), 2)
        enriched_rows.append(t)
        
    summary = {
        'total_initial_units': tot_initial_u,
        'total_restock_units': tot_restock_u,
        'total_inward_units': tot_initial_u + tot_restock_u + tot_returned_u,
        'total_sold_units': tot_sold_u,
        'total_damaged_units': tot_damaged_u,
        'total_returned_units': tot_returned_u,
        'total_outward_units': tot_sold_u + tot_damaged_u,
        'net_units_change': (tot_initial_u + tot_restock_u + tot_returned_u) - (tot_sold_u + tot_damaged_u),
        'total_sales_value': round(tot_sales_val, 2),
        'total_cost_value': round(tot_cost_val, 2),
        'total_transactions_count': len(enriched_rows)
    }
    
    return jsonify({
        'success': True,
        'summary': summary,
        'transactions': enriched_rows
    })

@app.route('/api/admin/export/stock-transactions-csv', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_export_stock_transactions_csv():
    product_code = (request.args.get('product_code') or '').strip().upper() or None
    filter_type = (request.args.get('filter_type') or request.args.get('date_preset') or 'all').strip().lower()
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    tx_type = (request.args.get('transaction_type') or request.args.get('type') or 'ALL').strip().upper()
    search = request.args.get('search', '').strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query_conditions = []
    params = []
    
    if product_code:
        query_conditions.append("(st.product_code = ?)")
        params.append(product_code)
    else:
        if filter_type == 'today':
            query_conditions.append("(date(st.created_at) = date('now', 'localtime') OR date(st.created_at) = date('now'))")
        elif filter_type == 'yesterday':
            query_conditions.append("(date(st.created_at) = date('now', 'localtime', '-1 day') OR date(st.created_at) = date('now', '-1 day'))")
        elif filter_type in ('this_week', 'week', '7days', 'last_7_days'):
            query_conditions.append("date(st.created_at) >= date('now', 'localtime', '-7 days')")
        elif filter_type in ('this_month', 'month'):
            query_conditions.append("strftime('%Y-%m', st.created_at) = strftime('%Y-%m', 'now', 'localtime')")
        elif filter_type == 'custom' and start_date and end_date:
            query_conditions.append("date(st.created_at) BETWEEN ? AND ?")
            params.extend([start_date, end_date])
        elif start_date and end_date:
            query_conditions.append("date(st.created_at) BETWEEN ? AND ?")
            params.extend([start_date, end_date])
            
        if tx_type and tx_type != 'ALL':
            query_conditions.append("st.transaction_type = ?")
            params.append(tx_type)
            
        if search:
            search_pattern = f"%{search}%"
            query_conditions.append("(st.product_code LIKE ? OR st.product_name LIKE ? OR st.supplier_name LIKE ? OR st.notes LIKE ? OR st.operator LIKE ?)")
            params.extend([search_pattern, search_pattern, search_pattern, search_pattern, search_pattern])
            
    where_clause = f"WHERE {' AND '.join(query_conditions)}" if query_conditions else ""
    
    sql = f'''
        SELECT st.*, p.category
        FROM stock_transactions st
        LEFT JOIN products p ON st.product_id = p.id OR st.product_code = p.product_code
        {where_clause}
        ORDER BY st.created_at DESC, st.id DESC
    '''
    cursor.execute(sql, params)
    txs = cursor.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Tx ID', 'Timestamp', 'Barcode / Product Code', 'Garment Name', 'Category',
        'Transaction Type', 'Inward / Outward', 'Quantity (pcs)', 'Stock Before', 'Stock After / Balance',
        'Unit Cost Price (Rs)', 'Unit Selling Price (Rs)', 'Total Value (Rs)', 'Supplier / Notes / Reference', 'Operator'
    ])
    
    tot_in = 0
    tot_out = 0
    tot_val = 0.0
    
    for r in txs:
        row = dict(r)
        ttype = row['transaction_type']
        qty = int(row['quantity'] or 0)
        cp = float(row['cost_price'] or 0.0)
        sp = float(row['selling_price'] or 0.0)
        val = round(qty * (sp if ttype == 'SALE' else cp), 2)
        
        in_out = 'INWARD (+)' if ttype in ('INITIAL', 'RESTOCK', 'RETURN') else ('OUTWARD (-)' if ttype in ('SALE', 'DAMAGE') else 'ADJUST')
        if ttype in ('INITIAL', 'RESTOCK', 'RETURN'):
            tot_in += qty
        elif ttype in ('SALE', 'DAMAGE'):
            tot_out += qty
        tot_val += val
        
        writer.writerow([
            f"TX-{row['id']:05d}",
            row['created_at'],
            row['product_code'],
            row['product_name'],
            row.get('category') or 'General',
            ttype,
            in_out,
            qty,
            row['stock_before'],
            row['stock_after'],
            f"{cp:.2f}",
            f"{sp:.2f}",
            f"{val:.2f}",
            row.get('notes') or (f"Supplier: {row['supplier_name']}" if row.get('supplier_name') else '-'),
            row.get('operator') or 'admin'
        ])
        
    writer.writerow([])
    writer.writerow(['TOTALS / AUDIT SUMMARY', '', '', '', '', '', '', f"Total Inward: +{tot_in} pcs | Total Outward: -{tot_out} pcs", '', f"Net Change: {tot_in - tot_out} pcs", '', '', f"{tot_val:.2f}", '', ''])
    
    prefix = f"Stock_Passbook_{product_code}" if product_code else f"Stock_Movement_Ledger_{filter_type}"
    filename = f"{prefix}_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    return response

@app.route('/api/admin/export/damage-csv', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_export_damage_csv():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM damage_records ORDER BY id DESC')
    damages = cursor.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Damage ID', 'Timestamp', 'Barcode / Product Code', 'Garment Name',
        'Damaged Quantity (pcs)', 'Unit Cost Price (Rs)', 'Unit Selling Price (Rs)',
        'Gross Loss (Rs)', 'Recovery / Scrap Salvage (Rs)', 'Net Write-off Loss (Rs)',
        'Damage Reason', 'Action Taken', 'Notes', 'Recorded By'
    ])
    
    total_qty = 0
    total_loss = 0.0
    total_rec = 0.0
    total_net = 0.0
    
    for d in damages:
        row = dict(d)
        total_qty += row['quantity']
        total_loss += row['loss_amount']
        total_rec += row['recovery_amount']
        total_net += row['net_loss']
        writer.writerow([
            f"DAM-{row['id']:04d}",
            row['timestamp'],
            row['product_code'],
            row['product_name'],
            row['quantity'],
            f"{row['cost_price']:.2f}",
            f"{row['selling_price']:.2f}",
            f"{row['loss_amount']:.2f}",
            f"{row['recovery_amount']:.2f}",
            f"{row['net_loss']:.2f}",
            row['reason'],
            row['action_taken'],
            row.get('notes', ''),
            row.get('operator', 'Admin')
        ])
        
    writer.writerow([])
    writer.writerow([
        'TOTALS / WRITE-OFF SUMMARY', '', '', '',
        total_qty, '', '',
        f"{total_loss:.2f}", f"{total_rec:.2f}", f"{total_net:.2f}",
        '', '', '', ''
    ])
    
    filename = f"Damaged_Goods_WriteOff_Report_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    return response

@app.route('/api/admin/export/stock-valuation-csv', methods=['GET'])
@login_required(allowed_role='ADMIN')
def api_export_stock_valuation_csv():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT value FROM settings WHERE key = 'low_stock_threshold'")
    row = cursor.fetchone()
    low_stock_threshold = int(row['value']) if row else 5
    
    cursor.execute('''
        SELECT p.*,
               COALESCE((SELECT SUM(st.quantity) FROM stock_transactions st WHERE st.product_id = p.id AND st.transaction_type = 'RESTOCK'), 0) as restocked_qty,
               COALESCE((SELECT SUM(st.quantity) FROM stock_transactions st WHERE st.product_id = p.id AND st.transaction_type = 'SALE'), 0) as sold_qty,
               COALESCE((SELECT SUM(dr.quantity) FROM damage_records dr WHERE dr.product_id = p.id), 0) as damaged_qty,
               COALESCE((SELECT SUM(dr.net_loss) FROM damage_records dr WHERE dr.product_id = p.id), 0) as damage_loss
        FROM products p
        ORDER BY p.id DESC
    ''')
    products = cursor.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Barcode / Item Code', 'Garment Name', 'Category', 'Sizes',
        'Initial Stock (pcs)', 'Restocked / Inward (+pcs)', 'Sold (-pcs)', 'Damaged / Defect (-pcs)', 'Current Available Stock (pcs)',
        'Unit Cost Price (Rs)', 'Unit Selling Price (Rs)', 'Unit MRP (Rs)',
        'Total Cost Valuation (Rs)', 'Total Retail Valuation (Rs)', 'Expected Gross Profit (Rs)', 'Damage Loss (Rs)', 'Net Valuation (Rs)',
        'Profit Margin (%)', 'Stock Status'
    ])
    
    total_units = 0
    total_cost_val = 0.0
    total_retail_val = 0.0
    total_profit = 0.0
    total_damaged_units = 0
    total_damage_loss = 0.0
    
    for r in products:
        p = dict(r)
        stock_qty = int(p.get('stock') or 0)
        init_stock = int(p.get('initial_stock') or stock_qty)
        restock_qty = int(p.get('restocked_qty') or 0)
        sold_qty = int(p.get('sold_qty') or 0)
        damaged_qty = int(p.get('damaged_qty') or 0)
        damage_loss = float(p.get('damage_loss') or 0.0)
        cost_price = float(p.get('cost_price') or round(p['selling_price'] * 0.65, 2))
        selling_price = float(p.get('selling_price') or 0.0)
        mrp = float(p.get('mrp') or 0.0)
        
        cost_val = round(stock_qty * cost_price, 2)
        retail_val = round(stock_qty * selling_price, 2)
        profit = round(retail_val - cost_val, 2)
        net_val = round(cost_val - damage_loss, 2)
        margin_pct = round((profit / cost_val * 100), 1) if cost_val > 0 else 0.0
        
        status = 'Out of Stock' if stock_qty <= 0 else ('Low Stock' if stock_qty <= low_stock_threshold else 'In Stock')
        
        total_units += stock_qty
        total_cost_val += cost_val
        total_retail_val += retail_val
        total_profit += profit
        total_damaged_units += damaged_qty
        total_damage_loss += damage_loss
        
        writer.writerow([
            p['product_code'],
            p['name'],
            p.get('category', 'General'),
            p.get('sizes', 'Free Size'),
            init_stock,
            restock_qty,
            sold_qty,
            damaged_qty,
            stock_qty,
            f"{cost_price:.2f}",
            f"{selling_price:.2f}",
            f"{mrp:.2f}",
            f"{cost_val:.2f}",
            f"{retail_val:.2f}",
            f"{profit:.2f}",
            f"{damage_loss:.2f}",
            f"{net_val:.2f}",
            f"{margin_pct:.1f}%",
            status
        ])
        
    # Summary line at bottom
    writer.writerow([])
    writer.writerow([
        'TOTALS / SUMMARY', '', '', '',
        '', '', '', total_damaged_units, total_units,
        '', '', '',
        f"{total_cost_val:.2f}", f"{total_retail_val:.2f}", f"{total_profit:.2f}",
        f"{total_damage_loss:.2f}", f"{(total_cost_val - total_damage_loss):.2f}",
        f"{round((total_profit/total_cost_val*100),1) if total_cost_val > 0 else 0.0}%", ''
    ])
    
    filename = f"Stock_Valuation_Inventory_Report_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['Content-Type'] = 'text/csv; charset=utf-8'
    return response

if __name__ == '__main__':
    app.run(debug=True, port=5000)
