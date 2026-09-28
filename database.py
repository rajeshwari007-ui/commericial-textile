import sqlite3
import os
from auth_utils import hash_password

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'shop.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=20, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            mobile TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT CHECK(role IN ('ADMIN', 'CASHIER')) NOT NULL,
            status TEXT CHECK(status IN ('ACTIVE', 'INACTIVE')) NOT NULL DEFAULT 'ACTIVE',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Ensure two_factor_secret column exists in users table
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'two_factor_secret' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN two_factor_secret TEXT DEFAULT NULL")
        
    # Create audit_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            username TEXT,
            role TEXT,
            action TEXT NOT NULL,
            ip_address TEXT,
            details TEXT
        )
    ''')
    
    # Create products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_code TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT,
            image_path TEXT,
            stock INTEGER NOT NULL DEFAULT 0,
            quantity INTEGER NOT NULL DEFAULT 1,
            selling_price REAL NOT NULL,
            mrp REAL NOT NULL,
            discount REAL NOT NULL DEFAULT 0.0,
            gst REAL NOT NULL DEFAULT 0.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create sales table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bill_no TEXT NOT NULL UNIQUE,
            customer_name TEXT,
            customer_mobile TEXT,
            payment_mode TEXT NOT NULL,
            subtotal REAL NOT NULL,
            tax REAL NOT NULL,
            discount_amount REAL DEFAULT 0.0,
            coupon_code TEXT,
            total REAL NOT NULL,
            operator TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create sale_items table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sale_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER NOT NULL,
            product_code TEXT NOT NULL,
            product_name TEXT NOT NULL,
            size TEXT NOT NULL,
            price REAL NOT NULL,
            qty INTEGER NOT NULL,
            FOREIGN KEY(sale_id) REFERENCES sales(id)
        )
    ''')

    # Ensure sizes, category, cost_price, initial_stock, reorder_level columns exist in products table
    cursor.execute("PRAGMA table_info(products)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'sizes' not in columns:
        cursor.execute("ALTER TABLE products ADD COLUMN sizes TEXT DEFAULT 'Free Size'")
    if 'category' not in columns:
        cursor.execute("ALTER TABLE products ADD COLUMN category TEXT DEFAULT 'General'")
    if 'cost_price' not in columns:
        cursor.execute("ALTER TABLE products ADD COLUMN cost_price REAL DEFAULT 0.0")
    if 'initial_stock' not in columns:
        cursor.execute("ALTER TABLE products ADD COLUMN initial_stock INTEGER DEFAULT 0")
    if 'reorder_level' not in columns:
        cursor.execute("ALTER TABLE products ADD COLUMN reorder_level INTEGER DEFAULT 5")
    conn.commit()

    # Backfill default cost_price and initial_stock for products where missing
    cursor.execute("""
        UPDATE products 
        SET cost_price = ROUND(CASE WHEN cost_price > 0 THEN cost_price ELSE selling_price * 0.65 END, 2),
            initial_stock = CASE WHEN initial_stock > 0 THEN initial_stock ELSE stock END
        WHERE cost_price = 0 OR cost_price IS NULL OR initial_stock = 0 OR initial_stock IS NULL
    """)
    conn.commit()

    # Create stock_transactions table for tracking Inward, Restock, Sales, Returns, and Damages
    cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='stock_transactions'")
    row = cursor.fetchone()
    if row and row[0] and "CHECK" in row[0] and "DAMAGE" not in row[0]:
        cursor.execute("CREATE TABLE stock_transactions_temp AS SELECT * FROM stock_transactions")
        cursor.execute("DROP TABLE stock_transactions")
        cursor.execute('''
            CREATE TABLE stock_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER,
                product_code TEXT NOT NULL,
                product_name TEXT NOT NULL,
                transaction_type TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                cost_price REAL DEFAULT 0.0,
                selling_price REAL DEFAULT 0.0,
                stock_before INTEGER NOT NULL,
                stock_after INTEGER NOT NULL,
                supplier_name TEXT,
                notes TEXT,
                operator TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            INSERT INTO stock_transactions (id, product_id, product_code, product_name, transaction_type, quantity, cost_price, selling_price, stock_before, stock_after, supplier_name, notes, operator, created_at)
            SELECT id, product_id, product_code, product_name, transaction_type, quantity, cost_price, selling_price, stock_before, stock_after, supplier_name, notes, operator, created_at
            FROM stock_transactions_temp
        ''')
        cursor.execute("DROP TABLE stock_transactions_temp")
        conn.commit()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stock_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            product_code TEXT NOT NULL,
            product_name TEXT NOT NULL,
            transaction_type TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            cost_price REAL DEFAULT 0.0,
            selling_price REAL DEFAULT 0.0,
            stock_before INTEGER NOT NULL,
            stock_after INTEGER NOT NULL,
            supplier_name TEXT,
            notes TEXT,
            operator TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()

    # Backfill INITIAL stock transactions for existing products if missing
    cursor.execute('''
        SELECT p.id, p.product_code, p.name, p.initial_stock, p.stock, p.cost_price, p.selling_price, p.created_at 
        FROM products p
        WHERE NOT EXISTS (
            SELECT 1 FROM stock_transactions st 
            WHERE st.product_id = p.id OR st.product_code = p.product_code
        )
    ''')
    untracked_products = cursor.fetchall()
    for up in untracked_products:
        init_qty = up['initial_stock'] if (up['initial_stock'] and up['initial_stock'] > 0) else up['stock']
        cp = up['cost_price'] if (up['cost_price'] and up['cost_price'] > 0) else round(up['selling_price'] * 0.65, 2)
        sp = up['selling_price'] or 0.0
        cursor.execute('''
            INSERT INTO stock_transactions (product_id, product_code, product_name, transaction_type, quantity, cost_price, selling_price, stock_before, stock_after, notes, operator, created_at)
            VALUES (?, ?, ?, 'INITIAL', ?, ?, ?, 0, ?, 'Opening Initial Stock Registered', 'System', ?)
        ''', (up['id'], up['product_code'], up['name'], init_qty, cp, sp, init_qty, up['created_at']))
    conn.commit()

    # Create damage_records table for tracking damaged/defective garments and inventory loss write-offs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS damage_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            product_code TEXT NOT NULL,
            product_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            cost_price REAL NOT NULL,
            selling_price REAL NOT NULL,
            loss_amount REAL NOT NULL,
            reason TEXT NOT NULL,
            action_taken TEXT NOT NULL DEFAULT 'SCRAPPED',
            recovery_amount REAL DEFAULT 0.0,
            net_loss REAL NOT NULL,
            notes TEXT,
            operator TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    ''')
    conn.commit()

    # Create credit_notes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credit_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            amount REAL NOT NULL,
            balance REAL NOT NULL,
            customer_mobile TEXT,
            customer_name TEXT,
            reason TEXT,
            status TEXT CHECK(status IN ('ACTIVE', 'REDEEMED', 'EXPIRED')) NOT NULL DEFAULT 'ACTIVE',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create expenses table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            expense_date DATE DEFAULT (DATE('now')),
            recorded_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create suppliers table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS suppliers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            contact_person TEXT,
            phone TEXT,
            email TEXT,
            city TEXT,
            gstin TEXT,
            status TEXT DEFAULT 'ACTIVE',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create purchases table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS purchases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_no TEXT NOT NULL,
            supplier_id INTEGER,
            supplier_name TEXT NOT NULL,
            total_amount REAL NOT NULL,
            purchase_date DATE DEFAULT (DATE('now')),
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create purchase_items table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS purchase_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            purchase_id INTEGER NOT NULL,
            product_id INTEGER,
            product_code TEXT NOT NULL,
            product_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            cost_price REAL NOT NULL,
            FOREIGN KEY(purchase_id) REFERENCES purchases(id)
        )
    ''')

    # Create customers table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            mobile TEXT NOT NULL UNIQUE,
            loyalty_points INTEGER DEFAULT 0,
            total_spent REAL DEFAULT 0.0,
            visit_count INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create returns table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS returns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            return_no TEXT NOT NULL UNIQUE,
            original_bill_no TEXT NOT NULL,
            customer_name TEXT,
            customer_mobile TEXT,
            product_code TEXT NOT NULL,
            product_name TEXT NOT NULL,
            size TEXT,
            qty INTEGER NOT NULL,
            refund_amount REAL NOT NULL,
            refund_mode TEXT NOT NULL,
            credit_note_code TEXT,
            reason TEXT,
            operator TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Ensure additional columns exist in sales table
    cursor.execute("PRAGMA table_info(sales)")
    sales_columns = [row[1] for row in cursor.fetchall()]
    if 'split_payment_json' not in sales_columns:
        cursor.execute("ALTER TABLE sales ADD COLUMN split_payment_json TEXT DEFAULT NULL")
    if 'salesperson' not in sales_columns:
        cursor.execute("ALTER TABLE sales ADD COLUMN salesperson TEXT DEFAULT 'General Staff'")
    if 'loyalty_points_earned' not in sales_columns:
        cursor.execute("ALTER TABLE sales ADD COLUMN loyalty_points_earned INTEGER DEFAULT 0")
    if 'loyalty_points_used' not in sales_columns:
        cursor.execute("ALTER TABLE sales ADD COLUMN loyalty_points_used INTEGER DEFAULT 0")
    if 'credit_note_used' not in sales_columns:
        cursor.execute("ALTER TABLE sales ADD COLUMN credit_note_used TEXT DEFAULT NULL")
    if 'credit_amount_used' not in sales_columns:
        cursor.execute("ALTER TABLE sales ADD COLUMN credit_amount_used REAL DEFAULT 0.0")
    conn.commit()

    # Create settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('low_stock_threshold', '5')")
    conn.commit()
        
    # Check if admin user exists
    cursor.execute("SELECT id FROM users WHERE role = 'ADMIN'")
    admin_exists = cursor.fetchone()
    
    if not admin_exists:
        default_admin_password = "adminpassword123"
        hashed = hash_password(default_admin_password)
        cursor.execute('''
            INSERT INTO users (name, username, email, mobile, password_hash, role, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            "System Administrator",
            "admin",
            "admin@readymadeshop.com",
            "9876543210",
            hashed,
            "ADMIN",
            "ACTIVE"
        ))
        conn.commit()
        print("*" * 50)
        print("DATABASE INITIALIZED: Default admin account created!")
        print("Username: admin")
        print("Password: adminpassword123")
        print("*" * 50)
        
    conn.close()

if __name__ == '__main__':
    init_db()
