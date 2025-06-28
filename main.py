import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re
import io
import csv
import random
import string


# --- App Initialization ---
app = Flask(__name__)
app.secret_key = "supersecretkey"

DATABASE = 'database.db'
ADMIN_EMAIL = "admin@gmail.com"

# --- Database Setup ---
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()

        # Users table
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT
        )''')

        # Customers table
        cur.execute('''CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            name TEXT,
            address TEXT,
            phone TEXT,
            email TEXT,
            pan TEXT,
            gst TEXT
        )''')

        # Certificates table
        cur.execute('''CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            cert_type TEXT,
            status TEXT,
            activation_date TEXT,
            expiration_date TEXT,
            verified INTEGER DEFAULT 0,
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS certificate_types (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
        )''')
        conn.commit()

# --- Helper Functions ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session["user_id"] = user["id"]
            session["user_email"] = user["email"]
            session["role"] = "admin" if user["email"] == ADMIN_EMAIL else "deo"
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials", "error")
    return render_template('login.html')

@app.route('/signup', methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        hashed_pw = generate_password_hash(password)
        role = "admin" if email == ADMIN_EMAIL.lower() else "deo"

        try:
            conn = get_db_connection()
            conn.execute("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
                         (name, email, hashed_pw, role))
            conn.commit()
            conn.close()
            flash("Signup successful. Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Email already exists.", "error")
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()

    certificates = conn.execute("""
        SELECT cert.*, customers.name as customer_name
        FROM certificates cert
        JOIN customers ON cert.customer_id = customers.id
        ORDER BY cert.id DESC
    """).fetchall()

    all_customers = conn.execute("SELECT id, name, code FROM customers ORDER BY name").fetchall()
    cert_types_query = conn.execute("""
        SELECT name FROM certificate_types
        UNION
        SELECT DISTINCT cert_type FROM certificates
        ORDER BY name ASC
    """).fetchall()

    cert_types = [ct[0] for ct in cert_types_query]       
    conn.close()

    return render_template("dashboard.html",
                           certificates=certificates,
                           all_customers=all_customers,
                           cert_types=cert_types,
                           role=session.get("role"))
@app.route('/import-csv', methods=['POST'])
def import_csv():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = request.files.get('csv_file')
    if not file:
        flash("No file uploaded", "error")
        return redirect(url_for('dashboard'))

    import io, csv
    from datetime import datetime

    try:
        content = file.read().decode('utf-8-sig')  # handle BOM
        stream = io.StringIO(content)
        reader = csv.reader(stream)
        headers = next(reader)

        stream.seek(0)
        dict_reader = csv.DictReader(stream)

        # Identify the customer name column (case-insensitive)
        customer_col = None
        for key in dict_reader.fieldnames:
            if key.strip().lower() == "customer name":
                customer_col = key
                break

        if not customer_col:
            flash("CSV must contain a 'Customer Name' column", "error")
            return redirect(url_for('dashboard'))

        conn = get_db_connection()
        cursor = conn.cursor()

        customer_count = 0
        certificate_count = 0
        seen_customers = set()

        for row in dict_reader:
            print(f"🔍 Row: {row}")
            customer_name = (row.get(customer_col) or "").strip()
            if not customer_name:
                print("⚠️ Skipping row with empty customer name.")
                continue

            # Insert or get customer
            cursor.execute("SELECT id FROM customers WHERE name = ?", (customer_name,))
            customer = cursor.fetchone()
            if customer:
                customer_id = customer["id"]
                print(f"✅ Existing customer: {customer_name} (ID: {customer_id})")
            else:
                try:
                    cursor.execute(
                        "INSERT INTO customers (name) VALUES (?)",
                        (customer_name,)
                    )
                    customer_id = cursor.lastrowid
                    customer_count += 1
                    print(f"✅ Inserted new customer: {customer_name} (ID: {customer_id})")
                except sqlite3.IntegrityError as err:
                    print(f"❌ Customer insert failed for {customer_name}: {err}")
                    cursor.execute("SELECT id FROM customers WHERE name = ?", (customer_name,))
                    existing = cursor.fetchone()
                    if existing:
                        customer_id = existing["id"]
                        print(f"📌 Found fallback customer: {customer_name} (ID: {customer_id})")
                    else:
                        flash(f"Failed to insert or find customer: {customer_name}", "error")
                        continue

            seen_customers.add(customer_name)

            for col_key in row:
                if col_key.strip().lower() == "customer name":
                    continue

                value = (row.get(col_key) or "").strip()
                if not value or value == "-":
                    continue

                try:
                    # Parse and clean the expiration date
                    date_str = value.split(" - ")[-1].strip().replace("/", "-")

                    try:
                        exp_date = datetime.strptime(date_str, "%m-%d-%Y")
                    except ValueError:
                        try:
                            exp_date = datetime.strptime(date_str, "%Y-%m-%d")
                        except ValueError:
                            print(f"❌ Invalid date format: {date_str}")
                            continue

                    act_date = exp_date.replace(year=exp_date.year - 1)
                    status = "Expired" if exp_date.date() < datetime.today().date() else "Active"

                    # Insert certificate
                    try:
                        cursor.execute("""
                            INSERT INTO certificates (customer_id, cert_type, status, activation_date, expiration_date, verified)
                            VALUES (?, ?, ?, ?, ?, 0)
                        """, (
                            customer_id,
                            col_key.strip(),
                            status,
                            act_date.strftime("%Y-%m-%d"),
                            exp_date.strftime("%Y-%m-%d")
                        ))
                        certificate_count += 1
                        print(f"📄 Added cert '{col_key.strip()}' for '{customer_name}'")
                    except Exception as cert_err:
                        print("❌ Cert insert failed:")
                        print(f"Customer ID: {customer_id}")
                        print(f"Type: {col_key.strip()}, Act: {act_date}, Exp: {exp_date}")
                        print("Error:", cert_err)

                except Exception as parse_err:
                    print(f"❌ Failed to parse certificate for {customer_name} - {col_key}: {parse_err}")
                    continue

        conn.commit()
        conn.close()
        print("✅ DB commit complete.")

        flash(f"✅ Imported {customer_count} new customers and {certificate_count} certificates successfully!", "success")

    except Exception as e:
        print("❌ CSV Import Error:", e)
        flash(f"❌ Import failed: {e}", "error")

    return redirect(url_for('dashboard'))

@app.route('/manage-customers')
def manage_customers():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    customers = conn.execute("SELECT * FROM customers ORDER BY name ASC").fetchall()
    conn.close()
    return render_template("manage_customers.html", customers=customers)
@app.route('/manage-certificates')
def manage_certificates():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    manual_types = conn.execute("SELECT name, 'manual' as source FROM certificate_types").fetchall()
    auto_types = conn.execute("SELECT DISTINCT cert_type as name, 'auto' as source FROM certificates").fetchall()
    conn.close()

    combined = manual_types + [r for r in auto_types if r['name'] not in [m['name'] for m in manual_types]]
    return render_template("manage_certificates.html", cert_types=combined)
@app.route('/add-cert-type', methods=['POST'])
def add_certificate_type():
    if 'user_id' not in session or session.get("role") != "admin":
        flash("Unauthorized", "error")
        return redirect(url_for('manage_certificates'))

    name = request.form.get('cert_name', '').strip()
    if not name:
        flash("Certificate name required", "error")
        return redirect(url_for('manage_certificates'))

    try:
        conn = get_db_connection()
        conn.execute("INSERT INTO certificate_types (name) VALUES (?)", (name,))
        conn.commit()
        conn.close()
        flash("Certificate type added successfully!", "success")
    except sqlite3.IntegrityError:
        flash("Certificate type already exists.", "error")

    return redirect(url_for('manage_certificates'))
@app.route('/delete-certificate-type', methods=["POST"])
def delete_certificate_type():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized", "error")
        return redirect(url_for('manage_certificates'))

    name = request.form.get("name").strip()
    source = request.form.get("source")

    conn = get_db_connection()
    try:
        if source == 'manual':
            conn.execute("DELETE FROM certificate_types WHERE name = ?", (name,))
        elif source == 'auto':
            conn.execute("DELETE FROM certificates WHERE cert_type = ?", (name,))
        conn.commit()
        flash(f"Deleted certificate type: {name}", "success")
    except Exception as e:
        flash(f"Error deleting certificate type: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('manage_certificates'))
@app.route('/report')
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    name_filter = request.args.get('name', '').strip().lower()
    status_filter = request.args.get('status', '')
    type_filter = request.args.get('type', '')

    conn = get_db_connection()

    query = '''
        SELECT c.name AS customer_name, c.code AS customer_code,
               cert.cert_type, cert.status,
               cert.activation_date, cert.expiration_date,
               (SELECT COUNT(*) FROM certificates WHERE customer_id = c.id) as total_certs
        FROM certificates cert
        JOIN customers c ON cert.customer_id = c.id
    '''
    filters = []
    params = []

    if name_filter:
        filters.append("LOWER(c.name) LIKE ?")
        params.append(f"%{name_filter}%")
    if status_filter:
        filters.append("cert.status = ?")
        params.append(status_filter)
    if type_filter:
        filters.append("cert.cert_type = ?")
        params.append(type_filter)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    query += " ORDER BY c.name ASC, cert.cert_type ASC"

    report = conn.execute(query, params).fetchall()

    cert_types = [row["cert_type"] for row in conn.execute("SELECT DISTINCT cert_type FROM certificates").fetchall()]
    conn.close()

    return render_template("report.html", report=report, cert_types=cert_types)
@app.route('/download-report')
def download_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    name_filter = request.args.get('name', '').strip().lower()
    status_filter = request.args.get('status', '')
    type_filter = request.args.get('type', '')

    conn = get_db_connection()

    query = '''
        SELECT c.name AS customer_name, cert.cert_type, cert.status,
               cert.activation_date, cert.expiration_date
        FROM certificates cert
        JOIN customers c ON cert.customer_id = c.id
    '''
    filters = []
    params = []

    if name_filter:
        filters.append("LOWER(c.name) LIKE ?")
        params.append(f"%{name_filter}%")
    if status_filter:
        filters.append("cert.status = ?")
        params.append(status_filter)
    if type_filter:
        filters.append("cert.cert_type = ?")
        params.append(type_filter)

    if filters:
        query += " WHERE " + " AND ".join(filters)

    query += " ORDER BY c.name ASC, cert.cert_type ASC"

    report = conn.execute(query, params).fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Customer Name", "Certificate Type", "Status", "Activation Date", "Expiration Date"])

    for row in report:
        writer.writerow([
            row["customer_name"], row["cert_type"], row["status"],
            row["activation_date"], row["expiration_date"]
        ])

    output.seek(0)
    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=customer_report.csv"})
@app.route('/add-customer', methods=["POST"])
def add_customer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get("role") != "admin":
        flash("Only admin can add customers.", "error")
        return redirect(url_for('dashboard'))
    code = request.form.get("code", "").strip().upper()
    name = request.form.get("name").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    pan = request.form.get("pan", "").strip()
    gst = request.form.get("gst", "").strip()
    address = request.form.get("address", "").strip()
    if not code or not name:
        flash("Customer ID and name are required", "error")
        return redirect(url_for('dashboard'))
    
    
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO customers (code, name, address, email, phone, pan, gst)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (code, name, address, email, phone, pan, gst))
        conn.commit()
        flash("Customer added successfully!", "success")
    except Exception as e:
        flash(f"Error adding customer: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('dashboard'))
from dateutil.relativedelta import relativedelta

@app.route('/add-certificate', methods=["POST"])
def add_certificate():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    customer_id = request.form.get("customer_id")
    cert_type = request.form.get("cert_type", "").strip()
    expiration_date = request.form.get("expiration_date")
    activation_date = request.form.get("activation_date")

    if not customer_id or not cert_type or not expiration_date or not activation_date:
        flash("All fields are required to add a certificate.", "error")
        return redirect(url_for('dashboard'))
    
    try:
        exp_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        act_date = datetime.strptime(activation_date, "%Y-%m-%d")
        if act_date > exp_date:
            flash("Activation date cannot be later than Expiration date.", "error")
            return redirect(url_for('dashboard'))
        today = datetime.today().date()

        # Set status based on expiration
        status = "Expired" if exp_date.date() < today else "Unverified"

        # Prevent duplicates
        conn = get_db_connection()
        duplicate = conn.execute("""
            SELECT 1 FROM certificates
            WHERE customer_id = ? AND cert_type = ?
        """, (customer_id, cert_type)).fetchone()

        if duplicate:
            conn.close()
            flash("This certificate already exists for the customer.", "error")
            return redirect(url_for('dashboard'))

        # Insert new certificate
        conn.execute("""
            INSERT INTO certificates (customer_id, cert_type, status, activation_date, expiration_date, verified)
            VALUES (?, ?, ?, ?, ?, 0)
        """, (
            customer_id,
            cert_type,
            status,
            act_date.strftime("%Y-%m-%d"),
            exp_date.strftime("%Y-%m-%d")
        ))
        conn.commit()
        conn.close()

        flash("Certificate added successfully!", "success")

    except Exception as e:
        flash(f"Error adding certificate: {e}", "error")

    return redirect(url_for('dashboard'))



@app.route('/verify/<int:cert_id>', methods=["POST"])
def verify(cert_id):
    if 'user_id' not in session or session.get("role") != "admin":
        flash("Only admin can verify certificates.", "error")
        return redirect(url_for('dashboard'))

    try:
        conn = get_db_connection()
        cert = conn.execute("SELECT expiration_date FROM certificates WHERE id = ?", (cert_id,)).fetchone()
        if not cert:
            flash("Certificate not found", "error")
            return redirect(url_for('dashboard'))

        exp_date = datetime.strptime(cert["expiration_date"], "%Y-%m-%d")
        status = "Expired" if exp_date.date() < datetime.today().date() else "Active"

        conn.execute("""
            UPDATE certificates SET verified = 1, status = ? WHERE id = ?
        """, (status, cert_id))
        conn.commit()
        conn.close()

        flash("Certificate verified successfully!", "success")
    except Exception as e:
        flash(f"Verification failed: {e}", "error")

    return redirect(url_for('dashboard'))

@app.route('/delete-customer/<int:id>', methods=['POST'])
def delete_customer(id):
    if 'user_id' not in session or session.get("role") != "admin":
        flash("Unauthorized access", "error")
        return redirect(url_for('manage_customers'))

    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM certificates WHERE customer_id = ?", (id,))
        conn.execute("DELETE FROM customers WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        flash("Customer and all associated certificates deleted.", "success")
    except Exception as e:
        flash(f"Error deleting customer: {e}", "error")

    return redirect(url_for('manage_customers'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


def clean_and_parse_date(raw_date):
    """
    Cleans irregular date strings and returns a valid datetime object.
    Supports formats like:
    - '2023-05-12'
    - '12/5/2023'
    - ' y-12/5/2023 '
    - '2023/5/12'
    """
    if not raw_date or raw_date.strip() == "":
        return None

    # Remove unwanted characters (like 'y-', spaces, dashes at front)
    cleaned = re.sub(r'[^0-9/.\-]', '', raw_date.strip())

    # Common fixes:
    cleaned = cleaned.replace('.', '/').replace('-', '/')

    # Try different formats
    date_formats = ["%d/%m/%Y", "%Y/%m/%d", "%d-%m-%Y", "%Y-%m-%d", "%d/%m/%y", "%Y/%d/%m"]
    
    for fmt in date_formats:
        try:
            return datetime.strptime(cleaned, fmt)
        except:
            continue

    return None
# --- Start Server ---
if __name__ == '__main__':
    init_db()
    app.run(debug=True, host="0.0.0.0", port=2000)
