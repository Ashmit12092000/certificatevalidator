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
import json # Import json for storing approved/rejected roles

from dateutil.relativedelta import relativedelta

# --- App Initialization ---
app = Flask(__name__)
app.secret_key = "supersecretkey"

DATABASE = 'database.db'
ADMIN_EMAIL = "admin@gmail.com"
APPROVER_EMAIL = "approver@gmail.com" # New: Email for the Approver role

# --- Custom Jinja2 Filters ---
def from_json_filter(value):
    """Custom Jinja2 filter to parse a JSON string."""
    if value is None:
        return [] # Return empty list for None values
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return [] # Return empty list on decoding error

app.jinja_env.filters['from_json'] = from_json_filter


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

        # Customers table (Modified: Added status column)
        cur.execute('''CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            name TEXT,
            address TEXT,
            phone TEXT,
            email TEXT,
            pan TEXT,
            gst TEXT,
            status TEXT DEFAULT 'Pending' -- 'Pending', 'Awaiting Approval', 'SSO Setup Pending', 'Final Approval Pending', 'Verified', 'Rejected'
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

        # Certificate Types table
        cur.execute('''CREATE TABLE IF NOT EXISTS certificate_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )''')

        # Role Reports table (New)
        cur.execute('''CREATE TABLE IF NOT EXISTS role_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            generated_date TEXT NOT NULL,
            status TEXT NOT NULL, -- 'Awaiting Approval', 'SSO Setup Pending', 'Final Approval Pending', 'Completed', 'Rejected'
            approved_roles TEXT, -- JSON string of initially approved cert_types
            rejected_roles TEXT, -- JSON string of initially rejected cert_types
            approver_notes TEXT,
            FOREIGN KEY(customer_id) REFERENCES customers(id)
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
            # Assign role based on email
            if user["email"] == ADMIN_EMAIL.lower():
                session["role"] = "admin"
            elif user["email"] == APPROVER_EMAIL.lower(): # New: Approver role assignment
                session["role"] = "approver"
            else:
                session["role"] = "deo"
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
        
        # Assign role based on email during signup
        if email == ADMIN_EMAIL.lower():
            role = "admin"
        elif email == APPROVER_EMAIL.lower(): # New: Approver role assignment
            role = "approver"
        else:
            role = "deo"

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

    all_customers = conn.execute("SELECT id, name, code, status FROM customers ORDER BY name").fetchall() # Added status
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

    try:
        content = file.read().decode('utf-8-sig') # handle BOM
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
            customer_name = (row.get(customer_col) or "").strip()
            if not customer_name:
                continue

            # Insert or get customer
            cursor.execute("SELECT id FROM customers WHERE name = ?", (customer_name,))
            customer = cursor.fetchone()
            if customer:
                customer_id = customer["id"]
            else:
                try:
                    # New customers from CSV start as 'Pending'
                    cursor.execute(
                        "INSERT INTO customers (name, status) VALUES (?, ?)",
                        (customer_name, 'Pending') 
                    )
                    customer_id = cursor.lastrowid
                    customer_count += 1
                except sqlite3.IntegrityError as err:
                    cursor.execute("SELECT id FROM customers WHERE name = ?", (customer_name,))
                    existing = cursor.fetchone()
                    if existing:
                        customer_id = existing["id"]
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
                            continue

                    act_date = exp_date.replace(year=exp_date.year - 1)
                    status = "Expired" if exp_date.date() < datetime.today().date() else "Active"

                    # Insert certificate (initially unverified)
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
                    except Exception as cert_err:
                        # Log error but continue
                        print(f"Error inserting certificate for {customer_name} ({col_key}): {cert_err}")

                except Exception as parse_err:
                    # Log error but continue
                    print(f"Failed to parse certificate for {customer_name} - {col_key}: {parse_err}")
                    continue

        conn.commit()
        conn.close()

        flash(f"✅ Imported {customer_count} new customers and {certificate_count} certificates successfully!", "success")

    except Exception as e:
        flash(f"❌ Import failed: {e}", "error")

    return redirect(url_for('dashboard'))

@app.route('/manage-customers')
def manage_customers():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    customers = conn.execute("SELECT * FROM customers ORDER BY name ASC").fetchall()
    conn.close()
    return render_template("manage_customers.html", customers=customers, role=session.get("role"))

# New route for customer details page
@app.route('/customer-details/<int:customer_id>')
def customer_details(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    customer = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    
    if not customer:
        flash("Customer not found.", "error")
        conn.close()
        return redirect(url_for('manage_customers'))

    certificates = conn.execute("""
        SELECT * FROM certificates WHERE customer_id = ? ORDER BY cert_type ASC
    """, (customer_id,)).fetchall()

    # Fetch the latest relevant role report for display purposes
    # This could be 'Awaiting Approval', 'SSO Setup Pending', 'Final Approval Pending', 'Completed', or 'Rejected'
    latest_report = conn.execute("""
        SELECT * FROM role_reports 
        WHERE customer_id = ? 
        ORDER BY generated_date DESC LIMIT 1
    """, (customer_id,)).fetchone()

    conn.close()

    return render_template("customer_details.html", 
                           customer=customer, 
                           certificates=certificates,
                           latest_report=latest_report,
                           role=session.get("role"))

# New: Route to update customer details
@app.route('/update-customer/<int:customer_id>', methods=["POST"])
def update_customer(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Only Admin and Approver can update customer details
    if session.get("role") not in ["admin", "approver"]:
        flash("Unauthorized to update customer details.", "error")
        return redirect(url_for('customer_details', customer_id=customer_id))

    conn = get_db_connection()
    try:
        customer = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not customer:
            flash("Customer not found.", "error")
            return redirect(url_for('manage_customers'))

        # Get data from form
        name = request.form.get("name").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        pan = request.form.get("pan", "").strip()
        gst = request.form.get("gst", "").strip()
        address = request.form.get("address", "").strip()
        code = request.form.get("code", "").strip().upper() # Customer ID can also be updated

        if not code or not name:
            flash("Customer ID and name are required.", "error")
            return redirect(url_for('customer_details', customer_id=customer_id))

        conn.execute("""
            UPDATE customers SET 
                code = ?, 
                name = ?, 
                address = ?, 
                email = ?, 
                phone = ?, 
                pan = ?, 
                gst = ?
            WHERE id = ?
        """, (code, name, address, email, phone, pan, gst, customer_id))
        conn.commit()
        flash("Customer details updated successfully!", "success")

    except Exception as e:
        print(f"Error updating customer {customer_id}: {e}")
        flash(f"Error updating customer details: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('customer_details', customer_id=customer_id))


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
            # When deleting an 'auto' type, also remove associated certificates
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
        SELECT c.id AS customer_id, c.name AS customer_name, c.code AS customer_code,
               cert.cert_type, cert.status,
               cert.activation_date, cert.expiration_date,
               cert.verified, 
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
               cert.activation_date, cert.expiration_date, cert.verified
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
    writer.writerow(["Customer Name", "Certificate Type", "Status", "Activation Date", "Expiration Date", "Verified"])

    for row in report:
        writer.writerow([
            row["customer_name"], row["cert_type"], row["status"],
            row["activation_date"], row["expiration_date"], "Yes" if row["verified"] else "No"
        ])

    output.seek(0)
    return Response(output, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=customer_report.csv"})

@app.route('/add-customer', methods=["POST"])
def add_customer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Only DEO and Admin can add customers
    if session.get("role") not in ["admin", "deo"]: 
        flash("Unauthorized to add customers.", "error")
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
        # New customer status defaults to 'Pending'
        conn.execute("""
            INSERT INTO customers (code, name, address, email, phone, pan, gst, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (code, name, address, email, phone, pan, gst, 'Pending'))
        conn.commit()
        flash("Customer added successfully! Status: Pending for Approval.", "success")
    except Exception as e:
        flash(f"Error adding customer: {e}", "error")
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

@app.route('/add-certificate', methods=["POST"])
def add_certificate():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # New: Restrict certificate addition to only 'admin' role
    if session.get("role") != "admin":
        flash("Unauthorized to add certificates. Only administrators can add certificates.", "error")
        return redirect(url_for('dashboard'))

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
        status = "Expired" if exp_date.date() < today else "Active"

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

        # Insert new certificate (initially unverified)
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

        flash("Certificate added successfully! It requires approval.", "success")

    except Exception as e:
        flash(f"Error adding certificate: {e}", "error")

    return redirect(url_for('dashboard'))

# New: Route to generate a role report for a customer
@app.route('/generate-role-report/<int:customer_id>', methods=["POST"])
def generate_role_report(customer_id):
    if 'user_id' not in session or session.get("role") != "admin":
        flash("Unauthorized to generate role reports.", "error")
        return redirect(url_for('manage_customers'))

    conn = get_db_connection()
    cursor = conn.cursor() # Get a cursor object
    try:
        customer = cursor.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not customer:
            flash("Customer not found.", "error")
            return redirect(url_for('manage_customers'))
        
        # Check if customer status is 'Pending'. Only pending customers can have reports generated.
        if customer['status'] != 'Pending':
            flash(f"Cannot generate report. Customer status is '{customer['status']}'.", "error")
            return redirect(url_for('manage_customers'))

        # Check for existing 'Awaiting Approval' report for this customer
        existing_report = cursor.execute("""
            SELECT id FROM role_reports WHERE customer_id = ? AND status = 'Awaiting Approval'
        """, (customer_id,)).fetchone()

        if existing_report:
            flash("A report for this customer is already awaiting approval.", "error")
            return redirect(url_for('manage_customers'))

        # Get all unverified certificates for the customer
        unverified_certs = cursor.execute("""
            SELECT cert_type FROM certificates WHERE customer_id = ? AND verified = 0
        """, (customer_id,)).fetchall()

        if not unverified_certs:
            flash("No unverified certificates found for this customer to generate a report.", "error")
            return redirect(url_for('manage_customers'))

        # Create a new role report
        generated_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_status = "Awaiting Approval" # Initial status for the report

        cursor.execute("""
            INSERT INTO role_reports (customer_id, generated_date, status)
            VALUES (?, ?, ?)
        """, (customer_id, generated_date, report_status))
        report_id = cursor.lastrowid # Corrected: Use cursor.lastrowid

        # Update customer status
        cursor.execute("UPDATE customers SET status = ? WHERE id = ?", ('Awaiting Approval', customer_id))
        
        # Commit all changes
        conn.commit()

        flash(f"Role Report for {customer['name']} generated and sent for approval!", "success")
    except Exception as e:
        # Log the actual error for debugging
        print(f"Error generating role report for customer_id {customer_id}: {e}")
        flash(f"Error generating role report: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('manage_customers'))

# New: Route for Approver to view pending role reports
@app.route('/approval-queue')
def approval_queue():
    if 'user_id' not in session or session.get("role") != "approver":
        flash("Unauthorized access to approval queue.", "error")
        return redirect(url_for('dashboard'))

    conn = get_db_connection()
    # Fetch reports that are 'Awaiting Approval' or 'Final Approval Pending'
    reports = conn.execute("""
        SELECT rr.*, c.name as customer_name, c.code as customer_code
        FROM role_reports rr
        JOIN customers c ON rr.customer_id = c.id
        WHERE rr.status IN ('Awaiting Approval', 'Final Approval Pending')
        ORDER BY rr.generated_date DESC
    """).fetchall()

    # For each report, fetch the associated unverified certificates (only for initial approval)
    # For final approval, we just need to confirm the report itself.
    reports_with_certs = []
    for report in reports:
        report_dict = dict(report)
        if report['status'] == 'Awaiting Approval':
            certs = conn.execute("""
                SELECT cert_type, status, activation_date, expiration_date
                FROM certificates
                WHERE customer_id = ? AND verified = 0
            """, (report['customer_id'],)).fetchall()
            report_dict['certificates_for_approval'] = [dict(c) for c in certs]
        else:
            report_dict['certificates_for_approval'] = [] # No individual cert approvals needed for final confirmation
        
        reports_with_certs.append(report_dict)

    conn.close()
    return render_template('approval_queue.html', reports=reports_with_certs, role=session.get("role"))

# New: Route for Approver to approve/reject roles within a report (initial approval)
@app.route('/approve-reject-report/<int:report_id>', methods=["POST"])
def approve_reject_report(report_id):
    if 'user_id' not in session or session.get("role") != "approver":
        flash("Unauthorized to approve/reject reports.", "error")
        return redirect(url_for('approval_queue'))

    conn = get_db_connection()
    try:
        # Fetch report along with customer details
        report = conn.execute("""
            SELECT rr.*, c.name as customer_name, c.code as customer_code, c.status as customer_current_status
            FROM role_reports rr
            JOIN customers c ON rr.customer_id = c.id
            WHERE rr.id = ?
        """, (report_id,)).fetchone()

        if not report:
            flash("Role report not found.", "error")
            return redirect(url_for('approval_queue'))

        customer_id = report['customer_id']
        customer_name = report['customer_name'] 
        approver_notes = request.form.get('approver_notes', '').strip()
        
        # This route is for the *initial* approval of certificates
        if report['status'] != 'Awaiting Approval':
            flash("This report is not in the 'Awaiting Approval' state for certificate review.", "error")
            return redirect(url_for('approval_queue'))

        approved_cert_types = request.form.getlist('approve_cert_type') 
        rejected_cert_types = request.form.getlist('reject_cert_type') 

        all_certs_for_customer = conn.execute("""
            SELECT id, cert_type FROM certificates WHERE customer_id = ? AND verified = 0
        """, (customer_id,)).fetchall()

        approved_count = 0
        rejected_count = 0

        for cert in all_certs_for_customer:
            if cert['cert_type'] in approved_cert_types:
                # Certificates remain unverified at this stage
                # conn.execute("UPDATE certificates SET verified = 1 WHERE id = ?", (cert['id'],)) # REMOVED THIS LINE
                approved_count += 1
            elif cert['cert_type'] in rejected_cert_types:
                conn.execute("UPDATE certificates SET status = 'Rejected' WHERE id = ?", (cert['id'],)) 
                rejected_count += 1

        # Determine the outcome of this initial approval step
        if approved_count > 0:
            # If any certificates are approved, move to SSO Setup Pending
            conn.execute("UPDATE customers SET status = ? WHERE id = ?", ('SSO Setup Pending', customer_id))
            conn.execute("UPDATE role_reports SET status = ?, approved_roles = ?, rejected_roles = ?, approver_notes = ? WHERE id = ?", 
                         ('SSO Setup Pending', json.dumps(approved_cert_types), json.dumps(rejected_cert_types), approver_notes, report_id))
            flash(f"Role Report for {customer_name} initially approved! Status changed to 'SSO Setup Pending'.", "success")
        else:
            # If no certificates were approved, the report is rejected at this stage
            conn.execute("UPDATE customers SET status = ? WHERE id = ?", ('Rejected', customer_id)) 
            conn.execute("UPDATE role_reports SET status = ?, approved_roles = ?, rejected_roles = ?, approver_notes = ? WHERE id = ?", 
                         ('Rejected', json.dumps(approved_cert_types), json.dumps(rejected_cert_types), approver_notes, report_id))
            flash(f"Role Report for {customer_name} rejected. No certificates verified.", "error")
        
        conn.commit()

    except Exception as e:
        print(f"Error processing initial report approval for report_id {report_id}: {e}")
        flash(f"Error processing initial report approval: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('approval_queue'))

# New: Admin action to mark SSO Setup as Complete
@app.route('/mark-sso-complete/<int:customer_id>', methods=["POST"])
def mark_sso_complete(customer_id):
    if 'user_id' not in session or session.get("role") != "admin":
        flash("Unauthorized to mark SSO setup complete.", "error")
        return redirect(url_for('manage_customers'))

    conn = get_db_connection()
    try:
        customer = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if not customer:
            flash("Customer not found.", "error")
            return redirect(url_for('manage_customers'))

        if customer['status'] != 'SSO Setup Pending':
            flash(f"Cannot mark SSO setup complete. Customer status is '{customer['status']}'.", "error")
            return redirect(url_for('manage_customers'))

        # Find the most recent 'SSO Setup Pending' report for this customer
        # Assuming one report per customer at a time for this workflow phase
        report = conn.execute("""
            SELECT id FROM role_reports 
            WHERE customer_id = ? AND status = 'SSO Setup Pending'
            ORDER BY generated_date DESC LIMIT 1
        """, (customer_id,)).fetchone()

        if not report:
            flash("No 'SSO Setup Pending' report found for this customer.", "error")
            return redirect(url_for('manage_customers'))

        report_id = report['id']

        # Update customer status to 'Final Approval Pending'
        conn.execute("UPDATE customers SET status = ? WHERE id = ?", ('Final Approval Pending', customer_id))
        
        # Update report status to 'Final Approval Pending'
        conn.execute("UPDATE role_reports SET status = ? WHERE id = ?", ('Final Approval Pending', report_id))
        
        conn.commit()
        flash(f"SSO Setup for {customer['name']} marked complete. Sent for final approval!", "success")

    except Exception as e:
        print(f"Error marking SSO setup complete for customer_id {customer_id}: {e}")
        flash(f"Error marking SSO setup complete: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('manage_customers'))

# New: Approver action for final confirmation
@app.route('/final-confirm-sso/<int:report_id>', methods=["POST"])
def final_confirm_sso(report_id):
    if 'user_id' not in session or session.get("role") != "approver":
        flash("Unauthorized for final SSO confirmation.", "error")
        return redirect(url_for('approval_queue'))

    conn = get_db_connection()
    try:
        report = conn.execute("""
            SELECT rr.*, c.name as customer_name, c.id as customer_id, c.status as customer_current_status
            FROM role_reports rr
            JOIN customers c ON rr.customer_id = c.id
            WHERE rr.id = ?
        """, (report_id,)).fetchone()

        if not report:
            flash("Role report not found for final confirmation.", "error")
            return redirect(url_for('approval_queue'))

        if report['status'] != 'Final Approval Pending' or report['customer_current_status'] != 'Final Approval Pending':
            flash("This report is not in the 'Final Approval Pending' state.", "error")
            return redirect(url_for('approval_queue'))

        customer_id = report['customer_id']
        customer_name = report['customer_name']

        # Get the list of initially approved roles from the report
        approved_roles_json = report['approved_roles']
        approved_roles = json.loads(approved_roles_json) if approved_roles_json else []

        # Mark only the initially approved certificates as verified
        for cert_type in approved_roles:
            conn.execute("""
                UPDATE certificates SET verified = 1 
                WHERE customer_id = ? AND cert_type = ? AND verified = 0
            """, (customer_id, cert_type))

        # Update customer status to 'Verified' (Final)
        conn.execute("UPDATE customers SET status = ? WHERE id = ?", ('Verified', customer_id))
        
        # Update report status to 'Completed'
        conn.execute("UPDATE role_reports SET status = ? WHERE id = ?", ('Completed', report_id))
        
        conn.commit()
        flash(f"Final SSO confirmation for {customer_name} completed. Customer is now Verified!", "success")

    except Exception as e:
        print(f"Error during final SSO confirmation for report_id {report_id}: {e}")
        flash(f"Error during final SSO confirmation: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for('approval_queue'))


@app.route('/verify/<int:cert_id>', methods=["POST"])
def verify(cert_id):
    # This route is now less critical as verification happens via role reports.
    # However, keeping it for direct manual verification if needed outside the workflow.
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
        conn.execute("DELETE FROM role_reports WHERE customer_id = ?", (id,)) # Also delete associated reports
        conn.execute("DELETE FROM customers WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        flash("Customer and all associated certificates and reports deleted.", "success")
    except Exception as e:
        flash(f"Error deleting customer: {e}", "error")

    return redirect(url_for('manage_customers'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# --- Start Server ---
if __name__ == '__main__':
    init_db()
    app.run(debug=True, host="0.0.0.0", port=2000)
