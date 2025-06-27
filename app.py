
import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re
import io
import csv

from dateutil.relativedelta import relativedelta

app = Flask(__name__)
app.secret_key = "supersecretkey"
DATABASE = 'database.db'
ADMIN_EMAIL = "admin@example.com"

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()

        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT
        )''')

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
        conn.commit()

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
        email = request.form["email"]
        password = request.form["password"]
        hashed_pw = generate_password_hash(password)
        role = "admin" if email == ADMIN_EMAIL else "deo"
        try:
            conn = get_db_connection()
            conn.execute("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", (name, email, hashed_pw, role))
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
        SELECT cert.*, customers.name as customer_name, customers.code as customer_code
        FROM certificates cert
        JOIN customers ON cert.customer_id = customers.id
        ORDER BY cert.id DESC
    """).fetchall()
    all_customers = conn.execute("SELECT id, name, code FROM customers ORDER BY name").fetchall()
    cert_types = [row['cert_type'] for row in conn.execute("SELECT DISTINCT cert_type FROM certificates").fetchall()]
    conn.close()
    return render_template("dashboard.html", certificates=certificates, all_customers=all_customers, cert_types=cert_types, role=session.get("role"))

@app.route('/import-csv', methods=['POST'])
def import_csv():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    file = request.files.get('csv_file')
    if not file:
        flash("No file uploaded", "error")
        return redirect(url_for('dashboard'))
    try:
        stream = io.StringIO(file.stream.read().decode("utf-8"))
        reader = csv.DictReader(stream)
        conn = get_db_connection()
        cursor = conn.cursor()
        customer_count = 0
        certificate_count = 0
        for row in reader:
            customer_name = row.get("Customer Name", "").strip()
            if not customer_name:
                continue
            cursor.execute("SELECT id FROM customers WHERE name = ?", (customer_name,))
            customer = cursor.fetchone()
            if customer:
                customer_id = customer["id"]
            else:
                cursor.execute("INSERT INTO customers (name) VALUES (?)", (customer_name,))
                customer_id = cursor.lastrowid
                customer_count += 1
            for key, value in row.items():
                if key.lower() == "customer name":
                    continue
                date_str = value.strip().split(" - ")[-1].replace("/", "-")
                try:
                    exp_date = datetime.strptime(date_str, "%m-%d-%Y")
                except:
                    try:
                        exp_date = datetime.strptime(date_str, "%Y-%m-%d")
                    except:
                        continue
                act_date = exp_date - relativedelta(years=1)
                status = "Expired" if exp_date.date() < datetime.today().date() else "Active"
                cursor.execute("""
                    INSERT INTO certificates (customer_id, cert_type, status, activation_date, expiration_date, verified)
                    VALUES (?, ?, ?, ?, ?, 0)
                """, (customer_id, key.strip(), status, act_date.strftime("%Y-%m-%d"), exp_date.strftime("%Y-%m-%d")))
                certificate_count += 1
        conn.commit()
        conn.close()
        flash(f"✅ Imported {customer_count} new customers and {certificate_count} certificates successfully!", "success")
    except Exception as e:
        print("CSV Import Error:", e)
        flash(f"❌ Import failed: {e}", "error")
    return redirect(url_for('dashboard'))

@app.route('/update-customer-code', methods=["POST"])
def update_customer_code():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Unauthorized access", "error")
        return redirect(url_for('manage_customers'))

    customer_id = request.form.get("customer_id")
    customer_code = request.form.get("customer_code").strip()

    if not customer_code:
        flash("Customer ID cannot be empty.", "error")
        return redirect(url_for('manage_customers'))

    try:
        conn = get_db_connection()
        conn.execute("UPDATE customers SET code = ? WHERE id = ?", (customer_code, customer_id))
        conn.commit()
        conn.close()
        flash("Customer ID updated successfully!", "success")
    except Exception as e:
        flash(f"Failed to update customer ID: {e}", "error")

    return redirect(url_for('manage_customers'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=2546)
