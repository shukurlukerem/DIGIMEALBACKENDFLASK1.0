import os 
import uuid 
import string 
from dotenv import load_dotenv
import psycopg2
import qrcode 
import base64 
import json 
from PIL import Image 
from flask_cors import cross_origin 
import smtplib 
import ssl 
from email.mime.text import MIMEText 
from email.mime.multipart import MIMEMultipart 
import atexit 
import logging 
import random 
import sqlite3 
from io import BytesIO 
from datetime import date 
from flask_cors import CORS 
from flask import Flask, request, jsonify 
import jwt 
import datetime 
from functools import wraps


app = Flask(__name__)
CORS(app, resources={r"*": {"origins": "*"}})

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')

DB_CONFIG = {
    'dbname': os.getenv('db_name'),
    'user': os.getenv('db_user'),
    'password': os.getenv('db_password'),
    'host': os.getenv('db_host'),
    'port': os.getenv('db_port')
}

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        ad varchar(50),
        soyad varchar(50),
        digimealusername varchar(15) PRIMARY KEY, 
        password varchar(15),  
        fakulte varchar(10), 
        approved varchar(2),
        email TEXT,
        fin_kod TEXT
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS qr_codes (
        id TEXT PRIMARY KEY, 
        username TEXT, 
        image BYTEA, 
        date TEXT, 
        status INTEGER DEFAULT 1, 
        status_scanner INTEGER DEFAULT 1, 
        scanner_time TEXT,
        scanner_status TEXT,
        FOREIGN KEY (username) REFERENCES users(digimealusername)
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS all_users (
        ad TEXT,
        soyad TEXT,
        ata_adi TEXT,
        fin_kod TEXT UNIQUE, 
        telefon_nomresi TEXT,
        fakulte TEXT,
        qrup_no TEXT,
        status TEXT,
        bilet INTEGER,
        email TEXT,
        approved INTEGER,
        digimealusername TEXT,
        otp INTEGER,
        password TEXT,
        document BYTEA,
        qeydiyyat_tarixi TEXT,
        qeyd TEXT
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS scanner_identification (
        scanner_username TEXT PRIMARY KEY, 
        scanner_password TEXT,
        scanner_istifadeci_adi TEXT, 
        faculty TEXT 
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS admins_identification (
        usernameadmin TEXT PRIMARY KEY,
        passwordadmin TEXT,
        istifadeci_adi TEXT,
        faculty TEXT
    )''')

    conn.commit()
    cursor.close()
    conn.close()

init_db()


# JWT token generation
def generate_jwt(username, is_admin=False, is_scanner=False):
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=10)
    payload = {
        'username': username,
        'is_admin': is_admin,
        'scanner': is_scanner,
        'exp': expiration_time
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def check_scanner_login(scanner_username, scanner_password):
    try:
        conn =  get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scanner_identification WHERE scanner_username = %s AND scanner_password = %s", 
                       (scanner_username, scanner_password))
        scanner = cursor.fetchone()
        if scanner:
            token = generate_jwt(scanner_username, is_admin=False, is_scanner=True)
            return {"success": True, "username": scanner_username, "message": "Login successful", "token": token}
        else:
            return {"success": False, "message": "Incorrect username or password"}
    finally:
        conn.close()

# Function to check user login
def check_login(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE digimealusername = %s AND password = %s", (username, password))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user:
        token = generate_jwt(username)
        return {"success": True, "username": username, "message": "Login successful", "token": token}
    return {"success": False, "message": "Incorrect username or password"}


# Function to check admin login
def check_login(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM adminsidenfication WHERE usernameadmin = %s AND passwordadmin = %s", (username, password))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    if user:
        token = generate_jwt(username)
        return {"success": True, "username": username, "message": "Login successful", "token": token}
    return {"success": False, "message": "Incorrect username or password"}


def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(receiver_email, username, otp): 
    sender_email = os.getenv('send_email') 
    sender_password =  os.getenv('send_email_password')
 
    subject = "Sizin OTP kodunuz!" 
    body = f"Sizin bir dəfəlik OTP kodunuz: {otp}\n\n Bu OTP kodu 5 dəqiqə ərzində aktivdir. \n\n İstifadəçi adı: {username} \n\n Link: http://10.10.4.112:3000/user-pass-creater?" 
 
    message = MIMEMultipart() 
    message["From"] = sender_email 
    message["To"] = receiver_email 
    message["Subject"] = subject 
    message.attach(MIMEText(body, "plain")) 
 
    try: 
        context = ssl.create_default_context() 
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server: 
            server.login(sender_email, sender_password) 
            server.sendmail(sender_email, receiver_email, message.as_string()) 
 
        print(f"OTP sent successfully to {receiver_email}") 
        return otp  # Return OTP for verification 
 
    except Exception as e: 
        print(f"Error sending OTP: {e}") 
        return None

def generate_username():
    conn = get_db_connection
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT MAX(CAST(digimealusername AS INTEGER)) FROM all_users")
        result = cursor.fetchone()[0]
        if result is None:
            return 20250000  # Start with a base username value
        return int(result) + 1
    except Exception as e:
        print(f"Error generating username: {e}")
        return None
    finally:
        conn.close()

# # Generate a random password
# def generate_pass_for_user():
#     letters_and_digits = string.ascii_letters + string.digits
#     symbols = string.punctuation

#     password = random.choice(symbols)
#     password += ''.join(random.choice(letters_and_digits) for _ in range(7))
#     password = ''.join(random.sample(password, len(password)))

#     return password

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            token = token.split(" ")[1]  # Extract token part from "Bearer <token>"
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = payload['username']
            is_admin = payload['is_admin']
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return jsonify({'message': 'Token is invalid!'}), 403

        # Add user info to the request context
        request.current_user = current_user
        request.is_admin = is_admin
        return f(*args, **kwargs)

    return decorated_function


# Routes for user and admin login
@app.route('/user/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"}), 400

    result = check_login(username, password)
    return jsonify(result), 200 if result['success'] else 401

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admins_identification WHERE usernameadmin = %s AND passwordadmin = %s", (username, password))
    admin = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if admin:
        token = generate_jwt(username, is_admin=True)
        return jsonify({"success": True, "username": username, "message": "Login successful", "token": token}), 200
    return jsonify({"success": False, "message": "Incorrect username or password"}), 401


#############

@app.route('/admin/get_admin_username', methods=['POST'])
def get_admin_username():
    data = request.json
    usernameadmin = data.get('usernameadmin')

    if not usernameadmin:
        return jsonify({"success": False, "message": "Username is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT istifadeci_adi, faculty FROM admins_identification WHERE usernameadmin = %s', (usernameadmin,))
        result = cursor.fetchall()
        results_for_admin = [{"istifadeciadi": row[0], "faculty": row[1]} for row in result]

        if results_for_admin:
            return jsonify({"success": True, "results": results_for_admin}), 200
        else:
            return jsonify({"success": False, "message": "Username not found"}), 404
    except psycopg2.Error as e:
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()

#working code for fac admin registiration
@app.route('/add', methods=['POST'])
@token_required
def add():
    try:
        data = request.json
        required_fields = ['firstname', 'lastname', 'fathername', 'fincode', 'phonenumber', 'fakulte', 
                           'groupnumber', 'status', 'bilet', 'email', 'registrationDate', 'note']
        
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({"error": f"'{field}' is required."}), 400
        
        firstname = data['firstname']
        lastname = data['lastname']
        fathername = data['fathername']
        fincode = data['fincode']
        phonenumber = data['phonenumber']
        fakulte = data['fakulte']
        qrup_no = data['groupnumber']
        status = data['status']
        bilet = data['bilet']
        email = data['email']
        registrationDate = data['registrationDate']
        note = data['note']
        
        sessiya_json = json.dumps({"session_start": registrationDate})
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(''' 
            INSERT INTO all_users (ad, soyad, ata_adi, fin_kod, telefon_nomresi, fakulte, qrup_no, 
                                   status, bilet, email, qeyd, approved, sessiya, qeydiyyat_tarixi)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (firstname, lastname, fathername, fincode, phonenumber, fakulte, qrup_no, 
              status, bilet, email, note, 0, sessiya_json, registrationDate))
        
        cursor.execute(''' 
            INSERT INTO users (ad, soyad, status, email, fakulte, approved, fin_kod)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        ''', (firstname, lastname, status, email, fakulte, 1, fincode))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({"message": "Record added successfully."}), 201
    
    except psycopg2.IntegrityError as e:
        return jsonify({"error": "Duplicate entry. The fin_kod or email might already exist."}), 400
    except psycopg2.Error as e:
        return jsonify({"error": "Database error occurred.", "details": str(e)}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred.", "details": str(e)}), 50

@app.route('/notapproved/<faculty>', methods=['GET'])
@token_required
def get_not_approved_students(faculty):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT ad, soyad, ata_adi, digimealusername, fin_kod, telefon_nomresi, fakulte, qrup_no, status, bilet, email FROM all_users WHERE fakulte = %s AND approved = 0', 
            (faculty,)
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        
        if rows:
            result = [
                {
                    "ad": row[0], "soyad": row[1], "ata_adi": row[2], "digimealusername": row[3],
                    "fin_kod": row[4], "phonenumber": row[5], "fakulte": row[6], "qrup_no": row[7],
                    "status": row[8], "bilet": row[9], "email": row[10]
                }
                for row in rows
            ]
            return {"results": result}, 200
        else:
            return {"message": "No students found for the specified faculty."}, 404
    except psycopg2.Error as e:
        return {"error": str(e)}, 500
    

@app.route('/fac_approved/<faculty>', methods=['GET'])
@token_required
def fac_get_approved_students(faculty):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT ad, soyad, ata_adi, digimealusername, fin_kod, telefon_nomresi, fakulte, qrup_no, status, bilet, email, qeyd FROM all_users WHERE fakulte = %s AND approved = 1', 
            (faculty,)
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        
        if rows:
            result = [
                {
                    "ad": row[0], "soyad": row[1], "ata_adi": row[2], "digimealusername": row[3],
                    "fin_kod": row[4], "phonenumber": row[5], "fakulte": row[6], "qrup_no": row[7],
                    "status": row[8], "bilet": row[9], "email": row[10], "qeyd": row[11]
                }
                for row in rows
            ]
            return {"results": result}, 200
        else:
            return {"message": "No students found for the specified faculty."}, 404
    except psycopg2.Error as e:
        return {"error": str(e)}, 500

# Super Admin approved users route
@app.route('/superadmin_approved/', methods=['GET'])
@token_required
def get_approved_students_sp_admin():
    try:
        print("Attempting to fetch approved students...")

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                print("Database connection established.")

                cursor.execute(
                    '''SELECT ad, soyad, ata_adi, digimealusername, fin_kod, telefon_nomresi, 
                              fakulte, qrup_no, status, bilet, email, qeyd 
                       FROM all_users WHERE approved = 1'''
                )
                rows = cursor.fetchall()
                print(f"Rows fetched: {len(rows)}")

        # Process rows
        result = [
            {
                "ad": row[0],
                "soyad": row[1],
                "ata_adi": row[2],
                "digimealusername": row[3],
                "fin_kod": row[4],
                "phonenumber": row[5],
                "fakulte": row[6],
                "qrup_no": row[7],
                "status": row[8],
                "bilet": row[9],
                "email": row[10],
                "qeyd": row[11]
            }
            for row in rows
        ]

        return jsonify({"results": result}), 200

    except psycopg2.Error as e:
        print(f"PostgreSQL error occurred: {str(e)}")
        return jsonify({"error": "Database error", "details": str(e)}), 500

    except Exception as e:
        print(f"Unexpected error occurred: {str(e)}")
        return jsonify({"error": "Unexpected error", "details": str(e)}), 500


@app.route('/superadmin_session_ended/', methods=['GET'])
@token_required
def get_session_ended_students_sp_admin():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    '''SELECT ad, soyad, ata_adi, digimealusername, fin_kod, telefon_nomresi, 
                              fakulte, qrup_no, status, bilet, email 
                       FROM all_users WHERE approved = 2'''
                )
                rows = cursor.fetchall()
                print(f"Rows fetched for session-ended users: {len(rows)}")

        result = [
            {
                "ad": row[0],
                "soyad": row[1],
                "ata_adi": row[2],
                "digimealusername": row[3],
                "fin_kod": row[4],
                "phonenumber": row[5],
                "fakulte": row[6],
                "qrup_no": row[7],
                "status": row[8],
                "bilet": row[9],
                "email": row[10]
            }
            for row in rows
        ]

        return jsonify({"results": result}), 200

    except psycopg2.Error as e:
        print(f"PostgreSQL error occurred: {str(e)}")
        return jsonify({"error": "Database error", "details": str(e)}), 500
    

# Super Admin waiting approved route
@app.route('/superadmin_notapproved/', methods=['GET'])
@token_required
def get_not_approved_students_sp_admin():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    '''SELECT ad, soyad, ata_adi, digimealusername, fin_kod, telefon_nomresi, 
                              fakulte, qrup_no, status, bilet, email 
                       FROM all_users WHERE approved = 0'''
                )
                rows = cursor.fetchall()
        
        result = [
            {
                "ad": row[0],
                "soyad": row[1],
                "ata_adi": row[2],
                "digimealusername": row[3],
                "fin_kod": row[4],
                "phonenumber": row[5],
                "fakulte": row[6],
                "qrup_no": row[7],
                "status": row[8],
                "bilet": row[9],
                "email": row[10]
            }
            for row in rows
        ]
        
        return jsonify({"results": result}), 200

    except psycopg2.Error as e:
        return jsonify({"error": "Database error", "details": str(e)}), 500


# @app.route('/request-otp/<email>', methods=['POST'])
# def request_otp(email):
#     if not email:
#         return jsonify({'message': 'Email is required'}), 400

#     otp = generate_otp()

#     try:
#         with get_db_connection() as conn:
#             with conn.cursor() as cursor:
#                 cursor.execute("UPDATE all_users SET otp = %s WHERE email = %s", (otp, email))
#                 conn.commit()

#         return jsonify({'message': 'OTP set successfully'}), 200

#     except psycopg2.Error as e:
#         return jsonify({'message': f'Database error: {e}'}), 500


@app.route('/verify-otp', methods=['POST'])
@token_required
def verify_otp():
    data = request.json
    username = data.get('username')
    otp = data.get('otp')
    password = data.get('password')
    print(password, username, otp)
    currentDate = datetime.date.today()

    if not username or not otp or not password:
        return jsonify({'message': 'Username, OTP, and password are required'}), 400

    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()

        # Retrieve the OTP from the database
        cursor.execute("SELECT otp FROM all_users WHERE digimealusername = %s", (username,))
        result = cursor.fetchone()

        if result and str(result[0]) == otp:
            cursor.execute("""
                UPDATE all_users  
                SET approved = 1, otp = NULL, password = %s, qeydiyyat_tarixi = %s 
                WHERE digimealusername = %s
            """, (password, currentDate, username))

            cursor.execute("""
                UPDATE users  
                SET approved = 1, password = %s  
                WHERE digimealusername = %s
            """, (password, username))

            conn.commit()
            cursor.close()
            conn.close()

            return jsonify({
                'message': 'OTP verified successfully',
                'digimealusername': username
            }), 200
        else:
            return jsonify({'message': 'Invalid OTP'}), 400
    except psycopg2.Error as e:
        return jsonify({'message': f'Database error: {e}'}), 500

@app.route('/sesion_end/<digimealusername>', methods=['GET'])
@token_required
def sesion_end(digimealusername):
    current_date = datetime.date.today().strftime('%Y-%m-%d')
    logging.info(f"Session end requested for user: {digimealusername}")

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Fetch current 'sessiya' JSON
                cursor.execute('SELECT sessiya FROM all_users WHERE digimealusername = %s', (digimealusername,))
                result = cursor.fetchone()

                if not result:
                    logging.warning(f"User {digimealusername} not found.")
                    return {"error": "User not found."}, 404

                sessiya = result[0] if result[0] else "{}"  # Handle NULL case
                sessiya_data = json.loads(sessiya)

                # Add session end date dynamically
                dynamic_key = f"sessiya_bitme_{current_date}"
                sessiya_data[dynamic_key] = current_date

                updated_sessiya = json.dumps(sessiya_data)

                # Update database
                cursor.execute("""
                    UPDATE all_users
                    SET sessiya = %s::jsonb, approved = 2
                    WHERE digimealusername = %s
                """, (updated_sessiya, digimealusername))

                cursor.execute("""
                    UPDATE users 
                    SET approved = 2
                    WHERE digimealusername = %s
                """, (digimealusername,))

                conn.commit()
                return {"message": "Session ended successfully", "username": digimealusername}, 200

    except psycopg2.Error as e:
        logging.error(f"PostgreSQL error: {str(e)}")
        return {"error": f"Database error: {str(e)}"}, 500
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return {"error": f"An unexpected error occurred: {str(e)}"}, 500


@app.route('/sesion_recover/<digimealusername>', methods=['GET'])
@token_required
def sesion_recover(digimealusername):
    current_date = datetime.date.today().strftime('%Y-%m-%d')
    logging.info(f"Session recovery requested for user: {digimealusername}")

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Fetch current 'sessiya' JSON
                cursor.execute('SELECT sessiya FROM all_users WHERE digimealusername = %s', (digimealusername,))
                result = cursor.fetchone()

                if not result:
                    logging.warning(f"User {digimealusername} not found.")
                    return {"error": "User not found."}, 404

                sessiya = result[0] if result[0] else "{}"
                sessiya_data = json.loads(sessiya)

                # Add session start date dynamically
                new_key = f"sessiya_baslama_{current_date}"
                sessiya_data[new_key] = current_date

                updated_sessiya = json.dumps(sessiya_data)

                # Update database
                cursor.execute("""
                    UPDATE all_users
                    SET sessiya = %s::jsonb, approved = 1
                    WHERE digimealusername = %s
                """, (updated_sessiya, digimealusername))

                cursor.execute("""
                    UPDATE users 
                    SET approved = 1
                    WHERE digimealusername = %s
                """, (digimealusername,))

                conn.commit()
                return {"message": "Session recovered successfully", "username": digimealusername}, 200

    except psycopg2.Error as e:
        logging.error(f"PostgreSQL error: {str(e)}")
        return {"error": f"Database error: {str(e)}"}, 500
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return {"error": f"An unexpected error occurred: {str(e)}"}, 500



@app.route('/delete_user/<fin_kod>', methods=['DELETE'])
@token_required
def delete_user(fin_kod):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('DELETE FROM all_users WHERE fin_kod = %s', (fin_kod,))
                cursor.execute('DELETE FROM users WHERE fin_kod = %s', (fin_kod,))
                conn.commit()

                if cursor.rowcount > 0:
                    return {"message": f"User with FIN code '{fin_kod}' successfully deleted."}, 200
                else:
                    return {"message": f"No user found with FIN code '{fin_kod}'."}, 404
    except psycopg2.Error as e:
        return {"error": str(e)}, 500


# Route to generate QR code for user
@app.route('/user/generate_qr', methods=['POST'])
@token_required
def generate_qr():
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({"success": False, "message": "Username is required."}), 400

    today = str(date.today())

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT id, image, date FROM qr_codes WHERE username = %s AND date = %s', (username, today))
                existing_qr = cursor.fetchone()

                if existing_qr:
                    return jsonify({
                        "success": True,
                        "id": existing_qr[0],
                        "image": existing_qr[1],
                        "date": existing_qr[2]
                    })

                # Generate a new QR code with a unique ID
                qr_id = str(uuid.uuid4())  
                qr_image = generate_qr_code(qr_id)  

                cursor.execute('''INSERT INTO qr_codes (id, username, image, date, status) 
                                  VALUES (%s, %s, %s, %s, 1)''',
                               (qr_id, username, qr_image, today))

                conn.commit()

                return jsonify({
                    "success": True,
                    "id": qr_id,  
                    "image": qr_image,
                    "date": today
                })

    except psycopg2.Error as e:
        return jsonify({"error": f"Database error: {str(e)}"}), 500


# Function to generate QR code image
def generate_qr_code(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)  
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode("utf-8")


# Route to get the username for a user
@app.route('/user/username', methods=['POST'])
@token_required
def get_username():
    digimealusername = request.current_user  

    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute('SELECT ad FROM users WHERE digimealusername = %s', (digimealusername,))
                result = cursor.fetchone()

                if result:
                    return jsonify({"success": True, "istifadeci_adi": result[0]}), 200
                else:
                    return jsonify({"success": False, "message": "Username not found"}), 404

    except psycopg2.Error as e:
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    

@app.route('/user/settings/', methods=['GET'])
@token_required
def get_user_settings():
    digimealusername = request.current_user  # Get the username from the token
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT ad, soyad, status FROM users WHERE digimealusername = %s', (digimealusername,))
        user = cursor.fetchone()
        
        if user:
            return jsonify({
                "ad": user[0],
                "soyad": user[1],
                "status": user[2]
            }), 200
        else:
            return jsonify({"error": "User not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/user/history/<username>', methods=['GET'])
@token_required
def history(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, date, status FROM qr_codes WHERE username = %s', (username,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    qr_data = [{"id": row[0], "date": row[1], "status": row[2]} for row in rows]
    return jsonify(qr_data), 200

@app.route('/user/get_qrs/<username>', methods=['GET'])
@token_required
def get_qrs(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, image, date, status FROM qr_codes WHERE username = %s', (username,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    qr_data = [{"id": row[0], "image": row[1], "date": row[2], "status": row[3]} for row in rows]
    return jsonify(qr_data), 200

@app.route('/scanner/login', methods=['POST'])
def scanner_login():
    data = request.json
    scanner_username = data.get('username')
    scanner_password = data.get('password')
    if not scanner_username or not scanner_password:
        return jsonify({"success": False, "message": "Username and password required"}), 400
    result = check_scanner_login(scanner_username, scanner_password)
    return jsonify(result), 200 if result['success'] else 401

@app.route('/scanner/get_scanner_username', methods=['POST'])
@token_required
def get_scanner_username():
    data = request.json
    usernamesc = data.get('usernamesc')

    if not usernamesc:
        return jsonify({"success": False, "message": "Username is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT scanner_istifadeci_adi, faculty FROM scanner_identification WHERE scanner_username = %s', 
                       (usernamesc,))
        result = cursor.fetchall()

        results_for_sc = [{"istifadeciadi": row[0], "faculty": row[1]} for row in result]

        if results_for_sc:
            return jsonify({"success": True, "results": results_for_sc}), 200
        else:
            return jsonify({"success": False, "message": "Username not found"}), 404
    except psycopg2.Error as e:
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/scannerscan', methods=['POST'])
def update_status_in_db():
    conn = None
    try:
        data = request.get_json()
        qr_id = data.get("qr_id")
        bufet = data.get("bufet")

        if not qr_id or not bufet:
            return jsonify({"message": "QR ID and bufet are required"}), 400

        print(f"QR ID received: {qr_id}, Bufet received: {bufet}")

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the QR ID exists with status 1
        print(f"Executing query with QR ID: {qr_id}")
        cursor.execute("SELECT * FROM qr_codes WHERE id = %s AND status = 1", (qr_id,))
        result = cursor.fetchone()

        if result:
            # Update status to 0 and set bufet value if a match is found
            print(f"Found QR ID: {qr_id}, updating status and bufet.")
            cursor.execute("UPDATE qr_codes SET status = 0, bufet = %s WHERE id = %s", (bufet, qr_id))
            conn.commit()
            return jsonify({"message": f"QR Code {qr_id} status updated and bufet set to {bufet}."}), 200
        else:
            print(f"No matching QR ID {qr_id} with status 1 found.")
            return jsonify({"message": f"No matching QR ID {qr_id} with status 1 found."}), 404
    except psycopg2.Error as e:
        print(f"Error updating status in database: {e}")
        return jsonify({"message": "Database error occurred"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/get_bufet_account', methods=['GET'])
@token_required
def get_bufet_account():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT date, qiymet, bufet FROM qr_codes WHERE status = 0 AND bufet IS NOT NULL")
        result = cursor.fetchall()

        if result:
            qr_codes = [{"date": row[0], "qiymet": row[1], "bufet": row[2]} for row in result]
            return jsonify({"success": True, "data": qr_codes}), 200
        else:
            return jsonify({"success": False, "message": "No data found"}), 404

    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return jsonify({"success": False, "message": "Database error occurred"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/get_last_5_qr_codes', methods=['GET'])
@token_required
def get_last_5_qr_codes_route():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM qr_codes ORDER BY date DESC LIMIT 5"
        cursor.execute(query)
        rows = cursor.fetchall()
        print(rows)

        result = []
        for row in rows:
            result.append({
                'username': row[1],  
                'date': row[3],      
                'status': row[4],    
                'qiymet': row[5],    
            })

        return jsonify(result)
    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return jsonify({"success": False, "message": "Database error occurred"}), 500
    finally:
        if conn:
            conn.close()



@app.route('/get_all_user_account', methods=['GET'])
@token_required
def get_all_user_account():
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        cursor.execute("SELECT ad, soyad, ata_adi, fin_kod, fakulte, status, approved, digimealusername, document, qeydiyyat_tarixi, qeyd, telefon_nomresi, qrup_no, sessiya FROM all_users WHERE approved = 1")
        result = cursor.fetchall()
        
        if result:
            qr_codes = [{
                "ad": row[0], 
                "soyad": row[1], 
                "ata_adi": row[2],
                "fin_kod": row[3],
                "fakulte": row[4],
                "status": row[5],
                "approved": row[6],
                "digimealusername": row[7],
                "document": row[8],
                "qeydiyyat_tarixi": row[9],
                "qeyd": row[10],
                "phonenumber": row[11],
                "qrup_no": row[12],
                "sessiya": row[13]
            } for row in result]
            return jsonify({"success": True, "data": qr_codes}), 200
        else:
            return jsonify({"success": False, "message": "No data found"}), 404
    
    except psycopg2.Error as e:
        print(f"Database error: {e}")
        return jsonify({"success": False, "message": "Database error occurred"}), 500
    
    finally:
        if conn:
            conn.close()

def send_otp(receiver_email): 
    sender_email = "thik@aztu.edu.az" 
    sender_password = "xjxi kknj rvmt sciz" 
 
    otp = generate_otp() 
     
    # Email content 
    subject = "Sizin OTP kodunuz!" 
    body = f"Sizin bir dəfəlik OTP kodunuz: {otp}\n\n Bu OTP kodu 5 dəqiqə ərzində aktivdir." 
 
    # Setup email headers 
    message = MIMEMultipart() 
    message["From"] = sender_email 
    message["To"] = receiver_email 
    message["Subject"] = subject 
 
    # Attach email body 
    message.attach(MIMEText(body, "plain")) 
 
    # Secure connection with Gmail SMTP server 
    try: 
        context = ssl.create_default_context() 
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server: 
            server.login(sender_email, sender_password) 
            server.sendmail(sender_email, receiver_email, message.as_string()) 
 
        print(f"OTP sent successfully to {receiver_email}") 
        return otp  # Return OTP for verification 
 
    except Exception as e: 
        print(f"Error sending OTP: {e}") 
        return None

@app.route('/request-and-send-otp', methods=['POST'])
@token_required
def request_and_send_otp():
    data = request.get_json()
    receiver_email = data.get("email")
    print(receiver_email)

    if not receiver_email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    otp = generate_otp()
    username = generate_username()

    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET digimealusername = %s WHERE email = %s", (username, receiver_email))
        cursor.execute("UPDATE all_users SET otp = %s, digimealusername = %s WHERE email = %s", (otp, username, receiver_email))
        conn.commit()
        cursor.close()
        conn.close()
    except psycopg2.Error as e:
        return jsonify({"success": False, "message": f"Database error: {e}"}), 500

    otp_sent = send_otp(receiver_email, username, otp)
    if otp_sent:
        return jsonify({"success": True, "message": "OTP sent successfully"}), 200
    else:
        return jsonify({"success": False, "message": "Failed to send OTP"}), 5000



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=80)