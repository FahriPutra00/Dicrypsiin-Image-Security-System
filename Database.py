import mysql.connector
import hashlib
import streamlit as st
# Koneksi ke MySQL
def create_connection():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="database_encaes"
    )
    return conn

# Membuat tabel pengguna
def create_table_user():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255), email VARCHAR(255), name VARCHAR(255), password VARCHAR(255), level VARCHAR(255))")
    conn.commit()
    conn.close()
    
def create_table_encrypted_files():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS encrypted_files (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, file_name VARCHAR(255), encrypted_data LONGBLOB, FOREIGN KEY (user_id) REFERENCES users(id)) ROW_FORMAT=DYNAMIC")
    conn.commit()
    conn.close()

# Fungsi untuk melakukan verifikasi login
def verify_login(username, password):
    query = "SELECT * FROM users WHERE username = %s AND password = %s"
    conn = create_connection()
    cursor = conn.cursor()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute(query, (username, hashed_password))
    result = cursor.fetchone()
    conn.close()
    return result

def check_username_exist(username):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    existing_user = cursor.fetchone()
    conn.close()
    return existing_user is not None

def check_email_exist(email):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    existing_email = cursor.fetchone()
    conn.close()
    return existing_email is not None

def register_query(username, email, name, password):
    if check_username_exist(username):
        raise ValueError("Username already exists")

    if check_email_exist(email):
        raise ValueError("Email already exists")

    if check_email_exist(email) == False and check_username_exist(username) == False:
        lvuser = "user"
        conn = create_connection()
        cursor = conn.cursor()
        # Hash the password using hashlib.sha256
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        query = "INSERT INTO users (username, email, name, password, level) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(query, (username, email, name, hashed_password, lvuser))
        conn.commit()
        conn.close()

def admin_register_query(username, email, name, password, lvuser):
    if check_username_exist(username):
        raise ValueError("Username already exists")

    if check_email_exist(email):
        raise ValueError("Email already exists")

    if check_email_exist(email) == False and check_username_exist(username) == False:
        conn = create_connection()
        cursor = conn.cursor()
        # Hash the password using hashlib.sha256
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        query = "INSERT INTO users (username, email, name, password, level) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(query, (username, email, name, hashed_password, lvuser))
        conn.commit()
        conn.close()

def upload_encrypt_file(user_id, file_name, file_data):
    try:
        conn = create_connection()
        cursor = conn.cursor()
        query = "INSERT INTO encrypted_files (user_id, file_name, encrypted_data) VALUES (%s, %s, %s)"
        cursor.execute(query, (user_id, file_name, file_data))
        conn.commit()
        conn.close()
        st.success("File uploaded successfully!")
    except Exception as e:
        st.error(f"Error while uploading file: {e}")
        
def get_encrypted_files(user_id):
    conn = create_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM encrypted_files WHERE user_id = %s"
    cursor.execute(query, (user_id,))
    result = cursor.fetchall()
    conn.close()
    return result or []  # Return result or an empty list if result is None

def get_users():
    conn = create_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM users"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result


def delete_file(file_id):
    conn = create_connection()
    cursor = conn.cursor()
    sql = "DELETE FROM encrypted_files WHERE id = %s"
    cursor.execute(sql, (file_id,))
    conn.commit()
    conn.close()
    
def update_user(id,username,email,name,level):
    try:
        conn = create_connection()
        cursor = conn.cursor()
        sql = "UPDATE users SET username = %s, email = %s, name = %s, level = %s WHERE id = %s"
        cursor.execute(sql, (username, email, name, level, id))
        conn.commit()
        conn.close()
        st.success("User updated successfully!")
    except Exception as e:
        st.error(f"Error while updating user: {e}")

def delete_user(id):
    try:
        conn = create_connection()
        cursor = conn.cursor()
        # Delete associated records from encrypted_files table
        delete_files_query = "DELETE FROM encrypted_files WHERE user_id = %s"
        cursor.execute(delete_files_query, (id,))
        # Delete the user
        delete_user_query = "DELETE FROM users WHERE id = %s"
        cursor.execute(delete_user_query, (id,))
        conn.commit()
        conn.close()
        st.success("User deleted successfully!")
    except Exception as e:
        st.error(f"Error while deleting user: {e}")
