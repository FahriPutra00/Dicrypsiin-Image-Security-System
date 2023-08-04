import streamlit as st
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from streamlit_option_menu import option_menu
import warnings
import hashlib
from Database import *
from Login_Register import *
warnings.filterwarnings("ignore")

# Fungsi untuk mengenkripsi teks menggunakan AES
def encrypt_text(text, key):
    # Generate a 16-byte (128-bit) key using SHA-256
    key = hashlib.sha256(key).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_text = cipher.encrypt(pad(text, AES.block_size))
    return encrypted_text

# Fungsi untuk mendekripsi teks yang telah dienkripsi menggunakan AES
def decrypt_text(encrypted_text, key):
    # Generate a 16-byte (128-bit) key using SHA-256
    key = hashlib.sha256(key).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(encrypted_text), AES.block_size)
    return decrypted_text


# Function to encrypt image using BASE64 and AES
def encrypt_image(file_data, key):
    encrypted_data = encrypt_text(file_data, key)
    encoded_data = base64.b64encode(encrypted_data).decode('ascii')
    return encoded_data

# Function to decrypt image that has been encrypted using BASE64 and AES
def decrypt_image(encoded_data, key):
    decoded_data = base64.b64decode(encoded_data.encode('ascii'))
    decrypted_data = decrypt_text(decoded_data, key)
    return decrypted_data

def save_text_to_file(text, file_name):
    with open(file_name, "w") as file:
        file.write(text)

# Streamlit app
def main_admin():
    with st.sidebar:
        selected = option_menu("Menu",["Encoding Image","Decoding Image","Image Database Admin","User Database","Log out","About"],key="main_user",
                            icons=['file-earmark-arrow-up','blockquote-left',"archive","person-lines-fill",'box-arrow-right', 'gear'], menu_icon="cast",
                            default_index=0, styles={
            "container": {"padding": "5!important", "padding-top":"0px"},
            "nav-link": {"font-size": "16px", "text-align": "left", "margin":"5px"},
        })
    st.title("Dicrypsiin Admin Page")
    st.subheader(rf"Welcome {st.session_state['name']}")
    st.write("This application encrypts and decrypts images using BASE64 and AES encryption.")
    if selected =='Encoding Image':   
        st.title("Encrypt Image using BASE64 and AES")
        file = st.file_uploader("Select an image file to encrypt", type=["jpg", "png", "jpeg"], key="file_uploader", 
                                help="Only .jpg, .png, .jpeg files allowed", accept_multiple_files=False)
        if file is not None:
            file_data = file.read()
            with st.container():
                col1, col2 = st.columns(2)
                with col1:
                    st.image(file_data, use_column_width=True)
                with col2:
                    st.header("Select Output Encryption Format")
                    st.write("""Encryption using BASE64 and AES. BASE64 transformation is an algorithm for encoding and decoding
                    data into ASCII format, which is based on a base-64 number system. The resulting characters in this Base64 transformation
                    consist of A..Z, a..z, and 0..9, as well as two additional symbolic characters, namely + and /, and one equal sign (=)
                    character used for padding and aligning binary data.""")
                    file_name_in = file.name
                    key = st.text_input("Enter encryption key:",type="password")
                    download_format = st.radio("Select output format", ("PNG", "JPG", "JPEG", "TXT"),horizontal=True)
                    upload_to_database = st.checkbox("Upload to database", value=False, key="upload_to_database")
                    if st.button("Encrypt"):
                        key = key.encode('utf-8')  # Convert key to bytes
                        encoded_data = encrypt_image(file_data, key)
                        st.success("File encrypted successfully!")
                        st.text_area("Encoded Text", value=encoded_data)
                        
                        if download_format:
                            file_extension = download_format.lower()
                            file_name = f"encrypted_image_{file_name_in}.{file_extension}"
                            if file_extension == "png":
                                mime_type = "image/png"
                                encoded_data_bytes = encoded_data.encode('ascii')
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.download_button(rf"Download Encoded Image (.{download_format})", data=encoded_data_bytes,
                                                file_name=file_name, mime=mime_type)
                                with col2:
                                    if upload_to_database == True:
                                        with st.spinner('Uploading...'):
                                            upload_encrypt_file(st.session_state['id'], file_name, encoded_data)
                            elif file_extension == "jpg":
                                mime_type = "image/jpeg"
                                encoded_data_bytes = encoded_data.encode('ascii')
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.download_button(rf"Download Encoded Image (.{download_format})", data=encoded_data_bytes,
                                                file_name=file_name, mime=mime_type)
                                with col2:
                                    if upload_to_database == True:
                                        with st.spinner('Uploading...'):
                                            upload_encrypt_file(st.session_state['id'], file_name, encoded_data)
                            elif file_extension == "jpeg":
                                mime_type = "image/jpeg"
                                encoded_data_bytes = encoded_data.encode('ascii')
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.download_button(rf"Download Encoded Image (.{download_format})", data=encoded_data_bytes,
                                                file_name=file_name, mime=mime_type)
                                with col2:
                                    if upload_to_database == True:
                                        with st.spinner('Uploading...'):
                                            upload_encrypt_file(st.session_state['id'], file_name, encoded_data)
                            elif file_extension == "txt":
                                save_text_to_file(encoded_data, "EncodedImage.txt")
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.download_button(rf"Download Encoded Image (.{download_format})", data=open("EncodedImage.txt", 'rb').read(), file_name="EncodedImage.txt")
                                with col2:
                                    if upload_to_database == True:
                                        with st.spinner('Uploading...'):
                                            upload_encrypt_file(st.session_state['id'], file_name, encoded_data)
                            else:
                                mime_type = None

    if selected =='Decoding Image':
        st.title("Decrypt Image using BASE64 and AES")
        file = st.file_uploader("Select an encoded file", type=["txt","png", "jpg", "jpeg"], key="file_uploader", 
                                help="Only .txt, .png, .jpg, .jpeg files allowed", accept_multiple_files=False)
        encoded_text = st.text_area("Enter the encoded text")
        col1, col2 = st.columns(2)
        with col1:
            key = st.text_input("Enter decryption key:",type="password")
        with col2:
            download_format = st.radio("Select output format", ("PNG", "JPG", "JPEG"),horizontal=True)
        if file is not None or encoded_text:
            if file is not None:
                try:
                    encoded_text = file.read().decode('utf-8')
                except Exception as e:
                    st.error(f"Bukan Merupakan file enkripsi: {e}")
            if st.button("Decrypt"):
                key = key.encode('utf-8')  # Convert key to bytes
                try:
                    decrypted_image = decrypt_image(encoded_text, key)
                    st.success("Text decrypted successfully!")
                    with st.container():
                        col1, col2 = st.columns(2)
                        with col1:
                            st.image(decrypted_image, use_column_width=True)
                        with col2:
                            if download_format:
                                file_extension = download_format.lower()
                                file_name_dec = f"encrypted_image.{file_extension}"
                                if file_extension == "png":
                                    mime_type = "image/png"
                                elif file_extension == "jpg":
                                    mime_type = "image/jpeg"
                                elif file_extension == "jpeg":
                                    mime_type = "image/jpeg"
                                st.download_button(rf"Download Decoded {download_format}", data=decrypted_image, file_name=file_name_dec, mime=mime_type)
                except ValueError as e:
                    st.error("Dekripsi Gagal!, Silahkan cek kembali key yang anda masukkan")
    if selected=='Image Database Admin':
        st.subheader(f'Database {st.session_state["username"]}')
        files_data = get_encrypted_files(st.session_state['id'])
        # Display the data in a table
        if len(files_data) > 0:
            id = [file_data[0] for file_data in files_data]
            file_name = [file_data[2] for file_data in files_data]
            table_data = {'ID': id, 'File Name': file_name}
            
            # Create two columns: one for the table and the other for the delete buttons
            col_table, col_buttons = st.columns([3, 1])
            
            # Display the table in the first column
            with col_table:
                st.table(table_data)
            
            # Add delete buttons to each row in the second column
            with col_buttons:
                inputid = st.number_input("Enter ID to delete", min_value=1, max_value=9999999, value=1, step=1)
                delete_button = st.button(label=f'Delete Image id {inputid}', key=f'delete_{inputid}')
                if delete_button:
                    if st.session_state.get('confirm_delete', False):
                        delete_file(inputid)  # Call a function to delete the database entry
                        st.success("Image deleted successfully!")
                        st.session_state['confirm_delete'] = False  # Reset confirm_delete to False
                        st.experimental_rerun()
                    else:
                        st.warning("Are you sure you want to delete this Image?")
                        st.session_state['confirm_delete'] = True

        else:
            st.write("No encrypted files found")
            
        if len(files_data) > 0:
            # Interaction to decrypt a file
            selected_file = st.selectbox("Select a file to decrypt", [file_data[2] for file_data in files_data], key="file_select")
            col1, col2 = st.columns(2)
            with col1:
                key = st.text_input("Enter decryption key:",type="password")
                key = key.encode('utf-8')  # Convert key to bytes
            with col2:
                download_format = st.radio("Select output format", ("PNG", "JPG", "JPEG"),horizontal=True)
            file_index = [file_data[2] for file_data in files_data].index(selected_file)
            encrypted_data = files_data[file_index][3]
            if st.button("Decrypt"):
                try:
                    encoded_text = encrypted_data.decode('utf-8')
                    decrypted_image = decrypt_image(encoded_text, key)
                    st.success("Text decrypted successfully!")
                except ValueError:
                    st.error("Decryption failed. Please check the decryption key.")
                with st.container():
                    col1, col2 = st.columns(2)
                    with col1:
                        st.image(decrypted_image, use_column_width=True)
                    with col2:
                        if download_format:
                            file_extension = download_format.lower()
                            file_name_dec = f"encrypted_image.{file_extension}"
                            if file_extension == "png":
                                mime_type = "image/png"
                            elif file_extension == "jpg":
                                mime_type = "image/jpeg"
                            elif file_extension == "jpeg":
                                mime_type = "image/jpeg"
                            st.download_button(rf"Download Decoded {download_format}", data=decrypted_image, file_name=file_name_dec, mime=mime_type)
        else:
            st.write("No encrypted files found")
    if selected=='User Database':
        st.subheader(f'Database {st.session_state["username"]}')
        users_data = get_users()
        # Display the data in a table
        if len(users_data) > 0:
            id = [user_table[0] for user_table in users_data]
            username = [user_table[1] for user_table in users_data]
            name = [user_table[3] for user_table in users_data]
            email = [user_table[2] for user_table in users_data]
            level = [user_table[5] for user_table in users_data]
            table_data = {'ID': id, 'Username': username,"Name" : name, 'Email': email, 'Level': level}
            st.table(table_data)
        else:
            st.write("No users found")
        if len(users_data) > 0:
            selected_user = st.selectbox("Select a user to modify or delete", [user_data[1] for user_data in users_data], key="select_user")
            selected_user_index = [user_data[1] for user_data in users_data].index(selected_user)
            selected_user_data = users_data[selected_user_index]

            col1, col2 = st.columns(2)
            with col1:
                id = selected_user_data[0]  # Assign the ID directly from the selected user data
                st.write("User ID: ", id)
                username = st.text_input("Username: ", selected_user_data[1])
                name = st.text_input("Name: ", selected_user_data[3])
                email = st.text_input("Email: ", selected_user_data[2])
                level = st.selectbox("Level: ", ["user", "admin"], index=0 if selected_user_data[5] == "user" else 1)

            with col2:
                st.write("Pilih Pembaharuan atau Hapus : ")
                if st.button("Update"):
                    update_user(id, username, email, name, level)
                    st.success("User updated successfully!")
                    st.experimental_rerun()
                if st.button("Delete"):
                    if st.session_state.get('confirm_delete', False):
                        delete_user(id)
                        st.success("User deleted successfully!")
                        st.session_state['confirm_delete'] = False  # Reset confirm_delete to False
                        st.experimental_rerun()
                    else:
                        st.warning("Are you sure you want to delete this user?")
                        st.session_state['confirm_delete'] = True
        st.subheader("Add New User")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Add User or Admin"):
                admin_register_query(username, email, name, password, level)
                st.success("User added successfully!")
                st.experimental_rerun()
        with col2:
            username = st.text_input("Username: ",key="usrnm_reg_admin")
            name = st.text_input("Name: ",key="name_reg_admin")
            email = st.text_input("Email: ",key="em_reg_admin")
            password = st.text_input("Password: ", type="password", key="pw_reg_admin")
            level = st.selectbox("Level: ", ["user", "admin"], index=0, key="level_reg_admin")
    if selected=='Log out':
        st.subheader("Logout")    
        confirm_logout = st.button("Click to confirm logout")
        if confirm_logout:
            st.session_state.pop('is_logged_in', None)
            st.experimental_rerun()
        
    if selected == "About":
        st.title("About")
        st.write("This application was created by: Fahri Putra Herlambang")
        st.subheader("Apa Itu Base64?")
        st.markdown("""
        Algoritma Base64 adalah sebuah metode encoding yang mengubah data biner menjadi format teks dengan menggunakan kumpulan karakter khusus yang terdiri 
        dari huruf-huruf alfanumerik (A-Z, a-z), angka (0-9), serta dua karakter khusus (+ dan /). Tujuan utama dari algoritma ini adalah untuk mewakili data 
        biner dalam bentuk teks agar dapat diunggah, ditransmisikan, atau disimpan dengan lebih mudah.
                    """)

