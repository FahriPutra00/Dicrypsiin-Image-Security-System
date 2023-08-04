import streamlit as st
from streamlit_option_menu import option_menu
from Database import *
from ImageSecAES_Database import *
from ImageSecAES_Database_Admin import *
import warnings
warnings.filterwarnings("ignore")

# Halaman register
def register():
    st.subheader("Register")
    username = st.text_input("Username")
    email = st.text_input("Email")
    name = st.text_input("Name")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        try:
            register_query(username,email,name,password)
            st.success("Registrasi berhasil!")
        except ValueError as e:
            st.error(f"{e} Registrasi gagal. Coba lagi.")


# Halaman login
def login():
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    result = verify_login(username, password)
    if st.button("Login"):
        if result:
            st.success("Login berhasil!")
            st.session_state['is_logged_in'] = True
            st.session_state['id'] = result[0]
            st.session_state['username'] = result[1]
            st.session_state['name'] = result[3]
            st.session_state['level'] = result[5]
            st.experimental_rerun()
        else:
            st.error("Username atau password salah.")


# Main program
def login_main():
    st.markdown(
        """
        <style>
        .center {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    st.markdown('<div class="center"><h1>Dicrypsiin</h1></div>', unsafe_allow_html=True)
    create_table_user()
    create_table_encrypted_files()
    selected = option_menu(None,["Login","Register"],key="login_register", default_index=0,
                                icons=['box-arrow-in-left','box-arrow-in-up'], menu_icon="cast"
                                ,orientation="horizontal")
    with st.container():
        col1, col2, col3 = st.columns([1, 4, 1])
        with col1:
            st.empty()
        with col2:
            if selected == "Login":
                login()
            elif selected == "Register":
                register()
        with col3:
            st.empty()  

if __name__ == "__main__":
    is_logged_in = st.session_state.get('is_logged_in', False)

    if not is_logged_in:
        login_main()
    elif is_logged_in:
        user_id = st.session_state.get("id")
        user_level = st.session_state.get("level")
        if user_id and user_level is not None:
            if user_level == 'user':
                main_user()
            elif user_level == 'admin':
                main_admin()
            else:
                st.write("Error: Invalid user level")
        else:
            st.write("Error: Invalid user")
    else:
        st.write("Error: Invalid session state")
