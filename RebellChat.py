import argparse
import base64
import configparser
import ctypes
import json
import os
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import tkinter as tk
from tkinter import ttk
from datetime import datetime
from tkinter import messagebox, scrolledtext
from tkinter.simpledialog import askinteger, askstring
from cryptography.fernet import Fernet
from create_cert import create_temp_ssl_cert_and_key
from ciphertext import SALT_SIZE, derive_key, encrypt, decrypt

# Define constants
SALT_SIZE = 16
IV_SIZE = 16
TAG_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 16
MAC_SIZE = 16

def get_drive_info(drive_letter):
    drive_path = f"{drive_letter}:\\"
    kernel32 = ctypes.windll.kernel32

    volume_name_buffer = ctypes.create_unicode_buffer(1024)
    serial_number = ctypes.c_uint32()
    max_component_length = ctypes.c_uint32()
    file_system_flags = ctypes.c_uint32()
    file_system_name_buffer = ctypes.create_unicode_buffer(1024)

    kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(drive_path),
        volume_name_buffer,
        ctypes.sizeof(volume_name_buffer),
        ctypes.byref(serial_number),
        ctypes.byref(max_component_length),
        ctypes.byref(file_system_flags),
        file_system_name_buffer,
        ctypes.sizeof(file_system_name_buffer),
    )

    return volume_name_buffer.value, serial_number.value

class RebellChat:
    def __init__(self, master, start_server=False):
        self.master = master
        self.master.title("Chat Application")
        self.master.geometry("800x500")
        self.master.protocol("WM_DELETE_WINDOW", self.close_app)

        self.failed_attempts = {}  # Add a failed_attempts dictionary

        self.key = self.get_encryption_key()

        # Initialize the chat_window attribute
        self.chat_window = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, font=("Arial", 12))
        self.chat_window.config(state=tk.DISABLED)
        self.chat_window.place(x=10, y=10, width=580, height=400)
     
        self.password = None
        self.key = None
        self.server_port = None
            
        # Initialize the attributes
        self.username = ""
        self.server_ip = ""
        self.server_port = 0
            
        self.load_settings()

        self.is_server = False
        self.is_connected = False

        self.sock = None
        self.clients = {}
        self.create_widgets()
        
        if start_server:
            self.master.after(100, self.start_server)
        self.ssl_cert_path, self.ssl_key_path = None, None        

    def create_widgets(self):

        self.main_frame = tk.Frame(self.master, bg="white")
        self.main_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(0, weight=1)
        
        self.chat_box = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, font=("Arial", 12))
        self.chat_box.config(state=tk.DISABLED)
        self.chat_box.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.chat_box.columnconfigure(0, weight=1)
        self.chat_box.rowconfigure(0, weight=1)

        self.users_list = tk.Listbox(self.master, font=("Arial", 12))
        self.users_list.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        self.users_list.rowconfigure(0, weight=1)

        self.message_entry = tk.Entry(self.master, font=("Arial", 12))
        self.message_entry.grid(row=1, column=0, padx=10, pady=10, sticky="ew", rowspan=2)
        
        self.send_button = tk.Button(self.master, text="Send", font=("Arial", 12), command=self.send_message)
        self.send_button.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        self.message_entry.bind('<Return>', self.send_message_event)

        self.menu_bar = tk.Menu(self.master)

        self.light_style = ttk.Style()
        self.light_style.theme_use('clam')
        self.light_style.configure('LightSizegrip.TSizegrip', background='white')

        self.dark_style = ttk.Style()
        self.dark_style.theme_use('clam')
        self.dark_style.configure('DarkSizegrip.TSizegrip', background='black')

        self.server_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.server_menu.add_command(label="Start Server", command=self.start_server)
        self.server_menu.add_command(label="Stop Server", command=self.stop_server)

        self.client_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.client_menu.add_command(label="Connect", command=self.connect_client)
        self.client_menu.add_command(label="Disconnect", command=self.disconnect_client)

        self.settings_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.settings_menu.add_command(label="Set Username", command=self.set_username)
        self.settings_menu.add_command(label="Set Server IP", command=self.set_server_ip)
        self.settings_menu.add_command(label="Set Server Port", command=self.set_server_port)
        self.settings_menu.add_command(label="Set Password", command=self.set_password)
        self.settings_menu.add_separator()
        
        self.mode_var = tk.BooleanVar()
        self.mode_var.set(False)  # set initial mode to light
        
        def toggle_mode():
            mode = self.mode_var.get()
            if mode:  # dark mode
                self.master.config(bg="black")
                self.chat_box.config(bg="black", fg="white")
                self.users_list.config(bg="black", fg="white")
                self.message_entry.config(bg="black", fg="white")
                self.send_button.config(bg="black", fg="white")
                sizegrip.config(style='DarkSizegrip.TSizegrip')
                self.main_frame.config(bg="black")
                self.menu_bar.config(fg="white")
            else:  # light mode
                self.master.config(bg="white")
                self.chat_box.config(bg="white", fg="black")
                self.users_list.config(bg="white", fg="black")
                self.message_entry.config(bg="white", fg="black")
                self.send_button.config(bg="white", fg="black")
                sizegrip.config(style='LightSizegrip.TSizegrip')
                self.main_frame.config(bg="white")
                self.menu_bar.config(fg="black")
                
        self.settings_menu.add_checkbutton(label="Dark mode", variable=self.mode_var, command=toggle_mode)

        self.menu_bar.add_cascade(label="Server", menu=self.server_menu)
        self.menu_bar.add_cascade(label="Client", menu=self.client_menu)
        self.menu_bar.add_cascade(label="Settings", menu=self.settings_menu)
        
        self.master.config(menu=self.menu_bar)
        
        # Configure grid columns and rows to be resizable
        self.master.columnconfigure(0, weight=1)
        self.master.columnconfigure(1, weight=1)
        self.master.rowconfigure(0, weight=1)
        self.master.rowconfigure(1, weight=0)
        
        # Add sizegrip in the bottom right corner
        sizegrip = ttk.Sizegrip(self.master)
        sizegrip.grid(row=1, column=1, sticky="se")

    
    def close_app(self):
        if self.is_connected:
            if messagebox.askyesno("Close Application", "You are still connected. Are you sure you want to close the application?"):
                self.quit_chat()
        else:
            self.master.destroy()

    def quit_chat(self):
        if self.is_server:
            self.stop_server()
        elif self.is_connected:
            self.disconnect_client()

        self.master.destroy()

    def load_settings(self):
        config = configparser.ConfigParser()
        config.read('RebellChat.cfg')

        if 'SETTINGS' in config:
            if 'username' in config['SETTINGS']:
                self.username = config['SETTINGS']['username']
            if 'server_ip' in config['SETTINGS']:
                self.server_ip = config['SETTINGS']['server_ip']
            if 'server_port' in config['SETTINGS']:
                self.server_port = int(config['SETTINGS']['server_port'])
            if 'password' in config['SETTINGS']:
                encrypted_password = config['SETTINGS']['password']
                key = config['SETTINGS'].get('key')
                if key:
                    self.key = key.encode()
                    self.password = self.decrypt_password(encrypted_password)

    def set_password(self):
        password = askstring("Set Password", "Enter the password:", show='*')
        if password:
            self.password = password
            self.save_settings()

    def save_settings(self):
        config = configparser.ConfigParser()
        config.read('RebellChat.cfg')

        if 'SETTINGS' not in config:
            config.add_section('SETTINGS')

        config['SETTINGS']['username'] = self.username
        config['SETTINGS']['server_ip'] = self.server_ip
        config['SETTINGS']['server_port'] = str(self.server_port)

        # Encrypt password
        if self.password:
            key = Fernet.generate_key()
            cipher_suite = Fernet(key)
            cipher_text = cipher_suite.encrypt(self.password.encode())
            config['SETTINGS']['password'] = cipher_text.decode()
            config['SETTINGS']['key'] = key.decode()

        with open('RebellChat.cfg', 'w') as config_file:
            config.write(config_file)

    def accept_clients(self):
        while self.is_connected:
            try:
                conn, addr = self.server_sock.accept()  # Use the correct SSL wrapped socket object
                self.add_message_to_chat(f"Client {addr} connected.\n")
                client_thread = threading.Thread(target=self.receive_message, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                if self.is_connected:
                    messagebox.showerror("Error", f"Could not accept client: {e}")
                break

    def create_temp_ssl_cert_and_key(self):
        ssl_cert_path, ssl_key_path = None, None
        try:
            temp_dir = tempfile.mkdtemp()
            ssl_cert_path = os.path.join(temp_dir, 'cert.pem')
            ssl_key_path = os.path.join(temp_dir, 'key.pem')

            # Generate a self-signed SSL certificate
            os.system(f"openssl req -newkey rsa:2048 -x509 -nodes -keyout {ssl_key_path} -out {ssl_cert_path} -days 1 -subj '/CN=localhost'")
        except Exception as e:
            messagebox.showerror("Error", f"Error creating SSL certificate and key files: {e}")
        return ssl_cert_path, ssl_key_path

    def start_server(self):
        if not self.is_connected:
            try:
                self.is_server = True
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                # Allow the socket to be reused immediately after it is closed
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                # Resolve the server IP/domain name
                addr_info = socket.getaddrinfo(self.server_ip, self.server_port, socket.AF_INET, socket.SOCK_STREAM)
                addr = addr_info[0][-1]
                
                self.sock.bind(('0.0.0.0', self.server_port))  # Use configured server port
                self.sock.listen(5)

                ssl_cert_path, ssl_key_path = create_temp_ssl_cert_and_key()
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(certfile=ssl_cert_path, keyfile=ssl_key_path)

                self.server_sock = context.wrap_socket(self.sock, server_side=True)

                self.is_connected = True
                threading.Thread(target=self.accept_clients).start()
                self.add_message_to_chat("Server started.\n")
                self.update_users_list([self.username])  # Add server username to the user list
            except Exception as e:
                messagebox.showerror("Error", f"Could not start server: {e}")

    def stop_server(self):
        if self.is_server and self.is_connected:
            for conn in self.clients.values():
                conn.close()
            if self.ssl_cert_path and self.ssl_key_path:
                shutil.rmtree(os.path.dirname(self.ssl_cert_path))
            self.sock.close()
            self.is_connected = False
            self.is_server = False
            self.clients.clear()
            self.update_users_list([])
            self.add_message_to_chat("Server stopped.\n")
        else:
            messagebox.showerror("Error", "Not running as a server.")

    def connect_client(self):
        if not self.is_connected:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.server_ip, self.server_port))

                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                self.sock = context.wrap_socket(self.sock)

                self.is_connected = True
                threading.Thread(target=self.receive_message, args=(self.sock, None)).start()
                self.send_message(is_username=True)  # Send username to the server
                self.update_users_list([self.username])  # Add this line to add the client's username to the user list
            except Exception as e:
                messagebox.showerror("Error", f"Could not connect to server: {e}")

    def disconnect_client(self):
        if not self.is_server and self.is_connected:
            self.send_message(is_disconnect=True)
            self.sock.close()
            self.is_connected = False
            self.add_message_to_chat("Disconnected from server.\n")
            if self.ssl_cert_path and self.ssl_key_path:
                shutil.rmtree(os.path.dirname(self.ssl_cert_path))
        else:
            messagebox.showerror("Error", "Not connected as a client.")

    def set_username(self):
        old_username = self.username
        username = askstring("Set Username", "Enter your username:", initialvalue=self.username)
        if username:
            self.username = username
            self.save_settings()
            if self.is_connected and not self.is_server:
                self.send_message(old_username=old_username)

    def set_server_ip(self):
        server_ip = askstring("Set Server IP", "Enter server IP address:", initialvalue=self.server_ip)
        if server_ip:
            self.server_ip = server_ip
            self.save_settings()

    def set_server_port(self):
        server_port = askinteger("Set Server Port", "Enter server port number:", initialvalue=self.server_port)
        if server_port:
            self.server_port = server_port
            self.save_settings()

    def update_users_list(self, user_list):
        self.users_list.delete(0, tk.END)
        if self.is_server:
            user_list = list(set([self.username] + user_list))  # Remove duplicates by converting to a set, then back to a list
        for index, user in enumerate(user_list):
            self.users_list.insert(tk.END, user)
            if self.is_server and user == self.username:
                self.users_list.itemconfig(index, {"fg": "red"})
            elif not self.is_server and index == 0:
                self.users_list.itemconfig(index, {"fg": "red"})
            elif user == self.username:
                self.users_list.itemconfig(index, {"fg": "blue"})

    def broadcast_user_list(self):
        if self.is_server:
            user_list = [self.username] + list(self.clients.keys())
            message = f"ENCRYPTEDUSERLIST:{','.join(user_list)}"
            encrypted_message = self.encrypt_message_encoded(message)
            for conn in self.clients.values():
                conn.sendall(encrypted_message.encode())

#######################################################################
                
    def decrypt_password(self, encrypted_password):
        try:
            cipher_suite = Fernet(self.key)
            decrypted_password = cipher_suite.decrypt(encrypted_password.encode())
            return decrypted_password.decode()
        except Exception as e:
            messagebox.showerror("Error", f"Error decrypting password: {e}")
            return None

    def get_encryption_key(self):
        drive_letter = os.path.abspath(os.sep)[0]
        try:
            volume_label, serial_number = get_drive_info(drive_letter)
            key = f"{serial_number}-{volume_label}".encode()
            return base64.urlsafe_b64encode(key)
        except Exception as e:
            messagebox.showerror("Error", f"Error getting hard drive info: {e}")
            return None

    def encrypt_message_encoded(self, message):
        # Generate a random salt and derive a key from the password
        salt = os.urandom(SALT_SIZE)
        key = derive_key(self.password, salt)

        # Encrypt the message
        encrypted_data = encrypt(key, message)

        # Concatenate the nonce, tag, and ciphertext into a single byte string
        encrypted_message = salt + encrypted_data[0] + encrypted_data[1] + encrypted_data[2]

        # Encode the encrypted message with base64
        encrypted_message_encoded = base64.urlsafe_b64encode(encrypted_message).decode()

        return encrypted_message_encoded

    def send_message(self, is_username=False, is_disconnect=False, old_username=None):
        if self.is_connected:
            try:
                if is_username:
                    message = f"USERNAME:{self.username}"
                elif is_disconnect:
                    message = f"DISCONNECT:{self.username}"
                elif old_username:
                    message = f"USERNAMECHANGE:{old_username}:{self.username}"
                else:
                    message_text = self.message_entry.get().strip()
                    if not message_text:
                        return
                    message = f"{self.username}: {message_text}"
                    self.message_entry.delete(0, tk.END)

                # Generate a random salt and derive a key from the password
                salt = os.urandom(SALT_SIZE)
                key = derive_key(self.password, salt)

                # Encrypt the message
                encrypted_data = encrypt(key, message)

                # Concatenate the nonce, tag, and ciphertext into a single byte string
                encrypted_message = salt + encrypted_data[0] + encrypted_data[1] + encrypted_data[2]

                # Encode the encrypted message with base64
                encrypted_message_encoded = base64.urlsafe_b64encode(encrypted_message).decode()

                # Send the encoded encrypted message
                if not self.is_server:
                    self.sock.sendall(encrypted_message_encoded.encode())
                else:
                    for c_conn in self.clients.values():
                        c_conn.sendall(encrypted_message_encoded.encode())

                if not (is_username or is_disconnect or old_username):
                    self.add_message_to_chat(message)

            except Exception as e:
                messagebox.showerror("Error", f"Could not send message: {e}")
        else:
            messagebox.showerror("Error", "Not connected to a server or client.")           

    def receive_message(self, conn, addr):
        while self.is_connected:
            try:
                # Check if the connection is still alive
                if not self.is_socket_connected(conn):
                    raise ConnectionError("Client disconnected")

                data = conn.recv(1024)
                if not data:
                    raise ConnectionError("Client disconnected")

                encrypted_message_encoded = data.decode()
                encrypted_data = base64.urlsafe_b64decode(encrypted_message_encoded)

                # Extract the salt from the encrypted data
                salt = encrypted_data[:SALT_SIZE]

                # Derive the key from the password and salt
                key = derive_key(self.password, salt)

                # Decrypt the message
                nonce = encrypted_data[SALT_SIZE:SALT_SIZE + IV_SIZE]
                ciphertext = encrypted_data[SALT_SIZE + IV_SIZE:-TAG_SIZE]
                tag = encrypted_data[-TAG_SIZE:]
                message = decrypt(b"".join([nonce, ciphertext, tag]), key)

                if message.startswith("ENCRYPTEDUSERLIST:"):
                    user_list = message.split(":", 1)[1].split(",")
                    if self.is_server:
                        self.update_users_list(user_list)
                    else:
                        self.update_users_list(user_list[1:])  # Remove the client's own username from the list

                if message.startswith("USERNAME:"):
                    username = message.split(":", 1)[1]
                    if self.is_server:
                        self.clients[username] = conn
                        self.update_users_list([self.username] + list(self.clients.keys()))
                        self.broadcast_user_list()
                        # Send server username to the client
                        conn.sendall(f"SERVERUSERNAME:{self.username}".encode())
                    else:
                        self.update_users_list([username] + self.users_list.get(0, tk.END))
                elif message.startswith("SERVERUSERNAME:"):
                    server_username = message.split(":", 1)[1]
                    current_user_list = self.users_list.get(0, tk.END)
                    if server_username not in current_user_list:
                        self.update_users_list([server_username] + list(current_user_list))
                elif message.startswith("USERNAMECHANGE:"):
                    old_username, new_username = message.split(":", 1)[1].split(":", 1)
                    if self.is_server:
                        self.clients[new_username] = self.clients.pop(old_username)
                        self.update_users_list(list(self.clients.keys()))
                        self.broadcast_user_list()
                elif message.startswith("DISCONNECT:"):
                    username = message.split(":", 1)[1]
                    if self.is_server:
                        del self.clients[username]
                        conn.close()
                        self.update_users_list(list(self.clients.keys()))
                        self.broadcast_user_list()
                elif message.startswith("ENCRYPTEDUSERLIST:"):
                        encrypted_user_list_message = message.split(":", 1)[1]
                        decrypted_user_list_message = self.decrypt_message(encrypted_user_list_message)
                        user_list = decrypted_user_list_message.split(",")
                        if self.is_server:
                            self.update_users_list(user_list)
                        else:
                            self.update_users_list(user_list[1:])  # Remove the client's own username from the list

                elif message.startswith("USERLIST:"):
                    user_list = message.split(":", 1)[1].split(",")
                    try:
                        decrypted_user_list = [self.decrypt_password(user) for user in user_list]
                        if self.is_server:
                            self.update_users_list(decrypted_user_list)
                        else:
                            self.update_users_list(decrypted_user_list[1:])  # Remove the client's own username from the list
                    except Exception as e:
                        break
                else:
                    if self.is_server:
                        for c_conn in self.clients.values():
                            if c_conn != conn:
                                c_conn.sendall(data)
                        self.add_message_to_chat(message)
                    else:
                        self.add_message_to_chat(message)
            except ConnectionError as ce:
                print(f"Client disconnected: {addr}")
                if self.is_server:
                    user_list = [k for k, v in self.clients.items() if v == conn]
                    if user_list:
                        username = user_list[0]
                        del self.clients[username]
                        conn.close()
                        self.update_users_list(list(self.clients.keys()))
                        self.broadcast_user_list()
                break
            except Exception as e:
                # Check for the specific error messages indicating a wrong password attempt
                if str(e) == "MAC check failed" and self.is_server:
                    ip = addr[0]
                    self.failed_attempts[ip] = self.failed_attempts.get(ip, 0) + 1
                    if self.failed_attempts[ip] >= 3:  # Set the limit to 3 failed attempts
                        conn.sendall("Failed attempts limit reached. Connection closed.".encode())
                        conn.close()
                        print(f"Wrong password used 3 times from {ip}. Connection closed.")
                    else:
                        conn.sendall("Wrong password.".encode())
                        print(f"Wrong password used from {ip}")
                elif str(e).startswith("Invalid base64-encoded string"):
                    if not self.is_server:
                        messagebox.showerror("Error", "Wrong Password")
                else:
                    print(f"Error in receive_message(): {e}")
                   
    def is_socket_connected(self, conn):
        try:
            conn.sendall(b"")
        except Exception as e:
            if e.winerror == 10038 or e.winerror == 10057:
                return False
        return True

    def add_message_to_chat(self, message):
        formatted_message = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n"  # Add a newline character to the end of the message
        self.chat_box.config(state=tk.NORMAL)
        self.chat_box.insert(tk.END, formatted_message)
        self.chat_box.config(state=tk.DISABLED)
        self.chat_box.see(tk.END)  # Scroll to the end of the chat_box

    def send_message_event(self, event):
        self.send_message()

def main():
    root = tk.Tk()
    app = RebellChat(root)
    root.mainloop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RebellChat")
    parser.add_argument("--start-server", action="store_true", help="Start server directly")

    args = parser.parse_args()

    root = tk.Tk()
    app = RebellChat(root, start_server=args.start_server)
    root.mainloop()
