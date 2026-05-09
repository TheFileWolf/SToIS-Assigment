import socket
import threading
import tkinter as tk
import os
import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tkinter import simpledialog

def run_app():

    root = tk.Tk()
    root.withdraw()

    # Ask for both IP and Port
    SERVER_IP = simpledialog.askstring("Input", "Enter Server IP (Localhost = 127.0.0.1):", parent=root)
    PORT = simpledialog.askinteger("Input", "Enter Port:", parent=root)
    if not SERVER_IP or not PORT: return
    root.deiconify()
    
    root.title(f"Client Chat - Connecting to {SERVER_IP}")

    root.title("Client Chat")
    
    chat_box = tk.Text(root, width=50, height=15, state=tk.NORMAL)
    chat_box.pack(padx=10, pady=10)
    chat_box.insert(tk.END, "[System] Looking for server...\n")
    chat_box.config(state=tk.DISABLED)
    
    msg_input = tk.Entry(root, width=50, state=tk.DISABLED)
    msg_input.pack(padx=10, pady=(0, 10))

    session = {"conn": None, "aes": None}

    def log_msg(text):
        chat_box.config(state=tk.NORMAL)
        chat_box.insert(tk.END, text + "\n")
        chat_box.config(state=tk.DISABLED)
        chat_box.yview(tk.END)

    def receive():
        while True:
            try:
                data = session["conn"].recv(1024)
                if not data: 
                    log_msg("[System] The other person disconnected.")
                    break
                
                nonce = data[:12]
                ciphertext = data[12:]
                decrypted = session["aes"].decrypt(nonce, ciphertext, None)
                log_msg("Server: " + decrypted.decode())
            except:
                log_msg("[System] Connection suddenly lost.")
                break
        
        msg_input.config(state=tk.DISABLED)

    def send(event=None):
        if session["conn"] is None: return
        text = msg_input.get()
        if text != "":
            log_msg("Me: " + text)
            nonce = os.urandom(12)
            ciphertext = session["aes"].encrypt(nonce, text.encode(), None)
            session["conn"].sendall(nonce + ciphertext)
            msg_input.delete(0, tk.END)

    msg_input.bind("<Return>", send)

    def setup_network():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                s.connect((SERVER_IP, PORT))
                break
            except:
                time.sleep(2) 
                
        session["conn"] = s
        log_msg("[System] Connected! Exchanging secure keys...")

        try:
            param_bytes = s.recv(2048)
            parameters = serialization.load_pem_parameters(param_bytes)
            s.sendall(b"READY")

            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            
            server_key_bytes = s.recv(1024)
            server_pub_key = serialization.load_pem_public_key(server_key_bytes)
            s.sendall(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

            shared_secret = private_key.exchange(server_pub_key)
            aes_key = hashlib.sha256(shared_secret).digest()
            session["aes"] = AESGCM(aes_key)

            log_msg("[System] Connection Secure. You can now chat.")
            msg_input.config(state=tk.NORMAL)

            threading.Thread(target=receive, daemon=True).start()
            
        except Exception as e:
            log_msg(f"[System] Network Error: {e}")

    t = threading.Thread(target=setup_network)
    t.daemon = True
    t.start()
    
    root.mainloop()

if __name__ == "__main__":
    run_app()
