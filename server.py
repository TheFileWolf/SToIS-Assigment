import socket
import threading
import tkinter as tk
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tkinter import simpledialog

def run_app():
    
    root = tk.Tk()
    root.withdraw()

    # Ask the user for the port
    PORT = simpledialog.askinteger("Input", "Enter Port (e.g. 65432):", parent=root)
    if not PORT: return
    root.deiconify()
    
    root.title(f"Server Chat - Port {PORT}")
    

    chat_box = tk.Text(root, width=50, height=15, state=tk.NORMAL)
    chat_box.pack(padx=10, pady=10)
    chat_box.insert(tk.END, "[System] Waiting for client to connect...\n")
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
                log_msg("Client: " + decrypted.decode())
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
            print(nonce + ciphertext)
            msg_input.delete(0, tk.END)

    msg_input.bind("<Return>", send)

    def setup_network():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('0.0.0.0', PORT)) # '0.0.0.0' allows connections from other computers
            s.listen(1)
            
            conn, addr = s.accept()
            session["conn"] = conn
            log_msg("[System] Client found! Exchanging secure keys...")

            parameters = dh.generate_parameters(generator=2, key_size=512)
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()

            conn.sendall(parameters.parameter_bytes(encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3))
            conn.recv(1024) 
            conn.sendall(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

            client_key_bytes = conn.recv(1024)
            client_pub_key = serialization.load_pem_public_key(client_key_bytes)

            shared_secret = private_key.exchange(client_pub_key)
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
