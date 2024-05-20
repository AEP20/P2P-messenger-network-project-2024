import warnings
import asyncio
import json
import socket
import threading
import time
from cryptography.fernet import Fernet
import random
import tkinter as tk
from tkinter import ttk
from http.server import SimpleHTTPRequestHandler, HTTPServer
import requests
import os

class P2PMessengerApp(tk.Tk):
    def __init__(self, port): # GUI
        super().__init__()
        self.title("P2P Messenger")

        tk.Label(self, text="Username:").pack()
        self.username_entry = tk.Entry(self)
        self.username_entry.pack()
        ttk.Button(self, text="Save", command=self.register_user).pack()

        self.peer_list = tk.Listbox(self)
        self.peer_list.pack(side=tk.LEFT, fill=tk.BOTH)
        self.peer_list.bind("<<ListboxSelect>>", self.on_peer_select)

        self.chat_area = tk.Text(self)
        self.chat_area.pack(side=tk.LEFT, fill=tk.BOTH)

        self.message_entry = tk.Entry(self)
        self.message_entry.pack(side=tk.BOTTOM, fill=tk.X)
        self.message_entry.bind("<Return>", self.send_message_event)

        self.send_button = ttk.Button(self, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.BOTTOM)

       # self.log_viewer_button = ttk.Button(self, text="View Chat Log", command=self.open_log_viewer)
       # self.log_viewer_button.pack(side=tk.BOTTOM)

        self.username = None
        self.peers = {}
        self.connections = {}
        self.selected_peer = None
        self.shared_keys = {}
        self.chat_history = {}
        self.port = port

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #TCP
        self.server_socket.bind(('0.0.0.0', self.port)) 
        self.server_socket.listen()
        print(f"Server listening on port: {self.port}")

        threading.Thread(target=self.accept_connections, daemon=True).start()
        threading.Thread(target=self.peer_discovery, daemon=True).start()
        threading.Thread(target=self.start_http_server, daemon=True).start()

    def start_http_server(self):
        handler = SimpleHTTPRequestHandler
        httpd = HTTPServer(('0.0.0.0', self.port + 1), handler)
        print(f"HTTP server listening on port: {self.port + 1}")
        httpd.serve_forever()

    def get_ip_address(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #UDP
        try:
            s.connect(("10.255.255.255", 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = "127.0.0.1" # default IP address
        finally:
            s.close()
        return IP

    def announce_registration(self): # REGISTRATION ANNOUNCEMENT WITH USING UDP BROADCAST
        broadcast_ip = '255.255.255.255'
        broadcast_port = 6004

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock: #UDP
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            message = json.dumps({'username': self.username, 'ip': self.get_ip_address(), 'port': self.port}).encode('utf-8')
            while True:
                sock.sendto(message, (broadcast_ip, broadcast_port))
                time.sleep(8)

    def peer_discovery(self): # PEER DISCOVERY WITH USING UDP BROADCAST
        discovery_port = 6004 

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock: #UDP
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', discovery_port))

            while True:
                data, addr = sock.recvfrom(1024)
                try:
                    message = json.loads(data.decode('utf-8'))
                    peer_name = message['username']
                    peer_ip = message['ip']
                    peer_port = message['port']
                    self.add_peer(peer_name, peer_ip, peer_port)
                except json.JSONDecodeError:
                    print("Received an invalid JSON message.")

    def add_peer(self, peer_name, peer_ip, peer_port):
        self.peers[peer_name] = {'ip': peer_ip, 'port': peer_port, 'last_seen': time.time()}
        self.update_peer_list()

    def update_peer_list(self):
        self.peer_list.delete(0, tk.END)
        for peer_name, info in self.peers.items():
            status = "Online" if time.time() - info['last_seen'] <= 10 else "Away"
            self.peer_list.insert(tk.END, f"{peer_name} ({info['ip']}:{info['port']}) - {status}")

    def accept_connections(self): 
        while True:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, addr), daemon=True).start()

    def handle_client(self, client_socket, addr): # HANDLE CLIENT CONNECTIONS WITH TCP
        peer_name = None
        try:
            while True: 
                data = client_socket.recv(1024)
                if not data:
                    break

                peer_name = client_socket.getpeername()[0]

                message = json.loads(data.decode('utf-8'))
                if not peer_name:
                    peer_name = message['username']
                    self.add_peer(peer_name, addr[0], message.get('port', 7001))
                    self.initiate_key_exchange(client_socket)
                else:
                    if 'key' in message:
                        self.handle_key_exchange(peer_name, message['key'])
                    elif 'encrypted_message' in message:
                        decrypted_message = self.decrypt_message(peer_name, message['encrypted_message'])
                        self.display_message(peer_name, decrypted_message)
                        self.log_message(peer_name, decrypted_message, "RECEIVED")
                    elif 'chat_request' in message:
                        self.handle_chat_request(peer_name, message['chat_request'], client_socket)
                    else:
                        self.display_message(peer_name, message['unencrypted_message'])
                        self.log_message(peer_name, message['unencrypted_message'], "RECEIVED")
        except Exception as e:
            print(f"Error occurred: {e}")
        finally:
            client_socket.close()
            if peer_name in self.peers:
                del self.peers[peer_name]
                self.update_peer_list()

    def handle_chat_request(self, peer_name, request, client_socket): 
        if request == 'request':
            response = {'chat_request': 'accept'}
            client_socket.sendall(json.dumps(response).encode('utf-8'))
        elif request == 'accept':
            self.chat_area.insert(tk.END, f"{peer_name} accepted your chat request.\n")
            client_socket.close()
            threading.Thread(target=self.start_p2p_chat, args=(peer_name,)).start()

    def start_p2p_chat(self, peer_name): # P2P CHAT WITH TCP
        peer_ip = self.peers[peer_name]['ip']
        peer_port = self.peers[peer_name]['port']
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as p2p_socket: #TCP
                p2p_socket.connect((peer_ip, peer_port))
                self.chat_area.insert(tk.END, f"P2P connection established with {peer_name}.\n")
                while True:
                    message = input("Your message: ")
                    encrypted_message = self.encrypt_message(peer_name, message)
                    p2p_socket.sendall(json.dumps({'username': self.username, 'encrypted_message': encrypted_message}).encode('utf-8'))
                    data = p2p_socket.recv(1024)
                    if not data:
                        break
                    message = json.loads(data.decode('utf-8'))
                    decrypted_message = self.decrypt_message(peer_name, message['encrypted_message'])
                    self.chat_area.insert(tk.END, f"{peer_name}: {decrypted_message}\n")
        except Exception as e:
            print(f"Error in P2P connection: {e}")

    def register_user(self):
        self.username = self.username_entry.get()
        if not self.username:
            self.chat_area.insert(tk.END, "Please enter a username.\n")
            return
        self.username_entry.config(state="disabled")
        threading.Thread(target=self.announce_registration, daemon=True).start()

    def on_peer_select(self, event):
        selection = event.widget.curselection()
        if selection:
            index = selection[0]
            peer_info = event.widget.get(index)
            peer_details = peer_info.split(' ')[1].strip('()')
            peer_ip, peer_port = peer_details.split(':')
            peer_name = peer_info.split(' ')[0]
            self.selected_peer = {'name': peer_name, 'ip': peer_ip, 'port': int(peer_port)}
            self.chat_area.insert(tk.END, f"{peer_name} selected.\n")

    def send_message_event(self, event):
        self.send_message()

    def send_message(self): # SEND MESSAGE WITH TCP
        if not self.selected_peer:
            self.chat_area.insert(tk.END, "Please select a user.\n")
            return

        message = self.message_entry.get()
        if not message:
            return

        self.chat_area.insert(tk.END, f"{self.username}: {message}\n")
        self.message_entry.delete(0, tk.END)

        encrypted_message = self.encrypt_message(self.selected_peer['name'], message)
        msg = {'username': self.username, 'encrypted_message': encrypted_message}
        peer_ip = self.selected_peer['ip']
        peer_port = self.selected_peer['port']

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket: #TCP
                client_socket.connect((peer_ip, peer_port))
                client_socket.sendall(json.dumps(msg).encode('utf-8'))
        except Exception as e:
            print(f"Error sending message: {e}")

    def send_chat_request(self):
        if not self.selected_peer:
            self.chat_area.insert(tk.END, "Please select a user.\n")
            return

        peer_ip = self.selected_peer['ip']
        peer_port = self.selected_peer['port']

        request_message = {'username': self.username, 'chat_request': 'request'}

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket: #TCP
                client_socket.connect((peer_ip, peer_port))
                client_socket.sendall(json.dumps(request_message).encode('utf-8'))
        except Exception as e:
            print(f"Error sending chat request: {e}")

    def initiate_key_exchange(self, client_socket): # Diffie-Hellman key exchange
        p = 23
        g = 5
        a = random.randint(1, p - 1)
        A = pow(g, a, p)

        key_exchange_msg = {'key': A}
        client_socket.sendall(json.dumps(key_exchange_msg).encode('utf-8'))

        while True:
            data = client_socket.recv(1024)
            if data:
                try:
                    message = json.loads(data.decode('utf-8'))
                    if 'key' in message:
                        B = message['key']
                        shared_key = pow(B, a, p)
                        fernet_key = Fernet.generate_key()
                        self.shared_keys[client_socket.getpeername()[0]] = fernet_key
                        break
                except json.JSONDecodeError:
                    print("Received an invalid JSON message.")

    def handle_key_exchange(self, peer_name, B): # Diffie-Hellman key exchange
        p = 23
        g = 5
        b = random.randint(1, p - 1)
        A = B
        B = pow(g, b, p)

        shared_key = pow(A, b, p)
        fernet_key = Fernet.generate_key()
        self.shared_keys[peer_name] = fernet_key

    def encrypt_message(self, peer_name, message): # fernet symmetric encryption
        fernet_key = self.shared_keys.get(peer_name)
        if fernet_key:
            f = Fernet(fernet_key)
            encrypted_message = f.encrypt(message.encode())
            return encrypted_message.decode()
        return message

    def decrypt_message(self, peer_name, encrypted_message): # fernet symmetric decryption
        fernet_key = self.shared_keys.get(peer_name)
        if fernet_key:
            f = Fernet(fernet_key)
            decrypted_message = f.decrypt(encrypted_message.encode())
            return decrypted_message.decode()
        return encrypted_message

    def display_message(self, sender, message):
        self.chat_area.insert(tk.END, f"{sender}: {message}\n")

    def log_message(self, peer_name, message, direction): # LOGGING CHAT MESSAGES
        log_filename = f"{peer_name}_chat_log.json"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        log_entry = {
            "timestamp": timestamp,
            "direction": direction,
            "message": message
        }

        if os.path.exists(log_filename):
            with open(log_filename, "r") as log_file:
                chat_log = json.load(log_file)
        else:
            chat_log = []

        chat_log.append(log_entry)

        with open(log_filename, "w") as log_file:
            json.dump(chat_log, log_file, indent=4)

    def open_log_viewer(self): # OPEN CHAT LOG VIEWER
        server_ip = self.get_ip_address()
        server_port = self.port + 1
        peer_name = self.selected_peer['name'] if self.selected_peer else self.username
        LogViewerApp(server_ip, server_port, peer_name).mainloop()

class LogViewerApp(tk.Tk):
    def __init__(self, server_ip, server_port, peer_name):
        super().__init__()
        self.title("Chat Log Viewer")

        self.chat_area = tk.Text(self)
        self.chat_area.pack(side=tk.LEFT, fill=tk.BOTH)

        self.server_ip = server_ip
        self.server_port = server_port
        self.peer_name = peer_name

        self.chat_log_filename = f"{peer_name}_chat_log.json"

        self.update_chat_log()

    def update_chat_log(self):
        try:
            url = f"http://{self.server_ip}:{self.server_port}/{self.chat_log_filename}"
            response = requests.get(url)
            if response.status_code == 200:
                chat_log = response.json()
                self.chat_area.delete(1.0, tk.END)
                for entry in chat_log:
                    timestamp = entry["timestamp"]
                    direction = entry["direction"]
                    message = entry["message"]
                    self.chat_area.insert(tk.END, f"{timestamp} - {direction} - {message}\n")
            else:
                self.chat_area.insert(tk.END, "Cannot connect to server or file not found.\n")
        except Exception as e:
            self.chat_area.insert(tk.END, f"Error occurred: {e}\n")

        self.after(5000, self.update_chat_log)

if __name__ == "__main__":
    port = int(input("Enter port number: "))
    app = P2PMessengerApp(port)
    app.mainloop()


# SOCK_DGRAM --> UDP
# SOCK_STREAM --> TCP