# CMP2204 Introduction to Computer Networks Spring 2024 Term Project

## Description
This project is a messaging application that provides P2P (Peer-to-Peer) communication. It allows users to communicate directly with each other and securely transmit their messages by encrypting them. The application enables users to exchange keys among themselves to encrypt their messages.

## How It Works
- **User Registration:** When the application first opens, it asks the user to enter a username. This username is used to identify the user to others.
- **User Broadcast:** The username and IP address are broadcasted at regular intervals so that other users can discover this person.
- **User List:** Discovered users are displayed in a list and can be selected.
- **Sending Messages:** Messages can be sent to the selected user. Messages are transmitted in encrypted form.
- **Chat Log:** Sent and received messages are stored locally and can be viewed when desired.

## Setup and Running
1. Download or copy the project files.
2. Install the necessary Python libraries:
    ```bash
    pip install cryptography requests asyncio
    ```
3. Ensure your Python environment includes the following standard libraries (usually included by default):
    - warnings
    - json
    - socket
    - threading
    - time
    - random
    - tkinter
    - http.server
    - os
4. Run the application from the terminal with the following command:
    ```bash
    python gui.py
    ```
5. Enter a username in the opened window and click the "Save" button.

## Known Limitations
- The application only works for users on the same local network.
- The chat log is saved locally, so it cannot be accessed from other devices.

## Additional Notes
- While the application is running, it continuously searches for and discovers users. Therefore, network traffic may increase slightly.
- If a user goes offline, they are marked as "Away" in the list.
- Ensure the recipient is online before sending a message.
- Users need to have two computers running the application on the same local network to be able to communicate with each other.

## Why Both TCP and UDP Are Used?

### UDP:
- Due to its low latency and connectionless nature, UDP is ideal for operations requiring fast and frequent messaging, such as peer discovery.
- When used for registration announcements, UDP can broadcast messages widely across the network without guaranteeing their delivery.

### TCP:
- TCP is used for critical communications like sending and receiving messages because it provides reliable data transmission and data integrity.
- TCP ensures that data packets are delivered in order and without loss, guaranteeing that messages are received correctly.

### TCP-UDP Conclusion
In this application, the UDP protocol is used for peer discovery and registration announcements, while the TCP protocol is used for sending and receiving messages. This approach leverages the advantages of both protocols: the fast and low-latency nature of UDP, and the reliable and orderly data transmission of TCP, optimizing the application's performance and security.

## Diffie-Hellman and Fernet Encryption

### Diffie-Hellman:
- **Purpose:** Used for secure key exchange between peers.
- **How It Works:** When a connection is established, Diffie-Hellman is used to create a shared secret key. This key is used for encrypting communications between the peers.

### Fernet:
- **Purpose:** Used for encrypting and decrypting messages.
- **How It Works:** Messages are encrypted using the shared secret key generated by Diffie-Hellman. Fernet provides symmetric encryption, ensuring that the message can only be decrypted by the intended recipient with the correct key.

## Used IPs and Ports

### Discovery Channel (UDP Broadcast)
- **IP Address:** `255.255.255.255`
- **Port:** `6004`
- **Purpose:** Used to discover other peers on the network. Each user broadcasts their presence using this IP and port. At the same time, they listen for broadcasts from other users to discover them.

### Main Server (TCP Server)
- **IP Address:** `0.0.0.0` (Listens on all network interfaces)
- **Port:** Defined by the user when starting the application.
- **Purpose:** Accepts incoming TCP connections and facilitates peer-to-peer communication.

### HTTP Server
- **IP Address:** `0.0.0.0`
- **Port:** One more than the application's defined port (e.g., if the main server runs on port `x`, the HTTP server runs on port `x+1`).
- **Purpose:** Used to view chat logs via HTTP. This server serves log files over HTTP.

### P2P Communication (TCP)
- **IP Address:** Dynamically assigned (IP addresses of both peers)
- **Port:** Ports defined by both peers when establishing a TCP connection, usually `self.port` or `peer_port`.
- **Purpose:** Used to communicate directly with the selected peer. Ensures the transmission of encrypted messages.

## Program Flow and Steps

### User Registration and Announcement
- The user enters a username when the application starts and registers with the `register_user` method.
- The `announce_registration` method broadcasts the user's IP address, port number, and username via UDP.

### Peer Discovery
- The `peer_discovery` method listens for UDP broadcasts on port `6004`.
- It receives messages broadcasted by other users and adds new peers to the list.

### Accepting TCP Connections
- The `accept_connections` method accepts incoming TCP connections on the specified port.
- The `handle_client` method processes incoming connections and decrypts encrypted messages.

### Sending Messages
- The `send_message` method sends messages to the selected peer via TCP.
- Messages are encrypted before being sent to the peer.

### HTTP Server
- The `start_http_server` method starts an HTTP server on the port number one more than the defined port.
- Used to view chat logs over HTTP.

## Contributors
- [Deniz Özmen](https://github.com/denizozm)
- [Ahmet Emre Parmaksız](https://github.com/AEP20)
- [Mehmet Kaan Kurtuluş](https://github.com/mkaan3)
