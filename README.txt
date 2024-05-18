# Project: P2P Messenger Application

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
    pip install cryptography requests
    ```
3. Run the application from the terminal with the following command:
    ```bash
    python app.py
    ```
4. Enter a username in the opened window and click the "Save" button.

## Known Limitations
- The application only works for users on the same local network.
- The key exchange algorithm used for message encryption provides basic security and may be vulnerable to more advanced attacks.
- The chat log is saved locally, so it cannot be accessed from other devices.
- The user interface is simple and needs improvement in terms of user experience.

## Additional Notes
- While the application is running, it continuously searches for and discovers users. Therefore, network traffic may increase slightly.
- If a user goes offline, they are marked as "Away" in the list.
- Ensure the recipient is online before sending a message.
