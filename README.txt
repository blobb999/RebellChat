The RebellChat project is a Python application that supports both client and server modes and allows users to communicate with each other over a network using sockets. The application provides a GUI created using the tkinter library that includes a chat window, a text box for entering messages, a list of connected users, and menu options for configuring the application.

The RebellChat project uses the Fernet encryption algorithm from the cryptography library to encrypt messages with a key derived from a user-entered password. The project also supports SSL/TLS encryption for communication between the server and clients, with the SSL handshake being encrypted and thus preventing MITM attacks.

To further enhance security, the RebellChat project generates an encryption key based on information about the hard drive, such as the volume label and serial number. This key is used to encrypt messages in addition to the password-derived key.

Before sending the message, it is encrypted using AES-GCM encryption with a random salt and encryption key, and the encrypted message is base64-encoded.

The RebellChat project uses threading to allow multiple clients to connect to the server and communicate simultaneously. In addition, the project includes a dictionary of failed login attempts to detect brute-force attacks and disconnects a client after three failed login attempts.

The RebellChat can:
- be started direct in server mode with the parameter --start-server 
- supports IP and domain names