CS469 – Distributed Systems
Group Project – Secure Distributed Media Server

Overview
This project is a secure distributed media server written in C. It allows clients to connect to the server using SSL, browse music files by genre, download an MP3 file, and play it locally. The project demonstrates concurrency, process replication, encryption, authentication, and virtualization through the Windows Subsystem for Linux (WSL2).



--System Requirements--
The program was developed and tested in WSL2 running Ubuntu. It should work on most Linux systems that support OpenSSL, PortAudio, and mpg123.

If building from source, install the following packages:
sudo apt update
sudo apt install build-essential libssl-dev libmpg123-dev portaudio19-dev

Prebuilt binaries for both the server and client are included. Rebuilding is optional.



----Build Instructions----
the makefile builds both the server and client.
run:
make
make clean

the server links statically to openssl and crypto by default. this means the server binary carries its encryption libraries internally, so it can run even if the grader’s linux system does not have openssl installed or if the user cannot use sudo. this improves portability and fault tolerance.

the client links dynamically to mpg123 and portaudio. these libraries are used for mp3 decoding and audio playback, and static linking often fails on linux because static archives for audio are not usually included. keeping them dynamic ensures easy compilation on most systems and smaller file size.

--optional builds:--
make dyn (forces both client and server to link dynamically)
make FULL_STATIC=1 (tries full static build; may fail on glibc systems)



---Debug Mode---
• Debug mode shows live details of what the program is doing, including TLS setup and thread activity.
• It is turned on by default with `#define DEBUG 1` near the top of both source files.
• You can change it by rebuilding the program with `make DEBUG=1` to enable or `make DEBUG=0` to disable.
• Each debug line follows the same pattern: `[filename][function][tag] message`.
• Use debug mode to check certificate loading, handshake success, and client or server connection steps.



---CERTIFICATES: Explaination and use ---
Folder:
• All certificates and keys are stored in ./certs.

Server uses:
• server.crt → public certificate (identifies the server)
• server.key → private key for TLS encryption and signing
• ca.crt → certificate authority that signs and verifies the chain

Client uses:
• client.crt → client’s public certificate for authentication
• client.key → client’s private key for authentication and encryption
• ca.crt → trusted root authority for verifying the server

--How they work together--
• The client connects and sends its certificate (client.crt) to the server.
• The server verifies the client’s cert against the ca.crt file.
• The server presents its own server.crt, and the client verifies it with the same ca.crt.
• Once both sides are verified, a secure TLS channel is established.
• All commands and MP3 data are now encrypted in transit.
• Both programs load their keys and certificates automatically from the certs folder at startup.


---Generate certificates and keys---
If you do not have the certificates OR you want to generate a fresh set, follow these steps →
Run these from the project root. Each command is one line to avoid shell continuation issues.

• CA
openssl genrsa -out certs/ca.key 2048
openssl req -x509 -new -sha256 -days 3650 -subj "/CN=CS469 CA" -key certs/ca.key -out certs/ca.crt

• Server
openssl genrsa -out certs/server.key 2048
openssl req -new -key certs/server.key -out certs/server.csr -subj "/CN=CS469 Server"
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt -days 825 -sha256

• Client
openssl genrsa -out certs/client.key 2048
openssl req -new -key certs/client.key -out certs/client.csr -subj "/CN=CS469 Client"
openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key -out certs/client.crt -days 825 -sha256

• Quick check
openssl verify -CAfile certs/ca.crt certs/server.crt certs/client.crt


----Project Structure----
media/ contains all MP3 files grouped by genre.
cert.pem and key.pem are in the root folder.
ssl-serveraudio and ssl-clientaudio are the compiled programs.
ssl-serveraudio.c and ssl-clientaudio.c are the source files.
Makefile builds both programs.
Project Proposal.pdf is included.


---Running the Project---
Start the server using:
./ssl-serveraudio 4433

You can run a second server for replication using:
./ssl-serveraudio 4434

To run the client, use:
./ssl-clientaudio   (runs port 4433 by default)
or
./ssl-clientaudio 4434
or
./ssl-clientaudio 127.0.0.1 4433

The default port is 4433.



---Example Use Case---
The client connects to the server and displays a list of genre folders. 
The user selects a folder and then a file. 
The file is downloaded and played automatically. 
Example session:


Connecting to server...
Authenticated successfully.
Available genres:
1 Classic_Rock
2 Indie_Alt
3 HipHop_Rap

Choose genre: 2 <<--User Input

Available files:
1 song_a.mp3
2 song_b.mp3
Choose file: 1 <<--User Input
Downloading song_a.mp3
Playback starting

The downloaded file is saved under downloads/<port><pid><folder>__<file>.mp3 to keep sessions separate


---Replication and Fault Tolerance---
The system demonstrates both replication and concurrent access:

Start two server replicas
    ./ssl-serveraudio 4433
    ./ssl-serveraudio 4434

Each server listens on a different port but serves the same ./media and ./certs folders.
Connect multiple clients simultaneously
    ./ssl-clientaudio 127.0.0.1 4433
    ./ssl-clientaudio 127.0.0.1 4433

Both clients can browse and download files at the same time, which proves threaded concurrency within a single server process

Test replication and failover
• while both clients are connected to 4433, stop or kill that server
• Example: press Ctrl+C in the 4433 terminal.
• Restart one client and connect to the backup server on 4434:
    ./ssl-clientaudio 127.0.0.1 4434

• The client can still list and download the same files from the replicated instance
• This shows that multiple servers can host identical data directories for fault tolerance
• Clients can switch between servers without changing certificates or reconfiguring security, demonstrating replication


--Virtualization--
The program runs under WSL2 to demonstrate virtualization. 
The environment can be verified using:
wsl -l -v
systemd-detect-virt
hostnamectl | grep virt



--Security--
• All communication is encrypted using OpenSSL. 
• The client and server authenticate with certificates. 
• Data and commands are transmitted over TLS.



--Concurrency Model--
The server is multithreaded. Each accepted client connection runs in its own thread created with pthread_create(). 
This allows multiple clients to connect and download files at the same time.



Flow:
• The server waits for connections with accept().
• When a client connects, the server creates a new thread using pthread_create().
• That thread runs serve_one(), which handles all communication with that client.
• After the session ends, the thread closes the connection and exits.




Other Details:
• Threads are detached with pthread_detach(), so they clean up automatically.
• The OpenSSL context (SSL_CTX) is shared safely between threads, and each client gets its own SSL object.
• The media directory is read-only, so threads do not need locks.
• The backlog limit allows up to 16 pending connections at once.



--Known Limitations--
• downloads cannot resume if interrupted; a dropped connection requires restarting the client.
• all reads and writes are blocking, so a slow or unresponsive server can make the client hang.
• the client uses sanitized filenames and adds port and process id to avoid overwriting, but long names may still be truncated.
• only ipv4 is supported; ipv6 connections will fail.
• audio playback can lag on wsl2 or fail if system audio is busy.
• file and folder lists are limited to 256 entries.
• ports below 1024 require sudo privileges.



--Testing Summary--

Virtualization: verified with WSL2
Concurrency: multiple clients connect to one server
Replication: multiple servers run on different ports
Encryption: verified using SSL handshake
Download: client retrieves and plays MP3 files
Fault tolerance: client reconnects to backup server without data loss



