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



--Build Instructions--
the makefile builds both the server and client.
run:
make
make clean

the server links statically to openssl and crypto by default. this means the server binary carries its encryption libraries internally, so it can run even if the grader’s linux system does not have openssl installed or if the user cannot use sudo. this improves portability and fault tolerance.

the client links dynamically to mpg123 and portaudio. these libraries are used for mp3 decoding and audio playback, and static linking often fails on linux because static archives for audio are not usually included. keeping them dynamic ensures easy compilation on most systems and smaller file size.

optional builds:
make dyn (forces both client and server to link dynamically)
make FULL_STATIC=1 (tries full static build; may fail on glibc systems)

--certificates--
two ssl files are required: cert.pem and key.pem. these are included. if missing, generate new ones with:
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"


--Project Structure--
media/ contains all MP3 files grouped by genre.
cert.pem and key.pem are in the root folder.
ssl-serveraudio and ssl-clientaudio are the compiled programs.
ssl-serveraudio.c and ssl-clientaudio.c are the source files.
Makefile builds both programs.
Project Proposal.pdf is included.


Running the Project
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



--Example Use Case--
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


--Replication and Fault Tolerance--
To test replication, start two servers on ports 4433 and 4434. Connect one or more clients to 4433. Then kill the server running on 4433. Reconnect clients to 4434. Playback and downloads continue normally.

--Virtualization--
The program runs under WSL2 to demonstrate virtualization. The environment can be verified using:
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

Details:
• Threads are detached with pthread_detach(), so they clean up automatically.
• The OpenSSL context (SSL_CTX) is shared safely between threads, and each client gets its own SSL object.
• The media directory is read-only, so threads do not need locks.
• The backlog limit allows up to 16 pending connections at once.

How to Verify:
• Run the server on one terminal, then connect two or more clients at the same time. 
• Each client can browse or download different files independently. 
• Downloads continue simultaneously, confirming concurrent thread handling.





--Known Limitations--
• downloads cannot resume if interrupted; a dropped connection requires restarting the client.
• all reads and writes are blocking, so a slow or unresponsive server can make the client hang.
• the client uses sanitized filenames and adds port and process id to avoid overwriting, but long names may still be truncated.
• only ipv4 is supported; ipv6 connections will fail.
• audio playback can lag on wsl2 or fail if system audio is busy.
• file and folder lists are limited to 256 entries.
• ports below 1024 require sudo privileges.



--Testing Summary--

Virtualization: verified with WSL2.
Concurrency: multiple clients connect to one server.
Replication: multiple servers run on different ports.
Encryption: verified using SSL handshake.
Download: client retrieves and plays MP3 files.
Fault tolerance: client reconnects to backup server without data loss.