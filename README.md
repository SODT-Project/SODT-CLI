# SODT Client CLI

SODT Client CLI is a command-line client for sending and receiving files over a SODT Server via the SODT Protocol.

## How It Works

1. The client connects to an SODT server.
2. The server provides the IDs of the other connected clients.
3. The clients perform a key exchange before communicating securely.
4. A file transfer is requested and starts after the receiving client accepts it.

The client uses ECDH to establish a session key. Messages and file data are then encrypted with AES-GCM.

## Features

- ECDH key exchange for secure client sessions
- AES-GCM encryption for messages and file transfers
- Send files to other connected clients
- Receive files in the users Downloads folder
- View live send and receive progress
- Optional automatic acceptance of key exchanges and file transfers
- Short aliases for frequently used commands

## Usage

### Requirements

- .NET 10 SDK
- Access to an SODT server
- The server's ECDSA public key in PEM format

### Run the client
- Download the Client CLI for your preferred OS under [Releases](https://github.com/SODT-Project/SODT-CLI/releases).
- Unpack the folder and run:

On Linux:
```bash
./SODT-CLI
```
On Windows:
```bash
SODT-CLI.exe
```
As Portable:
```bash
dotnet SODT-CLI.dll
```

### Main commands

```text
connect <host> <port>       Connect to a server
connect-default             Connect using defaultServer.txt
list-clients                List connected client IDs
exchange <clientId>         Exchange a session key with a client
send <clientId> <filePath>  Send a file
list-sends                  Show send progress; press q to stop
list-receives               Show receive progress; press q to stop
disconnect                  Disconnect from the server
help                        Show all available commands
```

Before connecting, configure the server's public key:

```text
set-default-key path/to/server-public-key.pem
```
or 
```text
set-default-key https://myserver.tld/sodt/public-key.pem
```
- The key is saved as `defaultServer.key` in the current directory. The client requires this key when connecting.
- To configure the default server, use `set-default-server <host> <port>`. Use `list-aliases` to see the available shortcuts, such as `c` for `connect-default` and `s` for `send`.
- Incoming files are saved in the user's Downloads folder.
- File transfers and key exchanges can be accepted automatically with `auto-accept-files`, `auto-accept-keys`, or `auto-accept-all`.


