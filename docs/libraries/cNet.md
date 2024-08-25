---
layout: default
---

# cNet (Copper Networking)

cNet is the networking library of Copper OS.
It uses [CryptoNet](CryptoNet) for encrypted messaging.

## Clients and Servers

#### setup(`onStart`)

Setup the cNet module.

##### Parameters:

* `onStart` (function) <br>
    The function to call when the event loop starts.

#### host(`serverName`, `discoverable?`, `hideCertificate?`, `modemSide?`, `certificate?`, `privateKey?`, `userTablePath?`)

Setup and host a cNet server.

##### Parameters:

* `serverName` (string) <br>
    The name of the server, which clients will use to connect to it. Also determines the channel that the server communicates on.
* `discoverable` (boolean) <br>
    (default: true) Whether this server responds to discover() requests. Disabling this is more secure as it means clients can't connect unless they already know the name of the server.
* `hideCertificate` (boolean) <br>
    (default: false) If true the server will not distribute its certificate to clients, either in discover() or connect() requests, meaning clients can only connect if they have already been given the certificate manually. Useful if you only want certain manually authorised clients to be able to connect.
* `modemSide` (string) <br>
    The modem the server should use.
* `certificate` (Certificate | string) <br>
    (default: "\<serverName\>.crt") The certificate of the server. This can either be the certificate table itself, or the name of a file that contains it. If the certicate and key files do not exist, new ones will be generated and saved to the specified files.
* `privateKey` (PrivateKey | string) <br>
    (default: "\<serverName\>_private.key") The private key of the server. This can either be the key table itself, or the name of a file that contains it. If the certicate and key files do not exist, new ones will be generated and saved to the specified files.
* `userTablePath` (string) <br>
    (default: "\<serverName\>_users.tbl") Path at which to store the user login details table, if/when users are added to the server.

##### Returns:

1. `server` (Server) <br>
    The server object.

#### connect(`serverName?`, `timeout?`, `certTimeout?`, `certificate?`, `modemSide?`, `certAuthKey?`, `allowUnsigned?`)

Open an encrypted connection to a cNet server, returning a socket object that can be used to send and receive messages from the server.

##### Parameters:

* `serverName` (string) <br>
    (default: inferred from certificate) The name of the server to connect to.
* `timeout` (number) <br>
    (default: 5) The number of seconds to wait for a response to the connection request. Will terminate early if a response is received.
* `certTimeout` (number) <br>
    (default: 1) The number of seconds to wait for certificate responses, if no certificate was provided.
* `certificate` (Certificate | string) <br>
    (default: "\<serverName\>.crt") The certificate of the server. Can either be the certificate of the server itself, or the name of a file that contains it. If no valid certificate is found a certificate request will be sent to the server.
* `modemSide` (string) <br>
    (default: a side with a modem) The modem to use to send and receive messages.
* `certAuthKey` (PublicKey | string) <br>
    (default: "certAuth.key") The certificate authority public key used to verify signatures, or the path of the file to load it from. If no valid key is found the connection will still go ahead, but signatures will not be checked.
* `allowUnsigned` (boolean) <br>
    (default: false) Whether to accept certificates with no valid signature. If no valid cert auth key is provided this is ignored, as the certificates cannot be checked without a key. This does not apply to the certificate provided by the user (if present), which is never verified (we trust them to get their own certificate right), only to certificates received through a certificate request.

##### Returns:

* `socket` (Socket)

#### send(`socket`, `message`)

Send an encrypted message over the given socket. The message can be pretty much any Lua data type.

##### Parameters:

* `socket` (Socket) <br>
* `message` (boolean | number | string | table | nil)
