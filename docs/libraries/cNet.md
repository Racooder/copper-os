---
layout: default
---

# cNet (Copper Networking)

cNet is the networking library of Copper OS.

## Libraries

### CryptoNet

`cNet.CryptoNet` can be used to access functions of the [CryptoNet](CryptoNet) library. However, this is rarely needed

## Enums

### MessageEventType

The possible types of the [CryptoNet](CryptoNet) message event.

| Event Type          | Trigger                         |
|---------------------|---------------------------------|
| `CONNECTION_CLOSED` | Client disconnected from server |
| `CONNECTION_OPENED` | Client connected to server      |
| `ENCRYPTED_MESSAGE` | Encrypted message is received   |
| `LOGIN`             | Client successfully logged in   |
| `LOGIN_FAILED`      | Client failed to log in         |
| `LOGOUT`            | Client logged out               |
| `MODEM_MESSAGE`     | Modem message is received       |
| `PLAIN_MESSAGE`     | Unencrypted message is received |

### CttpRequestMethod

The [possible methods](../protocols/cttp#request-methods) for a [CTTP Request](../protocols/cttp#requests).
These change nothing about the functionality of the request, but help to organize them.

### CttpStatus

The [possible statuses](../protocols/cttp#status-codes) for [CTTP Responses](../protocols/cttp#responses).

## Classes

### CttpRequest

| `requestMethod` | The [method](#cttprequestmethod) of the request                |
| `path`          |                                                                |
| `header`        | The [header](../protocols/cttp#request-headers) of the request |
| `data`          | Any data that is sent with the request                         |

- new(`requestMethod`: [CttpRequestMethod](#cttprequestmethod), `path`: [string](https://www.lua.org/pil/2.4.html), `header?`: [CttpHeader](#cttpheader), `data?`: [any](https://www.lua.org/pil/2.html)) : [CttpRequest](#cttprequest)

Creates a new cttprequest

### CttpResponse

| `statusCode`    | The [method](#cttprequestmethod) of the response                 |
| `statusMessage` |                                                                  |
| `header`        | The [header](../protocols/cttp#response-headers) of the response |
| `data`          | Any data that is sent with the response                          |

- new(`status`: [CttpStatus](#cttpstatus), `header?`: [CttpHeader](#cttpheader), `data?`: [any](https://www.lua.org/pil/2.html)) : [CttpResponse](#cttpresponse)

Creates a new cttpresponse

### CtcpConnection

| `Socket`    | The [CryptoNet](CryptoNet) Socket                   |
| `seqNumber` | The [CTCP](../protocols/ctcp) sequence number       |
| `ackNumber` | The [CTCP](../protocols/ctcp) acknowledgment number |

- new(`Socket`: [Socket](CryptoNet#Socket), `seqNumber`: [integer](https://www.lua.org/pil/2.3.html), `ackNumber`: [integer](https://www.lua.org/pil/2.3.html))

Creates a new ctcpconnection

## Functions

- checksum(`object`: [any](https://www.lua.org/pil/2.html)) : [integer](https://www.lua.org/pil/2.3.html)

Calculates a checksum for any serializable object

```lua
{% include examples/cNet/checksum.lua %}
```

- startEventLoop(`onStart`: [function](https://www.lua.org/pil/2.6.html))

Starts the [CryptoNet](CryptoNet) event loop.

`onStart` is a callback function that is called when [CryptoNet](CryptoNet) is set up.

```lua
{% include examples/cNet/host.lua %}
```

- host(`serverId`: [string](https://www.lua.org/pil/2.4.html), `modemQuery?`: [string](https://www.lua.org/pil/2.4.html))

```lua
{% include examples/cNet/host.lua %}
```

- connectCtcp(`serverId`: [string](https://www.lua.org/pil/2.4.html), `timeout?`: [number](https://www.lua.org/pil/2.3.html), `modemQuery?`: [string](https://www.lua.org/pil/2.4.html)) : [CtcpConnection](#ctcpconnection)/[nil](https://www.lua.org/pil/2.1.html)

Opens a connection to a server using the [CTCP Handshake](../protocols/ctcp#connection-handshake)

```lua
{% include examples/cNet/cttp_request.lua %}
```

- disconnectCtcp(`ctcpConnection`: [CtcpConnection](#ctcpconnection), `timeout?`: [number](https://www.lua.org/pil/2.3.html)) : [boolean](https://www.lua.org/pil/2.2.html)

Closes a [CTCP](../protocols/ctcp) connection using the [Finishing Handshake](../protocols/ctcp#closing-the-connection).

```lua
{% include examples/cNet/cttp_request.lua %}
```

- sendCttpRequest(`ctcpConnection`: [CtcpConnection](#ctcpconnection), `request`: [CttpRequest](#cttprequest), `timeout`: [number](https://www.lua.org/pil/2.3.html)) : [CttpResponse](#cttpresponse)/[nil](https://www.lua.org/pil/2.1.html), [boolean](https://www.lua.org/pil/2.2.html)

Sends a [CTTP Request](../protocols/cttp#requests) to a server.

```lua
{% include examples/cNet/cttp_request.lua %}
```

- connectAndSendCttpRequest(`serverId`: [string](https://www.lua.org/pil/2.4.html), `request`: [CttpRequest](#cttprequest), `timeout?`: [number](https://www.lua.org/pil/2.3.html), `modemQuery?`: [string](https://www.lua.org/pil/2.4.html)) : [CttpResponse](#cttpresponse)/[nil](https://www.lua.org/pil/2.1.html), [boolean](https://www.lua.org/pil/2.2.html), [boolean](https://www.lua.org/pil/2.2.html), [boolean](https://www.lua.org/pil/2.2.html)

Connects to a server, sends a [CTTP Request](../protocols/cttp#requests) and disconnects.

Returns the response, if the connection was successful, if the request was acknowledged and if the disconnect was acknowledged.

```lua
{% include examples/cNet/cttp_request_short.lua %}
```

- setMessageHandler(`eventType`: [MessageEventType](#messageeventtype), `handler`: [function](https://www.lua.org/pil/2.6.html))

Sets a custom handler for [CryptoNet Message Events](#messageeventtype)

```lua
{% include examples/cNet/message_handler.lua %}
```

- setRestApi(`requestMethod`: [CttpRequestMethod](#cttprequestmethod), `path`: [string](https://www.lua.org/pil/2.4.html), `handler`: [function](https://www.lua.org/pil/2.6.html))

Sets a handler for a [CTTP Request](../protocols/cttp#requests)

```lua
{% include examples/cNet/host.lua %}
```

- register(`serverId`: [string](https://www.lua.org/pil/2.4.html), `username`: [string](https://www.lua.org/pil/2.4.html), `password`: [string](https://www.lua.org/pil/2.4.html), `timeout`: [number](https://www.lua.org/pil/2.3.html), `modemQuery`: [string](https://www.lua.org/pil/2.4.html)) : [integer](https://www.lua.org/pil/2.3.html)

```lua
{% include examples/cNet/login.lua %}
```

- login(`connection`: [CtcpConnection](#ctcpconnection)/[table](https://www.lua.org/pil/2.5.html), `username`: [string](https://www.lua.org/pil/2.4.html), `password`: [string](https://www.lua.org/pil/2.4.html))

```lua
{% include examples/cNet/login.lua %}
```

- logout(`connection`: [CtcpConnection](#ctcpconnection))

```lua
{% include examples/cNet/login.lua %}
```

- setLogger(`logger`: [function](https://www.lua.org/pil/2.6.html))

```lua
{% include examples/cNet/set_logger.lua %}
```
