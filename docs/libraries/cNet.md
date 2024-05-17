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

| `CONNECTION_CLOSED` | Triggered when a client disconnected from a server |
| `CONNECTION_OPENED` | Triggered when a client connected to a server      |
| `ENCRYPTED_MESSAGE` | Triggered when an encrypted message is received    |
| `LOGIN`             | Triggered when a client successfully logged in     |
| `LOGIN_FAILED`      | Triggered when a client failed to log in           |
| `LOGOUT`            | Triggered when a client logged out                 |
| `MODEM_MESSAGE`     | Triggered when a modem message is received         |
| `PLAIN_MESSAGE`     | Triggered when an unencrypted message is received  |

### CttpRequestMethod

The [possible methods](../protocols/CTTP#Request-Methods) for a [CTTP Request](../protocols/CTTP#Requests).
These change nothing about the functionality of the request, but help to organize them.

### CttpStatus

The [possible statuses](../protocols/CTTP#Status-Codes) for [CTTP Responses](../protocols/CTTP#Responses).

### ModemSide

Possible attachment sides of the modem

| `TOP`    |
| `BOTTOM` |
| `BACK`   |
| `FRONT`  |
| `LEFT`   |
| `RIGHT`  |

## Classes

### CttpRequest

#### Fields

| `requestMethod` | The [method](#CttpRequestMethod) of the request   |
| `path`          |                                                   |
| `header`        | The [header](../protocols/CTTP#request-headers) of the request |
| `data`          | Any data that is sent with the request            |

#### Functions

- new(`requestMethod`: [CttpRequestMethod](#CttpRequestMethod), `path`: [string](https://www.lua.org/pil/2.4.html), `header?`: [CttpHeader](#CttpHeader), `data?`: [any](https://www.lua.org/pil/2.html)) : [CttpRequest](#CttpRequest)

Creates a new CttpRequest

### CttpResponse

#### Fields

| `statusCode`    | The [method](#CttpRequestMethod) of the response    |
| `statusMessage` |                                                     |
| `header`        | The [header](../protocols/CTTP#Response-Headers) of the response |
| `data`          | Any data that is sent with the response             |

#### Functions

- new(`status`: [CttpStatus](#CttpStatus), `header?`: [CttpHeader](#CttpHeader), `data?`: [any](https://www.lua.org/pil/2.html)) : [CttpResponse](#CttpResponse)

Creates a new CttpResponse

### CtcpConnection

#### Fields

| `Socket`    | The [CryptoNet](CryptoNet) Socket      |
| `seqNumber` | The [CTCP](../protocols/CTCP) sequence number       |
| `ackNumber` | The [CTCP](../protocols/CTCP) acknowledgment number |

#### Functions

- new(`Socket`: [Socket](CryptoNet#Socket), `seqNumber`: [integer](https://www.lua.org/pil/2.3.html), `ackNumber`: [integer](https://www.lua.org/pil/2.3.html))

Creates a new CtcpConnection

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

- host(`serverId`: [string](https://www.lua.org/pil/2.4.html), `modemSide?`: [ModemSide](#ModemSide))

```lua
{% include examples/cNet/host.lua %}
```

- connectCtcp(`serverId`: [string](https://www.lua.org/pil/2.4.html), `timeout?`: [number](https://www.lua.org/pil/2.3.html), `modemSide?`: [ModemSide](#ModemSide)) : [CtcpConnection](#CtcpConnection)/[nil](https://www.lua.org/pil/2.1.html)

Opens a connection to a server using the [CTCP Handshake](../protocols/CTCP#CTCP-handshake)

```lua
{% include examples/cNet/cttp_request.lua %}
```

- disconnectCtcp(`ctcpConnection`: [CtcpConnection](#CtcpConnection), `timeout?`: [number](https://www.lua.org/pil/2.3.html)) : [boolean](https://www.lua.org/pil/2.2.html)

Closes a [CTCP](../protocols/CTCP) connection using the [Finishing Handshake](../protocols/CTCP#closing the connection).

```lua
{% include examples/cNet/cttp_request.lua %}
```

- sendCttpRequest(`ctcpConnection`: [CtcpConnection](#CtcpConnection), `request`: [CttpRequest](#CttpRequest), `timeout`: [number](https://www.lua.org/pil/2.3.html)) : [CttpResponse](#CttpResponse)/[nil](https://www.lua.org/pil/2.1.html), [boolean](https://www.lua.org/pil/2.2.html)

Sends a [CTTP Request](../protocols/CTTP#Requests) to a server.

```lua
{% include examples/cNet/cttp_request.lua %}
```

- connectAndSendCttpRequest(`serverId`: [string](https://www.lua.org/pil/2.4.html), `request`: [CttpRequest](#CttpRequest), `timeout?`: [number](https://www.lua.org/pil/2.3.html), `modemSide?`: [ModemSide](#ModemSide)) : [CttpResponse](#CttpResponse)/[nil](https://www.lua.org/pil/2.1.html), [boolean](https://www.lua.org/pil/2.2.html), [boolean](https://www.lua.org/pil/2.2.html), [boolean](https://www.lua.org/pil/2.2.html)

Connects to a server, sends a [CTTP Request](../protocols/CTTP#Requests) and disconnects.

Returns the response, if the connection was successful, if the request was acknowledged and if the disconnect was acknowledged.

```lua
{% include examples/cNet/cttp_request_short.lua %}
```

- setMessageHandler(`eventType`: [MessageEventType](#MessageEventType), `handler`: [function](https://www.lua.org/pil/2.6.html))

Sets a custom handler for [CryptoNet Message Events](#MessageEventType)

```lua
{% include examples/cNet/message_handler.lua %}
```

- setRestApi(`requestMethod`: [CttpRequestMethod](#CttpRequestMethod), `path`: [string](https://www.lua.org/pil/2.4.html), `handler`: [function](https://www.lua.org/pil/2.6.html))

Sets a handler for a [CTTP Request](../protocols/CTTP#Requests)

```lua
{% include examples/cNet/host.lua %}
```

- register(`serverId`: [string](https://www.lua.org/pil/2.4.html), `username`: [string](https://www.lua.org/pil/2.4.html), `password`: [string](https://www.lua.org/pil/2.4.html), `timeout`: [number](https://www.lua.org/pil/2.3.html), `modemSide`: [ModemSide](#ModemSide)) : [integer](https://www.lua.org/pil/2.3.html)

```lua
{% include examples/cNet/login.lua %}
```

- login(`connection`: [CtcpConnection](#CtcpConnection)/[table](https://www.lua.org/pil/2.5.html), `username`: [string](https://www.lua.org/pil/2.4.html), `password`: [string](https://www.lua.org/pil/2.4.html))

```lua
{% include examples/cNet/login.lua %}
```

- logout(`connection`: [CtcpConnection](#CtcpConnection))

```lua
{% include examples/cNet/login.lua %}
```
