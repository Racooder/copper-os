---
layout: page
title: cNet (Copper Network)
permalink: /libraries/cNet
---

cNet is the networking library of Copper OS.

## Libraries

### CryptoNet

`cNet.CryptoNet` can be used to access functions of the [[CryptoNet]] library. However, this is rarely needed

## Enums

### MessageEventType

The possible types of the [[CryptoNet]] message event.

- `CONNECTION_CLOSED` - Triggered when a client disconnected from a server
- `CONNECTION_OPENED` - Triggered when a client connected to a server
- `ENCRYPTED_MESSAGE` - Triggered when an encrypted message is received
- `LOGIN` - Triggered when a client successfully logged in
- `LOGIN_FAILED` - Triggered when a client failed to log in
- `LOGOUT` - Triggered when a client logged out
- `MODEM_MESSAGE` - Triggered when a modem message is received
- `PLAIN_MESSAGE` - Triggered when an unencrypted message is received

### CttpRequestMethod

The [possible methods](https://github.com/Racooder/copper-os/wiki/CTTP#request-methods) for a [CTTP Request](https://github.com/Racooder/copper-os/wiki/CTTP#requests).
These change nothing about the functionality of the request, but help to organize them.

### CttpStatus

The [possible statuses](https://github.com/Racooder/copper-os/wiki/CTTP#Status-Codes) for [CTTP Responses](https://github.com/Racooder/copper-os/wiki/CTTP#Responses).

### ModemSide

Possible attachment sides of the modem

- `TOP`
- `BOTTOM`
- `BACK`
- `FRONT`
- `LEFT`
- `RIGHT`

## Classes

### CttpRequest

#### Fields

- `requestMethod` - The [method](https://github.com/Racooder/copper-os/wiki/cNet#CttpRequestMethod) of the request
- `path`
- `header` The [header](https://github.com/Racooder/copper-os/wiki/CTTP#Request-Headers) of the request
- `data` - Any data that is sent with the request

#### Functions

##### new(`requestMethod`: [CttpRequestMethod](https://github.com/Racooder/copper-os/wiki/cNet#CttpRequestMethod), `path`: [string](https://www.lua.org/pil/2.4.html), `header?`: [CttpHeader](https://github.com/Racooder/copper-os/wiki/cNet#CttpHeader), `data?`: [any](https://www.lua.org/pil/2.html)) : [CttpRequest](https://github.com/Racooder/copper-os/wiki/cNet#CttpRequest)

### CttpResponse

#### Fields

- `statusCode` - The [method](https://github.com/Racooder/copper-os/wiki/cNet#CttpRequestMethod) of the response
- `statusMessage`
- `header` The [header](https://github.com/Racooder/copper-os/wiki/CTTP#Response-Headers) of the response
- `data` - Any data that is sent with the response

#### Functions

##### new(`status`: [CttpStatus](https://github.com/Racooder/copper-os/wiki/cNet#CttpStatus), `header?`: [CttpHeader](https://github.com/Racooder/copper-os/wiki/cNet#CttpHeader), `data?`: [any](https://www.lua.org/pil/2.html)) : [CttpResponse](https://github.com/Racooder/copper-os/wiki/cNet#CttpResponse)

### CtcpConnection

#### Fields

- `socket` - The [[CryptoNet]] socket
- `seqNumber` - The [[CTCP]] sequence number
- `ackNumber` - The [[CTCP]] acknowledgment number

#### Functions

##### new(`socket`: [Socket](https://github.com/Racooder/copper-os/wiki/CryptoNet#Socket), `seqNumber`: [integer](https://www.lua.org/pil/2.3.html), `ackNumber`: [integer](https://www.lua.org/pil/2.3.html))

## Functions

##### checksum(`object`: [any](https://www.lua.org/pil/2.html)) : [integer](https://www.lua.org/pil/2.3.html)

Calculates a checksum for any serializable object

##### startEventLoop(`onStart`: [function](https://www.lua.org/pil/2.6.html))

Starts the [[CryptoNet]] event loop.

`onStart` is a callback function that is called when [[CryptoNet]] is set up.

##### host(`serverId`: [string](https://www.lua.org/pil/2.4.html), `modemSide?`: [ModemSide](https://github.com/Racooder/copper-os/wiki/cNet#ModemSide))

##### connectCtcp(`serverId`: [string](https://www.lua.org/pil/2.4.html), `timeout?`: [number](https://www.lua.org/pil/2.3.html), `modemSide?`: [ModemSide](https://github.com/Racooder/copper-os/wiki/cNet#ModemSide)) : [CtcpConnection](https://github.com/Racooder/copper-os/wiki/cNet#CtcpConnection)|[nil](https://www.lua.org/pil/2.1.html)

Opens a connection to a server using the [CTCP Handshake](https://github.com/Racooder/copper-os/wiki/CTCP#CTCP-Handshake)

##### disconnectCtcp(`ctcpConnection`: [CtcpConnection](https://github.com/Racooder/copper-os/wiki/cNet#CtcpConnection), `timeout?`: [number](https://www.lua.org/pil/2.3.html)) : [boolean](https://www.lua.org/pil/2.2.html)

Closes a [[CTCP]] connection using the [Finishing Handshake](https://github.com/Racooder/copper-os/wiki/CTCP#Closing the connection).

##### sendCttpRequest(`ctcpConnection`: [CtcpConnection](https://github.com/Racooder/copper-os/wiki/cNet#CtcpConnection), `request`: [CttpRequest](https://github.com/Racooder/copper-os/wiki/cNet#CttpRequest), `timeout`: [number](https://www.lua.org/pil/2.3.html)) : [CttpResponse](https://github.com/Racooder/copper-os/wiki/cNet#CttpResponse)|[nil](https://www.lua.org/pil/2.1.html), [boolean](https://www.lua.org/pil/2.2.html)

Sends a [CTTP Request](https://github.com/Racooder/copper-os/wiki/CTTP#Requests) to a server.

##### connectAndSendCttpRequest(`serverId`: [string](https://www.lua.org/pil/2.4.html), `request`: [CttpRequest](https://github.com/Racooder/copper-os/wiki/cNet#CttpRequest), `timeout?`: [number](https://www.lua.org/pil/2.3.html), `modemSide?`: [ModemSide](https://github.com/Racooder/copper-os/wiki/cNet#ModemSide)) : [CttpResponse](https://github.com/Racooder/copper-os/wiki/cNet#CttpResponse)|[nil](https://www.lua.org/pil/2.1.html), [boolean](https://www.lua.org/pil/2.2.html), [boolean](https://www.lua.org/pil/2.2.html), [boolean](https://www.lua.org/pil/2.2.html)

Connects to a server, sends a [CTTP Request](https://github.com/Racooder/copper-os/wiki/CTTP#Requests) and disconnects.

Returns the response, if the connection was successful, if the request was acknowledged and if the disconnect was acknowledged.

##### setMessageHandler(`eventType`: [MessageEventType](https://github.com/Racooder/copper-os/wiki/cNet#MessageEventType), `handler`: [function](https://www.lua.org/pil/2.6.html))

Sets a custom handler for [CryptoNet Message Events](https://github.com/Racooder/copper-os/wiki/cNet#MessageEventType)

##### setRestApi(`requestMethod`: [CttpRequestMethod](https://github.com/Racooder/copper-os/wiki/cNet#CttpRequestMethod), `path`: [string](https://www.lua.org/pil/2.4.html), `handler`: [function](https://www.lua.org/pil/2.6.html))

Sets a handler for a [CTTP Request](https://github.com/Racooder/copper-os/wiki/CTTP#Requests)

##### register(`serverId`: [string](https://www.lua.org/pil/2.4.html), `username`: [string](https://www.lua.org/pil/2.4.html), `password`: [string](https://www.lua.org/pil/2.4.html), `timeout`: [number](https://www.lua.org/pil/2.3.html), `modemSide`: [ModemSide](https://github.com/Racooder/copper-os/wiki/cNet#ModemSide)) : [integer](https://www.lua.org/pil/2.3.html)

##### login(`connection`: [CtcpConnection](https://github.com/Racooder/copper-os/wiki/cNet#CtcpConnection)|[table](https://www.lua.org/pil/2.5.html), `username`: [string](https://www.lua.org/pil/2.4.html), `password`: [string](https://www.lua.org/pil/2.4.html))

##### logout(`connection`: [CtcpConnection](https://github.com/Racooder/copper-os/wiki/cNet#CtcpConnection))
