---
layout: page
title: CTCP
permalink: /protocols/ctcp
---

# CTCP (Copper Transmission Control Protocol)

CTCP is used for reliably exchanging data. It is contained in a [[CNP]] packet's payload.
CTCP resembles the [TCP Protocol](https://de.wikipedia.org/wiki/Transmission_Control_Protocol), but is very simplified.

## CTCP Handshake

Each CTCP session starts with a three-way handshake.
First, the client sends a `SYN` packet to the host looking like this.

```
{
	Sequence number = random
	Acknowledgment number = 0
	Flags = {"SYN"}
}
```

Then the server answers with a `SYN-ACK` packet.

```
{
	Sequence number = random
	Acknowledgment number = SYN sequence number + 1
	Flags = {"SYN", "ACK"}
}
```

Finally, the client answers with a `ACK` packet looking like the following.

```
{
	Sequence number = SYN-ACK acknowledgment number
	Acknowledgment number = SYN-ACK sequence number + 1
	Flags = {"ACK"}
}
```

## Data Exchange

Now the data exchange can begin
The coordination of a CTCP data exchange works by counting up two values `P` and `Q`. After the handshake, `P1` is the same as the sequence number and `Q1` as the acknowledgment number of the `ACK` packet.

```
{
	Sequence number = P1
	Acknowledgment number = Q1
	Flags = {},
	Payload = any
}
```

The recipient acknowledges by sending a packet with the `ACK` flag and an acknowledgment number of `P1 + 1` this is now our `P2`.

```
{
	Sequence number = Q1
	Acknowledgment number = P2
	Flags = {"ACK"}
}
```

Then he sends the actual answer. In this answer, the sequence number is `P2` and the acknowledgment number is `Q1 + 1` this is now `Q2`.

```
{
	Sequence number = P2
	Acknowledgment number = Q2
	Flags = {}
	Payload = any
}
```

The original sender acknowledges the answer by sending a packet with the `ACK` flag and an acknowledgment number of `Q2 + 1` this is now `Q3`.

```
{
	Sequence number = P2
	Acknowledgment number = Q3
	Flags = {"ACK"}
}
```

For the next message, both the sequence and acknowledgment numbers would be `P2` and `Q3` again.

```
{
	Sequence number = P2
	Acknowledgment number = Q3
	Flags = {}
	Payload = string
}
```

## Closing the connection

Closing the connection works again with a three-way conversation.
First, the initiator sends a `FIN` packet with sequence and acknowledgment number, like during a [data exchange](https://github.com/Racooder/copper-os/wiki/CTCP#data-exchange).

```
{
	Sequence number = ?
	Acknowledgment number = ?
	Flags = {"FIN"}
}
```

Then the receiver answers with a `FIN-ACK` packet.

```
{
	Sequence number = FIN acknowledgment number
	Acknowledgment number = FIN sequence number + 1
	Flags = {"FIN", "ACK"}
}
```

Finally, the client answers with a `ACK` packet looking like the following.

```
{
	Sequence number = FIN-ACK acknowledgment number
	Acknowledgment number = FIN-ACK sequence number + 1
	Flags = {"ACK"}
}
```
