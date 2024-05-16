---
layout: default
---

# CTTP (Copper Text Transfer Protocol)

CTTP is used for requesting and sending data between a client and server. It is contained in a [[CTCP]] packet.
CTTP differs between requests and responses.
CTTP is in many points similar to the [HTTP Protocol](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP).

## Requests

A CTTP Request consist of a [request method](https://github.com/Racooder/copper-os/wiki/CTTP#request-methods), a path, the [header](https://github.com/Racooder/copper-os/wiki/CTTP#request-headers) and an optional data field.

```
{
	Request Method = "Any request method"
	Path = "Path of the document"
	Header = ...
	Data = any
}
```

### Request Methods

Possible request methods are

- `GET` - Get information from the server
- `POST` - Send information to the server
- `DELETE` - Delete information from the server

### Request Headers

Request headers can contain the following fields, but each of them is optional

## Responses

A CTTP Response consists of a [status code](https://github.com/Racooder/copper-os/wiki/CTTP#status-codes), its brief meaning, the [header](https://github.com/Racooder/copper-os/wiki/CTTP#response-headers) and an optional data field.

```
{
	Status Code = The numerical code of the status
	Status Message = "The status as text"
	Header = ...
	Data = any
}
```

### Status Codes

- `100` - Continue
- `102` - Processing
- `103` - Early Hints
- `200` - OK
- `201` - Created
- `202` - Accepted
- `301` - Moved Permanently
- `307` - Temporary Redirect
- `308` - Permanent Redirect
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `410` - Gone
- `420` - Enhance Your Calm
- `429` - Too Many Requests
- `498` - Token Expired
- `500` - Internal Server Error
- `501` - Not Implemented
- `503` - Service Unavailable
- `507` - Insufficient Storage
- `521` - Server Is Down
- `522` - Connection Timed Out

### Response Headers

Response headers can contain the following fields, but each of them is optional
