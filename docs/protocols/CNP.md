# CNP (Copper Network Protocol)

The outermost packet is always a CNP packet, it looks like this:

```
{
	Protocol = "Any protocol"
	Payload = The payload
}
```

- The `protocol` is the abbreviation of the used protocol for the payload.
- The `payload` is any object following the named protocol in `protocol`
