# IP Block Module (Redis-based)

A simple IP blocking module for the **Ferron** web server.  
It checks every incoming request against a Redis **SET** and blocks the request if the client IP is listed.

If an IP is blocked, the server responds with **HTTP 403 Forbidden**.

---

## Features

- Real-time IP blocking
- Uses Redis SET as the blocklist backend
- No in-memory cache (block/unblock takes effect immediately)
- Fail-safe design: requests are allowed if Redis is unavailable

---

## Requirements

- Redis server
- Blocked IPs stored as strings in a Redis SET
- Loaded via the Ferron module system

---

## Configuration

Example KDL configuration:

```kdl
dev.example.com {
    ip_block redis_url="redis://127.0.0.1:6379" redis_key="blocked_ips"

    log "/var/log/ferron/dev.access.log"
    error_log "/var/log/ferron/dev.error.log"
}
```
---

## Option

| Option      | Default                  | Description                          |
| ----------- | ------------------------ | ------------------------------------ |
| `ip_block`  | `true`                   | Enable the module                    |
| `redis_url` | `redis://127.0.0.1:6379` | Redis connection URL                 |
| `redis_key` | `blocked_ips`            | Redis SET key containing blocked IPs |

---

## Redis Data Structure

This module uses a Redis SET:
```redis-cli
SADD blocked_ips 192.168.1.10
SADD blocked_ips 203.0.113.5
```

Check membership:
```redis-cli
SISMEMBER blocked_ips 192.168.1.10
```
---

## Behavior

If the client IP is blocked → returns 403 Forbidden
Logs blocked IPs:
```log
Blocked IP: <ip_address>
```
If Redis fails or times out → the request is allowed

## Notes
Client IP is taken from socket_data.remote_addr
Does not modify request or response bodies
Designed to avoid blocking request handling on Redis errors
