**Configuration example:**

```kdl
dev.example.com {
    // Enable ip_block
    ip_block redis_url="redis://127.0.0.1:6379" redis_key="blocked_ips"

    // Enhanced logging for development
    log "/var/log/ferron/dev.access.log"
    error_log "/var/log/ferron/dev.error.log"

    // Custom test endpoints
    status 200 url="/test" body="Test endpoint working"
    status 500 url="/test-error" body="Simulated error"
}
```