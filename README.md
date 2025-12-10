# Ferron example module

This is an example module for Ferron, demonstrating how to create a custom HTTP handler module with Ferron.

## Notes

This module responds with "Hello World!" for "/hello" request paths.

## Additional KDL configuration directives

### Directives

- `example_handler [enable_example_handler: bool]`
  - This directive specifies whenever an example handler is enabled. This handler responds with "Hello World" for "/hello" request paths. Default: `example_handler #false`

**Configuration example:**

```kdl
dev.example.com {
    // Enable example handler for testing
    example_handler

    // Enhanced logging for development
    log "/var/log/ferron/dev.access.log"
    error_log "/var/log/ferron/dev.error.log"

    // Custom test endpoints
    status 200 url="/test" body="Test endpoint working"
    status 500 url="/test-error" body="Simulated error"
}
```

## Compiling Ferron with this module

To compile Ferron with this module, first clone the Ferron repository:

```bash
git clone https://github.com/ferronweb/ferron.git -b develop-2.x
cd ferron
```

Then, copy the `ferron-build.yaml` file to `ferron-build-override.yaml`:

```bash
cp ferron-build.yaml ferron-build-override.yaml
```

After that, add the following line to the `ferron-build-override.yaml` file:

```yaml
modules:
  # Other modules...
  - git: https://github.com/ferronweb/ferron-module-example.git
    crate: ferron-module-example
    loader: ExampleModuleLoader
```

It's suggested to define this module between the module with `ReverseProxyModuleLoader` and `FcgiModuleLoader`.

After modifying the `ferron-build-override.yaml` file, you can compile Ferron with this module by running the following command:

```bash
make build
```

Or if you're on Windows:

```batch
powershell -ExecutionPolicy Bypass .\build.ps1 Build
```

You can then package it in a ZIP archive using the following command:

```bash
make package
```

Or if you're on Windows:

```batch
powershell -ExecutionPolicy Bypass .\build.ps1 Package
```

The ZIP archive will be created in the `dist` directory, and can be installed using Ferron installer.
