# README

## Build

1. copy into `optee_examples` folder
2. go into the `build` folder
3. `make run`

## Architecture

```
                       ┌─┐                                                                                                         ,.-^^-._
                       ║"│                                                                                                        |-.____.-|
                       └┬┘                                                                                                        |        |
                       ┌┼┐                                                                                                        |        |
                        │                   ┌────────────────┐          ┌───────────────────┐            ┌───────────┐            |        |
                       ┌┴┐                  │user application│          │trusted application│            │OP-TEE core│            '-.____.-'
                      User                  └───────┬────────┘          └─────────┬─────────┘            └─────┬─────┘           /data/tee/
                       │ sets a key with            │                             │                            │                     │
                       │ ""seal-key s|set-key <id>""│                             │                            │                     │
                       │ ""-k [key]/-f <file>""     │                             │                            │                     │
                       │ ───────────────────────────>                             │                            │                     │
                       │                            │                             │                            │                     │
                       │                            │        write command        │                            │                     │
                       │                            │ ───────────────────────────>│                            │                     │
                       │                            │                             │                            │                     │
                       │                            │                             │write data object API call  │                     │
                       │                            │                             │───────────────────────────>│                     │
                       │                            │                             │                            │                     │
                       │                            │                             │                            │  write encrypted    │
                       │                            │                             │                            │  object to memory   │
                       │                            │                             │                            │────────────────────>│
                       │                            │                             │                            │                     │
                       │                            │                             │      returns sucess        │                     │
                       │                            │                             │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                     │
                       │                            │                             │                            │                     │
                       │                            │       returns success       │                            │                     │
                       │                            │ <─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                            │                     │
                       │                            │                             │                            │                     │
                       │       returns success      │                             │                            │                     │
                       │ <─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                             │                            │                     │
                       │                            │                             │                            │                     │
                       │ sets a key with            │                             │                            │                     │
                       │ ""seal-key g|get-key <id>""│                             │                            │                     │
                       │ ───────────────────────────>                             │                            │                     │
                       │                            │                             │                            │                     │
                       │                            │        read command         │                            │                     │
                       │                            │ ───────────────────────────>│                            │                     │
                       │                            │                             │                            │                     │
                       │                            │                             │return data object API call │                     │
                       │                            │                             │───────────────────────────>│                     │
                       │                            │                             │                            │                     │
                       │                            │                             │                            │ read encrypted      │
                       │                            │                             │                            │ object from memory  │
                       │                            │                             │                            │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
                       │                            │                             │                            │                     │
                       │                            │                             │    returns data object     │                     │
                       │                            │                             │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                     │
                       │                            │                             │                            │                     │
                       │                            │     returns data object     │                            │                     │
                       │                            │ <─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                            │                     │
                       │                            │                             │                            │                     │
                       │     returns data object    │                             │                            │                     │
                       │ <─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                             │                            │                     │
                       │                            │                             │                            │                     │
  ╔═══════════════════╗│ delete a key with          │                             │                            │                     │
  ║If the key is not ░║│ ""seal-key d|del-key <id>""│                             │                            │                     │
  ║needed any more    ║│ ───────────────────────────>                             │                            │                     │
  ║it can be deleted  ║│                            │                             │                            │                     │
  ╚═══════════════════╝│                            │                             │                            │                     │
                       │                            │       delete command        │                            │                     │
                       │                            │ ───────────────────────────>│                            │                     │
                       │                            │                             │                            │                     │
                       │                            │                             │delete data object API call │                     │
                       │                            │                             │───────────────────────────>│                     │
                       │                            │                             │                            │                     │
                       │                            │                             │                            │  delete encrypted   │
                       │                            │                             │                            │  object             │
                       │                            │                             │                            │────────────────────>│
                       │                            │                             │                            │                     │
                       │                            │                             │      returns success       │                     │
                       │                            │                             │<─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                     │
                       │                            │                             │                            │                     │
                       │                            │       returns success       │                            │                     │
                       │                            │ <─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                            │                     │
                       │                            │                             │                            │                     │
                       │       returns success      │                             │                            │                     │
                       │ <─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                             │                            │                     │
                      User                  ┌───────┴────────┐          ┌─────────┴─────────┐            ┌─────┴─────┐           /data/tee/
                       ┌─┐                  │user application│          │trusted application│            │OP-TEE core│             ,.-^^-._
                       ║"│                  └────────────────┘          └───────────────────┘            └───────────┘            |-.____.-|
                       └┬┘                                                                                                        |        |
                       ┌┼┐                                                                                                        |        |
                        │                                                                                                         |        |
                       ┌┴┐                                                                                                        '-.____.-'
```

## Further Features

- Base 64 encoding or something similar to avoid the command line issues with special characters
  - the cli issues make the key space smaller this is only ok because this is a PoC
  - this decreases security severely
- Thorough input checking: Improve input validation for command line and key file inputs. Currently, only ID validation is implemented.
- Error handling and consistency: Enhance error messages, cleanup on errors, and ensure consistent user experience.
- Integration tests: Develop integration tests to evaluate different input paths and improve application resilience.
- Code structure improvement: Split the application into multiple files for better maintainability and development.
  - this was tried but the build system didn't like it
  - after some hours of trying to understand the issue I concentrated on the task at hand which is
    not the style of the code but the functionality
- Trusted Application adjustments: Customize the Trusted Application portion to meet specific application needs, including further key encryption.
- Enhancing security: Explore additional encryption layers to improve security, considering the insecure default configuration for Hardware Unique Key (HUK) and chip ID.
- Seamless switching between namespaces: Enable seamless switching between namespaces to allow multiple applications to use the utility without accessing each other's keys.
