# Asynchronous HTTP Client library for ESP8266 and ESP32

**NOTE** This library is very much a work in progress.

## Missing functionality

- ESP8266 support
- chunked transfer encoding hasn't been tested
- keepalive functionality hasn't been tested
- output buffering (sending more than 5744 bytes at a time)
- anything outside of the unit tests, basically...

## To be done

- Internal buffer handling is wasteful. `cbuf` should be replaced with
  a char* deque implementation or something similar.
- Response header handling is clunky and dumb