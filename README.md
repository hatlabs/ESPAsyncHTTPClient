# Asynchronous HTTP Client library for ESP8266 and ESP32

**NOTE** This library is very much a work in progress.

## Missing functionality

- ESP8266 support
- chunked transfer encoding hasn't been tested
- keepalive functionality hasn't been tested
- multiline headers not supported yet
- output buffering (sending more than 5744 bytes at a time)
- anything outside of the unit tests, basically...

## To be done

- stringstreams are inefficient and slow and should be replaced with
  some dynamic ring buffer implementation
- Rewrite the parser as a push-down state automaton?
