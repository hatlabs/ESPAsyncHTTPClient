/**
 * Copyright (c) 2015, 2021 Markus Sattler, Evandro Luis Copercini, Matti Airas.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef AsyncHTTPClient_H_
#define AsyncHTTPClient_H_

#include <Arduino.h>

#include <memory>
#if defined(ESP8266)
#include <ESPAsyncTCP.h>
#elif defined(ESP32)
#include <AsyncTCP.h>
#endif

#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT 5000
#define HTTPCLIENT_DEFAULT_RESPONSE_TIMEOUT 5000

/// HTTP client errors
enum class HTTPClientError {
  NO_ERROR = 0,
  CONNECTION_REFUSED = -1,
  DNS_FAILED = -2,
  TCP_TIMEOUT = -3,
  SEND_HEADER_FAILED = -4,
  SEND_PAYLOAD_FAILED = -5,
  NOT_CONNECTED = -6,
  CONNECTION_LOST = -7,
  NO_STREAM = -8,
  NO_HTTP_SERVER = -9,
  OUT_OF_MEMORY = -10,
  ENCODING = -11,
  STREAM_WRITE = -12,
  READ_TIMEOUT = -13,
  CONNECTION_ABORTED = -14,
  CONNECTION_RESET = -15,
  CONNECTION_CLOSED = -16,
  NO_RESPONSE = -17,
  UNKNOWN = -18,
};

/// size for the stream handling
#define HTTP_TCP_BUFFER_SIZE 1460

/// HTTP codes see RFC7231
enum class HTTPStatusCode {
  CONTINUE = 100,
  SWITCHING_PROTOCOLS = 101,
  PROCESSING = 102,
  OK = 200,
  CREATED = 201,
  ACCEPTED = 202,
  NON_AUTHORITATIVE_INFORMATION = 203,
  NO_CONTENT = 204,
  RESET_CONTENT = 205,
  PARTIAL_CONTENT = 206,
  MULTI_STATUS = 207,
  ALREADY_REPORTED = 208,
  IM_USED = 226,
  MULTIPLE_CHOICES = 300,
  MOVED_PERMANENTLY = 301,
  FOUND = 302,
  SEE_OTHER = 303,
  NOT_MODIFIED = 304,
  USE_PROXY = 305,
  TEMPORARY_REDIRECT = 307,
  PERMANENT_REDIRECT = 308,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  PAYMENT_REQUIRED = 402,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  METHOD_NOT_ALLOWED = 405,
  NOT_ACCEPTABLE = 406,
  PROXY_AUTHENTICATION_REQUIRED = 407,
  REQUEST_TIMEOUT = 408,
  CONFLICT = 409,
  GONE = 410,
  LENGTH_REQUIRED = 411,
  PRECONDITION_FAILED = 412,
  PAYLOAD_TOO_LARGE = 413,
  URI_TOO_LONG = 414,
  UNSUPPORTED_MEDIA_TYPE = 415,
  RANGE_NOT_SATISFIABLE = 416,
  EXPECTATION_FAILED = 417,
  MISDIRECTED_REQUEST = 421,
  UNPROCESSABLE_ENTITY = 422,
  LOCKED = 423,
  FAILED_DEPENDENCY = 424,
  UPGRADE_REQUIRED = 426,
  PRECONDITION_REQUIRED = 428,
  TOO_MANY_REQUESTS = 429,
  REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
  INTERNAL_SERVER_ERROR = 500,
  NOT_IMPLEMENTED = 501,
  BAD_GATEWAY = 502,
  SERVICE_UNAVAILABLE = 503,
  GATEWAY_TIMEOUT = 504,
  HTTP_VERSION_NOT_SUPPORTED = 505,
  VARIANT_ALSO_NEGOTIATES = 506,
  INSUFFICIENT_STORAGE = 507,
  LOOP_DETECTED = 508,
  NOT_EXTENDED = 510,
  NETWORK_AUTHENTICATION_REQUIRED = 511
};

enum class HTTPTransferEncoding { IDENTITY, CHUNKED };

enum class HTTPConnectionState {
  DISCONNECTED = 10,
  KEEPALIVE = 11,
  CONNECTING = 12,
  CONNECTED = 13,
  REQUEST_SENT = 14,
  PARTIAL_HEADERS_RECEIVED = 15,
  HEADERS_RECEIVED = 16,
  PARTIAL_BODY_RECEIVED = 17,
  BODY_RECEIVED = 18,
  PARTIAL_TRAILERS_RECEIVED = 19,
  TRAILERS_RECEIVED = 20,
  DONE = 21,
  ERROR = 22
};

typedef std::function<void(HTTPConnectionState state)> ConnectionEventHandler;

class AsyncHTTPClient {
 public:
  AsyncHTTPClient();
  ~AsyncHTTPClient();

  bool begin(const char* url);
  bool begin(const char* host, uint16_t port, const char* uri = "/");

  void close(void);

  bool connected(void);

  void reuse(bool reuse);  /// keep-alive
  void user_agent(const char* user_agent);
  void authorization(const char* user, const char* password);
  void authorization(const char* auth);
  void connect_timeout(uint32_t connect_timeout);
  void response_timeout(uint32_t timeout);

  void use_http_10(bool use_http_10 = true);

  /// request handling
  bool GET(ConnectionEventHandler callback);
  bool PATCH(const char* payload, size_t size, ConnectionEventHandler callback);
  bool POST(const char* payload, size_t size, ConnectionEventHandler callback);
  bool PUT(const char* payload, size_t size, ConnectionEventHandler callback);
  bool send_request(const char* type, const char* payload, size_t size,
                    ConnectionEventHandler callback);

  void add_header(const char* name, const char* value);

  /// Response handling
  void add_response_header_filter(const char* header_name);
  void add_response_header_filter(const String header_name);
  void add_response_header_filter(const std::string header_name);
  void save_all_headers(bool save_all = true) { _save_all_headers = save_all; }
  const char* header(const char* name);
  const String header(const String name);
  const std::string header(const std::string name);
  const char* header(size_t i);
  const char* header_name(size_t i);
  int headers();
  bool has_header(const char* name);
  bool has_header(const String name);
  bool has_header(const std::string name);

  int size(void);
  int http_status_code() { return response_status_code_; }

  int response_string(char* dest);
  const std::string response_string();
  const String response_arduino_string();
  HTTPClientError last_error() { return last_error_; };
  const char* error_string(HTTPClientError error);
  const char* connection_state_string(HTTPConnectionState state);

  const std::stringstream& response() { return response_stream_; }

 protected:
  HTTPConnectionState connection_state_ = HTTPConnectionState::DISCONNECTED;
  HTTPClientError last_error_ = HTTPClientError::NO_ERROR;

  void update_state(HTTPConnectionState new_state, bool announce = true,
                    bool announce_always = false);

  bool begin_internal(const char* url, const char* expected_protocol);
  void disconnect(bool keepalive = false);
  void clear();
  int report_error(HTTPClientError error);
  bool connect(void);
  bool send_header(const char* type);
  int handle_header_response();
  void handle_header_line();
  void parse_header_start_line(const std::string& header_line);
  void parse_header_line(const std::string& header_line);

  bool async_write(const char* data, size_t size);
  bool async_write(std::stringstream& data);
  bool async_write(std::string& data);

  AsyncClient tcpclient_;

  ConnectionEventHandler client_event_handler_ = NULL;

  /// request handling
  std::string host_;
  uint16_t port_ = 0;
  int32_t connect_timeout_ = HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT;
  bool reuse_ = true;
  uint16_t response_timeout_ = HTTPCLIENT_DEFAULT_RESPONSE_TIMEOUT;
  bool use_http_10_ = false;

  std::string uri_;
  std::string protocol_;
  std::string headers_;
  std::string user_agent_ = "AsyncHTTPClient";
  std::string base64_authorization_;

  std::string request_type_;
  std::string request_payload_;

  void connect_event_handler(void* arg);
  void disconnect_event_handler(void* args);
  void data_event_handler(void* args, void* data, size_t len);
  void error_event_handler(void* args, int8_t error);
  void timeout_event_handler(void* args, uint32_t time);
  void poll_event_handler(void* args);

  /// Response handling

  // buffer to hold incoming data
  std::stringstream data_stream_;
  // buffer to data in progress of being decoded (HTTP headers, chunk headers)
  std::stringstream decode_stream_;
  // buffer to hold decoded content data
  std::stringstream response_stream_;

  // amount of content received
  int content_bytes_received_ = 0;
  // amount of chunked data still to be received
  int chunk_left_ = 0;

  void receive_header_data(bool trailer = false);
  void receive_body_data();

  void decode_body_data();
  void decode_identity_content();
  void decode_chunked_content();
  int next_chunk_size(std::stringstream& decode_stream);

  std::unordered_map<std::string, std::string> response_headers_;
  std::vector<std::string> response_header_order_;
  // save only these headers
  std::unordered_set<std::string> save_headers_;
  bool _save_all_headers = false;

  void save_response_header(const std::string& header_name,
                            const std::string& header_value);

  int response_status_code_ = 0;
  int content_size_ = -1;
  bool can_reuse_ = false;
  unsigned long last_activity_millis_ = 0;
  HTTPTransferEncoding transfer_encoding_ = HTTPTransferEncoding::IDENTITY;
};

#endif /* HTTPClient_H_ */
