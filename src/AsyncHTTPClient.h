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
#include <cbuf.h>

#include <memory>
#if defined(ESP8266)
#include <ESPAsyncTCP.h>
#elif defined(ESP32)
#include <AsyncTCP.h>
#endif

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

// FIXME: evt_type should be an enum
typedef std::function<void(HTTPConnectionState state)> ConnectionEventHandler;

class AsyncHTTPClient {
 public:
  AsyncHTTPClient();
  ~AsyncHTTPClient();

  bool begin(const char* url);
  bool begin(const char* host, uint16_t port, const char* uri = "/");

  void close(void);

  bool connected(void);

  void setReuse(bool reuse);  /// keep-alive
  void setUserAgent(const char* userAgent);
  void setAuthorization(const char* user, const char* password);
  void setAuthorization(const char* auth);
  void setConnectTimeout(uint32_t connectTimeout);
  void setResponseTimeout(uint32_t timeout);

  void useHTTP10(bool usehttp10 = true);

  /// request handling
  bool GET(ConnectionEventHandler callback);
  bool PATCH(const char* payload, size_t size, ConnectionEventHandler callback);
  bool POST(const char* payload, size_t size, ConnectionEventHandler callback);
  bool PUT(const char* payload, size_t size, ConnectionEventHandler callback);
  bool sendRequest(const char* type, const char* payload, size_t size,
                   ConnectionEventHandler callback);

  void addHeader(const char* name, const char* value, bool first = false,
                 bool replace = true);

  /// Response handling
  void collectHeaders(const char* headerKeys[], const size_t headerKeysCount);
  const char* header(const char* name);  // get request header value by name
  const char* header(size_t i);          // get request header value by number
  const char* headerName(size_t i);      // get request header name by number
  int headers();                         // get header count
  bool hasHeader(const char* name);      // check if header exists

  int getSize(void);
  int getHTTPStatus() { return _returnCode; }

  int getResponse(char* dest);
  const String getResponse();
  HTTPClientError getLastError() { return _lastError; };
  const char* errorToString(HTTPClientError error);
  const char* HTTPConnectionStateToString(HTTPConnectionState state);

  const cbuf* getResponseBuffer() { return _responseBuffer; }

 protected:
  HTTPConnectionState _connectionState = HTTPConnectionState::DISCONNECTED;
  HTTPClientError _lastError = HTTPClientError::NO_ERROR;

  struct RequestArgument {
    String key;
    String value;
  };

  void updateState(HTTPConnectionState newState, bool announce = true,
                   bool announceAlways = false);

  bool beginInternal(const char* url, const char* expectedProtocol);
  void disconnect(bool keepalive = false);
  void clear();
  int reportError(HTTPClientError error);
  bool connect(void);
  bool sendHeader(const char* type);
  int handleHeaderResponse();
  void handleHeaderLine();
  void parseHeaderStartLine(const String& headerLine);
  void parseHeaderLine(const String& headerLine);

  bool asyncWrite(const char* data, size_t size);

  AsyncClient* _tcpclient = NULL;

  ConnectionEventHandler _clientEventHandler = NULL;

  /// request handling
  String _host;
  uint16_t _port = 0;
  int32_t _connectTimeout = HTTPCLIENT_DEFAULT_CONNECT_TIMEOUT;
  bool _reuse = true;
  uint16_t _responseTimeout = HTTPCLIENT_DEFAULT_RESPONSE_TIMEOUT;
  bool _useHTTP10 = false;

  String _uri;
  String _protocol;
  String _headers;
  String _userAgent = "AsyncHTTPClient";
  String _base64Authorization;

  String _requestType;
  char* _requestPayload = NULL;

  void disconnectEventHandler(void* args);
  void dataEventHandler(void* args, void* data, size_t len);
  void errorEventHandler(void* args, int8_t error);
  void timeoutEventHandler(void* args, uint32_t time);
  void pollEventHandler(void* args);

  /// Response handling

  // buffer to hold incoming data
  cbuf* _dataBuffer = NULL;
  // buffer to data in progress of being decoded (HTTP headers, chunk headers)
  cbuf* _decodeBuffer = NULL;
  // buffer to hold decoded content data
  cbuf* _responseBuffer = NULL;

  // amount of content received
  int _contentBytesReceived = 0;
  // amount of chunked data still to be received
  int _chunkLeft = 0;

  void receiveHeaderData(bool trailer = false);
  void receiveBodyData();

  void decodeBodyData();
  void decodeIdentityContent();
  void decodeChunkedContent();

  RequestArgument* _currentHeaders = nullptr;
  size_t _headerKeysCount = 0;

  int _returnCode = 0;
  int _size = -1;
  bool _canReuse = false;
  unsigned long _lastActivityMillis = 0;
  HTTPTransferEncoding _transferEncoding = HTTPTransferEncoding::IDENTITY;
};

#endif /* HTTPClient_H_ */
