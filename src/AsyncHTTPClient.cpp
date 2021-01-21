#include <HardwareSerial.h>
/**
 * Copyright (c) 2021, Matti Airas. All rights reserved.
 * Adapted from prior work of Markus Sattler and Evandro Luis Copercini.
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
 *
 * Adapted in October 2018
 */

#include <Arduino.h>
#include <StreamString.h>
#include <base64.h>
#include <esp32-hal-log.h>

#include "AsyncHTTPClient.h"

namespace {
// from https://stackoverflow.com/a/23944175

bool icompare_pred(unsigned char a, unsigned char b) {
  return std::tolower(a) == std::tolower(b);
}

// case-insensitive comparison of std::string
bool icompare(std::string const& a, std::string const& b) {
  if (a.length() == b.length()) {
    return std::equal(b.begin(), b.end(), a.begin(), icompare_pred);
  } else {
    return false;
  }
}

// from https://stackoverflow.com/a/4643526

/// Replace all occurrences of "from" in "str" to "to"
void replaceSubstring(std::string str, std::string from, std::string to) {
  size_t index = 0;
  while (true) {
    /* Locate the substring to replace. */
    index = str.find("abc", index);
    if (index == std::string::npos) break;

    /* Make the replacement. */
    str.replace(index, 3, "def");

    /* Advance index forward so the next iteration doesn't pick it up as well.
     */
    index += 3;
  }
}

// trim from start (in place)
static inline void ltrimString(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
static inline void rtrimString(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// trim from both ends (in place)
static inline void trimString(std::string &s) {
    ltrimString(s);
    rtrimString(s);
}

}  // namespace

/**
 * constructor
 */
AsyncHTTPClient::AsyncHTTPClient()
    : _tcpclient{new AsyncClient},
      _dataBuffer{new cbuf(HTTP_TCP_BUFFER_SIZE)},
      _decodeBuffer{new cbuf(80)},
      _responseBuffer{new cbuf(HTTP_TCP_BUFFER_SIZE)} {}

/**
 * destructor
 */
AsyncHTTPClient::~AsyncHTTPClient() {
  _tcpclient->stop();
  delete _tcpclient;
  delete _dataBuffer;
  delete _decodeBuffer;
  delete _responseBuffer;
}

/**
 * @brief Update the connection state and optionally call the callback
 *
 * @param newState New state
 * @param announce Only call the callback if true
 * @param onlyStateChange Only call the callback if new state is different from
 * the onld one
 */
void AsyncHTTPClient::updateState(HTTPConnectionState newState, bool announce,
                                  bool announceAlways) {
  bool stateChanged = _connectionState != newState;
  log_d("updateState: %s -> %s", HTTPConnectionStateToString(_connectionState),
        HTTPConnectionStateToString(newState));
  _connectionState = newState;
  if (announce && (announceAlways || stateChanged)) {
    _clientEventHandler(_connectionState);
  }
}

void AsyncHTTPClient::clear() {
  _returnCode = 0;
  _size = -1;
  _headers = "";
  _clientEventHandler = NULL;
  _contentBytesReceived = 0;
  _chunkLeft = 0;
  _lastError = HTTPClientError::NO_ERROR;
  _lastActivityMillis = millis();
  _dataBuffer->flush();
  _decodeBuffer->flush();
  _responseBuffer->flush();
  _responseHeaders.clear();
  _responseHeaderOrder.clear();
  _saveAllHeaders = false;
  _saveHeaders.clear();
}

/**
 * parsing the url for all needed parameters
 * @param url String
 */
bool AsyncHTTPClient::begin(const char* url) {
  clear();
  _port = 80;
  return beginInternal(url, "http");
}

bool AsyncHTTPClient::begin(const char* host, uint16_t port, const char* uri) {
  clear();
  _host = host;
  _port = port;
  _uri = uri;
  return true;
}

bool AsyncHTTPClient::beginInternal(const char* url,
                                    const char* expectedProtocol) {
  std::string url_ = url;
  log_d("beginInternal: %s", url_.c_str());

  _canReuse = _reuse;

  _tcpclient->onDisconnect(
      [this](void* args, AsyncClient* tcpclient) {
        this->disconnectEventHandler(args);
      },
      _tcpclient);
  _tcpclient->onData(
      [this](void* args, AsyncClient* tcpclient, void* data, size_t len) {
        this->dataEventHandler(args, data, len);
      },
      _tcpclient);
  _tcpclient->onError(
      [this](void* args, AsyncClient* tcpclient, int8_t error) {
        this->errorEventHandler(args, error);
      },
      _tcpclient);
  _tcpclient->onTimeout(
      [this](void* args, AsyncClient* tcpclient, uint32_t time) {
        this->timeoutEventHandler(args, time);
      },
      _tcpclient);
  _tcpclient->onPoll(
      [this](void* args, AsyncClient* tcpclient) {
        this->pollEventHandler(args);
      },
      _tcpclient);

  log_v("url: %s", url_.c_str());
  clear();

  // check for : (http: or https:
  int index = url_.find(':');
  if (index == -1) {
    log_e("failed to parse protocol");
    return false;
  }

  _protocol = url_.substr(0, index);
  if (_protocol != expectedProtocol) {
    log_w("unexpected protocol: %s, expected %s", _protocol.c_str(),
          expectedProtocol);
    return false;
  }

  url_.erase(0, (index + 3));  // remove http:// or https://

  index = url_.find('/');
  std::string host = url_.substr(0, index);
  url_.erase(0, index);  // remove host part

  // get Authorization
  index = host.find('@');
  if (index >= 0) {
    // auth info
    std::string auth = host.substr(0, index);
    host.erase(0, index + 1);  // remove auth part including @
    _base64Authorization =
        std::string(base64::encode(String(auth.c_str())).c_str());
  }

  // get port
  index = host.find(':');
  if (index >= 0) {
    _host = host.substr(0, index);  // hostname
    host.erase(0, (index + 1));     // remove hostname + :
    _port = atoi(host.c_str());     // get port
  } else {
    _host = host;
  }
  _uri = url_;
  log_d("host: %s port: %d url: %s", _host.c_str(), _port, _uri.c_str());
  return true;
}

/**
 * @brief Close the connection
 *
 */
void AsyncHTTPClient::close(void) { disconnect(false); }

/**
 * disconnect
 * close the TCP socket
 */
void AsyncHTTPClient::disconnect(bool keepalive) {
  if (connected()) {
    if (_reuse && _canReuse && keepalive) {
      log_d("tcp keep open for reuse");
      updateState(HTTPConnectionState::KEEPALIVE);
    } else {
      log_d("tcp stop");
      _tcpclient->stop();
      // state update is done by event handler
    }
  } else {
    log_d("tcp is already closed");
  }
}

/**
 * connected
 * @return connected status
 */
bool AsyncHTTPClient::connected() {
  if (_tcpclient) {
    return _tcpclient->connected();
  }
  return false;
}

/**
 * try to reuse the connection to the server
 * keep-alive
 * @param reuse bool
 */
void AsyncHTTPClient::setReuse(bool reuse) { _reuse = reuse; }

/**
 * set User Agent
 * @param userAgent const char *
 */
void AsyncHTTPClient::setUserAgent(const char* userAgent) {
  _userAgent = userAgent;
}

/**
 * set the Authorization for the http request
 * @param user const char *
 * @param password const char *
 */
void AsyncHTTPClient::setAuthorization(const char* user, const char* password) {
  if (user && password) {
    String auth = user;
    auth += ":";
    auth += password;
    _base64Authorization = std::string(base64::encode(auth).c_str());
  }
}

/**
 * set the Authorizatio for the http request
 * @param auth const char * base64
 */
void AsyncHTTPClient::setAuthorization(const char* auth) {
  if (auth) {
    _base64Authorization = auth;
  }
}

/**
 * set the timeout (ms) for establishing a connection to the server
 * @param connectTimeout int32_t
 */
void AsyncHTTPClient::setConnectTimeout(uint32_t connectTimeout) {
  _connectTimeout = connectTimeout;
}

/**
 * set the timeout for receiving responses from the server
 * @param timeout unsigned int
 */
void AsyncHTTPClient::setResponseTimeout(uint32_t timeout) {
  _responseTimeout = timeout;
}

/**
 * use HTTP1.0
 * @param use
 */
void AsyncHTTPClient::useHTTP10(bool useHTTP10) {
  _useHTTP10 = useHTTP10;
  _reuse = !useHTTP10;
}

/**
 * send a GET request
 * @return true if successfully initiated
 */
bool AsyncHTTPClient::GET(ConnectionEventHandler callback) {
  return sendRequest("GET", "", 0, callback);
}

/**
 * sends a post request to the server
 * @param payload const char *
 * @param size size_t
 * @return true if successfully initiated
 */
bool AsyncHTTPClient::POST(const char* payload, size_t size,
                           ConnectionEventHandler callback) {
  log_d("POST: %s (%d)", payload, size);
  return sendRequest("POST", payload, size, callback);
}

/**
 * sends a patch request to the server
 * @param payload const char *
 * @param size size_t
 * @return true if successfully initiated
 */
bool AsyncHTTPClient::PATCH(const char* payload, size_t size,
                            ConnectionEventHandler callback) {
  return sendRequest("PATCH", payload, size, callback);
}

/**
 * sends a put request to the server
 * @param payload const char *
 * @param size size_t
 */
bool AsyncHTTPClient::PUT(const char* payload, size_t size,
                          ConnectionEventHandler callback) {
  return sendRequest("PUT", payload, size, callback);
}

/**
 * sendRequest
 * @param type const char *     "GET", "POST", ....
 * @param payload const char *  data for the message body if null not send
 * @param size size_t           size for the message body if 0 not send
 * @return true if the request was submitted for sending successfully
 */
bool AsyncHTTPClient::sendRequest(const char* type, const char* payload,
                                  size_t size,
                                  ConnectionEventHandler clientEventHandler) {
  _requestType = type;
  if (_requestPayload) {
    delete _requestPayload;
  }
  _requestPayload = new char[size];
  memcpy(_requestPayload, payload, size);

  _clientEventHandler = clientEventHandler;

  // set async event handlers
  _tcpclient->onConnect([=](void* arg, AsyncClient* tcpclient) {
    updateState(HTTPConnectionState::CONNECTED);
    if (_requestPayload && size > 0) {
      this->addHeader("Content-Length", String(size).c_str());
    }

    // send Header
    if (!sendHeader(_requestType.c_str())) {
      reportError(HTTPClientError::SEND_HEADER_FAILED);
      return;
    }

    // send Payload if needed
    if (size > 0) {
      log_d("sending payload: %s", _requestPayload);
      if (!this->asyncWrite(_requestPayload, size)) {
        reportError(HTTPClientError::SEND_PAYLOAD_FAILED);
        return;
      }
      log_d("payload sent");
    }

    updateState(HTTPConnectionState::REQUEST_SENT);
  });

  if (!connected()) {
    updateState(HTTPConnectionState::CONNECTING);
  }
  return connect();
}

void AsyncHTTPClient::disconnectEventHandler(void* args) {
  updateState(HTTPConnectionState::DISCONNECTED);
}

void AsyncHTTPClient::dataEventHandler(void* args, void* data, size_t len) {
  char temp[len + 1];
  memcpy(temp, data, len);
  temp[len] = 0;
  log_d("data:\n%s", temp);
  // ensure that the incoming data fits in our buffer
  if (len > _dataBuffer->room()) {
    _dataBuffer->resizeAdd(len - _dataBuffer->room() + 1);
  }
  _dataBuffer->write((char*)data, len);
  while (!_dataBuffer->empty()) {
    switch (this->_connectionState) {
      case HTTPConnectionState::CONNECTED:
        // request not sent yet - something is wrong
        // FIXME: disconnect
        reportError(HTTPClientError::NO_HTTP_SERVER);
        break;
      case HTTPConnectionState::REQUEST_SENT:
      case HTTPConnectionState::PARTIAL_HEADERS_RECEIVED:
        receiveHeaderData();
        break;
      case HTTPConnectionState::HEADERS_RECEIVED:
      case HTTPConnectionState::PARTIAL_BODY_RECEIVED:
        decodeBodyData();
        break;
      case HTTPConnectionState::BODY_RECEIVED:
        // we might still be getting optional trailers if
        // Transfer-Encoding is chunked
        if (_transferEncoding == HTTPTransferEncoding::CHUNKED) {
          receiveHeaderData();
        }
        break;
      case HTTPConnectionState::PARTIAL_TRAILERS_RECEIVED:
        receiveHeaderData();
        break;
      case HTTPConnectionState::DONE:
        disconnect(true);
        break;
      case HTTPConnectionState::ERROR:
        disconnect(false);
        break;
      default:
        break;
    }
  }
}

void AsyncHTTPClient::receiveHeaderData(bool trailer) {
  while (!_dataBuffer->empty()) {
    int c = _dataBuffer->read();
    if (c == '\n') {
      // We got our line
      this->handleHeaderLine();
      break;
    } else {
      if (_decodeBuffer->room() == 0) {
        // grow the buffer in chunks of 80 chars
        _decodeBuffer->resizeAdd(80);
      }
      _decodeBuffer->write(c);
    }
  }
}

void AsyncHTTPClient::errorEventHandler(void* args, int8_t error) {
  // TCP level error
  const char* errStr = _tcpclient->errorToString(error);
  log_e("AsyncTCP error: %s", errStr);
  HTTPClientError clientError;
  switch (error) {
    case ERR_MEM:
      clientError = HTTPClientError::OUT_OF_MEMORY;
      break;
    case ERR_CONN:
      clientError = HTTPClientError::NOT_CONNECTED;
      break;
    case -55:
      clientError = HTTPClientError::DNS_FAILED;
      break;
    case ERR_IF:
      clientError = HTTPClientError::UNKNOWN;
      break;
    case ERR_ABRT:
      clientError = HTTPClientError::CONNECTION_ABORTED;
      break;
    case ERR_RST:
      clientError = HTTPClientError::CONNECTION_REFUSED;
      break;
    case ERR_CLSD:
      clientError = HTTPClientError::CONNECTION_CLOSED;
      break;
    case ERR_TIMEOUT:
      clientError = HTTPClientError::TCP_TIMEOUT;
    default:
      clientError = HTTPClientError::UNKNOWN;
  }
  reportError(clientError);
}

void AsyncHTTPClient::timeoutEventHandler(void* args, uint32_t time) {
  reportError(HTTPClientError::READ_TIMEOUT);
}

void AsyncHTTPClient::pollEventHandler(void* args) {
  unsigned long now = millis();
  auto elapsed = now - _lastActivityMillis;
  switch (_connectionState) {
    case HTTPConnectionState::CONNECTING:
      if (elapsed > _connectTimeout) {
        reportError(HTTPClientError::NO_RESPONSE);
      }
      break;
    case HTTPConnectionState::KEEPALIVE:
      _lastActivityMillis = now;
      break;
    default:
      if (elapsed > _responseTimeout) {
        reportError(HTTPClientError::READ_TIMEOUT);
      }
      break;
  }
}

/**
 * size of message body / payload
 * @return -1 if no info or > 0 when Content-Length is set by server
 */
int AsyncHTTPClient::getSize(void) { return _size; }

/**
 * @brief Decode the received partial chunk of the body content
 */
void AsyncHTTPClient::decodeBodyData() {
  switch (_transferEncoding) {
    case HTTPTransferEncoding::IDENTITY:
      decodeIdentityContent();
      break;
    case HTTPTransferEncoding::CHUNKED:
      decodeChunkedContent();
      break;
    default:
      reportError(HTTPClientError::ENCODING);
      break;
  }
}

/**
 * @brief Decode identity-encoded content
 */
void AsyncHTTPClient::decodeIdentityContent() {
  // "decoding" identity data means simply copying it over
  size_t len = _dataBuffer->available();
  char tempBuf[len];
  _dataBuffer->read(tempBuf, len);
  if (_responseBuffer->room() < len) {
    _responseBuffer->resizeAdd(len - _responseBuffer->room() + 1);
    log_v("resized contentBuffer to %d", _responseBuffer->size());
  }
  _responseBuffer->write(tempBuf, len);
  _contentBytesReceived += len;
  log_v("Received %d of %d bytes", _contentBytesReceived, _size);
  if (_contentBytesReceived == _size) {
    updateState(HTTPConnectionState::DONE);
  } else {
    updateState(HTTPConnectionState::PARTIAL_BODY_RECEIVED, true, true);
  }
}

/**
 * @brief Decode chunked transfer-content-encoding content
 */
void AsyncHTTPClient::decodeChunkedContent() {
  while (_dataBuffer->available()) {
    if (_chunkLeft) {
      int readLen;
      if (_dataBuffer->available() >= _chunkLeft) {
        readLen = _chunkLeft;
      } else {
        readLen = _dataBuffer->available();
      }
      char tempBuf[readLen];
      _dataBuffer->read(tempBuf, readLen);
      if (_responseBuffer->room() < readLen) {
        _responseBuffer->resizeAdd(readLen - _responseBuffer->room() + 1);
        log_v("resized contentBuffer to %d", _responseBuffer->size());
      }
      _responseBuffer->write(tempBuf, readLen);
      _chunkLeft -= readLen;
      _contentBytesReceived += readLen;
    } else {
      if (_dataBuffer->available() < 12) {
        // there might not be data for the new chunk size -- wait
        // until there's more data
        break;
      }

      if (_contentBytesReceived > 0) {
        // not at the first chunk - consume the separating CRLF first
        char buf[2];
        char expected[] = "\r\n";
        _dataBuffer->read(buf, 2);
        if (strncmp(buf, expected, 2) != 0) {
          reportError(HTTPClientError::ENCODING);
          return;
        }
      }

      // read the new chunk size

      char chunkSizeStr[10];
      int i = 0;
      bool gotNewline = false;
      while (i < 10) {
        char c = _dataBuffer->read();
        if (c == '\n') {
          chunkSizeStr[i++] = 0;
          gotNewline = true;
          break;
        } else {
          chunkSizeStr[i++] = c;
        }
      }
      if (!gotNewline) {
        reportError(HTTPClientError::ENCODING);
        return;
      }

      _chunkLeft = strtol(chunkSizeStr, NULL, 16);
    }
  }
  return;
}

/**
 * @brief Return the server response so far decoded as a null-terminated string
 *
 */
int AsyncHTTPClient::getResponseString(char* dest) {
  size_t len = _responseBuffer->available();
  _responseBuffer->read(dest, len);
  dest[len] = 0;
  return len;
}

const std::string AsyncHTTPClient::getResponseString() {
  size_t len = _responseBuffer->available();
  char buf[len + 1];
  _responseBuffer->read(buf, len);
  buf[len] = 0;
  return std::string(buf);
}

/**
 * @brief Return the server response so far as a String object
 *
 * @return const String
 */
const String AsyncHTTPClient::getResponseAString() {
  size_t len = _responseBuffer->available();
  char buf[len + 1];
  _responseBuffer->read(buf, len);
  buf[len] = 0;
  return String(buf);
}

const char* AsyncHTTPClient::HTTPConnectionStateToString(
    HTTPConnectionState state) {
  switch (state) {
    case HTTPConnectionState::DISCONNECTED:
      return "DISCONNECTED";
      break;
    case HTTPConnectionState::KEEPALIVE:
      return "KEEPALIVE";
      break;
    case HTTPConnectionState::CONNECTING:
      return "CONNECTING";
      break;
    case HTTPConnectionState::CONNECTED:
      return "CONNECTED";
      break;
    case HTTPConnectionState::REQUEST_SENT:
      return "REQUEST_SENT";
      break;
    case HTTPConnectionState::PARTIAL_HEADERS_RECEIVED:
      return "PARTIAL_HEADERS_RECEIVED";
      break;
    case HTTPConnectionState::HEADERS_RECEIVED:
      return "HEADERS_RECEIVED";
      break;
    case HTTPConnectionState::PARTIAL_BODY_RECEIVED:
      return "PARTIAL_BODY_RECEIVED";
      break;
    case HTTPConnectionState::BODY_RECEIVED:
      return "BODY_RECEIVED";
      break;
    case HTTPConnectionState::PARTIAL_TRAILERS_RECEIVED:
      return "PARTIAL_TRAILERS_RECEIVED";
      break;
    case HTTPConnectionState::TRAILERS_RECEIVED:
      return "TRAILERS_RECEIVED";
      break;
    case HTTPConnectionState::DONE:
      return "DONE";
      break;
    case HTTPConnectionState::ERROR:
      return "ERROR";
      break;
    default:
      return "undefined";
  }
}

/**
 * converts error code to String
 * @param error int
 * @return String
 */
const char* AsyncHTTPClient::errorToString(HTTPClientError error) {
  switch (error) {
    case HTTPClientError::NO_ERROR:
      return "No error";
    case HTTPClientError::CONNECTION_REFUSED:
      return "Connection refused";
    case HTTPClientError::DNS_FAILED:
      return "DNS lookup failed";
    case HTTPClientError::TCP_TIMEOUT:
      return "TCP timeout";
    case HTTPClientError::SEND_HEADER_FAILED:
      return "Failed to send request headers";
    case HTTPClientError::SEND_PAYLOAD_FAILED:
      return "Failed to send request payload";
    case HTTPClientError::NOT_CONNECTED:
      return "Not connected";
    case HTTPClientError::CONNECTION_LOST:
      return "Connection lost";
    case HTTPClientError::NO_STREAM:
      return "No stream";
    case HTTPClientError::NO_HTTP_SERVER:
      return "No HTTP server";
    case HTTPClientError::OUT_OF_MEMORY:
      return "Out of memory";
    case HTTPClientError::ENCODING:
      return "Transfer-Encoding not supported";
    case HTTPClientError::READ_TIMEOUT:
      return "Read Timeout";
    case HTTPClientError::CONNECTION_ABORTED:
      return "Connection aborted";
    case HTTPClientError::CONNECTION_RESET:
      return "Connection reset";
    case HTTPClientError::CONNECTION_CLOSED:
      return "Connection closed";
    case HTTPClientError::NO_RESPONSE:
      return "No response from server";
    case HTTPClientError::UNKNOWN:
      return "Unknown error";
    default:
      return "Unrecognized error code";
  }
}

/**
 * adds Header to the request
 * @param name
 * @param value
 * @param first
 */
void AsyncHTTPClient::addHeader(const char* name, const char* value) {
  std::string name_ = name;

  // not allow set of Header handled by code
  if (!icompare(name_, "Connection") && !icompare(name_, "User-Agent") &&
      !icompare(name_, "Host") &&
      !(icompare(name_, "Authorization") && _base64Authorization.length())) {
    std::stringstream headerLine;

    headerLine << name_ << ": " << value << "\r\n";

    _headers.append(headerLine.str());
  }
}

/**
 * @brief Add a response header filter.
 * Only the headers added to be filtered are saved for later retrieval.
 * @param headerName Header to be saved
 */
void AsyncHTTPClient::addResponseHeaderFilter(const std::string headerName) {
  _saveHeaders.insert(headerName);
}

void AsyncHTTPClient::addResponseHeaderFilter(const char* headerName) {
  addResponseHeaderFilter(std::string(headerName));
}

void AsyncHTTPClient::addResponseHeaderFilter(const String headerName) {
  addResponseHeaderFilter(headerName.c_str());
}

/**
 * @brief Retrieve response header by name
 *
 * @param name Header to get
 * @return const char*
 */
const char* AsyncHTTPClient::header(const char* name) {
  return header(std::string(name)).c_str();
}

const std::string AsyncHTTPClient::header(std::string name) {
  auto search = _responseHeaders.find(name);
  if (search != _responseHeaders.end()) {
    return search->second.c_str();
  } else {
    return "";
  }
}

/**
 * @brief Retrieve response header by index
 *
 * @param i
 * @return const char*
 */
const char* AsyncHTTPClient::header(size_t i) {
  if (i < _responseHeaders.size()) {
    return _responseHeaders.find(_responseHeaderOrder[i])->second.c_str();
  }
  return "";
}

const char* AsyncHTTPClient::headerName(size_t i) {
  if (i < _responseHeaderOrder.size()) {
    return _responseHeaderOrder[i].c_str();
  }
  return "";
}

int AsyncHTTPClient::headers() { return _responseHeaders.size(); }

bool AsyncHTTPClient::hasHeader(const std::string name) {
  auto search = _responseHeaders.find(name);
  return search != _responseHeaders.end();
}

bool AsyncHTTPClient::hasHeader(const char* name) {
  return hasHeader(std::string(name));
}

/**
 * init TCP connection
 * @return true if connection is ok
 */
bool AsyncHTTPClient::connect(void) {
  if (connected()) {
    if (_reuse) {
      log_d("already connected, reusing connection");
    } else {
      log_d("already connected, try reuse!");
    }
    return true;
  }

  if (!_tcpclient) {
    log_d("HTTPClient::begin was not called or returned error");
    return false;
  }

  return _tcpclient->connect(_host.c_str(), _port);
}

bool AsyncHTTPClient::asyncWrite(std::stringstream& data) {
  char buf[256];
  while (!data.eof()) {
    int size = data.readsome(buf, 256);
    if (_tcpclient->space() > size) {
      _tcpclient->add(buf, size);
    }
  }
  return _tcpclient->send();
}

bool AsyncHTTPClient::asyncWrite(const char* data, size_t size) {
  char temp[size + 1];
  memcpy(temp, data, size);
  temp[size] = 0;
  log_d("sending: %s", temp);
  // FIXME: sending more than 5744 bytes (default value of TCP_WND)
  // might never work - proper buffering is needed
  if (_tcpclient->space() > size) {
    _tcpclient->add(data, size);
    return _tcpclient->send();
  }
  return false;
}

/**
 * sends HTTP request header
 * @param type (GET, POST, ...)
 * @return status
 */
bool AsyncHTTPClient::sendHeader(const char* type) {
  if (!connected()) {
    return false;
  }

  std::stringstream header;

  header << type << " ";
  header << _uri << " HTTP/1.";

  if (_useHTTP10) {
    header << "0";
  } else {
    header << "1";
  }

  header << "\r\nHost: ";
  header << _host;
  if (_port != 80 && _port != 443) {
    header << ':';
    header << _port;
  }
  header << "\r\nUser-Agent: ";
  header << _userAgent << "\r\nConnection: ";

  if (_reuse) {
    header << "keep-alive";
  } else {
    header << "close";
  }
  header << "\r\n";

  if (!_useHTTP10) {
    header << "Accept-Encoding: identity;q=1,chunked;q=0.1,*;q=0\r\n";
  }

  if (_base64Authorization.length()) {
    replaceSubstring(_base64Authorization, "\n", "");
    header << "Authorization: Basic ";
    header << _base64Authorization;
    header << "\r\n";
  }

  header << _headers << "\r\n";

  const std::string headerStr = header.str();
  const char* headerCStr = headerStr.c_str();
  int len = headerStr.length();
  log_d("Sending headers:\n%s", headerCStr);
  return this->asyncWrite(headerCStr, len);
}

/**
 * @brief Handle a single header line
 */
void AsyncHTTPClient::handleHeaderLine() {
  size_t len = _decodeBuffer->available();

  char line[len + 1];
  _decodeBuffer->read(line, len);
  line[len] = 0;
  std::string headerLine(line);

  trimString(headerLine);  // remove \r

  switch (_connectionState) {
    case HTTPConnectionState::REQUEST_SENT:
      // response must begin with HTTP/1.x
      parseHeaderStartLine(headerLine);
      break;
    case HTTPConnectionState::BODY_RECEIVED:
    case HTTPConnectionState::PARTIAL_HEADERS_RECEIVED:
    case HTTPConnectionState::PARTIAL_TRAILERS_RECEIVED:
      // must be a header line or an empty delimiter line
      parseHeaderLine(headerLine);
      break;
    default:
      log_e("shouldn't end up here");
      reportError(HTTPClientError::NO_HTTP_SERVER);
      break;
  }
}

void AsyncHTTPClient::parseHeaderStartLine(const std::string& headerLine) {
  if (!(headerLine.substr(0, 7) == "HTTP/1.")) {
    log_e("Response doesn't start with HTTP/1.x");
    reportError(HTTPClientError::NO_HTTP_SERVER);
    return;
  }
  if (_canReuse) {
    // FIXME: standard allows for multi-character minor version
    _canReuse = (headerLine[sizeof "HTTP/1." - 1] != '0');
  }
  _returnCode = atoi(headerLine.substr(9, headerLine.find(' ', 9)).c_str());
  if (_connectionState == HTTPConnectionState::BODY_RECEIVED) {
    updateState(HTTPConnectionState::PARTIAL_TRAILERS_RECEIVED);
  } else {
    updateState(HTTPConnectionState::PARTIAL_HEADERS_RECEIVED);
  }
}

void AsyncHTTPClient::parseHeaderLine(const std::string& headerLine) {
  std::string transferEncoding;

  int colonIndex = headerLine.find(':');
  if (colonIndex != -1) {
    // colon present - assume key-value pair
    std::string headerName = headerLine.substr(0, colonIndex);
    std::string headerValue = headerLine.substr(colonIndex + 1);
    trimString(headerValue);

    if (icompare(headerName, "Content-Length")) {
      _size = atoi(headerValue.c_str());
    }

    if (_canReuse && icompare(headerName,"Connection")) {
      if (headerValue.find("close") >= 0 &&
          headerValue.find("keep-alive") < 0) {
        _canReuse = false;
      }
    }

    if (icompare(headerName,"Transfer-Encoding")) {
      transferEncoding = headerValue;
    }

    std::string headerName_(headerName.c_str());
    std::string headerValue_(headerValue.c_str());
    if (_saveAllHeaders ||
        _saveHeaders.find(headerName_) != _saveHeaders.end()) {
      saveResponseHeader(headerName_, headerValue_);
    }

    if (_connectionState == HTTPConnectionState::BODY_RECEIVED) {
      updateState(HTTPConnectionState::PARTIAL_TRAILERS_RECEIVED);
    }
  } else if (headerLine.empty()) {
    // Finished receiving headers
    log_d("code: %d", _returnCode);

    if (_size > 0) {
      log_d("size: %d", _size);
    }

    if (transferEncoding.length() > 0) {
      if (icompare(transferEncoding, "chunked")) {
        _transferEncoding = HTTPTransferEncoding::CHUNKED;
      } else {
        reportError(HTTPClientError::ENCODING);
        return;
      }
    } else {
      _transferEncoding = HTTPTransferEncoding::IDENTITY;
    }

    if (!_returnCode) {
      log_d("Remote host is not an HTTP Server!");
      reportError(HTTPClientError::NO_HTTP_SERVER);
      return;
    }
    if (_connectionState == HTTPConnectionState::PARTIAL_TRAILERS_RECEIVED) {
      updateState(HTTPConnectionState::DONE);
    } else {
      updateState(HTTPConnectionState::HEADERS_RECEIVED);
    }
    return;
  } else {
    log_d("Invalid header line received");
    reportError(HTTPClientError::NO_HTTP_SERVER);
    return;
  }
}

void AsyncHTTPClient::saveResponseHeader(const std::string& headerName,
                                         const std::string& headerValue) {
  log_d("saving header %s: %s", headerName.c_str(), headerValue.c_str());
  if (hasHeader(headerName)) {
    std::string newValue(header(headerName) + std::string(", ") + headerValue);
    _responseHeaders.erase(headerName);
    _responseHeaders.insert(std::make_pair(headerName, newValue));
  } else {
    _responseHeaders.insert(std::make_pair(headerName, headerValue));
  }
}

/**
 * called to handle error return, may disconnect the connection if still exists
 * @param error
 * @return error
 */
int AsyncHTTPClient::reportError(HTTPClientError error) {
  _lastError = error;
  log_w("error(%d): %s", error, errorToString(error));
  if (connected()) {
    log_d("tcp stop");
    _tcpclient->stop();
  }
  updateState(HTTPConnectionState::ERROR);
  return (int)error;
}
