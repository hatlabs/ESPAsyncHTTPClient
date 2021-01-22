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
 */

#include <Arduino.h>
#include <StreamString.h>
#include <base64.h>
#include <esp32-hal-log.h>

#include "async_http_client.h"

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
void replace_substring(std::string str, std::string from, std::string to) {
  size_t index = 0;
  while (true) {
    /* Locate the substring to replace. */
    index = str.find(from, index);
    if (index == std::string::npos) break;

    /* Make the replacement. */
    str.replace(index, from.length(), to);

    /* Advance index forward so the next iteration doesn't pick it up as well.
     */
    index += 3;
  }
}

// trim from start (in place)
static inline void trim_left(std::string& s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
            return !std::isspace(ch);
          }));
}

// trim from end (in place)
static inline void trim_right(std::string& s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       [](unsigned char ch) { return !std::isspace(ch); })
              .base(),
          s.end());
}

// trim from both ends (in place)
static inline void trim(std::string& s) {
  trim_left(s);
  trim_right(s);
}

}  // namespace

/**
 * constructor
 */
AsyncHTTPClient::AsyncHTTPClient() {}

/**
 * destructor
 */
AsyncHTTPClient::~AsyncHTTPClient() {
  tcpclient_.stop();
}

/**
 * @brief Update the connection state and optionally call the callback
 *
 * @param new_state New state
 * @param announce Only call the callback if true
 */
void AsyncHTTPClient::update_state(HTTPConnectionState new_state, bool announce,
                                   bool announce_always) {
  bool state_changed = connection_state_ != new_state;
  log_d("update_state: %s -> %s", connection_state_string(connection_state_),
        connection_state_string(new_state));
  connection_state_ = new_state;
  if (announce && (announce_always || state_changed)) {
    client_event_handler_(connection_state_);
  }
}

void AsyncHTTPClient::clear() {
  response_status_code_ = 0;
  content_size_ = -1;
  headers_ = "";
  client_event_handler_ = NULL;
  content_bytes_received_ = 0;
  chunk_left_ = 0;
  last_error_ = HTTPClientError::NO_ERROR;
  last_activity_millis_ = millis();
  request_type_ = "";
  request_payload_ = "";
  data_stream_.str("");
  decode_stream_.str("");
  response_stream_.str("");
  response_headers_.clear();
  response_header_order_.clear();
  _save_all_headers = false;
  save_headers_.clear();
}

/**
 * parsing the url for all needed parameters
 * @param url String
 */
bool AsyncHTTPClient::begin(const char* url) {
  clear();
  port_ = 80;
  return begin_internal(url, "http");
}

bool AsyncHTTPClient::begin(const char* host, uint16_t port, const char* uri) {
  clear();
  host_ = host;
  port_ = port;
  uri_ = uri;
  return true;
}

bool AsyncHTTPClient::begin_internal(const char* url,
                                     const char* expected_protocol) {
  std::string url_ = url;
  can_reuse_ = reuse_;

  tcpclient_.onConnect(
      [this](void* args, AsyncClient* tcpclient) {
        this->connect_event_handler(args);
      },
      &tcpclient_);
  tcpclient_.onDisconnect(
      [this](void* args, AsyncClient* tcpclient) {
        this->disconnect_event_handler(args);
      },
      &tcpclient_);
  tcpclient_.onData(
      [this](void* args, AsyncClient* tcpclient, void* data, size_t len) {
        this->data_event_handler(args, data, len);
      },
      &tcpclient_);
  tcpclient_.onError(
      [this](void* args, AsyncClient* tcpclient, int8_t error) {
        this->error_event_handler(args, error);
      },
      &tcpclient_);
  tcpclient_.onTimeout(
      [this](void* args, AsyncClient* tcpclient, uint32_t time) {
        this->timeout_event_handler(args, time);
      },
      &tcpclient_);
  tcpclient_.onPoll(
      [this](void* args, AsyncClient* tcpclient) {
        this->poll_event_handler(args);
      },
      &tcpclient_);

  clear();

  // check for : (http: or https:
  int index = url_.find(':');
  if (index == -1) {
    log_e("failed to parse protocol");
    return false;
  }

  protocol_ = url_.substr(0, index);
  if (protocol_ != expected_protocol) {
    log_w("unexpected protocol: %s, expected %s", protocol_.c_str(),
          expected_protocol);
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
    base64_authorization_ =
        std::string(base64::encode(String(auth.c_str())).c_str());
  }

  // get port
  index = host.find(':');
  if (index >= 0) {
    host_ = host.substr(0, index);  // hostname
    host.erase(0, (index + 1));     // remove hostname + :
    port_ = atoi(host.c_str());     // get port
  } else {
    host_ = host;
  }
  uri_ = url_;
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
    if (reuse_ && can_reuse_ && keepalive) {
      log_d("tcp keep open for reuse");
      update_state(HTTPConnectionState::KEEPALIVE);
    } else {
      log_d("tcp stop");
      tcpclient_.stop();
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
  return tcpclient_.connected();
}

/**
 * try to reuse the connection to the server
 * keep-alive
 * @param reuse bool
 */
void AsyncHTTPClient::reuse(bool reuse) { reuse_ = reuse; }

/**
 * set User Agent
 * @param userAgent const char *
 */
void AsyncHTTPClient::user_agent(const char* userAgent) {
  user_agent_ = userAgent;
}

/**
 * set the Authorization for the http request
 * @param user const char *
 * @param password const char *
 */
void AsyncHTTPClient::authorization(const char* user, const char* password) {
  if (user && password) {
    String auth = user;
    auth += ":";
    auth += password;
    base64_authorization_ = std::string(base64::encode(auth).c_str());
  }
}

/**
 * set the Authorizatio for the http request
 * @param auth const char * base64
 */
void AsyncHTTPClient::authorization(const char* auth) {
  if (auth) {
    base64_authorization_ = auth;
  }
}

/**
 * set the timeout (ms) for establishing a connection to the server
 * @param timeout int32_t
 */
void AsyncHTTPClient::connect_timeout(uint32_t timeout) {
  connect_timeout_ = timeout;
}

/**
 * set the timeout for receiving responses from the server
 * @param timeout unsigned int
 */
void AsyncHTTPClient::response_timeout(uint32_t timeout) {
  response_timeout_ = timeout;
}

/**
 * use HTTP1.0
 * @param use
 */
void AsyncHTTPClient::use_http_10(bool use_http_10) {
  use_http_10_ = use_http_10;
  reuse_ = !use_http_10;
}

/**
 * send a GET request
 * @return true if successfully initiated
 */
bool AsyncHTTPClient::GET(ConnectionEventHandler callback) {
  return send_request("GET", "", 0, callback);
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
  return send_request("POST", payload, size, callback);
}

/**
 * sends a patch request to the server
 * @param payload const char *
 * @param size size_t
 * @return true if successfully initiated
 */
bool AsyncHTTPClient::PATCH(const char* payload, size_t size,
                            ConnectionEventHandler callback) {
  return send_request("PATCH", payload, size, callback);
}

/**
 * sends a put request to the server
 * @param payload const char *
 * @param size size_t
 */
bool AsyncHTTPClient::PUT(const char* payload, size_t size,
                          ConnectionEventHandler callback) {
  return send_request("PUT", payload, size, callback);
}

/**
 * sendRequest
 * @param type const char *     "GET", "POST", ....
 * @param payload const char *  data for the message body if null not send
 * @param size size_t           size for the message body if 0 not send
 * @return true if the request was submitted for sending successfully
 */
bool AsyncHTTPClient::send_request(
    const char* type, const char* payload, size_t size,
    ConnectionEventHandler client_event_handler) {
  request_type_ = type;
  request_payload_ = std::string(payload, size);

  client_event_handler_ = client_event_handler;

  if (!connected()) {
    update_state(HTTPConnectionState::CONNECTING);
  }
  return connect();
}

void AsyncHTTPClient::connect_event_handler(void* arg) {
    update_state(HTTPConnectionState::CONNECTED);
    size_t size = request_payload_.length();
    if (size > 0) {
      this->add_header("Content-Length", String(size).c_str());
    }

    // send Header
    if (!send_header(request_type_.c_str())) {
      report_error(HTTPClientError::SEND_HEADER_FAILED);
      return;
    }

    // send Payload if needed
    if (size > 0) {
      if (!this->async_write(request_payload_)) {
        report_error(HTTPClientError::SEND_PAYLOAD_FAILED);
        return;
      }
    }

    update_state(HTTPConnectionState::REQUEST_SENT);
  }

void AsyncHTTPClient::disconnect_event_handler(void* args) {
  update_state(HTTPConnectionState::DISCONNECTED);
}

void AsyncHTTPClient::data_event_handler(void* args, void* data, size_t len) {
  data_stream_.write((char*)data, len);
  while (data_stream_.rdbuf()->in_avail()) {
    switch (this->connection_state_) {
      case HTTPConnectionState::CONNECTED:
        // request not sent yet - something is wrong
        // FIXME: disconnect
        report_error(HTTPClientError::NO_HTTP_SERVER);
        break;
      case HTTPConnectionState::REQUEST_SENT:
      case HTTPConnectionState::PARTIAL_HEADERS_RECEIVED:
        receive_header_data();
        break;
      case HTTPConnectionState::HEADERS_RECEIVED:
      case HTTPConnectionState::PARTIAL_BODY_RECEIVED:
        decode_body_data();
        break;
      case HTTPConnectionState::BODY_RECEIVED:
        // we might still be getting optional trailers if
        // Transfer-Encoding is chunked
        if (transfer_encoding_ == HTTPTransferEncoding::CHUNKED) {
          receive_header_data();
        }
        break;
      case HTTPConnectionState::PARTIAL_TRAILERS_RECEIVED:
        receive_header_data();
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

void AsyncHTTPClient::receive_header_data(bool trailer) {
  while (data_stream_.rdbuf()->in_avail()) {
    int c = data_stream_.get();
    if (c == '\n') {
      // We got our line
      this->handle_header_line();
      break;
    } else {
      decode_stream_.put(c);
    }
  }
}

void AsyncHTTPClient::error_event_handler(void* args, int8_t error) {
  // TCP level error
  const char* errStr = tcpclient_.errorToString(error);
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
  report_error(clientError);
}

void AsyncHTTPClient::timeout_event_handler(void* args, uint32_t time) {
  report_error(HTTPClientError::READ_TIMEOUT);
}

void AsyncHTTPClient::poll_event_handler(void* args) {
  unsigned long now = millis();
  auto elapsed = now - last_activity_millis_;
  switch (connection_state_) {
    case HTTPConnectionState::CONNECTING:
      if (elapsed > connect_timeout_) {
        report_error(HTTPClientError::NO_RESPONSE);
      }
      break;
    case HTTPConnectionState::KEEPALIVE:
      last_activity_millis_ = now;
      break;
    default:
      if (elapsed > response_timeout_) {
        report_error(HTTPClientError::READ_TIMEOUT);
      }
      break;
  }
}

/**
 * size of message body / payload
 * @return -1 if no info or > 0 when Content-Length is set by server
 */
int AsyncHTTPClient::size(void) { return content_size_; }

/**
 * @brief Decode the received partial chunk of the body content
 */
void AsyncHTTPClient::decode_body_data() {
  switch (transfer_encoding_) {
    case HTTPTransferEncoding::IDENTITY:
      decode_identity_content();
      break;
    case HTTPTransferEncoding::CHUNKED:
      decode_chunked_content();
      break;
    default:
      report_error(HTTPClientError::ENCODING);
      break;
  }
}

/**
 * @brief Decode identity-encoded content
 */
void AsyncHTTPClient::decode_identity_content() {
  // "decoding" identity data means simply copying it over
  while (data_stream_.rdbuf()->in_avail()) {
    // FIXME: is there a neater way to do this?
    char temp_buf[256];
    int size = data_stream_.readsome(temp_buf, 256);
    response_stream_.write(temp_buf, size);
    content_bytes_received_ += size;
    if (content_bytes_received_ == content_size_) {
      break;
    }
  }
  if (content_bytes_received_ == content_size_) {
    update_state(HTTPConnectionState::DONE);
  } else {
    update_state(HTTPConnectionState::PARTIAL_BODY_RECEIVED, true, true);
  }
}

/**
 * @brief Decode chunked transfer-content-encoding content
 */
void AsyncHTTPClient::decode_chunked_content() {
  while (data_stream_.rdbuf()->in_avail()) {
    if (chunk_left_) {
      char buf[chunk_left_];
      int size = data_stream_.readsome(buf, chunk_left_);
      chunk_left_ -= size;
      response_stream_.write(buf, size);
      content_bytes_received_ += size;
    } else {
      char c = data_stream_.get();
      decode_stream_.put(c);
      if (c == '\n') {
        int res = next_chunk_size(decode_stream_);
        if (res == -1) {
          // not enough input
          continue;
        } else if (res == -2) {
          // unexpected input
          report_error(HTTPClientError::ENCODING);
          return;
        } else {
          chunk_left_ = res;
        }
      }
    }
    if (content_bytes_received_ == content_size_) {
      update_state(HTTPConnectionState::BODY_RECEIVED);
      return;
    }
  }
}

int AsyncHTTPClient::next_chunk_size(std::stringstream& decode_stream) {
  // read stream into a string for easier parsing
  std::string orig_string = decode_stream.str();
  std::string decode_string = orig_string;

  if (content_bytes_received_ > 0) {
    // not at the first chunk - consume the separating CRLF first

    std::string crlf = decode_string.substr(0, 2);
    if (crlf != "\r\n") {
      // unexpected; bail out
      return -2;
    }
    decode_string.erase(0, 2);
  }
  if (decode_string.find("\r\n") == -1) {
    // the actual chunk size line is not yet available
    return -1;
  }
  trim(decode_string);
  // ignore any possible chunk extension
  int semicolon_pos = decode_string.find(';');
  if (semicolon_pos != -1) {
    decode_string.erase(semicolon_pos, -1);
  }
  if (decode_string.length() == 0) {
    // unexpected; bail out
    return -2;
  }
  // empty the decode stream before returning the value
  decode_stream.str("");
  return strtol(decode_string.c_str(), NULL, 16);
}

/**
 * @brief Return the server response so far decoded as a null-terminated string
 *
 */
int AsyncHTTPClient::response_string(char* dest) {
  std::string str = response_stream_.str();
  response_stream_.str("");
  size_t len = str.length();
  memcpy(dest, str.c_str(), len + 1);
  return len;
}

const std::string AsyncHTTPClient::response_string() {
  const std::string str = response_stream_.str();
  response_stream_.str("");
  return str;
}

/**
 * @brief Return the server response so far as a String object
 *
 * @return const String
 */
const String AsyncHTTPClient::response_arduino_string() {
  return String(response_string().c_str());
}

const char* AsyncHTTPClient::connection_state_string(
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
const char* AsyncHTTPClient::error_string(HTTPClientError error) {
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
void AsyncHTTPClient::add_header(const char* name, const char* value) {
  std::string name_ = name;

  // not allow set of Header handled by code
  if (!icompare(name_, "Connection") && !icompare(name_, "User-Agent") &&
      !icompare(name_, "Host") &&
      !(icompare(name_, "Authorization") && base64_authorization_.length())) {
    std::stringstream header_line;

    header_line << name_ << ": " << value << "\r\n";

    headers_.append(header_line.str());
  }
}

/**
 * @brief Add a response header filter.
 * Only the headers added to be filtered are saved for later retrieval.
 * @param header_name Header to be saved
 */
void AsyncHTTPClient::add_response_header_filter(
    const std::string header_name) {
  save_headers_.insert(header_name);
}

void AsyncHTTPClient::add_response_header_filter(const char* header_name) {
  add_response_header_filter(std::string(header_name));
}

void AsyncHTTPClient::add_response_header_filter(const String header_name) {
  add_response_header_filter(header_name.c_str());
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
  auto search = response_headers_.find(name);
  if (search != response_headers_.end()) {
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
  if (i < response_headers_.size()) {
    return response_headers_.find(response_header_order_[i])->second.c_str();
  }
  return "";
}

const char* AsyncHTTPClient::header_name(size_t i) {
  if (i < response_header_order_.size()) {
    return response_header_order_[i].c_str();
  }
  return "";
}

int AsyncHTTPClient::headers() { return response_headers_.size(); }

bool AsyncHTTPClient::has_header(const std::string name) {
  auto search = response_headers_.find(name);
  return search != response_headers_.end();
}

bool AsyncHTTPClient::has_header(const char* name) {
  return has_header(std::string(name));
}

/**
 * init TCP connection
 * @return true if connection is ok
 */
bool AsyncHTTPClient::connect(void) {
  if (connected()) {
    if (reuse_) {
      log_d("already connected, reusing connection");
      // launch the connection callback manually
      connect_event_handler(NULL);
    } else {
      log_d("already connected, try reuse!");
    }
    return true;
  }

  return tcpclient_.connect(host_.c_str(), port_);
}

bool AsyncHTTPClient::async_write(std::stringstream& data) {
  char buf[256];
  while (data.rdbuf()->in_avail()) {
    int size = data.readsome(buf, 256);
    if (tcpclient_.space() > size) {
      tcpclient_.add(buf, size);
    } else {
      return false;
    }
  }
  return tcpclient_.send();
}

bool AsyncHTTPClient::async_write(std::string& data) {
  int size = data.length();
  if (tcpclient_.space() > size) {
    return tcpclient_.add(data.c_str(), size);
  }
  return false;
}

bool AsyncHTTPClient::async_write(const char* data, size_t size) {
  char temp[size + 1];
  memcpy(temp, data, size);
  temp[size] = 0;
  // FIXME: sending more than 5744 bytes (default value of TCP_WND)
  // might never work - proper buffering is needed
  if (tcpclient_.space() > size) {
    tcpclient_.add(data, size);
    return tcpclient_.send();
  }
  return false;
}

/**
 * sends HTTP request header
 * @param type (GET, POST, ...)
 * @return status
 */
bool AsyncHTTPClient::send_header(const char* type) {
  if (!connected()) {
    return false;
  }

  std::stringstream header;

  header << type << " ";
  header << uri_ << " HTTP/1.";

  if (use_http_10_) {
    header << "0";
  } else {
    header << "1";
  }

  header << "\r\nHost: ";
  header << host_;
  if (port_ != 80 && port_ != 443) {
    header << ':';
    header << port_;
  }
  header << "\r\nUser-Agent: ";
  header << user_agent_ << "\r\nConnection: ";

  if (reuse_) {
    header << "keep-alive";
  } else {
    header << "close";
  }
  header << "\r\n";

  if (!use_http_10_) {
    header << "Accept-Encoding: identity;q=1,chunked;q=0.1,*;q=0\r\n";
  }

  if (base64_authorization_.length()) {
    replace_substring(base64_authorization_, "\n", "");
    header << "Authorization: ";
    header << base64_authorization_;
    header << "\r\n";
  }

  header << headers_ << "\r\n";

  const std::string header_str = header.str();
  const char* header_cstr = header_str.c_str();
  int len = header_str.length();
  return this->async_write(header_cstr, len);
}

/**
 * @brief Handle a single header line
 */
void AsyncHTTPClient::handle_header_line() {
  std::string header_line = decode_stream_.str();
  decode_stream_.str("");

  trim(header_line);  // remove \r

  switch (connection_state_) {
    case HTTPConnectionState::REQUEST_SENT:
      // response must begin with HTTP/1.x
      parse_header_start_line(header_line);
      break;
    case HTTPConnectionState::BODY_RECEIVED:
    case HTTPConnectionState::PARTIAL_HEADERS_RECEIVED:
    case HTTPConnectionState::PARTIAL_TRAILERS_RECEIVED:
      // must be a header line or an empty delimiter line
      parse_header_line(header_line);
      break;
    default:
      log_e("shouldn't end up here");
      report_error(HTTPClientError::NO_HTTP_SERVER);
      break;
  }
}

void AsyncHTTPClient::parse_header_start_line(const std::string& header_line) {
  if (!(header_line.substr(0, 7) == "HTTP/1.")) {
    log_e("Response doesn't start with HTTP/1.x");
    report_error(HTTPClientError::NO_HTTP_SERVER);
    return;
  }
  if (can_reuse_) {
    // FIXME: standard allows for multi-character minor version
    can_reuse_ = (header_line[sizeof "HTTP/1." - 1] != '0');
  }
  response_status_code_ =
      atoi(header_line.substr(9, header_line.find(' ', 9)).c_str());
  if (connection_state_ == HTTPConnectionState::BODY_RECEIVED) {
    update_state(HTTPConnectionState::PARTIAL_TRAILERS_RECEIVED);
  } else {
    update_state(HTTPConnectionState::PARTIAL_HEADERS_RECEIVED);
  }
}

void AsyncHTTPClient::parse_header_line(const std::string& header_line) {
  std::string transfer_encoding;

  int colon_index = header_line.find(':');
  if (colon_index != -1) {
    // colon present - assume key-value pair
    std::string header_name = header_line.substr(0, colon_index);
    std::string header_value = header_line.substr(colon_index + 1);
    trim(header_value);

    if (icompare(header_name, "Content-Length")) {
      content_size_ = atoi(header_value.c_str());
    }

    if (can_reuse_ && icompare(header_name, "Connection")) {
      if (header_value.find("close") >= 0 &&
          header_value.find("keep-alive") < 0) {
        can_reuse_ = false;
      }
    }

    if (icompare(header_name, "Transfer-Encoding")) {
      transfer_encoding = header_value;
    }

    std::string header_name_(header_name.c_str());
    std::string header_value_(header_value.c_str());
    if (_save_all_headers ||
        save_headers_.find(header_name_) != save_headers_.end()) {
      save_response_header(header_name_, header_value_);
    }

    if (connection_state_ == HTTPConnectionState::BODY_RECEIVED) {
      update_state(HTTPConnectionState::PARTIAL_TRAILERS_RECEIVED);
    }
  } else if (header_line.empty()) {
    // Finished receiving headers
    log_d("code: %d", response_status_code_);

    if (content_size_ > 0) {
      log_d("size: %d", content_size_);
    }

    if (transfer_encoding.length() > 0) {
      if (icompare(transfer_encoding, "chunked")) {
        transfer_encoding_ = HTTPTransferEncoding::CHUNKED;
      } else {
        report_error(HTTPClientError::ENCODING);
        return;
      }
    } else {
      transfer_encoding_ = HTTPTransferEncoding::IDENTITY;
    }

    if (!response_status_code_) {
      log_d("Remote host is not an HTTP Server!");
      report_error(HTTPClientError::NO_HTTP_SERVER);
      return;
    }
    if (connection_state_ == HTTPConnectionState::PARTIAL_TRAILERS_RECEIVED) {
      update_state(HTTPConnectionState::DONE);
    } else {
      update_state(HTTPConnectionState::HEADERS_RECEIVED);
    }
    return;
  } else {
    log_d("Invalid header line received");
    report_error(HTTPClientError::NO_HTTP_SERVER);
    return;
  }
}

void AsyncHTTPClient::save_response_header(const std::string& header_name,
                                           const std::string& header_value) {
  if (has_header(header_name)) {
    std::string new_value(header(header_name) + std::string(", ") +
                          header_value);
    response_headers_.erase(header_name);
    response_headers_.insert(std::make_pair(header_name, new_value));
  } else {
    response_headers_.insert(std::make_pair(header_name, header_value));
  }
}

/**
 * called to handle error return, may disconnect the connection if still exists
 * @param error
 * @return error
 */
int AsyncHTTPClient::report_error(HTTPClientError error) {
  last_error_ = error;
  log_w("error(%d): %s", error, error_string(error));
  if (connected()) {
    log_d("tcp stop");
    tcpclient_.stop();
  }
  update_state(HTTPConnectionState::ERROR);
  return (int)error;
}
