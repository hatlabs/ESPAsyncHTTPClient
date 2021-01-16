#define CORE_DEBUG_LEVEL ARDUHAL_LOG_LEVEL_VERBOSE

#include <Arduino.h>
#include <unity.h>

#include <WiFi.h>
#include <WiFiMulti.h>

#include "AsyncHTTPClient.h"

void test_http_get_200() {
  AsyncHTTPClient http;
  http.begin("http://httpbin.org/robots.txt");
  
  bool done = false;

  http.GET([&](HTTPConnectionState state) {
    switch (state) {
      case HTTPConnectionState::DISCONNECTED:
      case HTTPConnectionState::ERROR:
      case HTTPConnectionState::DONE:
        done = true;
        break;
      default:
        break;
    }
  });

  // verify that the operation was not synchronous
  TEST_ASSERT_EQUAL(false, done);

  while (!done) {
    delay(50);
  }

  TEST_ASSERT_EQUAL(200, http.getHTTPStatus());
  
  String expected = "User-agent: *\nDisallow: /deny\n";
  String response = http.getResponse();
  TEST_ASSERT_EQUAL_STRING(expected.c_str(), response.c_str());

  Serial.printf("asserted successfully\n");

  http.close();
}

void test_http_get_dns_site_not_found() {
  AsyncHTTPClient http;
  bool result = http.begin("http://doesnotexist.httpbin.org/robots.txt");
  TEST_ASSERT_EQUAL(true, result);

  int done = false;
  http.GET([&](HTTPConnectionState state) {
    switch (state) {
      case HTTPConnectionState::DISCONNECTED:
      case HTTPConnectionState::ERROR:
      case HTTPConnectionState::DONE:
        done = true;
        break;
      default:
        break;
    }
  });

  TEST_ASSERT_EQUAL(false, done);

  while (!done) {
    delay(50);
  }

  TEST_ASSERT_EQUAL(HTTPClientError::DNS_FAILED, http.getLastError());
  http.close();
}

void test_http_get_connection_refused() {
  AsyncHTTPClient http;
  // site exists but doesn't allow connections
  bool result = http.begin("http://127.0.0.1/robots.txt");
  TEST_ASSERT_EQUAL(true, result);

  int done = false;
  http.GET([&](HTTPConnectionState state) {
    switch (state) {
      case HTTPConnectionState::DISCONNECTED:
      case HTTPConnectionState::ERROR:
      case HTTPConnectionState::DONE:
        done = true;
        break;
      default:
        break;
    }
  });

  TEST_ASSERT_EQUAL(false, done);

  while (!done) {
    delay(50);
  }

  TEST_ASSERT_EQUAL(HTTPClientError::CONNECTION_REFUSED, http.getLastError());
  http.close();
}

void test_http_get_404() {
  AsyncHTTPClient http;
  bool result = http.begin("http://httpbin.org/status/404");
  TEST_ASSERT_EQUAL(true, result);

  int done = false;
  http.GET([&](HTTPConnectionState state) {
    // Serial.printf("New state: %s\n", http.HTTPConnectionStateToString(state));
    switch (state) {
      case HTTPConnectionState::DISCONNECTED:
      case HTTPConnectionState::ERROR:
      case HTTPConnectionState::DONE:
        done = true;
        break;
      default:
        break;
    }
  });

  TEST_ASSERT_EQUAL(false, done);

  while (!done) {
    delay(50);
  }

  TEST_ASSERT_EQUAL(404, http.getHTTPStatus());
  http.close();
}

void test_http_post_200() {
  AsyncHTTPClient http;
  bool result = http.begin("http://httpbin.org/post");
  TEST_ASSERT_EQUAL(true, result);

  http.setConnectTimeout(2000);
  http.setResponseTimeout(2000);

  const char* request_payload = "param1=value1";
  size_t len = strlen(request_payload);

  bool done = false;
  http.POST(request_payload, len,
    [&](HTTPConnectionState state) {
      // Serial.printf("New state: %s\n", http.HTTPConnectionStateToString(state));
      switch (state) {
        case HTTPConnectionState::DISCONNECTED:
          Serial.println("DISCONNECTED");
          break;
        case HTTPConnectionState::ERROR:
          Serial.println("ERROR");
          break;
        case HTTPConnectionState::DONE:
          Serial.println("DONE");
          done = true;
          break;
        default:
          break;
      }
    });

  //TEST_ASSERT_EQUAL(false, done);

  while (!done) {
    delay(50);
  }

  TEST_ASSERT_EQUAL(200, http.getHTTPStatus());
  String payload = http.getResponse();
  TEST_ASSERT_TRUE(payload.indexOf("\"data\": \"param1=value1\",") >= 0);
  http.close();
}

void test_http_get_auth_200() {
  AsyncHTTPClient http;
  bool result = http.begin("http://httpbin.org/bearer");
  TEST_ASSERT_EQUAL(true, result);
  http.addHeader("Authorization", "Bearer 123456");

    int done = false;
  http.GET([&](HTTPConnectionState state) {
    switch (state) {
      case HTTPConnectionState::DISCONNECTED:
      case HTTPConnectionState::ERROR:
      case HTTPConnectionState::DONE:
        done = true;
        break;
      default:
        break;
    }
  });

  TEST_ASSERT_EQUAL(false, done);

  while (!done) {
    delay(50);
  }
  
  TEST_ASSERT_EQUAL(200, http.getHTTPStatus());
  String payload = http.getResponse();
  String expected = "{\n  \"authenticated\": true, \n  \"token\": \"123456\"\n}\n";
  TEST_ASSERT_EQUAL_STRING(expected.c_str(), payload.c_str());
  http.close();
}

void test_http_get_multi_packet_200() {
  AsyncHTTPClient http;
  http.begin("http://httpbin.org/range/3000");
  
  bool done = false;

  http.GET([&](HTTPConnectionState state) {
    switch (state) {
      case HTTPConnectionState::DISCONNECTED:
      case HTTPConnectionState::ERROR:
      case HTTPConnectionState::DONE:
        done = true;
        break;
      default:
        break;
    }
  });

  // verify that the operation was not synchronous
  TEST_ASSERT_EQUAL(false, done);

  while (!done) {
    delay(50);
  }

  TEST_ASSERT_EQUAL(200, http.getHTTPStatus());
  
  String response = http.getResponse();

  TEST_ASSERT_EQUAL(3000, response.length());

  http.close();
}


WiFiMulti wifiMulti;

void setup() {
  Serial.begin(115200);
  Serial.println();
  Serial.println();
  Serial.println();

  delay(100);

  WiFi.mode(WIFI_MODE_STA);
  wifiMulti.addAP(WIFI_SSID, WIFI_PASSPHRASE);

  while (wifiMulti.run() != WL_CONNECTED) {
    delay(2000);
    Serial.println("Establishing connection to WiFi..");
  }
  delay(200);
  UNITY_BEGIN();
}

void loop() {
  RUN_TEST(test_http_get_200);
  RUN_TEST(test_http_get_dns_site_not_found);
  RUN_TEST(test_http_get_connection_refused);
  RUN_TEST(test_http_get_404);
  RUN_TEST(test_http_post_200);
  RUN_TEST(test_http_get_auth_200);
  RUN_TEST(test_http_get_multi_packet_200);

  UNITY_END();
}
