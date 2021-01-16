
#ifndef UNIT_TEST

#define CORE_DEBUG_LEVEL ARDUHAL_LOG_LEVEL_VERBOSE
#include <Arduino.h>

#if defined(ESP8266)
  #include <ESP8266WiFi.h>
  #include <ESP8266WiFiMulti.h>
  typedef ESP8266WiFiMulti WiFiMulti
#elif defined(ESP32)
  #include <WiFi.h>
  #include <WiFiMulti.h>
#endif
//

#include "AsyncHTTPClient.h"

#define USE_SERIAL Serial

WiFiMulti wifiMulti;

void setup() {

    USE_SERIAL.begin(115200);

    USE_SERIAL.println();
    USE_SERIAL.println();
    USE_SERIAL.println();

    for(uint8_t t = 4; t > 0; t--) {
        USE_SERIAL.printf("[SETUP] WAIT %d...\n", t);
        USE_SERIAL.flush();
        delay(1000);
    }

    wifiMulti.addAP(WIFI_SSID, WIFI_PASSPHRASE);
}

bool done = false;

void loop() {
    AsyncHTTPClient http;
    done = false;
    // wait for WiFi connection
    if((wifiMulti.run() == WL_CONNECTED)) {
        USE_SERIAL.print("IP address of Device: ");
        USE_SERIAL.println(WiFi.localIP().toString().c_str());

        String output;

        auto connection_handler = [&](HTTPConnectionState state) {
            USE_SERIAL.print("New state: ");
            USE_SERIAL.println((int)state);
            USE_SERIAL.flush();

            switch (state) {
                case HTTPConnectionState::ERROR:
                    USE_SERIAL.print("Received error: ");
                    USE_SERIAL.println(http.errorToString(http.getLastError()));
                    done = true;
                    break;
                case HTTPConnectionState::DONE:
                    USE_SERIAL.println("ALL DONE");
                    output = http.getResponse();
                    Serial.println(output);
                    done = true;
                    break;
                default:
                    break;
            }
        };

        USE_SERIAL.print("[HTTP] begin...\n");
        http.begin("http://httpbin.org/robots.txt"); //HTTP

        http.setConnectTimeout(2000);
        http.setResponseTimeout(2000);

        http.setReuse(true);

        USE_SERIAL.print("[HTTP] GET...\n");
        // start connection and send HTTP header
        http.GET(connection_handler);

        while (!done) {
            delay(100);
        }
        
        // // httpCode will be negative on error
        // if(httpCode > 0) {
        //     // HTTP header has been send and Server response header has been handled
        //     USE_SERIAL.printf("[HTTP] GET... code: %d\n", httpCode);

        //     // file found at server
        //     if(httpCode == HTTP_CODE_OK) {
        //         String payload = http.getString();
        //         USE_SERIAL.println(payload);
        //     }
        // } else {
        //     USE_SERIAL.printf("[HTTP] GET... failed, error: %s\n", http.errorToString(httpCode).c_str());
        // }

        http.close();
    }

    delay(1000);
}

#endif