package com.jadaptive.oauth.client;

import jakarta.json.JsonObject;

public class OAuth2Objects {
    
    public record NameValuePair(String name, String value) {}
    
    public final static record BearerToken(String error, String error_description, 
                                           String access_token, long expires_in, 
                                           String nonce, String token_type, String refresh_token) {
        public BearerToken(JsonObject json) {
            this(
                json.getString("error", null),
                json.getString("error_description", null),
                json.getString("access_token", null),
                json.getJsonNumber("expires_in") == null ? 0 : json.getJsonNumber("expires_in").longValue(),
                json.getString("nonce", null),
                json.getString("token_type", "Bearer"),
                json.getString("refresh_token", null)
            );
        }
    }
    
    public final static record DeviceCode(String device_code,
                                        long expires_in,
                                        String user_code,
                                        String verification_uri,
                                        String verification_uri_complete,
                                        long interval) {
        
        public DeviceCode(JsonObject json) {
            this(
                json.getString("device_code", null),
                json.getJsonNumber("expires_in") == null ? 0 : json.getJsonNumber("expires_in").longValue(),
                json.getString("user_code"),
                json.getString("verification_uri"),
                json.getString("verification_uri_complete"),
                json.getJsonNumber("interval") == null ? 0 : json.getJsonNumber("interval").longValue()
            );
        }
    }
}
