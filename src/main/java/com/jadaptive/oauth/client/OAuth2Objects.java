package com.jadaptive.oauth.client;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;

public class OAuth2Objects {
    
    public record NameValuePair(String name, String value) {}
    
    public final static record BearerToken(String error, String error_description,
                                           String access_token, long expires_in,
                                           String nonce, String token_type, String refresh_token,
                                           long issued_at) {
        public BearerToken(JsonObject json) {
            this(
                json.getString("error", null),
                json.getString("error_description", null),
                json.getString("access_token", null),
                json.getJsonNumber("expires_in") == null ? 0 : json.getJsonNumber("expires_in").longValue(),
                json.getString("nonce", null),
                json.getString("token_type", "Bearer"),
                json.getString("refresh_token", null),
                json.getJsonNumber("issued_at") == null ? System.currentTimeMillis() / 1000
                        : json.getJsonNumber("issued_at").longValue()
            );
        }

        public static BearerToken fromJSON(String json) {
            return new BearerToken(JsonUtil.parseJSON(json));
        }

        public String toJSON() {
            return toJsonObject().toString();
        }

        public JsonObject toJsonObject() {
            JsonObjectBuilder bldr = Json.createObjectBuilder();
            if (error != null) {
                bldr.add("error", error);
            }
            if (error_description != null) {
                bldr.add("error_description", error_description);
            }
            if (access_token != null) {
                bldr.add("access_token", access_token);
            }
            if (nonce != null) {
                bldr.add("nonce", nonce);
            }
            if (token_type != null) {
                bldr.add("token_type", token_type);
            }
            if (refresh_token != null) {
                bldr.add("refresh_token", refresh_token);
            }
            if (expires_in > 0) {
                bldr.add("expires_in", expires_in);
            }
            if (issued_at > 0) {
                bldr.add("issued_at", issued_at);
            }
            return bldr.build();
        }

        public boolean isExpired() {
            if (expires_in <= 0) {
                return true;
            }
            long now = System.currentTimeMillis() / 1000;
            return issued_at + expires_in <= now;
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
