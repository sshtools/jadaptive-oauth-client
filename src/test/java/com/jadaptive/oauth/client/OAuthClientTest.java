package com.jadaptive.oauth.client;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.*;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.Base64;
import java.io.IOException;
import java.net.URI;

public class OAuthClientTest {

    private WireMockServer wireMockServer;
    private boolean promptCalled;
    private boolean tokenHandlerCalled;
        private boolean tokenReadyCalled;
        private boolean tokenIssuedCalled;

    @BeforeEach
    public void setup() {
        wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMockServer.start();
        configureFor("localhost", wireMockServer.port());
        promptCalled = false;
        tokenHandlerCalled = false;
        tokenReadyCalled = false;
        tokenIssuedCalled = false;
    }

    @AfterEach
    public void teardown() {
        wireMockServer.stop();
    }

    @Test
    public void testDeviceAuthorizationGrant_WithDPoP_Success() throws Exception {
        // Generate a test keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(kp.getPrivate().getEncoded()) +
                "\n-----END PRIVATE KEY-----";

        // Mock the device code endpoint
        stubFor(post(urlEqualTo("/oauth2/device"))
                .withHeader("DPoP", matching(".*"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"device_code\": \"mock-device-code\", \"user_code\": \"mock-user-code\", \"verification_uri\": \"http://mock/verify\", \"verification_uri_complete\": \"http://mock/verify?code=mock-user-code\", \"expires_in\": 600, \"interval\": 1 }")));

        // Mock the token endpoint
        stubFor(post(urlPathEqualTo("/oauth2/token"))
                .withHeader("DPoP", matching(".*"))
                .withRequestBody(containing("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"))
                .withRequestBody(containing("device_code=mock-device-code"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"access_token\": \"mock-access-token\", \"token_type\": \"DPoP\", \"expires_in\": 3600 }")));

        Http http = new Http.Builder().withUri(URI.create("http://localhost:" + wireMockServer.port() + "/")).withClient(java.net.http.HttpClient.newHttpClient()).build();

        OAuthClient.Builder bldr = new OAuthClient.Builder()
                .withHttp(http)
                .withScope("read write")
                .withDPoP(true)
                .withPrivateKey(privateKeyPEM)
                .onPrompt(deviceCode -> {
                    assertEquals("mock-device-code", deviceCode.device_code());
                    assertEquals("mock-user-code", deviceCode.user_code());
                    promptCalled = true;
                })
                .onToken((deviceCode, token, authenticatedHttp) -> {
                    assertEquals("mock-access-token", token.access_token());
                    tokenHandlerCalled = true;
                                })
                                .onTokenReady((deviceCode, token, authenticatedHttp) -> {
                                        tokenReadyCalled = true;
                                })
                                .onTokenIssued(token -> tokenIssuedCalled = true);

        OAuthClient client = bldr.build();
        client.authorize();

        assertTrue(promptCalled, "onPrompt should have been called");
        assertTrue(tokenHandlerCalled, "onToken should have been called");
        assertTrue(tokenReadyCalled, "onTokenReady should have been called");
        assertTrue(tokenIssuedCalled, "onTokenIssued should have been called");
        
        // specifically verify the mock received DPoP 
        verify(postRequestedFor(urlEqualTo("/oauth2/device")).withHeader("DPoP", matching(".*")));
        verify(postRequestedFor(urlEqualTo("/oauth2/token")).withHeader("DPoP", matching(".*")));
    }

    @Test
    public void testDeviceAuthorizationGrant_Success() throws Exception {
        // Mock the device code endpoint
        stubFor(post(urlEqualTo("/oauth2/device"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"device_code\": \"mock-device-code\", \"user_code\": \"mock-user-code\", \"verification_uri\": \"http://mock/verify\", \"verification_uri_complete\": \"http://mock/verify?code=mock-user-code\", \"expires_in\": 600, \"interval\": 1 }")));

        // Mock the token endpoint (instant success scenario)
        stubFor(post(urlPathEqualTo("/oauth2/token"))
                .withRequestBody(containing("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"))
                .withRequestBody(containing("device_code=mock-device-code"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"access_token\": \"mock-access-token\", \"token_type\": \"Bearer\", \"expires_in\": 3600 }")));

        Http http = new Http.Builder().withUri(URI.create("http://localhost:" + wireMockServer.port() + "/")).withClient(java.net.http.HttpClient.newHttpClient()).build();

        OAuthClient.Builder bldr = new OAuthClient.Builder()
                .withHttp(http)
                .withScope("read write")
                .onPrompt(deviceCode -> {
                    assertEquals("mock-device-code", deviceCode.device_code());
                    assertEquals("mock-user-code", deviceCode.user_code());
                    promptCalled = true;
                })
                .onToken((deviceCode, token, authenticatedHttp) -> {
                    assertEquals("mock-access-token", token.access_token());
                    tokenHandlerCalled = true;
                                })
                                .onTokenReady((deviceCode, token, authenticatedHttp) -> tokenReadyCalled = true)
                                .onTokenIssued(token -> tokenIssuedCalled = true);

        OAuthClient client = bldr.build();
        client.authorize();

        assertTrue(promptCalled, "onPrompt should have been called");
        assertTrue(tokenHandlerCalled, "onToken should have been called");
        assertTrue(tokenReadyCalled, "onTokenReady should have been called");
        assertTrue(tokenIssuedCalled, "onTokenIssued should have been called");
    }

    @Test
    public void testDeviceAuthorizationGrant_AuthorizationPending_ThenSuccess() throws Exception {
        // Mock the device code endpoint
        stubFor(post(urlEqualTo("/oauth2/device"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"device_code\": \"mock-device-code\", \"user_code\": \"mock-user-code\", \"verification_uri\": \"http://mock/verify\", \"verification_uri_complete\": \"http://mock/verify?code=mock-user-code\", \"expires_in\": 600, \"interval\": 1 }")));

        // Mock the token endpoint: First pending, then success
        stubFor(post(urlPathEqualTo("/oauth2/token"))
                .inScenario("Polling State")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"error\": \"authorization_pending\" }"))
                .willSetStateTo("SUCCESS_STATE"));

        stubFor(post(urlPathEqualTo("/oauth2/token"))
                .inScenario("Polling State")
                .whenScenarioStateIs("SUCCESS_STATE")
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"access_token\": \"mock-access-token\", \"token_type\": \"Bearer\", \"expires_in\": 3600 }")));

        Http http = new Http.Builder().withUri(URI.create("http://localhost:" + wireMockServer.port() + "/")).withClient(java.net.http.HttpClient.newHttpClient()).build();

        OAuthClient client = new OAuthClient.Builder()
                .withHttp(http)
                .withScope("read play")
                .onPrompt(deviceCode -> promptCalled = true)
                .onToken((deviceCode, token, authenticatedHttp) -> tokenHandlerCalled = true)
                .onTokenReady((deviceCode, token, authenticatedHttp) -> tokenReadyCalled = true)
                .onTokenIssued(token -> tokenIssuedCalled = true)
                .build();

        long startTime = System.currentTimeMillis();
        client.authorize();
        long endTime = System.currentTimeMillis();

        assertTrue(promptCalled);
        assertTrue(tokenHandlerCalled);
        assertTrue(tokenReadyCalled);
        assertTrue(tokenIssuedCalled);
        assertTrue((endTime - startTime) >= 1000, "Should have slept at least 1 second due to authorization_pending");
    }

    @Test
    public void testDeviceAuthorizationGrant_AuthorizationDenied() throws Exception {
        stubFor(post(urlEqualTo("/oauth2/device"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"device_code\": \"mock-device-code\", \"user_code\": \"mock-user-code\", \"verification_uri\": \"http://mock/verify\", \"verification_uri_complete\": \"http://mock/verify?code=mock-user-code\", \"expires_in\": 600, \"interval\": 1 }")));

        stubFor(post(urlPathEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"error\": \"authorization_denied\" }")));

        Http http = new Http.Builder().withUri(URI.create("http://localhost:" + wireMockServer.port() + "/")).withClient(java.net.http.HttpClient.newHttpClient()).build();

        OAuthClient client = new OAuthClient.Builder()
                .withHttp(http)
                .withScope("read")
                .onPrompt(deviceCode -> promptCalled = true)
                .onToken((deviceCode, token, authenticatedHttp) -> tokenHandlerCalled = true)
                .onTokenReady((deviceCode, token, authenticatedHttp) -> tokenReadyCalled = true)
                .onTokenIssued(token -> tokenIssuedCalled = true)
                .build();

        assertThrows(AuthorizationTimeoutException.class, client::authorize);
        assertTrue(promptCalled);
        assertFalse(tokenHandlerCalled, "Token handler should not be called when denied");
        assertFalse(tokenReadyCalled, "Token ready handler should not be called when denied");
        assertFalse(tokenIssuedCalled, "Token issued handler should not be called when denied");
    }

    @Test
    public void testExistingBearerToken_Valid_UsesToken() throws Exception {
        Http http = new Http.Builder().withUri(URI.create("http://localhost:" + wireMockServer.port() + "/")).withClient(java.net.http.HttpClient.newHttpClient()).build();

        long issuedAt = (System.currentTimeMillis() / 1000) - 10;
        OAuth2Objects.BearerToken token = new OAuth2Objects.BearerToken(
                null,
                null,
                "existing-token",
                3600,
                null,
                "Bearer",
                null,
                issuedAt
        );

        OAuthClient client = new OAuthClient.Builder()
                .withHttp(http)
                .withScope("read")
                .withBearerToken(token)
                .onToken((deviceCode, bearerToken, authenticatedHttp) -> tokenHandlerCalled = true)
                .onTokenReady((deviceCode, bearerToken, authenticatedHttp) -> tokenReadyCalled = true)
                .onTokenIssued(bearerToken -> tokenIssuedCalled = true)
                .build();

        client.authorize();

        assertTrue(tokenHandlerCalled);
        assertTrue(tokenReadyCalled);
        assertFalse(promptCalled);
        assertFalse(tokenIssuedCalled);
        verify(0, postRequestedFor(urlEqualTo("/oauth2/device")));
    }

    @Test
    public void testExistingBearerToken_ExpiredWithRefresh_Refreshes() throws Exception {
        stubFor(post(urlPathEqualTo("/oauth2/token"))
                .withRequestBody(containing("grant_type=refresh_token"))
                .withRequestBody(containing("refresh_token=refresh-123"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"access_token\": \"refreshed-token\", \"token_type\": \"Bearer\", \"expires_in\": 3600, \"refresh_token\": \"refresh-123\" }")));

        Http http = new Http.Builder().withUri(URI.create("http://localhost:" + wireMockServer.port() + "/")).withClient(java.net.http.HttpClient.newHttpClient()).build();

        long issuedAt = (System.currentTimeMillis() / 1000) - 3600;
        OAuth2Objects.BearerToken token = new OAuth2Objects.BearerToken(
                null,
                null,
                "expired-token",
                1,
                null,
                "Bearer",
                "refresh-123",
                issuedAt
        );

                AtomicInteger generatorCalls = new AtomicInteger(0);
                OAuthClient client = new OAuthClient.Builder()
                .withHttp(http)
                .withScope("read")
                .withBearerToken(token)
                                .withDPoP(true)
                                .withRotateDpopOnRefresh(true)
                                .withDPoPKeyGenerator(() -> {
                                        generatorCalls.incrementAndGet();
                                        try {
                                                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                                                kpg.initialize(2048);
                                                return kpg.generateKeyPair();
                                        } catch (Exception e) {
                                                throw new IllegalStateException(e);
                                        }
                                })
                .onTokenReady((deviceCode, bearerToken, authenticatedHttp) -> tokenReadyCalled = true)
                .onToken((deviceCode, bearerToken, authenticatedHttp) -> tokenHandlerCalled = true)
                .onTokenIssued(bearerToken -> tokenIssuedCalled = true)
                .build();

        client.authorize();

        assertTrue(tokenHandlerCalled);
        assertTrue(tokenReadyCalled);
        assertTrue(tokenIssuedCalled);
        assertFalse(promptCalled);
                assertEquals(1, generatorCalls.get(), "DPoP key generator should be called on refresh");
        verify(1, postRequestedFor(urlPathEqualTo("/oauth2/token")));
    }

    @Test
    public void testExistingBearerToken_ExpiredNoRefresh_FallsBackToDeviceFlow() throws Exception {
        stubFor(post(urlEqualTo("/oauth2/device"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"device_code\": \"mock-device-code\", \"user_code\": \"mock-user-code\", \"verification_uri\": \"http://mock/verify\", \"verification_uri_complete\": \"http://mock/verify?code=mock-user-code\", \"expires_in\": 600, \"interval\": 1 }")));

        stubFor(post(urlPathEqualTo("/oauth2/token"))
                .withRequestBody(containing("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"))
                .withRequestBody(containing("device_code=mock-device-code"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{ \"access_token\": \"mock-access-token\", \"token_type\": \"Bearer\", \"expires_in\": 3600 }")));

        Http http = new Http.Builder().withUri(URI.create("http://localhost:" + wireMockServer.port() + "/")).withClient(java.net.http.HttpClient.newHttpClient()).build();

        long issuedAt = (System.currentTimeMillis() / 1000) - 3600;
        OAuth2Objects.BearerToken token = new OAuth2Objects.BearerToken(
                null,
                null,
                "expired-token",
                1,
                null,
                "Bearer",
                null,
                issuedAt
        );

        OAuthClient client = new OAuthClient.Builder()
                .withHttp(http)
                .withScope("read")
                .withBearerToken(token)
                .onPrompt(deviceCode -> promptCalled = true)
                .onTokenReady((deviceCode, bearerToken, authenticatedHttp) -> tokenReadyCalled = true)
                .onToken((deviceCode, bearerToken, authenticatedHttp) -> tokenHandlerCalled = true)
                .onTokenIssued(bearerToken -> tokenIssuedCalled = true)
                .build();

        client.authorize();

        assertTrue(promptCalled);
        assertTrue(tokenHandlerCalled);
        assertTrue(tokenReadyCalled);
        assertTrue(tokenIssuedCalled);
        verify(1, postRequestedFor(urlEqualTo("/oauth2/device")));
    }
}