# jadaptive-oauth-client

A lightweight, standalone OAuth 2.0 Device Code client for Java applications. It supports standard OAuth 2.0 device authorization flows as well as High-Security DPoP (Demonstrating Proof-of-Possession) token issuance.

## Features

- OAuth 2.0 Device Authorization Grant (RFC 8628)
- Demonstrating Proof-of-Possession at the Application Layer (DPoP) (RFC 9449)
- Custom standalone lightweight `Http` encapsulation.
- Zero extra dependencies for JWTs (utilizing native `java.security` libraries).

## Usage Examples

### 1. Standard OAuth 2.0 Device Flow

Using standard Bearer tokens without DPoP validation:

```java
import com.jadaptive.oauth.client.Http;
import com.jadaptive.oauth.client.OAuthClient;
import java.net.URI;
import java.net.http.HttpClient;

public class StandardOAuthExample {

    public static void main(String[] args) throws Exception {
        
        // 1. Build the HTTP provider targeting the OAuth server
        Http http = new Http.Builder()
            .withUri(URI.create("https://auth.example.com"))
            .withClient(HttpClient.newHttpClient())
            .build();
            
        // 2. Build the OAuthClient
        OAuthClient client = new OAuthClient.Builder()
            .withHttp(http)
            .withScope("read write")
            .onPrompt(deviceCode -> {
                // Prompt the user to visit the URL and enter the code
                System.out.println("Please visit: " + deviceCode.verification_uri_complete());
                System.out.println("Or visit " + deviceCode.verification_uri() + " and enter code: " + deviceCode.user_code());
            })
            .onTokenReady((deviceCode, token, authenticatedHttp) -> {
                // The client has successfully authenticated
                System.out.println("Authentication successful!");
                System.out.println("Access Token: " + token.access_token());
                
                // You can now use `authenticatedHttp` to make requests. It has the Authorization header pre-applied.
                // String response = authenticatedHttp.get("/api/secure-data");
            })
            .onTokenIssued(token -> {
                // Persist the token for later use
                String tokenJson = token.toJSON();
                System.out.println("Token JSON: " + tokenJson);
            })
            .build();
            
        // 3. Start the authorization process (blocks until successful or timeout)
        client.authorize();
    }
}
```

### 2. High-Security DPoP Flow

Demonstrating Proof-of-Possession (DPoP) issues bound sender tokens, preventing token interception and replay attacks. 
You can enable DPoP by simply providing an RSA Private Key. The library will automatically create the required JWTs.

```java
import com.jadaptive.oauth.client.Http;
import com.jadaptive.oauth.client.OAuthClient;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.nio.file.Paths;

public class DPoPOAuthExample {

    public static void main(String[] args) throws Exception {
        
        // 1. Build the HTTP target
        Http http = new Http.Builder()
            .withUri(URI.create("https://auth.example.com"))
            .withClient(HttpClient.newHttpClient())
            .build();
            
        // Assuming your private key is stored as PEM
        Path privateKeyPath = Paths.get("/path/to/private.key");
            
        // 2. Build the OAuthClient with DPoP Enabled
        OAuthClient client = new OAuthClient.Builder()
            .withHttp(http)
            .withScope("read write")
            .withDPoP(true)                                   // Enable DPoP
            .withPrivateKey(privateKeyPath)                   // Supply the private key for signing validation
            .onPrompt(deviceCode -> {
                System.out.println("Please visit: " + deviceCode.verification_uri_complete());
            })
            .onTokenReady((deviceCode, token, authenticatedHttp) -> {
                System.out.println("Authentication successful with DPoP bound token!");
                System.out.println("Token Type (Should be DPoP): " + token.token_type());
                System.out.println("Access Token: " + token.access_token());
                
                // `authenticatedHttp` will automatically contain the bound Authorization configurations
            })
            .onTokenIssued(token -> {
                String tokenJson = token.toJSON();
                System.out.println("Token JSON: " + tokenJson);
            })
            .build();
            
        // 3. Fire the authorization process
        client.authorize();
    }
}
```

### 3. Reuse or Refresh an Existing Token

If you already have a stored token, deserialize it and pass it to the builder. The client will:

- Use the token immediately if it is still valid.
- Refresh it if it is expired and has a refresh token.
- Fall back to the device flow if the token is expired and cannot be refreshed.

```java
import com.jadaptive.oauth.client.OAuth2Objects.BearerToken;

String tokenJson = loadFromDisk();
BearerToken token = BearerToken.fromJSON(tokenJson);

OAuthClient client = new OAuthClient.Builder()
    .withHttp(http)
    .withScope("read")
    .withBearerToken(token)
    .onTokenReady((deviceCode, newToken, authenticatedHttp) -> {
        System.out.println("Token ready: " + newToken.access_token());
    })
    .onTokenIssued(newToken -> {
        saveToDisk(newToken.toJSON());
    })
    .build();

client.authorize();
```
