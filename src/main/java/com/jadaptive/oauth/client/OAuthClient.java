package com.jadaptive.oauth.client;

import java.io.IOException;
import java.io.StringReader;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import com.jadaptive.oauth.client.OAuth2Objects.BearerToken;
import com.jadaptive.oauth.client.OAuth2Objects.DeviceCode;
import com.jadaptive.oauth.client.OAuth2Objects.NameValuePair;

import jakarta.json.Json;
import jakarta.json.JsonObject;

public final class OAuthClient {

	static Logger log = System.getLogger(OAuthClient.class.getName());
	
	public final static class Builder {
		private Optional<String> baseUrl = Optional.empty();
		private Optional<String> scope = Optional.empty();
	    private Optional<CertManager> certManager = Optional.empty();
		private Optional<Consumer<DeviceCode>> onPrompt = Optional.empty();
		private Optional<BiConsumer<DeviceCode, BearerToken>> onToken = Optional.empty();
	    
	    public Builder onPrompt(Consumer<DeviceCode> onPrompt) {
	    	this.onPrompt = Optional.of(onPrompt);
	    	return this;
	    }
	    
	    public Builder onToken(BiConsumer<DeviceCode, BearerToken> onToken) {
	    	this.onToken = Optional.of(onToken);
	    	return this;
	    }
		
		public Builder withBaseUrl(String baseUrl) {
			this.baseUrl = Optional.of(baseUrl);
			return this;
		}
		
		public Builder withScope(String scope) {
			this.scope = Optional.of(scope);
			return this;
		}
		
		public Builder withCertManagger(CertManager certManager) {
			this.certManager = Optional.of(certManager);
			return this;
		}
		
		public OAuthClient build() {
			return new OAuthClient(this);
		}
	}
	

	private final String baseUrl;
    private final Optional<CertManager> certManager;
	private final String scope;
	private final Optional<Consumer<DeviceCode>> onPrompt;
	private final Optional<BiConsumer<DeviceCode, BearerToken>> onToken;
	
	private OAuthClient(Builder bldr) {
		this.baseUrl = bldr.baseUrl.orElseThrow(() -> new IllegalStateException("No base URL provided"));
		this.scope = bldr.scope.orElseThrow(() -> new IllegalStateException("No scope provided"));
		this.certManager = bldr.certManager;
		this.onPrompt = bldr.onPrompt;
		this.onToken = bldr.onToken;
	}

	protected String doPost(String rootUrl, String url, NameValuePair[] headers, NameValuePair... postVariables)
            throws URISyntaxException, IOException, InterruptedException, ResponseException {

        if (!url.startsWith("/")) {
            url = "/" + url;
        }

        var client = getHttpClient(); 
        var bldr = HttpRequest.newBuilder(new URI(rootUrl + url))
                .header("Content-Type", "application/x-www-form-urlencoded");
        for(var hdr : headers) {
            bldr.header(hdr.name(), hdr.value());
        }
        var request = bldr.POST(Http.ofNameValuePairs(postVariables))
                .build();

        log.log(Level.INFO, "Executing request {}", request.toString());

        var response = client.send(request, HttpResponse.BodyHandlers.ofString());
        var body = response.body();
        if (response.statusCode() != 200) {
        	var ctype = response.headers().firstValue("Content-Type").orElse(null);
        	if("application/json".equals(ctype)) {
        		throw new ResponseException(parseJSON(body));
        	}
            throw new IOException(body);	            
        }
		return body;

    }

	public void authorize() throws IOException, ResponseException {
		/* Request OAuth2 Device Code flow, get the device code in return */
		try {
	        var device = new OAuth2Objects.DeviceCode(parseJSON(doPost(baseUrl, "oauth2/device",
	                new NameValuePair[0],
	                new NameValuePair("scope", scope)
	        )));
	        
	        
	        /* Prompt for device code */
	        var interval = device.interval() == 0 ? 5 : device.interval(); 
	        onPrompt.orElseThrow(() -> new IllegalStateException("No onPrompt handler")).accept(device);
	        
	        /* Await response */
	        var expire = System.currentTimeMillis() + ( device.expires_in() * 1000 );
	        log.log(Level.INFO, "Awaiting authorization for device {}", device.device_code());
	        while(System.currentTimeMillis() < expire) {
	
	        	/* Now authenticated, get our bearer token */
	            var response = new BearerToken(parseJSON(doPost(baseUrl, "/oauth2/token?",
	                    new NameValuePair[0],
	                    new NameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
	                    new NameValuePair("device_code", device.device_code()))
	            ));
	            
	            if(response.error() == null) {
	            	onToken.orElseThrow(() -> new IllegalStateException("No onToken handler."));
	            }
	            else if(response.error().equals("authorization_denied") || response.error().equals("expired_token")) {
	                break;
	            }
	            else if(response.error().equals("authorization_pending")) {
	                Thread.sleep(1000 * interval);
	            }
	            else if(response.error().equals("slow_down")) {
	                interval += 5;
	            }
	        }
		}
		catch(InterruptedException ie) {
			throw new IOException("Interrupted.", ie);
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException(e);
		}

        throw new AuthorizationTimeoutException();
	}

    protected HttpClient getHttpClient() {
        var bldr =  HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1);
        certManager.ifPresent(cm -> {
            bldr.sslContext(cm.getSSLContext()).sslParameters(cm.getSSLParameters());
        });
        return bldr.connectTimeout(Duration.ofSeconds(15)).followRedirects(HttpClient.Redirect.NORMAL).build();

    }

    protected static JsonObject parseJSON(String json) {
        if (log.isLoggable(Level.DEBUG)) {
            log.log(Level.DEBUG, json);
        }

        try(var rdr = Json.createReader(new StringReader(json))) {
            return rdr.readObject();
        }
    }
}
