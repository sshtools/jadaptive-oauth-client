package com.jadaptive.oauth.client;

import static com.jadaptive.oauth.client.JsonUtil.parseJSON;

import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;

import com.jadaptive.oauth.client.OAuth2Objects.BearerToken;
import com.jadaptive.oauth.client.OAuth2Objects.DeviceCode;
import com.jadaptive.oauth.client.OAuth2Objects.NameValuePair;

public final class OAuthClient {

	static Logger log = System.getLogger(OAuthClient.class.getName());
	
	public interface TokenHandler {
		void handle(DeviceCode deviceCode, BearerToken token, Http http) throws IOException, ResponseException;
	}
	
	public final static class Builder {
		private Optional<String> scope = Optional.empty();
	    private Optional<Supplier<Http>> httpProvider = Optional.empty();
		private Optional<Consumer<DeviceCode>> onPrompt = Optional.empty();
		private Optional<TokenHandler> onToken = Optional.empty();
	    
	    public Builder onPrompt(Consumer<DeviceCode> onPrompt) {
	    	this.onPrompt = Optional.of(onPrompt);
	    	return this;
	    }
	    
	    public Builder onToken(TokenHandler onToken) {
	    	this.onToken = Optional.of(onToken);
	    	return this;
	    }
		
		public Builder withScope(String scope) {
			this.scope = Optional.of(scope);
			return this;
		}

		public Builder withHttp(Http httpProvider) {
			return withHttp(() -> httpProvider);
		}
		
		public Builder withHttp(Supplier<Http> httpProvider) {
			this.httpProvider = Optional.of(httpProvider);
			return this;
		}
		
		public OAuthClient build() {
			return new OAuthClient(this);
		}
	}
	

    private Supplier<Http> httpProvider;
	private final String scope;
	private final Optional<Consumer<DeviceCode>> onPrompt;
	private final Optional<TokenHandler> onToken;
	
	private OAuthClient(Builder bldr) {
		this.scope = bldr.scope.orElseThrow(() -> new IllegalStateException("No scope provided"));
		this.httpProvider = bldr.httpProvider.orElseThrow(() -> new IllegalStateException("No HTTP provider provided"));;
		this.onPrompt = bldr.onPrompt;
		this.onToken = bldr.onToken;
	}

	public void authorize() throws IOException, ResponseException {
		/* Request OAuth2 Device Code flow, get the device code in return */
		try {
	        var http = httpProvider.get();
			var device = new OAuth2Objects.DeviceCode(parseJSON(http.postForm("oauth2/device",
	                new NameValuePair("scope", scope)
	        )));
	        
	        
	        /* Prompt for device code */
	        var interval = device.interval() == 0 ? 5 : device.interval(); 
	        onPrompt.orElseThrow(() -> new IllegalStateException("No onPrompt handler")).accept(device);
	        
	        /* Await response */
	        var expire = System.currentTimeMillis() + ( device.expires_in() * 1000 );
	        log.log(Level.DEBUG, "Awaiting authorization for device {}", device.device_code());
	        while(System.currentTimeMillis() < expire) {
	
	        	/* Now authenticated, get our bearer token */
	            var response = new BearerToken(parseJSON(http.postForm("/oauth2/token?",
	                    new NameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
	                    new NameValuePair("device_code", device.device_code()))
	            ));
	            
	            if(response.error() == null) {
	            	onToken.orElseThrow(() -> new IllegalStateException("No onToken handler.")).handle(
            			device, 
            			response, 
            			http.authenticate(response.token_type() + " " + response.access_token())
	            	);
	            	return;
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
		} 

        throw new AuthorizationTimeoutException();
	}
}
