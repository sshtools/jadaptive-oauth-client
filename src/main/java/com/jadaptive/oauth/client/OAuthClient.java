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
		private Optional<TokenHandler> onTokenReady = Optional.empty();
		private Optional<Consumer<BearerToken>> onTokenIssued = Optional.empty();
		private Optional<BearerToken> existingToken = Optional.empty();
		
		private boolean dpop = false;
		private java.security.KeyPair keyPair = null;
		private Optional<Supplier<java.security.KeyPair>> dpopKeyGenerator = Optional.empty();
		private boolean rotateDpopOnRefresh = false;
		
		public Builder withDPoP(boolean dpop) {
			this.dpop = dpop;
			return this;
		}
		
		public Builder withPrivateKey(String keyContent) throws Exception {
			this.keyPair = DPoPProofFactory.loadKeyPair(keyContent);
			return this;
		}

		public Builder withPrivateKey(java.nio.file.Path keyPath) throws Exception {
			this.keyPair = DPoPProofFactory.loadKeyPair(keyPath);
			return this;
		}

		public Builder withDPoPKeyGenerator(Supplier<java.security.KeyPair> keyGenerator) {
			this.dpopKeyGenerator = Optional.of(keyGenerator);
			return this;
		}

		public Builder withRotateDpopOnRefresh(boolean rotate) {
			this.rotateDpopOnRefresh = rotate;
			return this;
		}

	    
	    public Builder onPrompt(Consumer<DeviceCode> onPrompt) {
	    	this.onPrompt = Optional.of(onPrompt);
	    	return this;
	    }

	    @Deprecated
	    public Builder onToken(TokenHandler onToken) {
	    	this.onToken = Optional.of(onToken);
	    	return this;
	    }

	    public Builder onTokenReady(TokenHandler onTokenReady) {
	    	this.onTokenReady = Optional.of(onTokenReady);
	    	return this;
	    }

	    public Builder onTokenIssued(Consumer<BearerToken> onTokenIssued) {
	    	this.onTokenIssued = Optional.of(onTokenIssued);
	    	return this;
	    }

	    public Builder withBearerToken(BearerToken token) {
	    	this.existingToken = Optional.of(token);
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
	private final Optional<TokenHandler> onTokenReady;
	private final Optional<Consumer<BearerToken>> onTokenIssued;
	private final Optional<BearerToken> existingToken;
	private final boolean dpop;
	private final java.security.KeyPair keyPair;
	private final Optional<Supplier<java.security.KeyPair>> dpopKeyGenerator;
	private final boolean rotateDpopOnRefresh;
	private java.security.KeyPair currentDpopKeyPair;
	
	private OAuthClient(Builder bldr) {
		this.scope = bldr.scope.orElseThrow(() -> new IllegalStateException("No scope provided"));
		this.httpProvider = bldr.httpProvider.orElseThrow(() -> new IllegalStateException("No HTTP provider provided"));;
		this.onPrompt = bldr.onPrompt;
		this.onToken = bldr.onToken;
		this.onTokenReady = bldr.onTokenReady;
		this.onTokenIssued = bldr.onTokenIssued;
		this.existingToken = bldr.existingToken;
		this.dpop = bldr.dpop;
		this.keyPair = bldr.keyPair;
		this.dpopKeyGenerator = bldr.dpopKeyGenerator;
		this.rotateDpopOnRefresh = bldr.rotateDpopOnRefresh;
		this.currentDpopKeyPair = bldr.keyPair;
	}

	private java.security.KeyPair resolveDpopKeyPair(boolean forRefresh) {
		if (!dpop) {
			return null;
		}
		if (forRefresh && rotateDpopOnRefresh && dpopKeyGenerator.isPresent()) {
			currentDpopKeyPair = dpopKeyGenerator.get().get();
			return currentDpopKeyPair;
		}
		if (currentDpopKeyPair != null) {
			return currentDpopKeyPair;
		}
		if (dpopKeyGenerator.isPresent()) {
			currentDpopKeyPair = dpopKeyGenerator.get().get();
			return currentDpopKeyPair;
		}
		return null;
	}

	private void handleToken(DeviceCode device, BearerToken token, Http http) throws IOException, ResponseException {
		var authHttp = http.authenticate(token.token_type() + " " + token.access_token());
		boolean handled = false;
		if (onTokenReady.isPresent()) {
			onTokenReady.get().handle(device, token, authHttp);
			handled = true;
		}
		if (onToken.isPresent()) {
			onToken.get().handle(device, token, authHttp);
			handled = true;
		}
		if (!handled) {
			throw new IllegalStateException("No onTokenReady handler.");
		}
	}

	private BearerToken refreshToken(String refreshToken) throws IOException, ResponseException {
		var tokenHttp = httpProvider.get();
		var dpopKey = resolveDpopKeyPair(true);
		if (dpop && dpopKey != null) {
			String proof = DPoPProofFactory.generateProof("POST", tokenHttp.getUri().resolve("/oauth2/token").toString(), dpopKey);
			tokenHttp = new Http.Builder().fromHttp(tokenHttp).addHeaders(new NameValuePair("DPoP", proof)).build();
		}
		return new BearerToken(parseJSON(tokenHttp.postForm("/oauth2/token",
				new NameValuePair("grant_type", "refresh_token"),
				new NameValuePair("refresh_token", refreshToken)
		)));
	}

	public void authorize() throws IOException, ResponseException {
		/* Request OAuth2 Device Code flow, get the device code in return */
		try {
	        var http = httpProvider.get();

	        if (existingToken.isPresent()) {
	        	BearerToken token = existingToken.get();
	        	if (token.error() == null && token.access_token() != null) {
	        		if (!token.isExpired()) {
	        			handleToken(null, token, http);
	        			return;
	        		}
	        		if (token.refresh_token() != null) {
	        			BearerToken refreshed = refreshToken(token.refresh_token());
	        			if (refreshed.error() == null && refreshed.access_token() != null) {
	        				onTokenIssued.ifPresent(handler -> handler.accept(refreshed));
	        				handleToken(null, refreshed, http);
	        				return;
	        			}
	        		}
	        	}
	        }
	        
	        var deviceKey = resolveDpopKeyPair(false);
	        if (dpop && deviceKey != null) {
	        	String proof = DPoPProofFactory.generateProof("POST", http.getUri().resolve("oauth2/device").toString(), deviceKey);
	        	http = new Http.Builder().fromHttp(http).addHeaders(new NameValuePair("DPoP", proof)).build();
	        }
	        	        
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
	        
	            var tokenHttp = httpProvider.get();
	            var tokenKey = resolveDpopKeyPair(false);
	            if (dpop && tokenKey != null) {
	                String proof = DPoPProofFactory.generateProof("POST", tokenHttp.getUri().resolve("/oauth2/token").toString(), tokenKey);
	                tokenHttp = new Http.Builder().fromHttp(tokenHttp).addHeaders(new NameValuePair("DPoP", proof)).build();
	            }
	
	            var response = new BearerToken(parseJSON(tokenHttp.postForm("/oauth2/token",
	                    new NameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
	                    new NameValuePair("device_code", device.device_code()))
	            ));
	            
	            if(response.error() == null) {
	                /* Now authenticated, get our bearer token */
	            	onTokenIssued.ifPresent(handler -> handler.accept(response));
	            	handleToken(device, response, http);
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
