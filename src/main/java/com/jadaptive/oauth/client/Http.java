package com.jadaptive.oauth.client;

import java.io.IOException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import com.jadaptive.oauth.client.OAuth2Objects.NameValuePair;

public final class Http {

	public static final String APPLICATION_JSON = "application/json";
	public static final String APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded";

	public final static class Builder {
		private Optional<URI> uri = Optional.empty();
		private Optional<Supplier<HttpClient>> clientSupplier = Optional.empty();
		private List<NameValuePair> headers = new ArrayList<>();

		public Builder fromHttp(Http http) {
			return withUri(http.uri).
				withClient(http.clientSupplier).
				withHeaders(http.headers);
		}

		public Builder withHost(String hostname) {
			return withHost(hostname, 443);
		}
		
		public Builder withHost(String hostname, int port) {
			if(port == 443 || port == 0)
				return withUri(URI.create("https://" + hostname));
			else
				return withUri(URI.create("https://" + hostname + ":" + port));
		}
		
		public Builder withHeaders(NameValuePair... headers) {
			return withHeaders(Arrays.asList(headers));
		}
		
		public Builder withHeaders(Collection<NameValuePair> headers) {
			this.headers.clear();
			return addHeaders(headers);
		}
		
		public Builder addHeaders(NameValuePair... headers) {
			return addHeaders(Arrays.asList(headers));
		}
		
		public Builder addHeaders(Collection<NameValuePair> headers) {
			this.headers.addAll(headers);
			return this;
		}

		public Builder withUri(String uri) {
			return withUri(URI.create(uri));
		}

		public Builder withUri(URI uri) {
			this.uri = Optional.of(uri);
			return this;
		}

		public Builder withClient(HttpClient client) {
			return withClient(() -> client);
		}

		public Builder withDefaultClient(CertManager certManager) {
			return withClient(() -> {
		        var bldr =  HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1);
		        bldr.sslContext(certManager.getSSLContext()).sslParameters(certManager.getSSLParameters());
		        return bldr.connectTimeout(Duration.ofSeconds(15)).followRedirects(HttpClient.Redirect.NORMAL).build();
			});
		}

		public Builder withClient(Supplier<HttpClient> clientSupplier) {
			this.clientSupplier = Optional.of(clientSupplier);
			return this;
		}

		public Http build() {
			return new Http(this);
		}
	}

	static Logger log = System.getLogger(Http.class.getName());

	private final URI uri;
	private final Supplier<HttpClient> clientSupplier;
	private final List<NameValuePair> headers;

	private Http(Builder bldr) {
		this.uri = bldr.uri.orElseThrow(() -> new IllegalStateException("No URI supplied."));
		this.clientSupplier = bldr.clientSupplier.orElseThrow(() -> new IllegalStateException("No client supplied."));
		this.headers = Collections.unmodifiableList(new ArrayList<>(bldr.headers));
	}

	public String get(String path, NameValuePair... headers) throws IOException, ResponseException {
		var url = uri.resolve(path);
		var client = clientSupplier.get();

		try {
			var bldr = newBuilder(url).header("Content-Type", APPLICATION_X_WWW_FORM_URLENCODED);
			this.headers.forEach(h -> bldr.header(h.name(), h.value()));
			for (var hdr : headers) {
				bldr.header(hdr.name(), hdr.value());
			}
			var request = bldr.GET().build();

			log.log(Level.DEBUG, "Executing request " + request.toString());

			var response = client.send(request, HttpResponse.BodyHandlers.ofString());
			var body = response.body();
			if (response.statusCode() != 200) {
				var ctype = response.headers().firstValue("Content-Type").orElse(null);
				if (APPLICATION_JSON.equals(ctype)) {
					throw new ResponseException(JsonUtil.parseJSON(body), response.headers());
				}
				throw new IOException(body);
			}
			return body;
		} catch (InterruptedException e) {
			throw new IllegalStateException(e);
		}
	}
	
	public Http authenticate(String authentication) {
		return new Http.Builder().
			fromHttp(this).
			addHeaders(new NameValuePair[] {
				new NameValuePair("Authorization", authentication)
			}).
			build();
	}

	public String postJson(String path, String json)
			throws IOException, ResponseException {
		return post(path, new NameValuePair[0], APPLICATION_JSON, BodyPublishers.ofString(json));
	}

	public String postForm(String path, NameValuePair... postVariables)
			throws IOException, ResponseException {
		return post(path, new NameValuePair[0], APPLICATION_X_WWW_FORM_URLENCODED, ofNameValuePairs(postVariables));
	}

	public String post(String path, NameValuePair[] headers, String contentType, BodyPublisher content)
			throws IOException, ResponseException {
		var url = uri.resolve(path);
		var client = clientSupplier.get();

		try {
			var bldr = newBuilder(url).header("Content-Type", contentType);
			this.headers.forEach(h -> bldr.header(h.name(), h.value()));
			for (var hdr : headers) {
				bldr.header(hdr.name(), hdr.value());
			}
			var request = bldr.POST(content).build();

			log.log(Level.DEBUG, "Executing request " + request.toString());

			var response = client.send(request, HttpResponse.BodyHandlers.ofString());
			var body = response.body();
			if (response.statusCode() != 200) {
				var ctype = response.headers().firstValue("Content-Type").orElse(null);
				if (APPLICATION_JSON.equals(ctype)) {
					throw new ResponseException(JsonUtil.parseJSON(body), response.headers());
				}
				throw new IOException(body);
			}
			return body;
		} catch (InterruptedException e) {
			throw new IllegalStateException(e);
		}

	}

	private HttpRequest.Builder newBuilder(URI url) {
		return HttpRequest.newBuilder(url);
	}

	public static HttpRequest.BodyPublisher ofNameValuePairs(NameValuePair... parms) {
		var b = new StringBuilder();
		for (var n : parms) {
			if (b.length() > 0) {
				b.append("&");
			}
			b.append(URLEncoder.encode(n.name(), StandardCharsets.UTF_8));
			if (n.value() != null) {
				b.append('=');
				b.append(URLEncoder.encode(n.value(), StandardCharsets.UTF_8));
			}
		}
		return HttpRequest.BodyPublishers.ofString(b.toString());
	}
}
