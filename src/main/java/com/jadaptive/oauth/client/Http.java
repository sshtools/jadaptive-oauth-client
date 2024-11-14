package com.jadaptive.oauth.client;

import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;

import com.jadaptive.oauth.client.OAuth2Objects.NameValuePair;

public class Http {
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
