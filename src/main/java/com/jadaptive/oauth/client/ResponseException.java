package com.jadaptive.oauth.client;

import java.net.http.HttpHeaders;

import jakarta.json.JsonObject;

@SuppressWarnings("serial")
public final class ResponseException extends Exception {
	private final String error;
	private final int status;
	private final HttpHeaders httpHeaders;

	public ResponseException(JsonObject object, HttpHeaders httpHeaders) {
		super(object.getString("error_description", ""));
		this.httpHeaders = httpHeaders;
		error = object.getString("error");
		status = object.getInt("status", 200);
	}
	
	public HttpHeaders getHttpHeaders() {
	    return httpHeaders;
	}
	
	public int getStatus() {
		return status;
	}

	public String getError() {
		return error;
	}
	
}