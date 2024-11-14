package com.jadaptive.oauth.client;

import jakarta.json.JsonObject;

@SuppressWarnings("serial")
public final class ResponseException extends Exception {
	private final String error;

	public ResponseException(JsonObject object) {
		super(object.getString("error_description", ""));
		error = object.getString("error");
	}

	public String getError() {
		return error;
	}
	
}