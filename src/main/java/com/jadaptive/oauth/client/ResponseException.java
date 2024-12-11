package com.jadaptive.oauth.client;

import jakarta.json.JsonObject;

@SuppressWarnings("serial")
public final class ResponseException extends Exception {
	private final String error;
	private final int status;

	public ResponseException(JsonObject object) {
		super(object.getString("error_description", ""));
		error = object.getString("error");
		status = object.getInt("status", 200);
	}
	
	public int getStatus() {
		return status;
	}

	public String getError() {
		return error;
	}
	
}