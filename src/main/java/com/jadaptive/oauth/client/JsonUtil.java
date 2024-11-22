package com.jadaptive.oauth.client;

import java.io.StringReader;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.Collection;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;

public class JsonUtil {

	static Logger log = System.getLogger(JsonUtil.class.getName());
	
	public static JsonArray stringArray(Collection<String> vals) {
		var blr = Json.createArrayBuilder();
		vals.stream().forEach(blr::add);
		return blr.build();
	}

    public static JsonObject parseJSON(String json) {
        if (log.isLoggable(Level.DEBUG)) {
            log.log(Level.DEBUG, json);
        }

        try(var rdr = Json.createReader(new StringReader(json))) {
            return rdr.readObject();
        }
    }
}
