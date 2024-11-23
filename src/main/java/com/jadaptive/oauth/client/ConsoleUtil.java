package com.jadaptive.oauth.client;

import java.text.MessageFormat;
import java.util.Optional;
import java.util.ResourceBundle;

public class ConsoleUtil {

	public static void defaultConsoleDeviceCodePrompt(ResourceBundle bundle, OAuth2Objects.DeviceCode code) {
		 var ou = System.out;
         ou.println(bundle.getString("prompt"));
         ou.println();
         ou.println(ConsoleUtil.xtermLink(code.verification_uri_complete(), code.verification_uri()));
         ou.println(MessageFormat.format(bundle.getString("userCode"), code.user_code()));
         ou.flush();
     }
	
	public static String xtermLink(String url, String text) {
		 if(Optional.ofNullable(System.getenv("TERM")).orElse("vt100").startsWith("xterm")) {
			var bldr = new StringBuilder();
			bldr.append((char) 27 + "]8;;");
			bldr.append(url);
			bldr.append((char) 27 + "\\");
			bldr.append(text);
			bldr.append((char) 27 + "]8;;" + (char) 27 + "\\");
			return bldr.toString();
		}
		else {
			return text;
		}
	}
}
