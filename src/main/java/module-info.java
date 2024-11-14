
module com.jdapaptive.oauth.client {
	requires java.naming;
	requires transitive java.logging;
    requires transitive jakarta.json;
	requires transitive java.net.http;
	exports  com.jadaptive.oauth.client;
}