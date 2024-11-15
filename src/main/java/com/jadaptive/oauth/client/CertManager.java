package com.jadaptive.oauth.client;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.X509TrustManager;

public interface CertManager extends X509TrustManager, HostnameVerifier {

	SSLContext getSSLContext();

	SSLParameters getSSLParameters();

}
