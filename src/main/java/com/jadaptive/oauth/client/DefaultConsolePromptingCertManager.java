package com.jadaptive.oauth.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

public final class DefaultConsolePromptingCertManager extends PromptingCertManager {
	
	private Set<String> accepted = new HashSet<>();
	
	private final Supplier<List<String>> currentCertsSupplier;
	private final Consumer<List<String>> newCertsConsumer;

	public DefaultConsolePromptingCertManager(ResourceBundle bundle, boolean strictSSL, Supplier<List<String>> currentCertsSupplier, Consumer<List<String>> newCertsConsumer) {
		super(bundle, strictSSL);
		this.currentCertsSupplier = currentCertsSupplier;
		this.newCertsConsumer = newCertsConsumer;
	}

	public DefaultConsolePromptingCertManager(ResourceBundle bundle, Supplier<List<String>> currentCertsSupplier, Consumer<List<String>> newCertsConsumer) {
		super(bundle);
		this.currentCertsSupplier = currentCertsSupplier;
		this.newCertsConsumer = newCertsConsumer;
	}
	@Override
	public void accept(String encodedKey) {
		accepted.add(encodedKey);
	}

	@Override
	public boolean isAccepted(String encodedKey) {
		return accepted.contains(encodedKey) || currentCertsSupplier.get().contains(encodedKey);
	}

	@Override
	public boolean promptForCertificate(PromptType alertType, String title, String content, String key,
			String hostname, String message) {
		var ou = System.out;
		ou.println(alertType.name());
		ou.println(repeat(alertType.name().length(), '-'));
		ou.println();

		/* Title */
		if (title != null && title.length() > 0) {
			ou.println(title);
			ou.println(titleUnderline(title.length()));
			ou.println();
		}

		/* Content */
		ou.println(MessageFormat.format(content, hostname, message));
		ou.println();

		String yesAbbrev = bundle.getString("certificate.yes");
		String noAbbrev = bundle.getString("certificate.no");
		String saveAbbrev = bundle.getString("certificate.save");

		String reply = readLine(bundle.getString("certificate.prompt"), yesAbbrev,
				"(" + noAbbrev + ")", saveAbbrev);
		if (reply == null)
			throw new IllegalStateException("Aborted.");

		if (saveAbbrev.equalsIgnoreCase(reply)) {
			save(key);
			return true;
		} else if (yesAbbrev.equalsIgnoreCase(reply)) {
			return true;
		} else
			return false;
	}

	@Override
	public void reject(String encodedKey) {
		accepted.remove(encodedKey);
		var current = new HashSet<>(currentCertsSupplier.get());
		current.remove(encodedKey);
		newCertsConsumer.accept(new ArrayList<>(current));
	}

	@Override
	public void save(String encodedKey) {
		var current = new HashSet<>(currentCertsSupplier.get());
		current.add(encodedKey);
		newCertsConsumer.accept(new ArrayList<>(current));
	}
	
	@Override
	protected boolean isToolkitThread() {
		return true;
	}

	@Override
	protected void runOnToolkitThread(Runnable r) {
		r.run();
	}

	private String readLine(String prompt, Object... args) {
		var cnsl = System.console();
		if(cnsl == null) {
			System.out.print(MessageFormat.format(prompt, args));
			try {
				return new BufferedReader(new InputStreamReader(System.in)).readLine();
			} catch (IOException e) {
				throw new UncheckedIOException(e);
			}
		}
		else  {
			return cnsl.readLine(prompt, args);
		}
	}

    static String repeat(int times, char ch) {
		var l = new StringBuilder();
		for(int i = 0 ; i < times; i++) {
			l.append('=');
		}
		return l.toString();
	}
    
	static String titleUnderline(int len) {
		return repeat(len, '=');
	}
}
