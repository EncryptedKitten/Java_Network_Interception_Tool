package net.encryptedkitten.java_network_interception_tool.Version1_0_0;

import net.encryptedkitten.java_network_interception_tool.JavaAgentMain;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import static java.util.Objects.isNull;

public class CACerts {
	public static File cacerts_temp_file;
	public static String cacerts_password;
	public static KeyStore keystore;
	public static boolean saved = true;

	public static void load_cacerts_file(String location) throws IOException {
		byte[] cacerts_data = JavaAgent.load_url(location);

		cacerts_temp_file = File.createTempFile(JavaAgentMain.name + "_cacerts_temp", null);
		cacerts_temp_file.deleteOnExit();
		OutputStream cacerts_temp_file_out = new FileOutputStream(cacerts_temp_file);
		cacerts_temp_file_out.write(cacerts_data);
		cacerts_temp_file_out.flush();
		cacerts_temp_file_out.close();

		if (isNull(cacerts_password))
			cacerts_password = "changeit";

		System.setProperty("javax.net.ssl.trustStore", cacerts_temp_file.getAbsolutePath());
		System.setProperty("javax.net.ssl.trustStorePassword", cacerts_password);
	}

	public static void copy_cacerts_file() throws IOException {
		cacerts_temp_file = File.createTempFile(JavaAgentMain.name + "_cacerts_temp", null);
		cacerts_temp_file.deleteOnExit();

		String system_cacerts = System.getProperty("javax.net.ssl.trustStore");
		if (isNull(system_cacerts))
			system_cacerts = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" + File.separator + "cacerts";

		File system_cacerts_file = new File(system_cacerts);

		if (isNull(cacerts_password))
		{
			cacerts_password = System.getProperty("javax.net.ssl.trustStorePassword");
			if (isNull(cacerts_password)) {
				cacerts_password = "changeit";
				System.setProperty("javax.net.ssl.trustStorePassword", cacerts_password);
			}
		}

		System.out.println(cacerts_temp_file);

		Files.copy(system_cacerts_file.toPath(), cacerts_temp_file.toPath(), StandardCopyOption.REPLACE_EXISTING);

		System.setProperty("javax.net.ssl.trustStore", cacerts_temp_file.getAbsolutePath());
	}

	public static void load_cacerts() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
		FileInputStream is = new FileInputStream(cacerts_temp_file);
		keystore = KeyStore.getInstance(KeyStore.getDefaultType());
		keystore.load(is, cacerts_password.toCharArray());
		is.close();
	}

	public static void save_cacerts() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
		FileOutputStream out = new FileOutputStream(cacerts_temp_file);
		keystore.store(out, cacerts_password.toCharArray());
		out.close();

		saved = true;
	}

	public static void add_cert(String alias, String location) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
		if (isNull(cacerts_temp_file))
			copy_cacerts_file();

		if (isNull(keystore))
			load_cacerts();

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		InputStream certificate_is = new ByteArrayInputStream(JavaAgent.load_url(location));
		Certificate certs =  cf.generateCertificate(certificate_is);

		keystore.setCertificateEntry(alias, certs);

		saved = false;
	}
}
