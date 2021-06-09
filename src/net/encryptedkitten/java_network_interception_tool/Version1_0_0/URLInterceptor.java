package net.encryptedkitten.java_network_interception_tool.Version1_0_0;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import net.bytebuddy.dynamic.loading.ClassReloadingStrategy;
import net.encryptedkitten.java_network_interception_tool.JavaAgentMain;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.*;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static java.util.Objects.isNull;
import static net.bytebuddy.matcher.ElementMatchers.*;

public class URLInterceptor {
	public static List<String> blocked_urls;
	public static Map<String, String> host_replacements;
	public static boolean force_http = false;
	public static boolean force_https = false;
	public static boolean url_offline = false;
	public static String subdomain = null;
	public static String underscore = null;
	public static Proxy force_proxy = null;

public static void patchConstructor() {
		new ByteBuddy()
				.redefine(URL.class)
				.visit(Advice.to(URLInterceptor_constructor_3.class).on(isConstructor()
						.and(takesArguments(3))
						.and(takesArgument(0, URL.class))
						.and(takesArgument(1, String.class))
						.and(takesArgument(2, URLStreamHandler.class))
				))
				.visit(Advice.to(URLInterceptor_constructor_5.class).on(isConstructor()
						.and(takesArguments(5))
						.and(takesArgument(0, String.class))
						.and(takesArgument(1, String.class))
						.and(takesArgument(2, int.class))
						.and(takesArgument(3, String.class))
						.and(takesArgument(4, URLStreamHandler.class))
				))
				.make()
				.load(ClassLoadingStrategy.BOOTSTRAP_LOADER, ClassReloadingStrategy.fromInstalledAgent())
				.getLoaded();
	}

	public static void patchOpenConnection() {
		new ByteBuddy()
				.redefine(URL.class)
				.visit(Advice.to(URLInterceptor_openConnection_0.class).on(named("openConnection")
						.and(takesArguments(0))
				))
				.visit(Advice.to(URLInterceptor_openConnection_1.class).on(named("openConnection")
						.and(takesArguments(1))
						.and(takesArgument(0, Proxy.class))
				))
				.make()
				.load(ClassLoadingStrategy.BOOTSTRAP_LOADER, ClassReloadingStrategy.fromInstalledAgent())
				.getLoaded();
	}
}

class URLInterceptor_constructor_5 {
	@Advice.OnMethodEnter
	public static void intercept_enter(@Advice.Argument(value=0, readOnly=false) String protocol, @Advice.Argument(value=1, readOnly=false) String host, @Advice.Argument(value=2, readOnly=false) int port, @Advice.Argument(value=3, readOnly=false) String file, @Advice.Argument(value=4, readOnly=false) URLStreamHandler handler) throws MalformedURLException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		try {
			if (protocol.equals("http") || protocol.equals("https"))
			{
				Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + ".Version1_0_0.URLInterceptor");
				boolean url_offline = (boolean) thisClass.getField("url_offline").get(null);

				if (url_offline)
					throw new MalformedURLException();

				boolean force_http = (boolean) thisClass.getField("force_http").get(null);
				boolean force_https = (boolean) thisClass.getField("force_https").get(null);

				if (force_http)
					protocol = "http";
				else if (force_https)
					protocol = "https";

				String spec_port = protocol + "://" + host + ":" + port + file;
				String spec;

				if ((protocol.equals("http") && port == 80) || (protocol.equals("https") && port == 443))
					spec = protocol + "://" + host + file;
				else
					spec = spec_port;

				List<String> blocked_urls = (List<String>) thisClass.getField("blocked_urls").get(null);

				//The url is malformed if we don't like it.
				if (blocked_urls.contains(spec) || blocked_urls.contains(spec.split(Pattern.quote("://"), 2)[1]) ||
						blocked_urls.contains(spec_port) || blocked_urls.contains(spec_port.split(Pattern.quote("://"), 2)[1]))
					throw new MalformedURLException();

				Map<String, String> host_replacements = (Map<String, String>) thisClass.getField("host_replacements").get(null);


				String subdomain = (String) thisClass.getField("subdomain").get(null);
				String underscore = (String) thisClass.getField("underscore").get(null);

				if (host_replacements.containsKey(host))
					host = host_replacements.get(host);

				else if (!isNull(subdomain))
					host = host + subdomain;

				else if (!isNull(underscore))
					host = host.replace('.', '_') + underscore;
			}
		}
		catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e)
		{
			Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + "." + JavaAgent.version + ".JavaAgent");
Method error_exit = thisClass.getMethod("error_exit", Exception.class);
error_exit.invoke(null, e);
		}
	}
}

class URLInterceptor_constructor_3 {
	@Advice.OnMethodEnter
	public static void intercept_enter(@Advice.Argument(value=0, readOnly=false) URL context, @Advice.Argument(value=1, readOnly=false) String spec, @Advice.Argument(value=2, readOnly=false) URLStreamHandler handler) throws MalformedURLException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		try {
			String protocol = spec.split(Pattern.quote("://"), 2)[0];

			if (protocol.equals("http") || protocol.equals("https")) {
				Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + ".Version1_0_0.URLInterceptor");
				boolean url_offline = (boolean) thisClass.getField("url_offline").get(null);

				if (url_offline)
					throw new MalformedURLException();

				boolean force_http = (boolean) thisClass.getField("force_http").get(null);
				boolean force_https = (boolean) thisClass.getField("force_https").get(null);

				if (force_http) {
					protocol = "http";

					spec = protocol + "://" + spec.split(Pattern.quote("://"))[1];
				}
				else if (force_https) {
					protocol = "https";

					spec = protocol + "://" + spec.split(Pattern.quote("://"))[1];
				}

				List<String> blocked_urls = (List<String>) thisClass.getField("blocked_urls").get(null);

				//The url is malformed if we don't like it.
				if (blocked_urls.contains(spec) || blocked_urls.contains(spec.split(Pattern.quote("://"), 2)[1]))
					throw new MalformedURLException();

				Map<String, String> host_replacements = (Map<String, String>) thisClass.getField("host_replacements").get(null);

				String[] segments = spec.split(Pattern.quote("://"));

				if (segments.length >= 2) {
					String host = segments[1].split(Pattern.quote("/"))[0];

					if (host.charAt(0) == '[')
						host = host.split(Pattern.quote("]"))[0] + "]";
					else
						host = host.split(Pattern.quote(":"))[0];

					String subdomain = (String) thisClass.getField("subdomain").get(null);
					String underscore = (String) thisClass.getField("underscore").get(null);

					if (host_replacements.containsKey(host))
						spec = spec.replaceFirst(Pattern.quote(host), host_replacements.get(host));

					else if (!isNull(subdomain))
						spec = spec.replaceFirst(Pattern.quote(host), host + subdomain);

					else if (!isNull(underscore))
						spec = spec.replaceFirst(Pattern.quote(host), host.replace('.', '_') + underscore);
				}
			}
		}
		catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e)
		{
			Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + "." + JavaAgent.version + ".JavaAgent");
Method error_exit = thisClass.getMethod("error_exit", Exception.class);
error_exit.invoke(null, e);
		}
	}
}

class URLInterceptor_openConnection_0 {
	@Advice.OnMethodEnter(skipOn=Object.class)
	public static Object intercept_enter(@Advice.This URL this_URL) throws MalformedURLException {

		if (this_URL.getProtocol().equals("http") || this_URL.getProtocol().equals("https"))
			return new Object();

		return null;
	}

	@Advice.OnMethodExit
	public static Object intercept_exit(@Advice.This URL this_URL, @Advice.Return(readOnly=false) URLConnection returnValue) throws MalformedURLException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		try {
			if (this_URL.getProtocol().equals("http") || this_URL.getProtocol().equals("https"))
				returnValue = this_URL.openConnection(null);
		}
		catch (IOException e)
		{
			Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + "." + JavaAgent.version + ".JavaAgent");
Method error_exit = thisClass.getMethod("error_exit", Exception.class);
error_exit.invoke(null, e);
		}

		return null;
	}
}

class URLInterceptor_openConnection_1 {
	@Advice.OnMethodEnter
	public static void intercept_enter(@Advice.This URL this_URL, @Advice.Argument(value=0, readOnly=false) Proxy proxy) throws MalformedURLException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		try {
			if (this_URL.getProtocol().equals("http") || this_URL.getProtocol().equals("https"))
			{
				Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + ".Version1_0_0.URLInterceptor");

				proxy = (Proxy) thisClass.getField("force_proxy").get(null);
			}
		}
		catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e)
		{
			Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + "." + JavaAgent.version + ".JavaAgent");
Method error_exit = thisClass.getMethod("error_exit", Exception.class);
error_exit.invoke(null, e);
		}
	}
}