package net.encryptedkitten.java_network_interception_tool.Version1_0_0;

import com.github.ooxi.jdatauri.DataUri;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import net.bytebuddy.agent.ByteBuddyAgent;
import org.xbill.DNS.SimpleResolver;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;

import static java.util.Objects.isNull;

public class JavaAgent {

	#if BUILD == "net.encryptedkitten.minecraft_javaagent"
		public static boolean ran_no_blocked_servers = false;
	#endif

	public static final String loggingName = "PREPROCESSOR_LOGGING_NAME";

	public static final String version = "Version1_0_0";

	public static boolean printStackTrace = true;
	public static boolean exitOnFailure = true;
	public static int failureExitCode = 2;
	public static boolean debug = false;

	public static boolean ran_install_bytebuddy_agent = false;
	public static boolean ran_no_classloader_signature = false;
	public static boolean ran_no_security_verify = false;
	public static boolean ran_patch_url_constructor = false;
	public static boolean ran_patch_url_openConnection = false;
	public static boolean ran_getresourceasstream = false;
	public static boolean ran_set_cacerts = false;
	public static boolean ran_patch_inetaddress_getallbyname = false;

	public static boolean run_add_system_hosts = true;

	//No DER Certificate should be this big, so its more than enough buffer area.
	//Default cacerts is only around 150-200 kb, you'd need to have a lot of certs in there to need more than 1 megabyte.
	public static final int BUFFER_SIZE = 1024 * 1024;

	public static List<String> comma_separated_args(String agentArgs)
	{
		List<String> return_value = new ArrayList<>();
		int start = 0;
		int bracket_n = 0;
		boolean quoted = false;
		String mode = "none";
		for (int i = 0; i < agentArgs.length(); i++) {
			if (mode.equals("none"))
			{
				mode = (agentArgs.charAt(i) == '{') ? "json" : "url";

				start = i;
			}

			if (mode.equals("json") && agentArgs.charAt(i) == '\"' && agentArgs.charAt(i - 1) != '\\')
			{
				quoted = !quoted;
			}
			else if (mode.equals("json") && !quoted && agentArgs.charAt(i) == '{')
			{
				bracket_n++;
			}
			else if (mode.equals("json") && !quoted && agentArgs.charAt(i) == '}')
			{
				bracket_n--;
			}
			else if (bracket_n == 0 && !quoted && agentArgs.charAt(i) == ',')
			{
				mode = "none";

				String arg = agentArgs.substring(start, i);
				if (arg.length() != 0)
					return_value.add(arg);
			}
		}

		String arg = agentArgs.substring(start);
		if (arg.length() != 0)
			return_value.add(arg);

		return return_value;
	}

	public static void premain(String agentArgs, Instrumentation instrumentation){
		try
		{
			System.out.println(loggingName + " - Executing " + version + "\n");

			List<String> agentArgsList = comma_separated_args(agentArgs);

			Gson gson = new Gson();

			if (agentArgsList.size() != 0) {

				for (String agentArg : agentArgsList) {
					load_config(gson, agentArg);
				}

				if (!CACerts.saved)
					CACerts.save_cacerts();

				if (!isNull(InetAddressInterceptor.dns_resolver) && run_add_system_hosts)
					add_system_hosts();

				System.out.print(loggingName + " - Complete\n");
			}
			else
			{
				System.out.print(" - Failed\n");
				System.out.println(loggingName + " has failed. You did not supply any arguments to the JavaAgent. If you would like to run it without any arguments, just supply an empty json object, {}, as the argument.\n\n");

				help();

				if(exitOnFailure) System.exit(failureExitCode);
			}
		}
		catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException | KeyManagementException e)
		{
			error(e);
		}
	}

	public static void load_config(Gson gson, String agentArg) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		if (agentArg.charAt(0) != '{') {
			agentArg = new String(load_url(agentArg), StandardCharsets.UTF_8);
		} else {
			System.out.println(loggingName + " - Loading Config From Command Line");
		}

		JsonObject json = gson.fromJson(agentArg, JsonObject.class);
		System.out.print(" - Succeeded\n");

		if (json.has("printStackTrace"))
			printStackTrace = json.get("printStackTrace").getAsBoolean();

		if (json.has("exitOnFailure"))
			exitOnFailure = json.get("exitOnFailure").getAsBoolean();

		if (json.has("failureExitCode"))
			failureExitCode = json.get("failureExitCode").getAsInt();

		if (json.has("debug"))
			debug = json.get("debug").getAsBoolean();

		dns_mods(json);

		ssl_mods(json);

		class_mods(json);

		url_mods(json);

		if (json_default_true(json, "patch")) {
			System.out.print(loggingName + " - Patching Java\n");
			patch(json);
			System.out.print(loggingName + " - Patching Java - Succeeded\n");
		}
	}

	public static void class_mods(JsonObject json) throws IOException {
		#if BUILD == "net.encryptedkitten.minecraft_javaagent"
		if (json.has("yggdrasil_session_pubkey")) {
			System.out.print(loggingName + " - Loading fake yggdrasil_session_pubkey.der from " + json.get("yggdrasil_session_pubkey").getAsString());
			loadFakeKey(json.get("yggdrasil_session_pubkey").getAsString());
			System.out.print(" - Succeeded\n");
		}
		#else
		if (json.has("resource_replacements")) {
			System.out.print(loggingName + " - Setting up resource replacements");
			JsonObject resources = json.get("resource_replacements").getAsJsonObject();
			for (String resource_name : resources.keySet()) {
				if (!ClassInterceptor.resource_replacements.containsKey(resource_name)) {
					byte[] resource = load_url(resources.get(resource_name).getAsString());
					ClassInterceptor.resource_replacements.put(resource_name, resource);
				}
			}
			System.out.print(" - Succeeded\n");
		}
		#endif
	}

	public static void url_mods(JsonObject json)
	{
		url_prototocol_mods(json);
		url_http_mods(json);
	}

	public static void url_http_mods(JsonObject json)
	{
		if (!ran_patch_url_openConnection && !InetAddressInterceptor.offline && json.has("force_proxy"))
		{
			System.out.print(loggingName + " - Running force_proxy patch");

			if (debug)
				System.out.print(" (Sets URL openConnection to force all http and https connections through the specified proxy, or to force a direct connection.)");

			if (json.get("force_proxy").isJsonNull())
				URLInterceptor.force_proxy = Proxy.NO_PROXY;

			else if (json.get("force_proxy").isJsonObject()) {
				Proxy.Type proxy_type = null;

				JsonObject proxy_settings = json.get("force_proxy").getAsJsonObject();

				if (proxy_settings.get("type").getAsString().toLowerCase().equals("http"))
					proxy_type = Proxy.Type.HTTP;

				else if (proxy_settings.get("type").getAsString().toLowerCase().equals("socks"))
					proxy_type = Proxy.Type.SOCKS;

				String address = proxy_settings.get("address").getAsString();
				int port = proxy_settings.get("port").getAsInt();

				SocketAddress addr = new InetSocketAddress(address, port);

				URLInterceptor.force_proxy = new Proxy(proxy_type, addr);
			}

			System.out.print(" - Succeeded\n");
		}

		if (!URLInterceptor.url_offline && do_url_patches(json)) {
			if (isNull(URLInterceptor.blocked_urls))
				URLInterceptor.blocked_urls = new ArrayList<>();

			if (isNull(URLInterceptor.host_replacements))
				URLInterceptor.host_replacements = new HashMap<>();

			if (json.has("blocked_urls")) {
				System.out.print(loggingName + " - Setting up blocked URLs");
				for (JsonElement blocked_url : json.get("blocked_urls").getAsJsonArray()) {
					URLInterceptor.blocked_urls.add(blocked_url.getAsString());
				}
				System.out.print(" - Succeeded\n");
			}

			if (json.has("host_replacements")) {
				System.out.print(loggingName + " - Setting up host replacements");
				JsonObject json_host_replacements = json.get("host_replacements").getAsJsonObject();
				for (String host : json_host_replacements.keySet()) {
					if (!URLInterceptor.host_replacements.containsKey(host))
						URLInterceptor.host_replacements.put(host, json_host_replacements.get(host).getAsString());
				}
				System.out.print(" - Succeeded\n");
			}

			#if BUILD == "net.encryptedkitten.minecraft_javaagent"
				if (!ran_no_blocked_servers && json_default_false(json, "no_blocked_servers")) {
					System.out.print(loggingName + " - Blocking https://sessionserver.mojang.com/blockedservers");

					URLInterceptor.blocked_urls.add("sessionserver.mojang.com/blockedservers");
					ran_no_blocked_servers = true;

					System.out.print(" - Succeeded\n");
				}
			#endif

			if (isNull(URLInterceptor.subdomain) && json.has("subdomain")) {
				System.out.print(loggingName + " - Setting up subdomain suffix");
				URLInterceptor.subdomain = json.get("subdomain").getAsString();
				System.out.print(" - Succeeded\n");
			}

			else if (isNull(URLInterceptor.underscore) && json.has("underscore")) {
				System.out.print(loggingName + " - Setting up underscore-d subdomain suffix");
				URLInterceptor.underscore = json.get("underscore").getAsString();
				System.out.print(" - Succeeded\n");
			}
		}
	}

	public static void url_prototocol_mods(JsonObject json)
	{
		if (json_default_false(json, "url_offline")) {
			System.out.print(loggingName + " - Running url_offline patch");

			if (debug)
				System.out.print(" (Sets URL to throw MalformedURLException on all http or https URLs.)");
			URLInterceptor.url_offline = true;
			System.out.print(" - Succeeded\n");
		}

		else if (json_default_false(json, "force_http")) {
			System.out.print(loggingName + " - Running force_http patch");

			if (debug)
				System.out.print(" (Sets URL to make all https URLs instead use http.)");
			URLInterceptor.force_http = true;
			System.out.print(" - Succeeded\n");
		}

		else if (json_default_false(json, "force_https")) {
			System.out.print(loggingName + " - Running force_https patch");

			if (debug)
				System.out.print(" (Sets URL to make all http URLs instead use https.)");
			URLInterceptor.force_https = true;
			System.out.print(" - Succeeded\n");
		}
	}

	public static boolean json_default_false(JsonObject json, String key)
	{
		return json.has(key) && json.get(key).getAsBoolean();
	}

	public static boolean json_default_true(JsonObject json, String key)
	{
		return !json.has(key) || json.get(key).getAsBoolean();
	}

	public static void dns_mods(JsonObject json) throws IOException {
		if (do_dns_patches(json)) {
			if (json_default_false(json, "offline"))
				InetAddressInterceptor.offline = true;
			else if (json_default_false(json, "dns_offline"))
				InetAddressInterceptor.dns_offline = true;

			if (isNull(InetAddressInterceptor.blocked_hosts))
				InetAddressInterceptor.blocked_hosts = new ArrayList<>();

			if (isNull(InetAddressInterceptor.static_hosts))
				InetAddressInterceptor.static_hosts = new HashMap<>();

			if (isNull(InetAddressInterceptor.dns_resolver))
			{
				if (json.has("dns_resolver"))
					InetAddressInterceptor.dns_resolver = new SimpleResolver(json.get("dns_resolver").getAsString());
				else
					InetAddressInterceptor.dns_resolver = new SimpleResolver();
			}

			if (json.has("blocked_hosts")) {
				System.out.print(loggingName + " - Setting up blocked hosts");
				for (JsonElement blocked_host : json.get("blocked_hosts").getAsJsonArray()) {
					InetAddressInterceptor.blocked_hosts.add(blocked_host.getAsString());
				}
				System.out.print(" - Succeeded\n");
			}

			if (json.has("static_hosts")) {
				System.out.print(loggingName + " - Setting up static hosts");
				JsonObject json_static_hosts = json.get("static_hosts").getAsJsonObject();
				for (String host : json_static_hosts.keySet()) {
					if (!InetAddressInterceptor.static_hosts.containsKey(host))
						InetAddressInterceptor.static_hosts.put(host, json_static_hosts.get(host).getAsString());
				}
				System.out.print(" - Succeeded\n");
			}

			if (json.has("hosts_files")) {
				System.out.print(loggingName + " - Setting up hosts files");
				JsonArray hosts_files = json.get("hosts_files").getAsJsonArray();

				for (JsonElement hosts_file_element: hosts_files)
				{
					String hosts_file = hosts_file_element.getAsString();
					if (hosts_file.startsWith("http://") || hosts_file.startsWith("https://") || hosts_file.startsWith("file://") || hosts_file.startsWith("data:"))
						hosts_file = new String(load_url(hosts_file), StandardCharsets.UTF_8);

					parse_hosts_file(hosts_file);
				}

				System.out.print(" - Succeeded\n");
			}

			if (run_add_system_hosts && json.has("respect_system_hosts")) {
				if (json.get("respect_system_hosts").getAsBoolean())
					add_system_hosts();
				run_add_system_hosts = false;
			}
		}
	}

	public static void add_system_hosts() throws IOException {
		System.out.print(loggingName + " - Adding system hosts file");

		String hosts_file = "/etc/hosts";
		File hosts_file_file = new File(hosts_file);

		if (System.getProperty("os.name").toLowerCase().contains("win")) {
			hosts_file = System.getenv("SystemRoot") + "\\System32\\drivers\\etc\\hosts";
			hosts_file_file = new File(hosts_file);

			if (hosts_file_file.isFile())
			{
				hosts_file = System.getenv("WinDir") + "\\hosts";
				hosts_file_file = new File(hosts_file);
			}
		}

		if (hosts_file_file.isFile() && hosts_file_file.canRead()) {
			hosts_file = "file://" + ((hosts_file.charAt(0) == '/') ? "" : "/") + hosts_file.replace('\\', '/');
			hosts_file = new String(load_url(hosts_file), StandardCharsets.UTF_8);

			parse_hosts_file(hosts_file);
			System.out.print(" - Succeeded\n");
		}
		else
		{
			System.out.print(" - Failed - Unable to locate or read from system hosts file\n");
		}
	}

	public static void parse_hosts_file(String hosts_file)
	{
		boolean changed = true;

		while (changed)
		{
			changed = false;

			if (hosts_file.contains("  "))
			{
				hosts_file = hosts_file.replaceAll(Pattern.quote("  "), " ");
				changed = true;
			}

			if (hosts_file.contains("\t"))
			{
				hosts_file = hosts_file.replaceAll(Pattern.quote("\t"), " ");
				changed = true;
			}

			if (hosts_file.contains("\n "))
			{
				hosts_file = hosts_file.replaceAll(Pattern.quote("\n "), " ");
				changed = true;
			}

			if (hosts_file.startsWith(" "))
			{
				hosts_file = hosts_file.substring(1);
				changed = true;
			}
		}

		String[] hosts_file_lines = hosts_file.replaceAll(Pattern.quote("\r"), "").split(Pattern.quote("\n"));

		for (String hosts_file_line: hosts_file_lines)
		{
			if (hosts_file_line.charAt(0) != '#')
			{
				String[] hosts_components = hosts_file_line.split(Pattern.quote(" "));

				for (int i = 1; i < hosts_components.length; i++)
				{
					if (!InetAddressInterceptor.static_hosts.containsKey(hosts_components[i]))
						InetAddressInterceptor.static_hosts.put(hosts_components[i], hosts_components[0]);
				}
			}
		}
	}

	public static void ssl_mods(JsonObject json) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
		if (json_default_false(json, "no_ssl")) {
			System.out.print(loggingName + " - Running no_ssl patch");

			if (debug)
				System.out.print(" (Sets HttpsURLConnection.setDefaultHostnameVerifier to use a Hostname Verifier that will accept any certificate.)");
			NoSSL.patchSSL();
			System.out.print(" - Succeeded\n");
		}

		else if (json.has("cacerts")) {
			System.out.print(loggingName + " - Running cacerts patch");

			if (debug)
				System.out.print(" (Sets javax.net.ssl.trustStore to a temporary file which can be loaded in from a URL and optionally can have additional certificates added to it.)");

			if (json.get("cacerts").isJsonPrimitive() && json.get("cacerts").getAsJsonPrimitive().isString())
				CACerts.load_cacerts_file(json.get("cacerts").getAsString());

			else if (json.get("cacerts").isJsonObject()) {
				JsonObject cacerts_settings = json.get("cacerts").getAsJsonObject();

				if (!ran_set_cacerts)
				{
					if (cacerts_settings.has("password"))
						CACerts.cacerts_password = cacerts_settings.get("password").getAsString();

					if (cacerts_settings.has("location"))
						CACerts.load_cacerts_file(cacerts_settings.get("location").getAsString());

					ran_set_cacerts = true;
				}

				if (cacerts_settings.has("certificates"))
				{
					JsonObject certificates = cacerts_settings.get("certificates").getAsJsonObject();
					for (String alias : certificates.keySet()) {
						CACerts.add_cert(alias, certificates.get(alias).getAsString());

						if (cacerts_settings.has("save") && cacerts_settings.get("save").getAsString().equals("after_certificate"))
							CACerts.save_cacerts();
					}
				}

				if (!CACerts.saved && cacerts_settings.has("save") && cacerts_settings.get("save").getAsString().equals("after_config"))
					CACerts.save_cacerts();
			}

			System.out.print(" - Succeeded\n");
		}
	}

	public static void error(Exception e)
	{
		System.out.print(" - Failed\n");
		System.out.println(loggingName + " has failed. The requested patches were not able to be applied. You should try again with a different set of patch of patch options.\n\n");

		help();

		error_exit(e);
	}

	public static void error_exit(Exception e)
	{
		if(printStackTrace) e.printStackTrace();
		if(exitOnFailure) System.exit(failureExitCode);
	}

	public static void help()
	{
		System.out.println(loggingName + " Help\n");
		System.out.println("The patch arguments are passed via the javaagent command line arguments, where the JavaAgent command is -javaagent:/path/to/javaagent.jar='THE_ARGUMENT_STRING_GOES_HERE'\n");

		#if BUILD == "net.encryptedkitten.minecraft_javaagent"
		System.out.println("They are formatted as a JSON string surrounded by single-tick quotes, such as '{\"yggdrasil_session_pubkey\":\"https://example.com/my_fake_yggdrasil_session_pubkey.der\", \"debug\":true}'\n");
		#else
		System.out.println("They are formatted as a JSON string surrounded by single-tick quotes, such as '{\"dns_resolver\":\"127.0.0.1\", \"debug\":true}'\n");
		#endif

		System.out.println("They can also be passed as an URL to a configuration file. At all of the help sections where a URL is supported, file:/// and data: URLs are included.\n");
		System.out.println("They will stay as the default if they are missing from the string, so you don't need to (but you can) have arguments in the argument string that are set as their listed default value.\n\n");
		System.out.println("Arguments | Options | Info\n\n");

		#if BUILD == "net.encryptedkitten.minecraft_javaagent"
		System.out.println("yggdrasil_session_pubkey | URL String/(key does not exist)(default) | Can be any URL type listed in the above help segment.\n");
		#else
		System.out.println("resource_replacements | object/{}(default) | A list of resources mapped to a URL of what their contents will be. All of the resources are loaded at start.\n");
		#endif

		System.out.println("debug | true/false(default) | Enable the informational text about what each of the patches is actually doing to Java behind the scenes.\n");
		System.out.println("no_security_verify | true/false(default) | Disables all public key signature verification. This is not recommended, because it could falsify unintended public key signature checks.\n");
		System.out.println("no_classloader_signature | true(default)/false | Disables all Java ClassLoader Signature Checks, to allow Java classes with invalid signatures to be loaded. Without this it seems to crash, so it's recommended to leave this as true.\n");
		System.out.println("patch | true(default)/false | Sets if the patch will actually run. If you want the program to actually patch Java, leave this as true, if you don't want patches, remove the -javaagent argument, or set it to an empty json object.\n");
		System.out.println("printStackTrace | true(default)/false | Sets if on an error, it will print the error stack trace.\n");
		System.out.println("exitOnFailure | true(default)/false | Sets if on an error, it will exit and terminate the JVM process.\n");
		System.out.println("failureExitCode | int/2(default) | Sets exit code used when it exits of failure if enabled, the default is 2, to differentiate it's exits from other JVM error exit code 1 exits.\n");
		System.out.println("no_ssl | true/false(default) | Sets if it should remove all SSL/TLS Certificate Checks.\n");
		System.out.println("blocked_urls | list/[](default) | Sets a list of URLS that will be not be allowed, and blocked.\n");
		System.out.println("host_replacements | object/{}(default) | Sets a list of hosts that will be changed.\n");

		#if BUILD == "net.encryptedkitten.minecraft_javaagent"
		System.out.println("no_blocked_servers | true/false(default) | Makes it so https://sessionserver.mojang.com/blockedservers, the blocked servers list, will not be loaded.\n");
		#endif

		System.out.println("url_offline | true/false(default) | Makes it so all http and https connections will throw MalformedURLException, and therefore not load.\n");
		System.out.println("force_http | true/false(default) | Makes it so all https connections will instead use http.\n");
		System.out.println("force_https | true/false(default) | Makes it so all http connections will instead use https.\n");
		System.out.println("subdomain | Domain String | Can be a string to have as the suffix for all URL requests. It should start with a dot, unless you want the subdomains themselves to have a suffix.\n");
		System.out.println("underscore | Domain String | Can be a string to have as the suffix for all URL requests, except the original host will have it's dots replaced with underscores. It should start with a dot, unless you want the subdomains themselves to have a suffix.\n");
		System.out.println("force_proxy | object/null/(key does not exist)(default) | Setting it to null, will force a direct connection, not setting it will disable forcing it, and an object will set the parameters as {\"type\":type, \"address\":address, \"port\":port} to be the settings for the proxy, with type being either http or socks.\n");
		System.out.println("cacerts | object/string/(key does not exist)(default) | Setting it to a string will load the cacerts file from that URL, and an object will set the parameters, all of which are optional, as {\"location\":cacerts_url_location, \"password\":cacerts_password, \"certificates\":[\"url_of_certificate_1\"], \"save\":\"after_certificate\"} with the save parameter being able to be after_config, to save the cacerts file after each config, after_certificate, to save after each individual certificate is loaded, and after_load, or any other value will result in it being saved at the end of the full loading sequence.\n");
		System.out.println("dns_offline | true/false(default) | Makes it so all DNS name resolutions fail.\n");
		System.out.println("offline | true/false(default) | Makes it so all InetAddresses will throw UnknownHostException.\n");
		System.out.println("dns_resolver | String/(key does not exist)(default) | Sets the DNS server to use for DNS queries.\n");
		System.out.println("blocked_hosts | list/[](default) | Sets a list of hostanames or IP addresses that will make InetAddress throw UnknownHostException.\n");
		System.out.println("static_hosts | object/{}(default) | Sets a list of domains that will either be statically linked to an alternate IP address, or an alternate domain.\n");
		System.out.println("hosts_files | list/[](default) | Sets a list of hosts files that it will all to the static_hosts list, they can be a string literal being the hosts file, or a URL to a hosts file.\n");
		System.out.println("respect_system_hosts | true/false/(key does not exist)(default) | Sets if it will respect the system host file, if it is unset, it will respect the system host file only if no config disables respecting it, true will force the system hosts file to be respected, and disallow other configs from disabling respecting it, and false will make it not load the system hosts file, unless a previous config has loaded it.\n");
	}

	public static boolean do_dns_patches(JsonObject json)
	{
		return json.has("dns_resolver") ||
				json.has("blocked_hosts") ||
				json.has("static_hosts") ||
				json_default_false(json, "dns_offline") ||
				json_default_false(json, "offline") ||
				json.has("respect_system_hosts");
	}

	public static boolean do_url_patches(JsonObject json)
	{
		return !InetAddressInterceptor.offline &&
				((json.has("subdomain") ||
						json.has("underscore") ||
						json.has("blocked_urls") ||
						json.has("host_replacements")) ||
						#if BUILD == "net.encryptedkitten.minecraft_javaagent"
						json_default_false(json, "no_blocked_servers") ||
						#endif
						json_default_false(json, "url_offline") ||
						json_default_false(json, "force_http") ||
						json_default_false(json, "force_https"));
	}

	public static byte[] load_url(String location) throws IOException {
		if (location.toLowerCase().startsWith("data:"))
		{
			return DataUri.parse(location, Charset.defaultCharset()).getData();
		}
		else {
			URL url = new URL(location);
			InputStream urlStream = url.openStream();

			byte[] tempBuffer = new byte[BUFFER_SIZE];
			int read = urlStream.read(tempBuffer);
			urlStream.close();

			byte[] returnValue = new byte[read];
			System.arraycopy(tempBuffer, 0, returnValue, 0, read);

			return returnValue;
		}
	}

	#if BUILD == "net.encryptedkitten.minecraft_javaagent"
	//Loads the fake yggdrasil_session_pubkey.der.
	public static void loadFakeKey(String location) throws IOException
	{
		ClassInterceptor.fake_yggdrasil_session_pubkey = load_url(location);
	}
	#endif

	public static void patch(JsonObject json) {

		if (!ran_install_bytebuddy_agent) {
			System.out.print(loggingName + " - Installing ByteBuddyAgent");
			if (debug)
				System.out.print(" (Used to apply the Java function patches. It does not install anything to the system, it just readies ByteBuddy to apply class modifications. No of these changes are permanent, so if you run the JVM without this JavaAgent, it will be unpatched.)");
			ByteBuddyAgent.install();
			System.out.print(" - Succeeded\n");

			ran_install_bytebuddy_agent = true;
		}

		if (!ran_no_classloader_signature && json_default_true(json, "no_classloader_signature")) {
			System.out.print(loggingName + " - Patching Java ClassLoader");
			if (debug)
				System.out.print(" (Patches the Java ClassLoader signature check because Java seems to crash without it. It strips all of the signatures from any classes being loaded, because a valid signature is ok, no signature is ok, but a bad signature will fail to load.)");
			ClassLoaderInterceptor.patchCheckCerts();
			System.out.print(" - Succeeded\n");

			ran_no_classloader_signature = true;
		}

		#if BUILD == "net.encryptedkitten.minecraft_javaagent"
		if (!ran_getresourceasstream && json.has("yggdrasil_session_pubkey"))
		{
			System.out.print(loggingName + " - Running yggdrasil_session_pubkey patch");

			if (debug)
				System.out.print(" (Patches java.lang.Class.getResourceAsStream(), which can used by Java classes to pull resources from the JAR Archive, and it is modified to intercept any request to access /yggdrasil_session_pubkey.der.)");
		#else

		if (!ran_getresourceasstream && json.has("resource_replacements"))
		{
			System.out.print(loggingName + " - Running resource_replacements patch");

			if (debug)
				System.out.print(" (Patches java.lang.Class.getResourceAsStream(), which can used by Java classes to pull resources from the JAR Archive, and it is modified to intercept the specified resources.)");
		#endif

			ClassInterceptor.patchGetResourceAsStream();
			System.out.print(" - Succeeded\n");

			ran_getresourceasstream = true;
		}

		if (!ran_no_security_verify && json_default_false(json, "no_security_verify"))
		{
			System.out.print(loggingName + " - Running no_security_verify patch");

			if (debug)
				System.out.print(" (Patches java.security.Signature.verify(), and makes it so all public-key verification requests return true. This is not as secure as the yggdrasil_session_pubkey patch, as it could allow Java public key verifications that are not for the yggdrasil_session_pubkey to return true when they otherwise would not.)");
			SignatureInterceptor.patchVerify();
			System.out.print(" - Succeeded\n");

			ran_no_security_verify = true;
		}

		if (!ran_patch_inetaddress_getallbyname && do_dns_patches(json)) {
			System.out.print(loggingName + " - Running InetAddress getAllByName patch");
			if (debug)
				System.out.print(" (Patches java.net.InetAddress getAllByName, to allow it to control how the hosts and IPs are resolved.)");
			InetAddressInterceptor.patchGetAllByName();
			System.out.print(" - Succeeded\n");

			ran_patch_inetaddress_getallbyname = true;
		}

		if (!ran_patch_url_constructor && do_url_patches(json)) {
			System.out.print(loggingName + " - Running URL constructor patch");
			if (debug)
				System.out.print(" (Patches java.net.URL constructor, to allow it to change the selected URLs when they are constructed.)");
			URLInterceptor.patchConstructor();
			System.out.print(" - Succeeded\n");

			ran_patch_url_constructor = true;
		}

		if (!ran_patch_url_openConnection && !isNull(URLInterceptor.force_proxy))
		{
			System.out.print(loggingName + " - Running URL openConnection patch");
			if (debug)
				System.out.print(" (Patches java.net.URL openConnection, to allow it to force a proxy setting or remove all proxy usage from URLs when connecting.)");
			URLInterceptor.patchOpenConnection();
			System.out.print(" - Succeeded\n");

			ran_patch_url_openConnection = true;
		}
	}
}