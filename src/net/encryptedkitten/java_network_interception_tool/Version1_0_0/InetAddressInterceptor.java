package net.encryptedkitten.java_network_interception_tool.Version1_0_0;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import net.bytebuddy.dynamic.loading.ClassReloadingStrategy;
import net.encryptedkitten.java_network_interception_tool.JavaAgentMain;
import org.xbill.DNS.*;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static java.util.Objects.isNull;
import static net.bytebuddy.matcher.ElementMatchers.*;

public class InetAddressInterceptor {
	public static List<String> blocked_hosts;
	public static Map<String, String> static_hosts;
	public static Resolver dns_resolver = null;
	public static boolean dns_offline = false;
	public static boolean offline = false;

	//Signature patches ClassLoader to nullify all signing certificates from the loaded class jars.
	public static void patchGetAllByName() {
		new ByteBuddy()
				.redefine(InetAddress.class)
				.visit(Advice.to(InetAddress_getAllByName_1.class).on(named("getAllByName")
						.and(takesArguments(1))
						.and(takesArgument(0, String.class))))
				.make()
				.load(ClassLoadingStrategy.BOOTSTRAP_LOADER, ClassReloadingStrategy.fromInstalledAgent())
				.getLoaded();
	}
}

class InetAddress_getAllByName_1 {
	@Advice.OnMethodEnter(skipOn=Object.class)
	public static Object intercept_enter(@Advice.Argument(value=0, readOnly=false) String host) throws UnknownHostException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		try {
			Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + ".Version1_0_0.InetAddressInterceptor");
			boolean offline = (boolean) thisClass.getField("offline").get(null);

			if (offline)
				throw new UnknownHostException(host + ": nodename nor servname provided, or not known");

			List<String> blocked_hosts = (List<String>) thisClass.getField("blocked_hosts").get(null);

			if (blocked_hosts.contains(host))
				throw new UnknownHostException(host + ": nodename nor servname provided, or not known");

			Map<String, String> static_hosts = (Map<String, String>) thisClass.getField("static_hosts").get(null);

			if (static_hosts.containsKey(host))
					host = static_hosts.get(host);

			if (host.charAt(0) == '[')
				return null;

			else
			{
				boolean ipv4 = true;

				String[] ipv4_parts = host.split(Pattern.quote("."));

				for (String ipv4_part : ipv4_parts) {
					try {
						int part = Integer.parseInt(ipv4_part);
						if (part < 0 || part > 255) {
							ipv4 = false;
							break;
						}
					} catch (NumberFormatException e) {
						ipv4 = false;
						break;
					}
				}

				if (ipv4)
					return null;
			}

			boolean dns_offline = (boolean) thisClass.getField("dns_offline").get(null);

			if (dns_offline)
				throw new UnknownHostException(host + ": nodename nor servname provided, or not known");

		} catch (IllegalAccessException | ClassNotFoundException | NoSuchFieldException e) {
			Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + "." + JavaAgent.version + ".JavaAgent");
Method error_exit = thisClass.getMethod("error_exit", Exception.class);
error_exit.invoke(null, e);
		}

		return new Object();
	}

	@Advice.OnMethodExit
	public static void intercept_exit(@Advice.Argument(value=0) String host, @Advice.Return(readOnly=false) InetAddress[] returnValue, @Advice.Enter Object entry) throws UnknownHostException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		try {
			Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + ".Version1_0_0.InetAddressInterceptor");

			Object dns_resolver = thisClass.getField("dns_resolver").get(null);

			if (!isNull(entry) && !isNull(dns_resolver))
			{

				Class<?> dnsResolverClass = ClassLoader.getSystemClassLoader().loadClass("org.xbill.DNS.Resolver");

				Class<?> dnsLookupClass = ClassLoader.getSystemClassLoader().loadClass("org.xbill.DNS.Lookup");
				Constructor<?> dnsLookupConstructor = dnsLookupClass.getConstructor(String.class, int.class);

				Object a_lookup = dnsLookupConstructor.newInstance(host, Type.A);
				dnsLookupClass.getMethod("setResolver", dnsResolverClass).invoke(a_lookup, dns_resolver);
				Object[] a_records = (Object[]) dnsLookupClass.getMethod("run").invoke(a_lookup);

				List<InetAddress> returnList = new ArrayList<InetAddress>();

				if (!isNull(a_records)) {
					Class<?> dnsARecordClass = ClassLoader.getSystemClassLoader().loadClass("org.xbill.DNS.ARecord");

					for (Object a_record : a_records) {
						returnList.add((InetAddress) dnsARecordClass.getMethod("getAddress").invoke(a_record));
					}
				}

				Object aaaa_lookup = dnsLookupConstructor.newInstance(host, Type.AAAA);
				dnsLookupClass.getMethod("setResolver", dnsResolverClass).invoke(aaaa_lookup, dns_resolver);
				Object[] aaaa_records = (Object[]) dnsLookupClass.getMethod("run").invoke(aaaa_lookup);

				if (!isNull(aaaa_records)) {
					Class<?> dnsAAAARecordClass = ClassLoader.getSystemClassLoader().loadClass("org.xbill.DNS.AAAARecord");

					for (Object aaaa_record : aaaa_records) {
						returnList.add((InetAddress) dnsAAAARecordClass.getMethod("getAddress").invoke(aaaa_record));
					}
				}

				if (returnList.size() == 0)
					throw new UnknownHostException(host + ": nodename nor servname provided, or not known");

				returnValue = new InetAddress[returnList.size()];
				returnValue = returnList.toArray(returnValue);
			}

		} catch (IllegalAccessException | ClassNotFoundException | NoSuchFieldException | InstantiationException e) {
			Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + "." + JavaAgent.version + ".JavaAgent");
Method error_exit = thisClass.getMethod("error_exit", Exception.class);
error_exit.invoke(null, e);
		}
	}
}