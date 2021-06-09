package net.encryptedkitten.java_network_interception_tool;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.regex.Pattern;

public class JavaAgentMain {
	public static final String name = "PREPROCESSOR_BUILD";

	public static void premain(String agentArgs, Instrumentation instrumentation) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		//Default (Current) version, can be changed by having the first comma separated parameter be VersionX_Y_Z
		String version = "PREPROCESSOR_VERSION";

		System.out.println("Starting JavaAgent " + version + "\n");

		if (agentArgs.charAt(0) != '{' && ((agentArgs.contains(",") && (agentArgs.indexOf(',') < agentArgs.indexOf(":"))) || !(agentArgs.contains(",") || agentArgs.contains(":")))) {
			String[] split = agentArgs.split(Pattern.quote(","), 2);
			version = split[0];
			agentArgs = split[1];
		}

		Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(name + "." + version + ".JavaAgent");
		Method JavaAgent_premain = thisClass.getMethod("premain", String.class, Instrumentation.class);
		JavaAgent_premain.invoke(null, agentArgs, instrumentation);
	}
}