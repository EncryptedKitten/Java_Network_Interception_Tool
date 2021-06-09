package net.encryptedkitten.java_network_interception_tool.Version1_0_0;

import net.bytebuddy.asm.Advice;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;

import static java.util.Objects.isNull;
import static net.bytebuddy.matcher.ElementMatchers.*;

import net.bytebuddy.dynamic.loading.ClassReloadingStrategy;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import net.encryptedkitten.java_network_interception_tool.JavaAgentMain;

public class ClassInterceptor {
	#if BUILD == "net.encryptedkitten.minecraft_javaagent"
		public static final String getResourceAsStream_replacedResource = "/yggdrasil_session_pubkey.der";
		public static byte[] fake_yggdrasil_session_pubkey;

		//Patches the reads from the /yggdrasil_session_pubkey.der resource to supply the fake yggdrasil_session_pubkey.der instead.
	#else
		public static Map<String, byte[]> resource_replacements;
	#endif
	public static void patchGetResourceAsStream() {
		new ByteBuddy()
				.redefine(Class.class)
				.visit(Advice.to(ClassInterceptor_getResourceAsStream.class).on(named("getResourceAsStream")))
				.make()
				.load(ClassLoadingStrategy.BOOTSTRAP_LOADER, ClassReloadingStrategy.fromInstalledAgent())
				.getLoaded();
	}

}
#if BUILD == "net.encryptedkitten.minecraft_javaagent"
class ClassInterceptor_getResourceAsStream {

	@Advice.OnMethodEnter(skipOn=Object.class)
	public static Object intercept_enter(@Advice.Argument(value=0) String arg) {
		if(arg.equals(ClassInterceptor.getResourceAsStream_replacedResource))
			return new Object();

		return null;
	}

	@Advice.OnMethodExit
	public static void intercept_exit(@Advice.Argument(value=0) String arg, @Advice.Return(readOnly=false) InputStream returnValue) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		try {
			Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + ".Version1_0_0.ClassInterceptor");

			if (isNull(returnValue) && (arg.equals(ClassInterceptor.getResourceAsStream_replacedResource)))
				returnValue = new ByteArrayInputStream((byte[]) thisClass.getField("fake_yggdrasil_session_pubkey").get(null));
		}
		catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e)
		{
			Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + "." + JavaAgent.version + ".JavaAgent");
Method error_exit = thisClass.getMethod("error_exit", Exception.class);
error_exit.invoke(null, e);
		}
	}
}
#else
class ClassInterceptor_getResourceAsStream {

	@Advice.OnMethodEnter(skipOn=Object.class)
	public static Object intercept_enter(@Advice.Argument(value=0) String arg) throws NoSuchMethodException, ClassNotFoundException, InvocationTargetException, IllegalAccessException {
		try {
			Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + ".Version1_0_0.ClassInterceptor");
			Map<String, byte[]> resource_replacements = (Map<String, byte[]>) thisClass.getField("resource_replacements").get(null);

			if (resource_replacements.containsKey(arg))
				return new Object();

		} catch (ClassNotFoundException | NoSuchFieldException | IllegalAccessException e)
		{
			Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + "." + JavaAgent.version + ".JavaAgent");
			Method error_exit = thisClass.getMethod("error_exit", Exception.class);
			error_exit.invoke(null, e);
		}

		return null;
	}

	@Advice.OnMethodExit
	public static void intercept_exit(@Advice.Argument(value=0) String arg, @Advice.Return(readOnly=false) InputStream returnValue, @Advice.Enter Object entry) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		try {
			if (isNull(returnValue) && !isNull(entry))
			{
				Class<?> thisClass = ClassLoader.getSystemClassLoader().loadClass(JavaAgentMain.name + ".Version1_0_0.ClassInterceptor");
				Map<String, byte[]> resource_replacements = (Map<String, byte[]>) thisClass.getField("resource_replacements").get(null);
				if (resource_replacements.containsKey(arg))
					returnValue = new ByteArrayInputStream(resource_replacements.get(arg));
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
#endif