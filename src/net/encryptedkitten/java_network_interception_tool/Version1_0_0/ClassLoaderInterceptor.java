package net.encryptedkitten.java_network_interception_tool.Version1_0_0;

import net.bytebuddy.asm.Advice;
import java.security.CodeSource;

import static net.bytebuddy.matcher.ElementMatchers.*;

import net.bytebuddy.dynamic.loading.ClassReloadingStrategy;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;

public class ClassLoaderInterceptor {

	//Signature patches ClassLoader to nullify all signing certificates from the loaded class jars.
	public static void patchCheckCerts() {
		new ByteBuddy()
				.redefine(ClassLoader.class)
				.visit(Advice.to(ClassLoaderInterceptor_checkCerts.class).on(named("checkCerts")))
				.make()
				.load(ClassLoadingStrategy.BOOTSTRAP_LOADER, ClassReloadingStrategy.fromInstalledAgent())
				.getLoaded();
	}
}

class ClassLoaderInterceptor_checkCerts {
	@Advice.OnMethodEnter
	public static void intercept_enter(@Advice.Argument(value=1, readOnly = false) CodeSource arg) {
		arg = null;
	}
}