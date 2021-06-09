package net.encryptedkitten.java_network_interception_tool.Version1_0_0;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import net.bytebuddy.dynamic.loading.ClassReloadingStrategy;

import java.security.Signature;

import static net.bytebuddy.matcher.ElementMatchers.named;

public class SignatureInterceptor {
	//Patches all public key verifications to return true.
	public static void patchVerify()
	{
		new ByteBuddy()
			.redefine(Signature.class)
			.visit(Advice.to(SignatureInterceptor.class).on(named("verify")))
			.make()
			.load(ClassLoadingStrategy.BOOTSTRAP_LOADER, ClassReloadingStrategy.fromInstalledAgent())
			.getLoaded();
	}

	@Advice.OnMethodEnter(skipOn=Object.class)
	public static Object intercept_enter() {
		return new Object();
	}

	@Advice.OnMethodExit
	public static void intercept_exit(@Advice.Return(readOnly=false) boolean returnValue) {
		returnValue = true;
	}
}