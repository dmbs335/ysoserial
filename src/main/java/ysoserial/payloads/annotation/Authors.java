package ysoserial.payloads.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.AnnotatedElement;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
public @interface Authors {
    String FROHOFF = "frohoff";
    String PWNTESTER = "pwntester";
    String CSCHNEIDER4711 = "cschneider4711";
    String MBECHLER = "mbechler";
    String JACKOFMOSTTRADES = "JackOfMostTrades";
    String MATTHIASKAISER = "matthias_kaiser";
    String GEBL = "gebl";
    String JACOBAINES = "jacob-baines";
    String JASINNER = "jasinner";
    String KULLRICH = "kai_ullrich";
    String TINT0 = "_tint0";
    String SCRISTALLI = "scristalli";
    String HANYRAX = "hanyrax";
    String EDOARDOVIGNATI = "EdoardoVignati";
    String YKOSTER = "ykoster";
    String MEIZJM3I = "meizjm3i";
    String SCICCONE = "sciccone";
    String ZEROTHOUGHTS = "zerothoughts";
    String NAVALORENZO = "navalorenzo";
    String JANG = "Jang";
    String ARTSPLOIT = "artsploit";
    String K4n5ha0 = "k4n5ha0";
    String SU18 = "su18";  // ConcurrentHashMap CC chains, CB3/CB4, SignedObjectWrap, BeanShell2
    String HUGO_SYN = "hugo-syn";  // WildFly1, Synacktiv research
    String FIREBASKY = "Firebasky";  // ROME3
    String MOGWAI_HMUNCH = "hmunch";  // CommonsBeanutilsH2
    String BOFEI_CHEN = "BofeiC";  // JDD framework
    String ZEMA1 = "zema1";  // CommonsCollections K-series
    String Y4TACKER = "Y4tacker";  // Jackson native deser chains
    String MWULFTANGE = "mwulftange";  // Handcrafted gadgets (Jdk8u20)
    String DMBS335 = "dmbs335";  // Cross-library (CC13, CCJndi2) + CSLM (CC16, CB5, CBJndi3) + PBQ (CC17, CB6, CBJndi4) + BidiMap (CC18-23, CC21, CB7, CBJndi5, CCJndi3) + Bag (CC24-25) + toString (CC26-27) + CrossFamily (ROME6, Hibernate4) + Groovy2 + ROME5/ROMEJndi2 + WebLogic1/2 (CVE-2016-3510/0638 wrappers)

    String[] value() default {};

    public static class Utils {
        public static String[] getAuthors(AnnotatedElement annotated) {
            Authors authors = annotated.getAnnotation(Authors.class);
            if (authors != null && authors.value() != null) {
                return authors.value();
            } else {
                return new String[0];
            }
        }
    }
}
