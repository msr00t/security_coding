



<img src="logo.png" alt="img" style="zoom:50%;" />













<div align = "center"><b><font size="7">Java安全编码指南</font></b></div>
<div align = "center"><b><font size="3"></font></b></div>
<div align = "center"><b></b></div>
<div style="page-break-after: always;"></div>

| **版本变更记录** |            |                                |  |
| :--------------: | :--------: | :----------------------------: | :----------------------: |
| **发布时间**     | **版本号** | **修订内容**                   | **修改人**               |
| 2021年9月30日 | V1.0       | 新建 | 8ypass |
|                  |            |                                |                          |
|                  |            |                                |                          |
|                  |            |                                |                          |
|                  |            |                                |                            |

<div style="page-break-after: always;"></div>
[TOC]



#  通用类

## 1. 代码实现

### 1.1 加密算法

#### 1.1.1<font color='red'>【必须】</font>禁止使用不安全的哈希算法

- DES和3DES MD5已经不再现代应用程序，应改为使用AES或RSA,SHA256。
```java
//PBKDF2-Hmac-SHA256加密案例
public static byte[] createHash(char[] password)
        throws NoSuchAlgorithmException, InvalidKeySpecException
{
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
    byte[] salt = new byte[8];
    random.nextBytes(salt);
    int iterCount = 50000;
    PBEKeySpec spec = new PBEKeySpec(password, salt, iterCount, 256);
    //PBKDF2WithHmacSHA256 is supportted from JDK1.8
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    byte[] hashed = skf.generateSecret(spec).getEncoded();
    return hashed;
}

```
#### 1.1.2<font color='red'>【必须】</font>禁止使用不安全的随机数生成器
- 伪随机生成器(PRNG)使用确认性数学算法来产生具有良好统计属性的数学序列,但这周数字序列并不具备真正的随即特性。伪随机数生成器通常以一个算术种子值为起始。算法使用该种子值生成一个输出及一个新的种子,这个种子又被用来生成下一个随机值.
- 伪随机数生成器 java.lang.Random
- 推荐使用java.security.SecureRandom
```java
//安全的随机数
public byte[] genRandBytes(int len)
{
	byte[] bytes = null;
	if (len > 0 && len < 1024)
	{
		bytes = new byte[len];
		SecureRandom random = new SecureRandom();
		random.nextBytes(bytes);
	}
	return bytes;
}
```


### 1.2 程序日志

#### 1.2.1 【建议】对每个重要行为都记录日志

- 确保重要行为都记录日志，且可靠保存6个月以上。


#### 1.2.2 【建议】禁止将未经验证的用户输入直接记录日志

- 当日志条目包含未经净化的用户输入时会引发记录注入漏洞。恶意用户会插入伪造的日志数据，从而让系统管理员以为是系统行为。


#### 1.2.3 <font color='red'>【必须】</font>避免在日志中保存敏感信息

- 不能在日志保存密码（包括明文密码和密文密码）、密钥(JWT Token)和其它敏感信息


### 1.3 系统口令

#### 1.3.1<font color='red'>【必须】</font>禁止使用空口令、弱口令、已泄露口令

#### 1.3.2 <font color='red'>【必须】</font>口令强度要求

>  口令强度须同时满足：
>  1. 密码长度大于13位【必须】
>  2.  密码中同一个字符不能重复3次 
>  3.  数字不能连续3位及以上 
>  4.  大写字母\小写字母\数字\特殊字符至少三种组合 
>  5. 必须包含下列元素：大小写英文字母、数字、特殊字符【必须】
>  6. 不得使用各系统、程序的默认初始密码【必须】
>  7. 不能与最近6次使用过的密码重复【建议】
>  8. 不得与其他外部系统使用相同的密码【建议】

#### 1.3.3 <font color='red'>【必须】</font>口令存储安全

* 禁止明文存储口令
* 禁止使用弱密码学算法（如DES和3DES）加密存储口令
* 使用不可逆算法和随机salt对口令进行加密存储

#### 1.3.4<font color='red'>【必须】</font>禁止传递明文口令
* 如登录表单在提交请求时,传输中的敏感字段中的值(username,password)需进行加密处理


#### 1.3.5 <font color='red'>【必须】</font>禁止在不安全的信道中传输口令

## 2. 配置&环境

### 2.1 平台安全

#### 2.1.1 <font color='red'>【必须】</font>使用安全管理器保护敏感操作

- 当应用需要加载非信任代码时,必须设置安全管理器,并且敏感操作必须经过安全管理器检查,防止被非信任代码调用。
```java
public class SensitiveHash
{
    Hashtable<Integer, String> ht = new Hashtable<Integer, String>();
    
    void removeEntry(Object key)
    {
        // 该例子示例使用安全管理器检查防止Hashtable实例中的条目被而已删除,如果调用者缺少SecurityPermission removeKeyPermission,则抛出异常
        check("removeKeyPermission");
        ht.remove(key);
    }
    private void check(String directive)
    {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null)
        {
            sm.checkSecurityAccess(directive);
        }
    }    
}
```
#### 2.1.2 <font color='red'>【必须】</font>防止特权区域内出现非法的数据

- java.security.AccessController类是java安全机制一部分,该类静态方法doPrivileged()执行的代码块不经过安全策略的检查,因此,任何含有doPrivileged()代码块的方法都需要保证敏感操作的安全性

```java
private void privilegedMethod(final String fileName) throws FileNotFoundException, InvalidArgumentException
{
    
    final String cleanFileName;
    cleanFileName = cleanAFileNameAndPath(fileName); //清除恶意传入的文件名内容,防止访问特权之外的文件
    try
    {
        FileInputStream fis = (FileInputStream) 
        AccessController.doPrivileged(new PrivilegedExceptionAction()
        {
            public FileInputStream run() throws FileNotFoundException
            {
                return new FileInputStream(cleanFileName);
            }
        });
        // do something with the file and then close it
    }
    catch (PrivilegedActionException e)
    {
        // forward to handler and log
    }
}
```
#### 2.1.3 <font color='red'>【必须】</font>避免完全依赖URLClassLoader和java.util.jar提供的默认自动签名认证机制
基于Java的技术通常使用Java Archive（JAR）特性为独立于平台的部署打包文件。例如，

对于Enterprise JavaBeans（EJB）、MIDlets（J2ME）和Weblogic Server J2EE等应用，JAR文件是首选的分发包方式。

Java Web Start提供的即点即击的安装也依赖于JAR文件格式打包。有需要时，厂商会为自己的JAR文件签名。这可以证明代码的真实性，但却不能保证代码的安全性。

客户代码可能缺乏代码签名的程序化检查。例如，URLClassLoader及其子类实例与java.util.jar自动验证JAR文件的签名。开发人员自定义的类加载器可能缺乏这项检查。而且，即便是在URLClassLoader中，自动验证也只是进行完整性检查，由于检查使用的是JAR包中未经验证的公钥，因此无法对加载类的真实性进行认证。合法的JAR文件可能会被恶意JAR文件替换，连同其中的公钥和摘要值也被适当替换和修改。

默认的自动签名验证过程仍然可以使用，但仅仅借助它是不够的。使用默认的自动签名验证过程的系统必须执行额外的检查来确保签名的正确性（（如与一个已知的受信任签名进行比较）。

#### 2.1.4 <font color='red'>【必须】</font>编写自定义类加载器时应调用超类的getPermission()函数
在自定义类加载器必须覆盖getPermissions()函数时，具体实现时，需要调用超类的getPermissions()函数，以顾及与遵循系统的默认安全策略。忽略了超类getPermissions()方法的自定义类加载器可能会加载权限提升了的非受信类。自定义类加载器时不要直接继承抽象的ClassLoader类。
```java
public class MyClassLoader extends URLClassLoader
{
    @Override
    protected PermissionCollection getPermissions(CodeSource cs)
    {
        PermissionCollection pc = super.getPermissions(cs);
        // allow exit from the VM anytime
        pc.add(new RuntimePermission("exitVM"));
        return pc;
    }
    // Other code…
}

```

### 2.2 配置信息

#### 2.2.1 <font color='red'>【必须】</font>密钥存储安全

- 在使用对称密码算法时，需要保护好加密密钥。


#### 2.2.2<font color='red'>【必须】</font>禁止硬编码敏感配置
- 禁止在源码中硬编码AK/SK、IP、数据库账号密码、JWT secret 阿里云 Access key secret等配置信息
- 应使用配置系统或KMS密钥管理系统。

### 2.3 运行环境

#### 2.3.1 <font color='red'>【必须】</font>生成代码不能包含任何调试入口点

一种常见的做法就是由于调试或者测试目的在代码中添加特定的后门代码，这些代码并没有打算与应用一起交付或者部署。当这类的调试代码不小心被留在了应用中，这个应用对某些无意的交互就是开放的。这些后门入口点可以导致安全风险，因为在设计和测试的时候并没有考虑到而且处于应用预期的运行情况之外。
被忘记的调试代码最常见的例子比如一个web应用中出现的调试方法。虽然这在产品生产的过程中也是可以接受的，但是在生产环境下，J2EE应用中的类是不应该定义有main()的。
```
//错误的例子
public static void main(String args[])
    {
        Stuff stuff = new Stuff();
        // Test stuff
    }
}

```

#### 2.3.2 <font color='red'>【必须】</font>不要禁用字节码验证

字节码验证器是JVM的一个内部组件,负责检测不合规的Java字节码.包含确认Class文件格式正确性,没有出现非法的类型转换,不会出现栈下溢。
```
//错误的案例 禁用字节码验证器

java -Xverify:none ApplicationName
```

```
//正确案例 启动字节码验证器 默认java就是启动的

java -Xverify:all ApplicationName
```

# 框架类

## 1.安全选项

### 1.1 spring

#### 1.1.1 <font color='red'>【必须】</font>springboot 禁止actuator未授权访问
可通过引入spring-security对actuator配置访问信息
```
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    management.security.enabled=true
    security.user.name=xxxxx
    security.user.password=xxxxx
```
#### 1.1.2 <font color='red'>【必须】</font>springboot actuator关闭非必要的接口

actuator包含以下接口
```
autoconfig
configprops
beans
dump
env
health
info
mappings
metrics
shutdown
trace
```
每个接口对应的功能不同,可在yaml文件中配置需要的接口
#### 1.1.3 <font color='red'>【必须】</font>springboot/springmvc不安全的框架绑定

springboot springmvc这类框架都有对象自动绑定的功能,常见的场景是遍历实体类中的参数传入的控制器进行后续操作.用户应禁用掉对应控制器中不需要的参数,防止框架自动绑定把参数传入到model进行处理.

#  后台类

## I. 代码实现

### 1.1 输入验证
#### 1.1.1<font color='red'>【必须】</font>按类型进行数据校验
- 所有程序外部输入的参数值，应进行数据校验。校验内容包括但不限于：数据长度、数据范围、数据类型与格式。如果校验不通过，应拒绝。
- 根据不同场景使用不同方法,如:白名单校验,黑名单过滤,基于框架自带的校验,如spring的JSR303


黑名单过滤

```java
//继承wrapper重写getparameter过滤参数
package com.demo.filter;

import com.demo.wrapper.filterwrapper;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class requestfilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        filterChain.doFilter(new filterwrapper((HttpServletRequest) servletRequest),servletResponse);


    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}

//filterwrapper
package com.demo.wrapper;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.Enumeration;
import java.util.Vector;

public class filterwrapper extends HttpServletRequestWrapper {

    ServletRequest req=null;

    public filterwrapper(HttpServletRequest request) {
        super(request);
        req=request;
    }


    @Override
    public String getParameter(String name) {

        String data=req.getParameter(name).replace("select","*").replace("union","*").replace("from","*");
        return data;
    }
}

```
白名单校验
```java
    public String getParameter(String name) {

        String data=req.getParameter(name);
        if(Pattern.matches("^[0-9A-Za-z]+$",data)){
            return data;
        }else{
            return null;
        }

    }
```
JSR303校验
```java
//使用JSR303校验需要引入以下依赖
		<dependency>
			<groupId>javax.validation</groupId>
			<artifactId>validation-api</artifactId>
		</dependency>
            
            
//一个实体类
@Valid
@Data
public class User {

    @DecimalMin("0") //设置值最小只能为0
    private BigDecimal free;
    
    @Email(message ='not email')
    private String email;

}
```

#### 1.1.2<font color='red'>【必须】</font>命令执行函数合法性校验

Runtim.exec经常被用来调用一个新进程,但是这个调用不会通过命令行shell来执行,因此无法通过管道符或链接的方式来连续执行多个命令,但是也需要注意某些可执行程序中特殊参数,如tcpdump的-Z参数



- 使用包括但不限于以下函数做命令执行的函数，需要对外部参数部分做合法性校验
  Runtime|ProcessBuilder|UNIXProcess|ProcessImpl|forkAndExec

- 注意事项:

  java在执行命令函数时,对传入String和String数组有不同的处理方法,传入String,第一个字符串当作被执行程序,后续字符均当成参数

```java
Runtime.getRuntime().exec("ping -t 127.0.0.1"); //这里除了ping被当作被执行程序,后续均当成参数

String[] command=new String[]{"cmd.exe","/c","ping","-c","127.0.0.1"};
Runtime.getRuntime().exec(commond); //基于数组执行
```

白名单校验例子

```java
StringBuffer str=new StringBuffer();
String temp="";
String data="127.0.0.1";

if(Pattern.matches("[0-9A-Za-z.]+",data)){ //通过正则匹配输入数据
            String[] command=new String[]{"cmd.exe","/c","ping","-a",data};
            Process result= Runtime.getRuntime().exec(command);
            BufferedReader buffer=new BufferedReader(new 	InputStreamReader(result.getInputStream()));
            while((temp=buffer.readLine())!=null){
                str.append(temp);
                str.append("\n");

            }
            System.out.println(str.toString());

        }
```



#### 1.1.3<font color='red'>【必须】</font>验证路径之前应该先将路径进行标准化

* 绝对路径名或相对路径名中可能会包含文件链接,如软连接,硬链接,快捷方式,别名,链接文件等,所有路径名在操作前都需要被完全解析到绝对路径进行判断

* 一个例子:

  当用户上传自定义压缩包到服务端后,服务端进行解压并存放到/tmp目录下，自定义压缩包中存在一个名为test的软连接文件(指向/var/www/html),服务端在解压操作完毕后并没有清空/tmp目录,用户在第二次自定义压缩包中设置路径test/123.class并上传,即可将文件上传到/var/www/html/目录一下，造成路径穿越

```java
//错误案例
File f=new File("path");
String absPath=f.getAbsolutePath(); //getAbsolutePath会返回文件绝对路径,但是不会解析文件链接
if(!isSecureDir(Paths.get(absPath))){
            
}

//正确案例
File f=new File("path");
String absPath=f.getCanonicalPath(); //getCanonicalPath会移除..,并解析文件链接
if(!isSecureDir(Paths.get(absPath))){
            
}
```

  


#### 1.1.4<font color='red'>【必须】</font>使用安全的方法获取用户请求地址

- 通过X-Forwarded-For Client-ip等字段获取到的ip均可伪造

```java
//错误案例
String data=req.getHeader("X-Forwarded-For");
if(data.equals("127.0.0.1")){
            //success
}else{
            //error
}
```
- 通过HttpServletRequest.getRemoteAddr获取
```java
//正确案例
String data=req.getRemoteAddr();
if(data.equals("127.0.0.1")){
	//success
}else{
	//error
}
```


### 1.2 SQL操作

#### 1.2.1 <font color='red'>【必须】</font>使用参数化查询

- 使用预编译方式，强制区分数据和命令，避免产生SQL注入漏洞。

```java
//mysql-connector包中的预编译操作
String name="com.mysql.cj.jdbc.Driver";
String connect="jdbc:mysql://localhost/mysql?user=root&password=root";
Class.forName(name);
String sql="select * from user where User = ?";
Connection conn=DriverManager.getConnection(connect);
PreparedStatement pre=conn.prepareStatement(sql);
pre.setString(1,"root"); //绑定值
ResultSet rs=pre.executeQuery();
```

* Mybatis框架中使用#{value},对参数进行预编译处理。

```xml
<select parameterType="String">
select * from user where name = #{name}
</select>

<update id="updateByExampleSelective" parameterType="map">
    update pay_channel_route
    <set>
      <if test="record.id != null">
        id = #{record.id,jdbcType=BIGINT}
      </if>
    </set>
</update>
```

#### 1.2.2 <font color='red'>【必须】</font>对参数进行过滤

- 对于比较复杂的SQL语句,在无法使用预编译,接收到外部参数拼接到SQL语句时，必须对外部参数进行安全过滤。

```java
public String strreplace(String args){
    args=args.replaceall("['|\"|%|union|select|from]","");
    return args;
}
```

### 1.3 执行命令

#### 1.3.1【建议】避免直接调用函数执行系统命令

- 相关功能的实现应避免直接调用系统命令（如`Runtime.exec()`、`ProcessBuilder.command()`、`ProcessImpl`、`UNIXProcess`），优先使用其他同类操作进行代替，比如：对文件进行读写操作,应通过文件系统API进行文件操作，而非直接调用命令执行函数进行操作
- 如评估无法避免，执行命令应避免拼接外部数据，同时进行执行命令的白名单限制。
```java
//对输入数据进行数据类型限制
StringBuffer str=new StringBuffer();
String temp="";
String data="127.0.0.1";

if(Pattern.matches("[0-9A-Za-z.]+",data)){ //通过正则匹配输入数据
            String[] command=new String[]{"cmd.exe","/c","ping","-a",data};
            Process result= Runtime.getRuntime().exec(command);
            BufferedReader buffer=new BufferedReader(new 	InputStreamReader(result.getInputStream()));
            while((temp=buffer.readLine())!=null){
                str.append(temp);
                str.append("\n");

            }
            System.out.println(str.toString());

        }

//ProcessBuilder

StringBuffer str = new StringBuffer();

String temp = "";

ProcessBuilder p = new ProcessBuilder();
String ip = "127.0.0.1";
if (Pattern.matches("[0-9A-Za-z.]+", ip)) {

            String[] command = new String[]{"cmd.exe", "/c", "ping", ip};
            p.command(command);
            Process result = p.start();
            BufferedReader buff = new BufferedReader(new InputStreamReader(result.getInputStream()));

            while ((temp = buff.readLine()) != null) {
                str.append(temp);
                str.append("\n");
            }
            System.out.println(str.toString());
}
```
#### 1.3.2<font color='red'>【必须】</font>过滤传入命令执行函数的字符

- 程序调用各类函数执行系统命令时，如果涉及的命令由外部传入，需要对外部传入的命令进行特殊字符的过滤后再拼接。

```java
public String strreplace(String args){
    args=args.replaceall("['|\"|$|?|`|(|)|;|\|%]","");
    return args;
}
```

### 1.4 XML读写

#### 1.4.1 <font color='red'>【必须】</font>禁用外部实体的方法

- 使用不可信数据来构造XML会导致XML注入漏洞,一个用户如果允许输入结构化的XML片段,则他可以在XML的数据域中注入XML标签来改写目标XML的文档结构与内容,XML解析器会对注入的标签进行识别和解释。

  

  以下是错误案例:

```java
//未经过检查的输入
private void createXMLStream(BufferedOutputStream buff, User user) throws IOException {
        String xmlString;
        xmlString="<user><role>operator</role></user><id>"+user.getName()+"</id>";
        buff.write(xmlString.getBytes());
        buff.flush();
}
```

```java
//dom4j SAXReader xxe
Element e=null;
SAXReader xml=new SAXReader();

Document doc=xml.read(new File("E:\\project\\java\\1.xml"));
List<Object> list=doc.selectNodes("/AAA/BBB/CD");
if(list.size()>0){
     e=(Element) list.get(0);
     Object obj=e.getData();
     System.out.println(obj);
}
```

```java
//DocumentBuilder xxe
DocumentBuilder dom=DocumentBuilderFactory.newInstance().newDocumentBuilder();
Document doc=dom.parse(new File("e:\\project\\java\\1.xml"));
NodeList n=doc.getElementsByTagName("CD");
if(n!=null){
            for(int i=0;i<n.getLength();i++){
                Node str=n.item(i);
                System.out.println(str.getFirstChild().getNodeValue());
	}
}
```

```java
//XMLInputFactory
XMLInputFactory xml=XMLInputFactory.newFactory();
XMLStreamReader x=xml.createXMLStreamReader(new FileReader("e:\\project\\java\\1.xml"));
```

```java
//SAXParser
SAXParserFactory factory = SAXParserFactory.newInstance();
SAXParser parser = factory.newSAXParser();
InputStream in = new ByteArrayInputStream(xmlstring.getBytes());
parser.parse(in,new  HandlerBase());
```

正确案例:

通过方法自带的功能禁用外部实体

```java
//SAXReader禁用外部实体
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
reader.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
reader.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);
reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);


//DocumentBuilder 禁用外部实体
dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
dbFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
dbFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
dbFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
dbFactory.setAttribute(XMLInputFactory.SUPPORT_DTD, false);  
dbFactory.setAttribute(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
dbFactory.setXIncludeAware(false);
dbFactory.setExpandEntityReferences(false);

//XMLInputFactory禁用外部实体
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
xif.setProperty(XMLInputFactory.SUPPORT_DTD, true); 

//SAXParser
saxBuilder.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
```

### 1.5 文件操作

#### 1.5.1<font color='red'>【必须】</font>文件类型限制

- 通过白名单校验方式对上传或者下载的文件类型、大小进行严格校验。仅允许业务所需文件类型上传，避免上传木马、WebShell等文件。

```java
//Servlet案例
protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        List<String> while_list=new ArrayList<>();
        while_list.add(".jpeg");
        while_list.add(".jpg");
        while_list.add(".json");
        while_list.add(".pdf");
        while_list.add(".png");
        Part p=req.getPart("file");


        String name=p.getSubmittedFileName();
        String type=name.substring(name.lastIndexOf(".")); //取后缀最后一位
        if(while_list.contains(type)){
            //上传相关操作
        }else{
            
            //别的操作
        }
```
```java
//Springboot案例
    @PostMapping(path = "/upload")
    @ResponseBody
    public String upload(@RequestParam("file") MultipartFile file) throws IOException {
        List<String> while_list=new ArrayList<>();
        while_list.add(".jpeg");
        while_list.add(".jpg");
        while_list.add(".json");
        while_list.add(".pdf");
        while_list.add(".png");
        
        if(file.isEmpty()){
            return "false";
        }
        String filename=file.getOriginalFilename();
        String ext=filename.substring(filename.lastIndexOf("."));
        if(while_list.contains(ext)){
            String filepath="./temp/";
            File dest=new File(filepath+filename);
            file.transferTo(dest);    
        }else{
     
        }  
        return "";
    }
```

#### 1.5.2 <font color='red'>【必须】</font>禁止外部文件存储于可执行目录

- 禁止外部文件存储于WEB容器的可执行目录。建议使用File类中的createTempDirectory方法处理临时文件和临时目录。

#### 1.5.3 <font color='red'>【必须】</font>避免路径拼接

- 文件目录避免外部参数拼接。保存文件时建议存储目录写死,并对文件名进行校验（字符类型、长度）。

#### 1.5.4 <font color='red'>【必须】</font>避免路径穿越

- 保存在本地文件系统时，必须对路径进行合法校验，避免目录穿越漏洞

```javascript
//通过File类自带的方法进行处理
File.getCanonicalPath()
File.isAbsolute()
```

#### 1.5.5 【建议】文件名hash化处理

- 建议文件保存时，将文件名替换为随机字符串,可使用java.lang.UUID来进行处理。

```javascript
    public String upload(@RequestParam("file") MultipartFile file) throws IOException {
        List<String> while_list=new ArrayList<>();
        while_list.add(".jpeg");
        while_list.add(".jpg");
        while_list.add(".json");
        while_list.add(".pdf");
        while_list.add(".png");

        if(file.isEmpty()){
            return "false";
        }
        String filename=file.getOriginalFilename();
        String ext=filename.substring(filename.lastIndexOf("."));
        if(while_list.contains(ext)){
            String savename=UUID.randomUUID().toString()+ext;
            String filepath="./temp/";
            File dest=new File(filepath+savename);
            file.transferTo(dest);

        }else{

        }

        return "";


    }
```
#### 1.5.6 <font color="red">【必须】</font>从ZipInputStream安全的提取文件

从java.util.zip.ZipInputStream中解压文件时需要小心谨慎。有两个特别的问题需要避免：一个是提取出的文件标准路径落在解压的目标目录之外，另一个是提取出的文件消耗过多的系统资源。对于前一种情况，攻击者可以从zip文件中往用户可访问的任何目录写入任意的数据。对于后一种情况，当资源使用远远大于输入数据所使用的资源的时，就可能会发生拒绝服务的问题。

```java
//正确案例
static final int BUFFER = 512;
static final int TOOBIG = 0x6400000; // max size of unzipped data, 100MB
static final int TOOMANY = 1024; // max number of files
// ...
private String sanitzeFileName(String entryName, String intendedDir) throws IOException
{
    File f = new File(intendedDir, entryName);
    String canonicalPath = f.getCanonicalPath();
    
    File iD = new File(intendedDir);
    String canonicalID = iD.getCanonicalPath();
    
    if (canonicalPath.startsWith(canonicalID))
    {
        return canonicalPath;
    }
    else
    {
        throw new IllegalStateException(
                "File is outside extraction target directory.");
    }
}
// ...
public final void unzip(String fileName) throws java.io.IOException
{
    FileInputStream fis = new FileInputStream(fileName);
    ZipInputStream zis = new ZipInputStream(new BufferedInputStream(fis));
    ZipEntry entry;
    int entries = 0;
    int total = 0;
    byte[] data = new byte[BUFFER];
    try
    {
        while ((entry = zis.getNextEntry()) != null)
        {
            System.out.println("Extracting: " + entry);
            int count;
            // Write the files to the disk, but ensure that the entryName is valid,
            // and that the file is not insanely big
            String name = sanitzeFileName(entry.getName(), ".");
            FileOutputStream fos = new FileOutputStream(name);
            BufferedOutputStream dest = new BufferedOutputStream(fos, BUFFER);
            while (total + BUFFER <= TOOBIG && (count = zis.read(data, 0, BUFFER)) != -1)
            {
                dest.write(data, 0, count);
                total += count;
            }
            dest.flush();
            dest.close();
            zis.closeEntry();
            entries++;
            if (entries > TOOMANY)
            {
                throw new IllegalStateException("Too many files to unzip.");
            }
            if (total > TOOBIG)
            {
                throw new IllegalStateException(
                        "File being unzipped is too big.");
            }
        }
    }
    finally
    {
        zis.close();
    }
}

```
#### 1.5.7 <font color="red">【必须】</font>临时文件使用完毕应及时删除

程序经常会在各系统的临时目录下创建临时文件,如/tmp与/var/tmp目录下,这些目录在系统一定时间内会被立即清理,但是不是立刻,在使用完毕后未进行清理会引发以下攻击场景。

文件被解压到/tmp目录下,但是操作完成后并未清空tmp目录,攻击者通过第二次上传压缩包解压到tmp目录,通过软连接达到任意目录上传文件的目的

#### 1.5.7 【建议】避免让外部进程阻塞在输入输出流上
java.lang.Runtime类的exec方法和ProcessBuilder.start方法可以被用来调用外部程序进程.这些外部程序运行时由java.lang.Process对象调用,这个对象包含一个输入流 输出流,以及一个错误流,这个进程可被java程序用来与外部程序通信,外部进程输入流是一个OutputStream对象.

不正确处理这些外部程序可能会导致一些意外的异常,dos 及其他问题.比如一个程序一直等待外部输入，外部没有提供,则会一直阻塞
```java
//错误案例

public class Exec
{
    public static void main(String args[]) throws IOException
    {
        Runtime rt = Runtime.getRuntime();
        Process proc = rt.exec("notemaker");
        int exitVal = proc.exitValue();
        //...
    }
}

```
程序未等Runtime调用完就执行exitvalue方法.

```java
//正确案例

public class Exec
{
    public static void main(String[] args) throws IOException,
            InterruptedException
    {
        
        Runtime rt = Runtime.getRuntime();
        Process proc = rt.exec("notemaker");
        
        // Any error message
        StreamGobbler errorGobbler = new StreamGobbler(proc.getErrorStream(),
                System.err);
        
        // Any output
        StreamGobbler outputGobbler = new StreamGobbler(proc.getInputStream(),
                System.out);
        
        errorGobbler.start();
        outputGobbler.start();
        
        int exitVal = proc.waitFor();
        // Any error
        errorGobbler.join(); // Handle condition where the
        outputGobbler.join(); // process ends before the threads finish
    }
}

```

### 1.6 网络请求

#### 1.6.1 <font color='red'>【必须】</font>限定访问网络地址范围

当程序需要从用户指定的`URL地址获取网页文本内容`、`加载指定地址的图片`、`进行下载`等操作时，需要对URL地址进行安全校验,防止SSRF攻击：

1. 只允许HTTP或HTTPS协议

2. 解析目标URL，获取其host

3. 解析host，获取host指向的IP地址转换成long型

4. 检查IP地址是否为内网IP

```python
# 以RFC定义的专有网络为例，如有自定义私有网段亦应加入禁止访问列表。
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
```

5. 请求URL

6. 如果有跳转，跳转后继续执行1(第一步)，否则对URL发起请求

### 1.7 响应输出

#### 1.7.1<font color='red'>【必须】</font>设置正确的HTTP响应包类型
响应包的HTTP头“Content-Type”必须正确配置响应包的类型，禁止非HTML类型的响应包设置为“text/html”。

#### 1.7.2<font color='red'>【必须】</font>设置安全的HTTP响应头

* X-Content-Type-Options

  添加“X-Content-Type-Options”响应头并将其值设置为“nosniff ”

* HttpOnly
   控制用户登鉴权的Cookie字段 应当设置HttpOnly属性以防止被XSS漏洞/JavaScript操纵泄漏。

* X-Frame-Options

  设置X-Frame-Options响应头，并根据需求合理设置其允许范围。该头用于指示浏览器禁止当前页面在frame、 iframe、embed等标签中展现。从而避免点击劫持问题。它有三个可选的值: DENY: 浏览器会拒绝当前页面加载任何frame页面; SAMEORIGIN:则frame页面的地址只能为同源域名下的页面 ALLOW-FROM origin:可以定义允许frame加载的页面地址。

#### 1.7.3<font color='red'>【必须】</font>页面包含第三方数据时须对第三方数据进行编码处理

- 当响应“Content-Type”为“text/html”类型时，需要对响应体进行编码处理,Servlet可自行继承Wrapper重写方法进行过滤,前后端分离的开发方式需要在返回的时候设置好Content-Type类型,如SpringBoot设置@Responsebody

```java
//重写wrapper
import javax.servlet.http.HttpServletRequest;  
import javax.servlet.http.HttpServletRequestWrapper;  
import org.apache.commons.lang3.StringEscapeUtils;  
      
    public class XssHttpServletRequestWrapper extends HttpServletRequestWrapper {  
      
        public XssHttpServletRequestWrapper(HttpServletRequest request) {  
            super(request);  
        }  
      
        @Override  
        public String getHeader(String name) {  
            return StringEscapeUtils.escapeHtml4(super.getHeader(name));  
        }  
      
        @Override  
        public String getQueryString() {  
            return StringEscapeUtils.escapeHtml4(super.getQueryString());  
        }  
      
        @Override  
        public String getParameter(String name) {  
            return StringEscapeUtils.escapeHtml4(super.getParameter(name));  
        }  
      
        @Override  
        public String[] getParameterValues(String name) {  
            String[] values = super.getParameterValues(name);  
            if(values != null) {  
                int length = values.length;  
                String[] escapseValues = new String[length];  
                for(int i = 0; i < length; i++){  
                    escapseValues[i] = StringEscapeUtils.escapeHtml4(values[i]);  
                }  
                return escapseValues;  
            }  
            return super.getParameterValues(name);  
        }  
          
    }
```

### 1.8 数据输出

#### 1.8.1<font color='red'>【必须】</font>敏感数据加密存储

- 敏感数据应使用安全的加解密算法进行存储
- 包含敏感信息的临时文件或缓存一旦不再需要应立刻删除

#### 1.8.2<font color='red'>【必须】</font>敏感信息必须由后台进行脱敏处理

- 敏感信息需要在后台进行脱敏后返回，禁止接口返回敏感信息后再交由前端/客户端进行脱敏处理。


#### 1.8.3<font color='red'>【必须】</font>高敏感信息禁止存储、展示

- 口令、密保答案、生物标识等鉴权信息禁止展示
- 非金融类业务，信用卡cvv码及日志禁止存储

#### 1.8.4<font color='red'>【必须】</font>个人敏感信息脱敏展示

在满足业务需求的情况下，个人敏感信息需脱敏展示，如：

- 身份证只显示第一位和最后一位字符，如3****************1。
- 移动电话号码隐藏中间6位字符，如134******48。
- 工作地址/家庭地址最多显示到“区”一级。
- 银行卡号仅显示最后4位字符，如************8639

#### 1.8.5【建议】隐藏后台地址

* 若程序对外提供了登录后台地址，应使用随机字符串隐藏地址。

```java
# 不要采取这种方式
String admin_login_url = "xxxx/login"
```

```java
# 安全示例
String admin_login_url = "xxxx/ranD0Str"
```

### 1.9 权限管理

#### 1.9.1<font color='red'>【必须】</font>默认鉴权

- 除非资源完全可对外开放，否则系统默认进行身份认证（使用白名单的方式放开不需要认证的接口或页面）。


#### 1.9.2【建议】授权遵循最小权限原则

- 程序默认用户应不具备任何操作权限。


#### 1.9.3<font color='red'>【必须】</font>避免越权访问

- 对于非公共操作，应当校验当前账号操作权限和数据权限校验。


1. 验证当前用户的登录态；
2. 从可信结构中获取经过校验的当前请求账号的身份信息（如：session），禁止从用户请求参数或Cookie中获取外部传入不可信用户身份直接进行查询；
3. 校验当前用户是否具备该操作权限；
4. 校验当前用户是否具备所操作数据的权限；
5. 校验当前操作是否账户是否预期账户。

#### 1.9.4【建议】及时清理不需要的权限

- 程序应定期清理非必需用户的权限。


### 1.10 异常处理

#### 1.10.1<font color='red'>【必须】</font>不向对外错误提示

* 应合理使用`try/except/finally` 处理系统异常，避免出错信息输出到前端。
* 对外环境禁止开启debug模式，或将程序运行日志输出到前端。

#### 1.10.2 <font color='red'>【必须】</font>禁止异常抛出敏感信息

#### 1.10.3 <font color='red'>【必须】</font>不要抑制或忽略已检查异常
编码人员常常会通过一个空的或者无意义的catch块来抑制捕获的已检查异常。每一个catch块都应该确保程序只会在继续有效的情况下才会继续运行下去。因此，catch块必须要么从异常情况进行恢复，要么重新抛出适合当前catch块上下文的另一个异常以允许最邻近的外层try-catch语句块来进行恢复工作。异常会打断应用原本预期的控制流程。例如，try块中位于异常发生点之后的任何表达式和语句都不会被执行。因此，异常必须被妥当处理。许多抑制异常的理由都是不合理的。

#### 1.10.4 <font color='red'>【必须】</font>方法发生异常时要恢复到之前的对象状态
当发生异常时,如果是关键的安全对象则需要维持其状态的一致性,如业务操作失败时,需要进行回滚



### 1.11 序列化和反序列化
#### 1.11.1【建议】序列化后的对象发送前需进行签名并加密
序列化数据在传输过程中要防止窃取和恶意篡改,使用安全的加密算法加密传输对象可以保护数据.

在以下场景中，需要对对象密封和数字签名来保证数据安全：

1) 序列化或传输敏感数据

2) 没有诸如SSL传输通道一类的安全通信通道或者对于有限的事务来说代价太高

3) 敏感数据需要长久保存（比如在硬盘驱动器上）

#### 1.11.2【建议】通过JEP290缓解反序列化漏洞

JEP290提供以下机制:

- 提供一个限制反序列化类的机制,包括白名单和黑名单
- 限制反序列化的深度和复杂度
- 为RMI远程调用对象提供了一个验证类的机制
- 定义一个可配置的过滤机制,比如可以通过配置properties文件的形式来定义过滤器