<div align = "center"><b><font size="7">Python安全编码指南</font></b></div>
<div align = "center"><b></b></div>
<div style="page-break-after: always;"></div>
| **版本变更记录** |            |                                |  |
| :--------------: | :--------: | :----------------------------: | :----------------------: |
| **发布时间**     | **版本号** | **修订内容**                   | **修改人**               |
| 2021年9月15日 | V1.0       | 新建 | 8ypass |
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

- DES和3DES MD5已经不再现代应用程序，应改为使用AES或SHA。
```python
from Crypto.Cipher import AES
import base64
password = '1234567890123456'.encode(encoding="utf-8")
text = '1234567890123456'.encode(encoding="utf-8")
model = AES.MODE_ECB
aes = AES.new(password,model)
en_text=aes.encrypt(text)
base64_en_text=base64.encodebytes(aes.encrypt(text))
print(base64_en_text)
print(base64.decodebytes(base64_en_text))
```
```python
sha256 = hashlib.sha256()
sha256.update('abc'.encode(encoding='utf-8'))
print(sha256.hexdigest())
```
#### 1.1.2<font color='red'>【必须】</font>禁止使用不安全的随机数生成器
- random模块是伪随机数生成器,所谓伪随机数,就是通过固定算法生成的，结果是可以预测，一般情况下需要伪随机数需要提供一个种子,如果没有设置,则种子为系统的时钟。推荐使用secrets模块生成安全的随机数
```python
#不安全的随机数
import random
random.randint(1,100)

#安全的随机数
import secrets
secret_generator=secrets.SystemRandom()
secret_generator.randint(1,100)
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

### 2.1 Python版本选择

#### 2.1.1【建议】使用Python 3.6+的版本

- 新增的项目应使用 Python 3.6+


> **为什么要这么做？**
> 由于 Python 2 在 [2020 年停止维护](https://www.python.org/doc/sunset-python-2/)，相关组件的漏洞不能得到及时修复与维护

### 2.2 第三方包安全

#### 2.2.2 <font color='red'>【必须】</font>禁止使用不安全的组件

- 有一些发布到PyPi的包与官方的包具有相似的名称,但却在包中添加了恶意代码,可以通过PyUp.io网址来校验第三方包是否安全。


### 2.3 配置信息

#### 2.3.1 <font color='red'>【必须】</font>密钥存储安全

- 在使用对称密码算法时，需要保护好加密密钥。


#### 2.3.2<font color='red'>【必须】</font>禁止硬编码敏感配置
- 禁止在源码中硬编码AK/SK、IP、数据库账号密码、JWT secret 阿里云 Access key secret等配置信息
- 应使用配置系统或KMS密钥管理系统。

# 框架类

## 1.安全选项

### 1.1 框架安全配置

#### 1.1.1 <font color='red'>【必须】</font>Django&Flask安全配置--关闭DEBUG模式

- 防止堆栈信息泄露

#### 1.1.2 <font color='red'>【必须】</font>Django安全配置--关闭swagger调试

- 防止接口信息泄露

#### 1.1.3<font color='red'>【必须】</font>Django安全配置--妥善保存SECRET_KEY

- 防止通过泄露的SECRET_KEY伪造用户信息

#### 1.1.4 【建议】Django安全配置--使用SecurityMiddleware

- 默认安全配置

#### 1.1.5 【建议】Django安全配置--设置SECURE_HSTS_SECONDS开启HSTS头，强制HTTPS访问

- 防止MITM攻击

#### 1.1.6 <font color='red'>【必须】</font>Django安全配置--设置SECURE_CONTENT_TYPE_NOSNIFF输出nosniff头，防止类型混淆类漏洞

- 防止浏览器内容嗅探功能导致XSS

#### 1.1.6 <font color='red'>【必须】</font>Django安全配置--设置SECURE_BROWSER_XSS_FILTER输出x-xss-protection头，让浏览器强制开启XSS过滤

- 作为XSS的消减措施

#### 1.1.7<font color='red'>【必须】</font>Django安全配置--设置SECURE_SSL_REDIRECT让HTTP的请求强制跳转到HTTPS

- 防止MITM攻击

#### 1.1.7 <font color='red'>【必须】</font>Django安全配置--设置SESSION_COOKIE_SECURE使Cookie为Secure，不允许在HTTP中传输

- 防止会话劫持

#### 1.1.8 <font color='red'>【必须】</font>Django安全配置--设置X_FRAME_OPTIONS返回X-FRAME-OPTIONS: DENY头，以防止被其他页面作为框架加载导致ClickJacking

- 防止clickjacking



#  后台类

## I. 代码实现

### 1.1 输入验证
#### 1.1.1<font color='red'>【必须】</font>按类型进行数据校验
- 所有程序外部输入的参数值，应进行数据校验。校验内容包括但不限于：数据长度、数据范围、数据类型与格式。如果校验不通过，应拒绝。

- 推荐使用组件：[Cerberus](https://github.com/pyeve/cerberus)、[jsonschema](https://github.com/Julian/jsonschema)、[Django-Validators](https://docs.djangoproject.com/en/dev/ref/validators/)

```python
# Cerberus示例
from cerberus import Validator

schema={'name':{'type':'integer'}}
v=Validator(schema)
document={'name':'test'}
result=v.validate(document)
print(result)
# jsonschema示例
schema = {
     "type" : "object",
     "properties" : {
         "price" : {"type" : "number"},
         "name" : {"type" : "string"},
     },
}
validate(instance={"name" : "Eggs", "price" : 34.99}, schema=schema)

# Django-Validators
class CustomerReportRecord(models.Model):
    time_raised = models.DateTimeField(default=timezone.now, editable=False)
    reference = models.CharField(unique=True, max_length=20)
    description = models.TextField()
```
#### 1.1.2<font color='red'>【必须】</font>命令执行函数合法性校验
- 使用包括但不限于以下函数做命令执行的函数，需要对外部参数部分做合法性校验
(os.system|os.spawn|os.popen|popen2\.|commands\.)\w*|(import|from)\s+\b(popen2|commands|subprocess.|importlib)\b
```python
#不合规代码，直接拼接外部参数拿去执行：
host = request.args.get("host")
os.system("ping %s" % host)
```
```python
#合规代码，对外部参数做合法格式校验
host = request.args.get("host")
if(re.match(r"(\d+\.){3}\d+$", host) is not None)
{
    os.system("ping %s" % host)
}
```
### 1.2 服务端模板渲染

#### 1.2.1 <font color='red'>【必须】</font>模板渲染过滤验证
- 使用模板内容与视图代码分开的形式，避免产生模板注入
```python
#不合规的代码
#直接把用户输入拼接到%s中，可直接导致模板注入
@app.route('/1')
def main():
    template = '''{%% extends "base.html" %%}
{%% block body %%}
    <div class="center-content error">
        <h1>Oops! That page doesn't exist.</h1>
        <h3>%s</h3>
    </div>
{%% endblock %%}
''' % (request.url)
    return render_template_string(template, dir=dir, help=help, locals=locals)
```
```python
 #合规代码
@app.route('/')
def safe():
    return render_template('home.html', url=request.args.get('p')) #模板内容与视图代码分开
```

### 1.3 SQL操作

#### 1.3.1 <font color='red'>【必须】</font>使用参数化查询

- 使用参数化SQL语句，强制区分数据和命令，避免产生SQL注入漏洞。

```python
# 错误示例
import mysql.connector

mydb = mysql.connector.connect(
... ...
)
cur = mydb.cursor()
userid = get_id_from_user()
# 使用%直接格式化字符串拼接SQL语句
cur.execute("SELECT `id`, `password` FROM `auth_user` WHERE `id`=%s " % (userid,)) 
myresult = cur.fetchall()
```

```python
# 安全示例
import mysql.connector

mydb = mysql.connector.connect(
... ...
)
cur = mydb.cursor()
userid = get_id_from_user()
# 将元组以参数的形式传入
cur.execute("SELECT `id`, `password` FROM `auth_user` WHERE `id`=%s ", (userid,))
myresult = cur.fetchall()
```

* 使用ORM框架来操作数据库，如：使用`SQLAlchemy`。

```python
# 安装sqlalchemy并初始化数据库连接
# pip install sqlalchemy
from sqlalchemy import create_engine
# 初始化数据库连接，修改为你的数据库用户名和密码
engine = create_engine('mysql+mysqlconnector://user:password@host:port/DATABASE')
```

```python
# 引用数据类型
from sqlalchemy import Column, String, Integer, Float
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
# 定义 Player 对象:
class Player(Base):
    # 表的名字:
    __tablename__ = 'player'

    # 表的结构:
    player_id = Column(Integer, primary_key=True, autoincrement=True)
    team_id = Column(Integer)
    player_name = Column(String(255))
    height = Column(Float(3, 2))
```

```python
# 增删改查
from sqlalchemy.orm import sessionmaker
# 创建 DBSession 类型:
DBSession = sessionmaker(bind=engine)
# 创建 session 对象:
session = DBSession()

# 增:
new_player = Player(team_id=101, player_name="Tom", height=1.98)
session.add(new_player)
# 删:
row = session.query(Player).filter(Player.player_name=="Tom").first()
session.delete(row)
# 改:
row = session.query(Player).filter(Player.player_name=="Tom").first()
row.height = 1.99
# 查:
rows = session.query(Player).filter(Player.height >= 1.88).all()

# 提交即保存到数据库:
session.commit()
# 关闭 session:
session.close()
```
#### 1.3.2 <font color='red'>【必须】</font>对参数进行过滤

- 对于比较复杂的SQL语句,在无法使用ORM框架,接收到外部参数拼接到SQL语句时，必须对外部参数进行安全过滤。

```python
def sql_filter(sql, max_length=20):
    dirty_stuff = ["\"", "\\", "/", "*", "'", "=", "-", "#", ";", "<", ">", "+", 
                   "&", "$", "(", ")", "%", "@", ","]
    for stuff in dirty_stuff:
        sql = sql.replace(stuff, "x")
    return sql[:max_length]
```

### 1.4 执行命令

#### 1.4.1【建议】避免直接调用函数执行系统命令

- 相关功能的实现应避免直接调用系统命令（如`os.system()`、`os.popen()`、`subprocess.call()`、`exec`、`eval`等），优先使用其他同类操作进行代替，比如：对文件进行读写操作,应通过文件系统API进行文件操作，而非直接调用命令执行函数进行操作
- 如评估无法避免，执行命令应避免拼接外部数据，同时进行执行命令的白名单限制。
```python
def exec_commond(cmd,arg,arg2):
	commond=""
	while_cmd=["ping","nslookup"]
	while_arg=["-t","-opt"]
	if cmd in while_cmd:
		commond=commond+cmd+" "
	if arg in while_arg:
		commond=commond+arg+"%s"
	if(re.match(r"(\d+\.){3}\d+$", arg2) is not None):
		os.system(commond % arg2)
```
#### 1.4.2<font color='red'>【必须】</font>过滤传入命令执行函数的字符

- 程序调用各类函数执行系统命令时，如果涉及的命令由外部传入，需要对外部传入的命令进行特殊字符的过滤后再拼接。

```python
import os
import sys
import shlex

domain = sys.argv[1]
# 替换可以用来注入命令的字符为空
badchars = "\n&;|'\"$()`-!@#%^&*-"
for char in badchars:
    domain = domain.replace(char, " ")

result = os.system(shlex.quote(domain)+"|passwd admin")
```

### 1.5 XML读写

#### 1.5.1 <font color='red'>【必须】</font>禁用外部实体的方法

- 通过python内置库自带的方法禁用外部实体，来预防XXE攻击。

```python
from lxml import etree
  
xmlData = etree.parse(xmlSource,etree.XMLParser(resolve_entities=False))
```

### 1.6 文件操作

#### 1.6.1<font color='red'>【必须】</font>文件类型限制

- 通过白名单校验方式对上传或者下载的文件类型、大小进行严格校验。仅允许业务所需文件类型上传，避免上传木马、WebShell等文件。

```python
import os
  
ALLOWED_EXTENSIONS = ['txt','jpg','png']
  
def allowed_file(filename):
    if ('.' in filename and 
        '..' not in filename and 
        os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS): #禁止了目录穿越和除白名单以外的文件上传
        
        return filename
    return None
```

#### 1.6.2 <font color='red'>【必须】</font>禁止外部文件存储于可执行目录

- 禁止外部文件存储于WEB容器的可执行目录。建议使用 [tempfile](https://docs.python.org/3/library/tempfile.html) 库处理临时文件和临时目录。

#### 1.6.3 <font color='red'>【必须】</font>避免路径拼接

- 文件目录避免外部参数拼接。保存文件时建议存储目录写死,并对文件名进行校验（字符类型、长度）。

#### 1.6.4 <font color='red'>【必须】</font>避免路径穿越

- 保存在本地文件系统时，必须对路径进行合法校验，避免目录穿越漏洞

```python
import os

upload_dir = '/tmp/upload/' # 预期的上传目录
file_name = '../../etc/hosts' # 用户传入的文件名
absolute_path = os.path.join(upload_dir, file_name) # /tmp/upload/../../etc/hosts
normalized_path = os.path.normpath(absolute_path) # /etc/hosts
if not normalized_path.startswith(upload_dir): # 检查最终路径是否在预期的上传目录中
    raise IOError()
```

#### 1.6.5 【建议】文件名hash化处理

- 建议文件保存时，将文件名替换为随机字符串。

```python
import uuid

def random_filename(filename):
    ext = os.path.splitext(filename)[1]
    new_filename = uuid.uuid4().hex + ext
    return new_filename
```
#### 1.6.6 <font color='red'>【必须】</font>使用os.path.join拼接路径时进行路径过滤

- 需要对传入参数中的/进行过滤

```python
import os

print(os.path.join('/var/www/html','/etc')) #这里直接返回/etc

print(os.path.join('/var/www/html','./etc')) #这里直接返回/var/www/html/etc
```

### 1.7 网络请求

#### 1.7.1 <font color='red'>【必须】</font>限定访问网络地址范围

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

### 1.8 响应输出

#### 1.8.1<font color='red'>【必须】</font>设置正确的HTTP响应包类型
响应包的HTTP头“Content-Type”必须正确配置响应包的类型，禁止非HTML类型的响应包设置为“text/html”。

#### 1.8.2<font color='red'>【必须】</font>设置安全的HTTP响应头

* X-Content-Type-Options

  添加“X-Content-Type-Options”响应头并将其值设置为“nosniff ”

* HttpOnly
   控制用户登鉴权的Cookie字段 应当设置HttpOnly属性以防止被XSS漏洞/JavaScript操纵泄漏。

* X-Frame-Options

  设置X-Frame-Options响应头，并根据需求合理设置其允许范围。该头用于指示浏览器禁止当前页面在frame、 iframe、embed等标签中展现。从而避免点击劫持问题。它有三个可选的值: DENY: 浏览器会拒绝当前页面加载任何frame页面; SAMEORIGIN:则frame页面的地址只能为同源域名下的页面 ALLOW-FROM origin:可以定义允许frame加载的页面地址。

#### 1.8.3<font color='red'>【必须】</font>页面包含第三方数据时须对第三方数据进行编码处理

- 当响应“Content-Type”为“text/html”类型时，需要对响应体进行编码处理

```python
# 推荐使用mozilla维护的bleach库来进行过滤
import bleach
bleach.clean('an <script>evil()</script> example')
# u'an &lt;script&gt;evil()&lt;/script&gt; example'
```

### 1.9 数据输出

#### 1.9.1<font color='red'>【必须】</font>敏感数据加密存储

- 敏感数据应使用安全的加解密算法进行存储
- 包含敏感信息的临时文件或缓存一旦不再需要应立刻删除

#### 1.9.2<font color='red'>【必须】</font>敏感信息必须由后台进行脱敏处理

- 敏感信息需要在后台进行脱敏后返回，禁止接口返回敏感信息后再交由前端/客户端进行脱敏处理。


#### 1.9.3<font color='red'>【必须】</font>高敏感信息禁止存储、展示

- 口令、密保答案、生物标识等鉴权信息禁止展示
- 非金融类业务，信用卡cvv码及日志禁止存储

#### 1.9.4<font color='red'>【必须】</font>个人敏感信息脱敏展示

在满足业务需求的情况下，个人敏感信息需脱敏展示，如：

- 身份证只显示第一位和最后一位字符，如3****************1。
- 移动电话号码隐藏中间6位字符，如134******48。
- 工作地址/家庭地址最多显示到“区”一级。
- 银行卡号仅显示最后4位字符，如************8639

#### 1.9.5【建议】隐藏后台地址

* 若程序对外提供了登录后台地址，应使用随机字符串隐藏地址。

```python
# 不要采取这种方式
admin_login_url = "xxxx/login"
```

```python
# 安全示例
admin_login_url = "xxxx/ranD0Str"
```

### 1.10 权限管理

#### 1.10.1<font color='red'>【必须】</font>默认鉴权

- 除非资源完全可对外开放，否则系统默认进行身份认证（使用白名单的方式放开不需要认证的接口或页面）。


#### 1.10.2【建议】授权遵循最小权限原则

- 程序默认用户应不具备任何操作权限。


#### 1.10.3<font color='red'>【必须】</font>避免越权访问

- 对于非公共操作，应当校验当前账号操作权限和数据权限校验。


1. 验证当前用户的登录态；
2. 从可信结构中获取经过校验的当前请求账号的身份信息（如：session），禁止从用户请求参数或Cookie中获取外部传入不可信用户身份直接进行查询；
3. 校验当前用户是否具备该操作权限；
4. 校验当前用户是否具备所操作数据的权限；
5. 校验当前操作是否账户是否预期账户。

#### 1.10.4【建议】及时清理不需要的权限

- 程序应定期清理非必需用户的权限。


### 1.11 异常处理

#### 1.11.1<font color='red'>【必须】</font>不向对外错误提示

* 应合理使用`try/except/finally` 处理系统异常，避免出错信息输出到前端。
* 对外环境禁止开启debug模式，或将程序运行日志输出到前端。

#### 1.11.2 <font color='red'>【必须】</font>禁止异常抛出敏感信息


### 1.12 并发

#### 1.12.1<font color='red'>【必须】</font>线程安全

- 对于并发操作，应当保证线程之间不会相互干扰，确保同一个内存地址只有一个线程操作，防止条件竞争。
- 可通过互斥锁保证线程之间互不干扰
```python
from threading import Thread,Lock
import time


x=Lock()
y=Lock()
a=100
def testx():
    global a
    x.acquire()
    a+=1
    print(a)
    x.release()
def testy():
    global a
    y.acquire()
    a-=1
    print(a)
    y.release()
    
if __name__ == '__main__':
    t1=Thread(target=testx)
    t2=Thread(target=testy)
    t1.start()
    t2.start()
```


