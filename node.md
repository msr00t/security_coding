

















<div align = "center"><b><font size="7">Nodejs安全编码指南</font></b></div>
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
```javascript
//aes加密案例
const CryptoJS = require("crypto-js");

let key = CryptoJS.enc.Utf8.parse('qwe@@$@#sdas!fgdfg'); 
let encryptedData  = CryptoJS.AES.encrypt("abc", key, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
});
let hexData = encryptedData.ciphertext.toString();
console.log(hexData);
//================加密================
 
 
//================解密================
let encryptedHexStr  = CryptoJS.enc.Hex.parse(hexData);
let encryptedBase64Str  = CryptoJS.enc.Base64.stringify(encryptedHexStr);
let decryptedData  = CryptoJS.AES.decrypt(encryptedBase64Str, key, {
    mode: CryptoJS.mode.ECB,
    padding: CryptoJS.pad.Pkcs7
});
let text = decryptedData.toString(CryptoJS.enc.Utf8);
console.log(text);
```
#### 1.1.2<font color='red'>【必须】</font>禁止使用不安全的随机数生成器
- random模块是伪随机数生成器,所谓伪随机数,就是通过固定算法生成的，结果是可以预测。推荐使用random-number-csprng模块生成安全的随机数
```javascript
//不安全的随机数
console.log(Math.random())
console.log(crypto.randomBytes(127))
console.log(crypto.randomBytes(127))
//安全的随机数
//使用prng生成
console.log(crypto.prng(127).toString())
//使用rng生成
console.log(crypto.rng(127).toString())
//使用random-number-csprng模块生成
var Promise = require("bluebird");
var randomNumber = require("random-number-csprng");
 
Promise.try(function() {
    return randomNumber(10, 30);
}).then(function(number) {
    console.log("Your random number:", number);
}).catch({code: "RandomGenerationError"}, function(err) {
    console.log("Something went wrong!");
});

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

### 2.1 第三方包安全

#### 2.1.1 <font color='red'>【必须】</font>禁止使用不安全的npm包

- 引入第三方npm包时需要经过安全检验,可以使用npm的nsp或requireSafe来检验第三方软件包的安全性。


### 2.2 配置信息

#### 2.2.1 <font color='red'>【必须】</font>密钥存储安全

- 在使用对称密码算法时，需要保护好加密密钥。


#### 2.2.2<font color='red'>【必须】</font>禁止硬编码敏感配置
- 禁止在源码中硬编码AK/SK、IP、数据库账号密码、JWT secret 阿里云 Access key secret等配置信息
- 应使用配置系统或KMS密钥管理系统。

# 框架类

## 1.安全选项

### 1.1 express框架helmet安全中间件配置

#### 1.1.1 <font color='red'>【必须】</font>express安全配置--通过xssFilter来过滤xss

```javascript
const express = require("express");
const helmet = require("helmet");
const app = express();

app.use(helmet.xssFilter());
```
#### 1.1.2 <font color='red'>【必须】</font>express安全配置--通过noSniff禁止浏览器嗅探文件类型
```javascript
const express = require("express");
const helmet = require("helmet");
const app = express();

app.use(helmet.noSniff());
```
#### 1.1.3 <font color='red'>【必须】</font>express安全配置--通过app设置X-Powerd-By为false关闭中间件显示
```javascript
const express = require("express");
const app = express();

app.set('x-powered-by',false);
```

#### 1.1.4 【建议】express安全配置--通过nocache禁止浏览器缓存
```javascript
const express = require("express");
const helmet = require("helmet");
const app = express();

app.use(helmet.nocache());
```

#### 1.1.5 【建议】express安全配置--通过contentSecurityPolicy设置内容安全策略
```javascript
const express = require("express");
const helmet = require("helmet");
const app = express();

app.use(helmet.contentSecurityPolicy());
```
#### 1.1.6 【建议】express安全配置--通过ienoopen为IE8设置X-Download-Options
```javascript
const express = require("express");
const helmet = require("helmet");
const app = express();

app.use(helmet.ienoopen());
```




#  后台类

## I. 代码实现

### 1.1 输入验证
#### 1.1.1<font color='red'>【必须】</font>按类型进行数据校验
- 所有程序外部输入的参数值，应进行数据校验。校验内容包括但不限于：数据长度、数据范围、数据类型与格式。如果校验不通过，应拒绝。

- 推荐使用组件：validator,express-validator

```javascript
//validator
var express=require('express');
var validator=require('validator');
var app=express();
app.get('/test',function(req,res){
	var data=req.query.email;
	res.setHeader('Content-Type','text/html;charset=utf8');
	if(validator.isEmail(data)){
		res.send(data);	
	}
	res.send('false');
});
app.listen(8088,function(){});

//express-validator
const { body, validationResult } = require('express-validator');
app.post(
  '/user',
  // username must be an email
  body('username').isEmail(),
  // password must be at least 5 chars long
  body('password').isLength({ min: 5 }),
  (req, res) => {
    // Finds the validation errors in this request and wraps them in an object with handy functions
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    User.create({
      username: req.body.username,
      password: req.body.password,
    }).then(user => res.json(user));
  },
);
```
#### 1.1.2<font color='red'>【必须】</font>命令执行函数合法性校验
- 使用包括但不限于以下函数做命令执行的函数，需要对外部参数部分做合法性校验
child_process.exec|child_process.execSync|child_process.spawn|child_process.spawnSync|child_process.execFile|child_process.execFileSync
```javascript
//错误的使用案例
const Router = require("express");
const app=Router();
const { exec } = require('child_process');
app.get("/exec", (req, res) => {
	const txt = req.query.txt;
	exec(txt, (err, stdout, stderr) => {
		if (err) { res.send({ err: 1 }) }
		res.send({stdout, stderr});
	});
});
app.listen(8888,()=>console.log('run'));
//错误的使用案例
const Router = require("express");
const app=Router();
const { execSync } = require('child_process');
app.get("/execSync", (req, res) => {
	const txt = req.query.txt;
	execSync(txt, (err, stdout, stderr) => {
		if (err) { res.send({ err: 1 }) }
		res.send({stdout, stderr});
	});
});
app.listen(8888,()=>console.log('run'));
```
```python
#合规代码，对外部参数做合法格式校验
const Router = require("express");
const app=Router();
const { exec } = require('child_process');
app.get("/exec", (req, res) => {
	const txt = req.query.txt;
	const ress=txt.match(/(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])/);
	
	if(ress){
		const commond="ping "+ress
		exec(commond, (err, stdout, stderr) => {
		if (err) { res.send({ err: 1 }) }
		res.send({stdout, stderr});
		});
	}

});

app.listen(8888,function(){});
```
#### 1.1.3<font color='red'>【必须】</font>外部传入数值需要进行相应校验及处理

* 对外部输入的数值,除了要限制数据类型之外,还要对输入数据的最小值 最大值进行设置,并对输入的数值中的边界值进行相应处理。
* 当外部输入数值超出边界值后,后台代码需要对该超出边界值的数值有相应的兼容和处理,避免不兼容导致后续操作出现逻辑问题。
```javascript
//错误案例
//当购买金额大于账户金额时,返回NaN,但并未对返回NaN后做相应处理,还是接着运算,最终更新用户的余额
const Router = require("express");
const app=Router();
var mysql=require('mysql');
var connection=mysql.createConnection(
{
	host:'localhost',
	user:'root',
	password:'root',
	database:'test123'
}
);


app.get("/buy", (req, res) => {
	
	
	const buy = req.query.buy;
	const my_price=80
	const can_buy=20
	const equals_price=buy < my_price?my_price:NaN
	
	const buy_price=+(equals_price-can_buy)

	var  addSql = 'INSERT INTO user_price(Id,values) VALUES(0,?)';
	var addSqlParams = [1,buy_price];
	connection.connect();	
	connection.query(addSql,addSqlParams,function (err, result) {
        if(err){
         console.log('[INSERT ERROR] - ',err.message);
         return;
        }        
	});
});

app.listen(8888,function(){});

```
```JavaScript
//正确案例
//先判断购买量是否大于市场总量,然后再判断用户余额是否大于购买量


const Router = require("express");
const app=Router();
var mysql=require('mysql');
var connection=mysql.createConnection(
{
	host:'localhost',
	user:'root',
	password:'root',
	database:'test123'
}
);


app.get("/buy", (req, res) => {
	
	
	const buy = req.query.buy;
	const my_price=80
	const can_buy=20
    if(buy>can_buy){
        //当购买数大于当前可购买的总量时,做相应处理
    }
    
	const equals_price=buy < my_price?my_price:NaN //对金额进行一个判断
	
	if(equals_price==my_price){
		const buy_price=+(equals_price-buy)
		var  addSql = 'INSERT INTO user_price(Id,values) VALUES(0,?)';
		var addSqlParams = [1,buy_price];
		connection.connect();	
		connection.query(addSql,addSqlParams,function (err, result) {
			if(err){
			 console.log('[INSERT ERROR] - ',err.message);
			 return;
			}        
		});	
	}else{
		
		//對於NaN相應的處理
		
	}
	
});

app.listen(8888,function(){});

```

#### 1.1.4<font color='red'>【必须】</font>使用安全的方法获取用户请求地址

- 通过X-Forwarded-For Client-ip等字段获取到的ip均可伪造

```javascript
//错误案例
const Router = require("express");
const app=Router();
const validator = require("validator");
const { execFileSync } = require('child_process');

var fs=require("fs");

var xss=require('node-xss').clean;


app.get("/test", (req, res) => {
	if(req.headers['X-Forwarded-For'] == 8.8.8.8){
		
		res.send('Password:');
	}
});
app.listen(8888,()=>console.log('run'));
```
- 通过req.socket.remoteAddress或req.connection.socket.remoteAddress获取的ip无法伪造
```javascript
//正确案例
const Router = require("express");
const app=Router();
const validator = require("validator");
const { execFileSync } = require('child_process');



app.get("/test", (req, res) => {
	if(req.socket.remoteAddress == 8.8.8.8){
		res.send('Password:')
	}
});
app.listen(8888,()=>console.log('run'));
```


### 1.2 SQL操作

#### 1.2.1 <font color='red'>【必须】</font>使用参数化查询

- 使用参数化SQL语句，强制区分数据和命令，避免产生SQL注入漏洞。

```javascript
//错误的案例
const Router = require("express");
const app=Router();
var mysql=require('mysql');
var connection=mysql.createConnection(
{
	host:'localhost',
	user:'root',
	password:'root',
	database:'test123'
}
);

app.get("/test", (req, res) => {
	connection.connect();
	connection.query('select * from message where aaa=\''+req.query.value+'\'',function(error,result,fields){
		console.log(error);
		res.send(result);
	});
	
	
});
app.listen(8888,()=>console.log('run'));
```

* 使用官方预编译模式来预防sql注入。

```javascript
//安全示例
app.post("/insert", (req, res) => {
	const data = req.query.data;
	var  addSql = 'INSERT INTO message(Id,values) VALUES(0,?)';
	var addSqlParams = [1,data];
	connection.connect();	
	connection.query(addSql,addSqlParams,function (err, result) {
        if(err){
         console.log('[INSERT ERROR] - ',err.message);
         return;
        }        
	});
 
	connection.end();
});
```

#### 1.2.2 <font color='red'>【必须】</font>对参数进行过滤

- 对于比较复杂的SQL语句,在无法使用ORM框架,接收到外部参数拼接到SQL语句时，必须对外部参数进行安全过滤。

```javascript
function strreplace(args){
    args=args.replace(/'|"|#|-|%|$|^|&|\||(|)/,'');
    return args;
}
```

### 1.3 执行命令

#### 1.3.1【建议】避免直接调用函数执行系统命令

- 相关功能的实现应避免直接调用系统命令（如`child_process.exec()`、`child_process.execSync()`、`child_process.spawn()`、`child_process.spawnSync()`、`child_process.execFile()`、`child_process.execFileSync`等），优先使用其他同类操作进行代替，比如：对文件进行读写操作,应通过文件系统API进行文件操作，而非直接调用命令执行函数进行操作
- 如评估无法避免，执行命令应避免拼接外部数据，同时进行执行命令的白名单限制。
```javascript
const { exec } = require('child_process');

var args="-t"
var commond="ping "
var while_list=new Array("-t","-a");

for(i=0;i<while_list.length;i++){
	
	if(args==while_list[i]){
		exec("ping "+while_list[i]+" 127.0.0.1",function(){});
	}
}
```
#### 1.3.2<font color='red'>【必须】</font>过滤传入命令执行函数的字符

- 程序调用各类函数执行系统命令时，如果涉及的命令由外部传入，需要对外部传入的命令进行特殊字符的过滤后再拼接。

```javascript
const { exec } = require('child_process');

var args=req.query.arg
var commond="|passwd admin"
args=args.replace(/`|$|;|(|@|#|%|^|?|'|"/,'')
commond=args+commond
exec(commond,function(){});
```

### 1.4 XML读写

#### 1.4.1 <font color='red'>【必须】</font>禁用外部实体的方法

- 使用xml2js，xml2js底层会自动忽略DTD。

```javascript
//XXE案例
const app = require("express")(),
const libxml = require("libxmljs");
app.post("/parser", (req, res) => {
  let xmlPayload = req.body,
  doc = libxml.parseXml(xmlPayload, { noent: true });
});
```

### 1.5 文件操作

#### 1.5.1<font color='red'>【必须】</font>文件类型限制

- 通过白名单校验方式对上传或者下载的文件类型、大小进行严格校验。仅允许业务所需文件类型上传，避免上传木马、WebShell等文件。

```javascript
//错误案例
const Router = require("express");
const app=Router();
const multer=require('multer');

var storage=multer.diskStorage({
	destination: function (req, file, cb) {
        cb(null, './images'); 
    },
    filename: function (req, file, cb) {
		console.log(file);
        cb(null, file.originalname);  
	}
});
var upload=multer({storage:storage});
var fs=require("fs");
app.post("/uploadimg", upload.single('file'),function(req,res){
});
app.listen(8888,()=>console.log('run'));

//正确案例
const Router = require("express");
const app=Router();
const multer=require('multer');

var storage=multer.diskStorage({
	destination: function (req, file, cb) {
        cb(null, './images'); 
    },
    filename: function (req, file, cb) {
		ext=file.originalname.substring(file.originalname.lastIndexOf(".")+1);
		if(ext=="png"){
			cb(null, file.originalname);  	
		}    
	}
});
var upload=multer({storage:storage});
var fs=require("fs");
app.post("/uploadimg", upload.single('file'),function(req,res){
});
app.listen(8888,()=>console.log('run'));
```

#### 1.5.2 <font color='red'>【必须】</font>禁止外部文件存储于可执行目录

- 禁止外部文件存储于WEB容器的可执行目录。建议使用fs库中的mkdtemp函数处理临时文件和临时目录。

#### 1.5.3 <font color='red'>【必须】</font>避免路径拼接

- 文件目录避免外部参数拼接。保存文件时建议存储目录写死,并对文件名进行校验（字符类型、长度）。

#### 1.5.4 <font color='red'>【必须】</font>避免路径穿越

- 保存在本地文件系统时，必须对路径进行合法校验，避免目录穿越漏洞

```javascript
//路径过滤操作
function strreplace(path){
    path=path.replace(/.|\//,'');
    return args;
}
```

#### 1.5.5 【建议】文件名hash化处理

- 建议文件保存时，将文件名替换为随机字符串,可使用crypto.randomUUID来进行处理。

```javascript
const Router = require("express");
const app=Router();
const multer=require('multer');

var storage=multer.diskStorage({
	destination: function (req, file, cb) {
        cb(null, './images'); 
    },
    filename: function (req, file, cb) {
		ext=file.originalname.substring(file.originalname.lastIndexOf(".")+1);
		if(ext=="png"){
            file.originalname=crypto.randomUUID().toString()+ext
			cb(null, file.originalname);  	
		}    
	}
});
var upload=multer({storage:storage});
var fs=require("fs");
app.post("/uploadimg", upload.single('file'),function(req,res){
});
app.listen(8888,()=>console.log('run'));
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

- 当响应“Content-Type”为“text/html”类型时，需要对响应体进行编码处理

```javascript
const Router = require("express");
const app=Router();
const validator = require("validator");
const { execFileSync } = require('child_process');
var xss=require('node-xss').clean;
app.get("/test", (req, res) => {
	const txt = req.query.txt;
	res.send(xss(txt));

});
app.listen(8888,()=>console.log('run'));
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

```javascript
# 不要采取这种方式
var admin_login_url = "xxxx/login"
```

```javascript
# 安全示例
var admin_login_url = "xxxx/ranD0Str"
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



